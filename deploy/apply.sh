#!/system/bin/sh
# 把 startup-config 改成内核后端 + Path A（dns-mode: off）。
# 已经是目标态则什么都不做（给 inotify 防重启循环）。
# 模块没加载则拒绝改配置，避免「YAML 写了 kernel 但设备节点不存在」的假启用。
set +e
KDG=/data/adb/kdnsguard
B=/data/user/0/com.boxproxy.box/files/box
CFG=$B/run/state/startup-config
BIN=$B/bin/mihomo
CTL=$B/bin/boxctl
BB=/data/adb/ksu/bin/busybox
LOG=$KDG/log
NEW=$KDG/mihomo-kdgp4final
PEM=$KDG/kdg_root.pem

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [apply] $*" >> "$LOG"; }

need_patch() {
	[ -f "$CFG" ] || return 1
	grep -q '^  backend: kernel$' "$CFG" || return 0
	grep -q '^  dns-mode: off$' "$CFG" || return 0
	grep -q '^  enhanced-mode: fake-ip$' "$CFG" && return 0
	return 1
}

ensure_node() {
	if [ -e /dev/kdnsguard ]; then
		return 0
	fi
	maj=$($BB awk '/kdnsguard/ {print $1; exit}' /proc/devices)
	[ -n "$maj" ] || return 1
	mknod /dev/kdnsguard c "$maj" 0
	chmod 660 /dev/kdnsguard
}

ensure_module() {
	if lsmod | grep -q '^kdnsguard'; then
		ensure_node
		return 0
	fi
	[ -f "$KDG/kdnsguard.ko" ] || { log "没有 kdnsguard.ko"; return 1; }
	insmod "$KDG/kdnsguard.ko" allow_intercept=1 || { log "insmod 失败"; return 1; }
	sleep 0.3
	ensure_node || { log "mknod 失败"; return 1; }
	maj=$($BB awk '/kdnsguard/ {print $1; exit}' /proc/devices)
	log "模块已加载 major=$maj"
}

patch_yaml() {
	# busybox awk。只动 dns.enhanced-mode 那一行和 listeners 的 dns-mode。
	$BB awk '
		/^  enhanced-mode: fake-ip$/ {
			print "  enhanced-mode: redir-host"
			print "  backend: kernel"
			print "  kernel-device: /dev/kdnsguard"
			print "  kernel-trust-file: /data/adb/kdnsguard/kdg_root.pem"
			print "  kernel-delegate-ebpf: false"
			next
		}
		/^  enhanced-mode: redir-host$/ {
			print
			# 若后面还没有 backend 行，补上（idempotent：已有则 awk 再扫到原行照印）
			next
		}
		/^  dns-mode: hijack$/ { print "  dns-mode: off"; next }
		{ print }
	' "$CFG" > "$CFG.kdgnew" || return 1
	# redir-host 已在、但缺 backend：再补一次
	if grep -q '^  enhanced-mode: redir-host$' "$CFG.kdgnew" && \
	   ! grep -q '^  backend: kernel$' "$CFG.kdgnew"; then
		$BB awk '
			/^  enhanced-mode: redir-host$/ {
				print
				print "  backend: kernel"
				print "  kernel-device: /dev/kdnsguard"
				print "  kernel-trust-file: /data/adb/kdnsguard/kdg_root.pem"
				print "  kernel-delegate-ebpf: false"
				next
			}
			{ print }
		' "$CFG.kdgnew" > "$CFG.kdgnew2" && mv "$CFG.kdgnew2" "$CFG.kdgnew"
	fi
	if ! grep -q '^  backend: kernel$' "$CFG.kdgnew"; then
		log "补丁后仍无 backend: kernel，放弃"
		rm -f "$CFG.kdgnew" "$CFG.kdgnew2"
		return 1
	fi
	mv "$CFG.kdgnew" "$CFG"
	chmod 600 "$CFG"
	return 0
}

ensure_core() {
	[ -x "$NEW" ] || { log "没有 mihomo-kdgp4final"; return 1; }
	want=$($BB md5sum "$NEW" | $BB awk '{print $1}')
	have=$($BB md5sum "$BIN" | $BB awk '{print $1}')
	[ "$want" = "$have" ] && return 0
	log "替换核心 $have -> $want"
	"$CTL" service stop >/dev/null 2>&1
	sleep 1
	pidof mihomo >/dev/null && kill -9 $(pidof mihomo) 2>/dev/null
	sleep 1
	cp "$NEW" "$BIN.new" || return 1
	chown root:net_admin "$BIN.new"
	chmod 6755 "$BIN.new"
	chcon u:object_r:app_data_file:s0 "$BIN.new" 2>/dev/null
	mv "$BIN.new" "$BIN"
	return 0
}

[ -f "$KDG/enabled" ] || { log "未启用，跳过"; exit 0; }
lsmod | grep -q '^kdnsguard' || ensure_module || exit 1
ensure_node || exit 1
[ -f "$PEM" ] || { log "没有信任锚 $PEM"; exit 1; }

need_core=0
if [ -x "$NEW" ]; then
	want=$($BB md5sum "$NEW" | $BB awk '{print $1}')
	have=$($BB md5sum "$BIN" | $BB awk '{print $1}')
	[ "$want" != "$have" ] && need_core=1
fi
need_yaml=0
need_patch && need_yaml=1

if [ "$need_core" -eq 0 ] && [ "$need_yaml" -eq 0 ]; then
	exit 0
fi

[ "$need_core" -eq 1 ] && ensure_core
[ "$need_yaml" -eq 1 ] && patch_yaml

settings put global private_dns_mode off 2>/dev/null
"$CTL" service restart >/dev/null 2>&1
log "已应用 need_core=$need_core need_yaml=$need_yaml pid=$(pidof mihomo)"
exit 0
