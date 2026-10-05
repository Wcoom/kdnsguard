#!/system/bin/sh
# KernelSU service.d：开机把 kdnsguard 接到 Path A。
# 与 boxproxy-box.sh 并行；我们等它把 startup-config 写出来再补丁并重启核心。
(
set +e
export PATH="/data/adb/magisk:/data/adb/ksu/bin:/data/adb/ap/bin:/system/bin:$PATH"
KDG=/data/adb/kdnsguard
B=/data/user/0/com.boxproxy.box/files/box
CFG=$B/run/state/startup-config
STATE=$(dirname "$CFG")
CTL=$B/bin/boxctl
BB=/data/adb/ksu/bin/busybox
LOG=$KDG/log

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [boot] $*" >> "$LOG"; }

[ -f "$KDG/enabled" ] || exit 0
mkdir -p "$KDG"
: >> "$LOG"

while [ "$(getprop init.svc.bootanim 2>/dev/null)" != "stopped" ]; do
	sleep 5
done

# 先加载模块，再等 BoxProxy。顺序反过来会让核心先以用户态起来再被我们重启。
if ! lsmod | grep -q '^kdnsguard'; then
	if [ -f "$KDG/kdnsguard.ko" ]; then
		insmod "$KDG/kdnsguard.ko" allow_intercept=1
		log "insmod rc=$?"
	else
		log "没有 kdnsguard.ko，放弃"
		exit 0
	fi
fi
if [ ! -e /dev/kdnsguard ]; then
	maj=$($BB awk '/kdnsguard/ {print $1; exit}' /proc/devices)
	if [ -n "$maj" ]; then
		mknod /dev/kdnsguard c "$maj" 0
		chmod 660 /dev/kdnsguard
		log "mknod major=$maj"
	else
		log "读不到 major，放弃改配置"
		exit 0
	fi
fi

i=0
while [ $i -lt 60 ]; do
	[ -x "$CTL" ] && [ -f "$CFG" ] && break
	sleep 2
	i=$((i + 1))
done
if [ ! -f "$CFG" ]; then
	log "等不到 startup-config，放弃"
	exit 0
fi
sleep 8

settings put global private_dns_mode off 2>/dev/null
sh "$KDG/apply.sh"
# 循环自检：BoxProxy 从 DB 重生配置时，最多 20 秒补回。
# 不用 inotifyd —— KernelSU 的 adb su -c 会收掉普通守护进程；
# 本段跑在 service.d 的子 shell 里，是 init 的子孙，循环能活过整次开机。
sh "$KDG/loop.sh"
log "开机完成 pid=$(pidof mihomo)"
) >/dev/null 2>&1 &
exit 0
