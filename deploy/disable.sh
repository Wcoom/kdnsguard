#!/system/bin/sh
# 停掉常驻：还原核心与配置、卸模块、下次开机不再启用。
set +e
KDG=/data/adb/kdnsguard
B=/data/user/0/com.boxproxy.box/files/box
CFG=$B/run/state/startup-config
BIN=$B/bin/mihomo
CTL=$B/bin/boxctl
LOG=$KDG/log
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [disable] $*" >> "$LOG"; }

rm -f "$KDG/enabled"
killall inotifyd 2>/dev/null
killall kdgwatchd 2>/dev/null
# loop.sh 看到 enabled 消失后自己退出；这里再兜一次
pkill -f "$KDG/loop.sh" 2>/dev/null

"$CTL" service stop >/dev/null 2>&1
sleep 1
pidof mihomo >/dev/null && kill -9 $(pidof mihomo) 2>/dev/null
sleep 1

if [ -x "$KDG/kdgctl" ]; then
	"$KDG/kdgctl" disable >/dev/null 2>&1
fi
rmmod kdnsguard 2>/dev/null

if [ -f "$KDG/mihomo.stock" ]; then
	cp -a "$KDG/mihomo.stock" "$BIN"
	chown root:net_admin "$BIN"
	chmod 6755 "$BIN"
	chcon u:object_r:app_data_file:s0 "$BIN" 2>/dev/null
	log "核心已还原 $(md5sum "$BIN" | awk '{print $1}')"
fi
if [ -f "$KDG/startup-config.stock" ]; then
	cp -a "$KDG/startup-config.stock" "$CFG"
	log "配置已还原 $(md5sum "$CFG" | awk '{print $1}')"
fi

rm -f /data/adb/service.d/99-kdnsguard.sh
"$CTL" service start >/dev/null 2>&1
log "已停用 pid=$(pidof mihomo)"
echo "kdnsguard 常驻已关闭"
exit 0
