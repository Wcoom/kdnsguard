#!/system/bin/sh
# 常驻自检：配置被 BoxProxy 冲掉就再补。挂在 service.d 的子 shell 里，
# 开机后是 init 的子孙，不经过 adb su。
set +e
KDG=/data/adb/kdnsguard
LOG=$KDG/log
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [loop] $*" >> "$LOG"; }
log "自检循环开始 pid=$$"
while [ -f "$KDG/enabled" ]; do
	sh "$KDG/apply.sh"
	sleep 20
done
log "enabled 已撤，循环退出"
exit 0
