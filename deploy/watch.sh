#!/system/bin/sh
# 监视 BoxProxy 重生 startup-config。变了且不再是内核后端就再 apply。
# busybox inotifyd：事件作为 $1，路径作为 $2。
set +e
KDG=/data/adb/kdnsguard
LOG=$KDG/log
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [watch] $*" >> "$LOG"; }

[ -f "$KDG/enabled" ] || exit 0
# 防抖：BoxProxy 可能连写几次
sleep 1
log "事件 $1 $2"
sh "$KDG/apply.sh"
exit 0
