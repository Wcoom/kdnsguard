#!/system/bin/sh
# 开机流程走完后的收尾：清引导标记（表示"这次加载没有把设备弄崩"）。
MODDIR=${0%/*}
LOG="$MODDIR/onboot.log"
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG"; }

rm -f "$MODDIR/.boot"

# 节点若在 post-fs-data 阶段还没建（内核模块那时可能尚未注册），这里补一次。
if [ ! -e /dev/kdnsguard ]; then
	MAJ=$(awk '/kdnsguard/ {print $1; exit}' /proc/devices 2>/dev/null)
	[ -n "$MAJ" ] && mknod /dev/kdnsguard c "$MAJ" 0 && chmod 600 /dev/kdnsguard && \
		log "设备节点已补建 major=$MAJ"
fi

# 记一行状态：内核自启是否已完成接管（诊断用，不影响任何行为）。
sleep 20
if [ -x "$MODDIR/kdgctl" ]; then
	OWN=$("$MODDIR/kdgctl" health 2>/dev/null | awk '/ownership/ {print $5; exit}')
	log "开机后 ownership=${OWN:-?}（2 = 内核已接管 53）"
fi
