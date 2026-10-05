#!/system/bin/sh
# kdnsguard 模块开机脚本（KernelSU/Magisk 的 post-fs-data 阶段）。
#
# 它只做两件内核做不了的事：insmod、建设备节点。信任锚与接管都由模块自己在
# 内核里完成（编进 .ko 的 CA + 自动 PREPARE/COMMIT 重试），因此这里**没有**
# 任何"等 mihomo、等配置、喂证书"的步骤 —— 这正是「开机不依赖脚本」的落点。
MODDIR=${0%/*}
LOG="$MODDIR/onboot.log"
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG"; }

# ── 引导保护：绝不让设备进入开机循环 ──────────────────────────────────
# 标记在加载**之前**创建，由 service.sh（开机完成后才跑）清除。
# 于是「下次开机还看到标记」就等于「上次加载把设备弄崩了」—— 立刻自我停用，
# 不再加载。要恢复只需删掉 $MODDIR/disable。
if [ -f "$MODDIR/.boot" ]; then
	touch "$MODDIR/disable"
	rm -f "$MODDIR/.boot"
	log "上次开机未走到 service.sh，已自我停用（删 $MODDIR/disable 可恢复）"
	exit 0
fi
[ -f "$MODDIR/disable" ] && exit 0
touch "$MODDIR/.boot" 2>/dev/null

[ -f "$MODDIR/kdnsguard.ko" ] || { log "没有 kdnsguard.ko，跳过"; exit 0; }
if [ -d /sys/module/kdnsguard ]; then
	log "模块已在（内建或已加载），跳过 insmod"
else
	insmod "$MODDIR/kdnsguard.ko" allow_intercept=1 auto_start=1
	log "insmod rc=$?"
fi

# 设备节点：Android 的 /dev 是 tmpfs，devtmpfs 不会替字符设备建节点。
# 主设备号动态分配，读 /proc/devices 取。
if [ ! -e /dev/kdnsguard ]; then
	MAJ=$(awk '/kdnsguard/ {print $1; exit}' /proc/devices 2>/dev/null)
	if [ -n "$MAJ" ]; then
		mknod /dev/kdnsguard c "$MAJ" 0
		chmod 600 /dev/kdnsguard
		log "设备节点已建 major=$MAJ"
	else
		log "init_net 里还看不到 kdnsguard（下一阶段走 service.sh 再试）"
	fi
fi
