SKIPUNZIP=0
# kdnsguard 模块安装期检查。
#
# 模块是**树外 KO**，与内核 vermagic 绑定：内核一换（刷机、OTA），旧 .ko 就装不
# 上去。所以这里明确核对并把结论打出来，而不是让用户开机后才发现 insmod 失败。

ui_print "- kdnsguard：内核态 DNS 接管（树外 KO + 开机自加载）"

ARCH=$(uname -m)
[ "$ARCH" = "aarch64" ] || abort "! 本模块只支持 aarch64，当前 $ARCH"

KVER=$(uname -r)
ui_print "- 当前内核: $KVER"

KO="$MODPATH/kdnsguard.ko"
[ -f "$KO" ] || abort "! 模块包里没有 kdnsguard.ko"

# vermagic 是内核写进 .ko 的版本串，必须与 uname -r 一致才能加载。
VERMAGIC=$(strings "$KO" | grep -m1 -E '^6\.[0-9]+\.[0-9]+' | head -1)
case "$KVER" in
	*"$VERMAGIC"*) ui_print "- vermagic 匹配: $VERMAGIC" ;;
	*) ui_print "! 警告: 模块 vermagic（$VERMAGIC）与当前内核（$KVER）可能不符"
	   ui_print "! 若开机后日志显示 insmod 失败，请用匹配内核重新构建 .ko" ;;
esac

set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/kdnsguard.ko" 0 0 0644
set_perm "$MODPATH/post-fs-data.sh" 0 0 0755
set_perm "$MODPATH/service.sh" 0 0 0755
[ -f "$MODPATH/kdgctl" ] && set_perm "$MODPATH/kdgctl" 0 0 0755

ui_print "- 开机时内核模块会自带信任锚并自行完成 PREPARE/COMMIT（无需脚本）"
ui_print "- 引导异常自我保护：连续两次开机未完成会自我停用，绝不进入开机循环"
ui_print "- 完成"
