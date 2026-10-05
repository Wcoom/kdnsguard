#!/system/bin/sh
# 字符设备失败路径反向探针 + rmmod。必须在还原阶段、核心已停之后跑。
# 旧代码：短写 / pwrite 偏移会漏 kdg_op_exit，rmmod 永久等待。
T=/data/local/tmp
OUT=$T/kdg-final

echo "########## chrneg ##########"
$T/chrneg /dev/kdnsguard | tee $OUT/chrneg.txt
echo "chrneg rc=$?"

echo
echo "########## rmmod（限 15s；卡住即本轮修法没生效）##########"
# toybox timeout 存在；没有就用 busybox
TO=timeout
command -v timeout >/dev/null || TO=/data/adb/ksu/bin/busybox\ timeout
$TO 15 rmmod kdnsguard
echo "rmmod rc=$?"
lsmod | grep kdns && echo '!!! 模块还在' || echo '模块已卸'
[ ! -e /proc/modules ] || grep kdns /proc/modules || true
echo "kdg_pool 线程=$(ps -A | grep -c '\[kdg_pool\]' || echo 0)"
echo "CHRNEG_OK"
