#!/system/bin/sh
# 最小窗口：只验证 SO_REUSEADDR。不换核心、不改配置。
set +e
T=/data/local/tmp
OUT=$T/kdg-final
KO=$T/kdnsguard.ko
mkdir -p $OUT

echo "########## 0. 基线 ##########"
echo "private_dns=$(settings get global private_dns_mode)"
echo "mihomo=$(pidof mihomo || echo stopped)"
echo "modules=$(lsmod | wc -l)"
lsmod | grep kdns || echo 'kdnsguard 未加载'

echo "########## 1. 加载 ##########"
rmmod kdnsguard 2>/dev/null
dmesg -c >/dev/null 2>&1
insmod $KO allow_intercept=1 || { echo insmod fail; exit 1; }
MAJOR=$(dmesg | sed -n 's/.*\/dev\/kdnsguard 已注册（major \([0-9]*\).*/\1/p' | tail -1)
echo "major=$MAJOR"
rm -f /dev/kdnsguard
mknod /dev/kdnsguard c $MAJOR 0
chmod 660 /dev/kdnsguard
$T/kdgctl trust $T/kdg_root.pem
echo "--- PREPARE 1 ---"
$T/kdgctl prepare 1
echo "--- COMMIT ---"
$T/kdgctl commit 1
$T/kdgctl 2>&1 | grep -E 'ownership|listener_ready'

echo "########## 2. TCP 查询（制造 TIME_WAIT）##########"
$T/netprobe tcp 223.5.5.5 example.com
$T/netprobe tcp 8.8.8.8 github.com
ss -tln 2>/dev/null | grep 1054 || echo 'ss 看不到内核 socket（预期）'
echo "TIME_WAIT on 1054:"
grep 'sport=1054' /proc/net/nf_conntrack | head -6

echo "########## 3. DISABLE 后立刻 PREPARE（旧代码这里 EADDRINUSE）##########"
$T/kdgctl disable
echo "ownership after disable:"
$T/kdgctl 2>&1 | grep ownership
echo "--- PREPARE 2 ---"
$T/kdgctl prepare 2
echo "prepare2 rc=$?"
$T/kdgctl 2>&1 | grep -E 'ownership|listener_ready'
echo "--- COMMIT 2 ---"
$T/kdgctl commit 2
$T/netprobe udp 223.5.5.5 example.com
$T/kdgctl disable

echo "########## 4. 卸模块 ##########"
$T/chrneg /dev/kdnsguard
if command -v timeout >/dev/null; then
	timeout 15 rmmod kdnsguard
else
	/data/adb/ksu/bin/busybox timeout 15 rmmod kdnsguard
fi
lsmod | grep kdns && echo '!!! 模块还在' || echo '模块未加载'
echo "warn=$(dmesg | grep -cE 'BUG:|WARNING:|Oops|CFI failure|Internal error')"
echo "REUSE_OK"
