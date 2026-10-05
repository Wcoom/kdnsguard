#!/system/bin/sh
# 还原：停核心 → chrneg → 原二进制 + 原配置逐字节回去 → disable → rmmod。
# 必须尽量跑完：cleanup trap 在部署前也可能进来。
set +e
B=/data/user/0/com.boxproxy.box/files/box
BIN=$B/bin/mihomo
CFG=$B/run/state/startup-config
T=/data/local/tmp
OUT=$T/kdg-final
CTL=$B/bin/boxctl

echo "########## 1. 停核心 ##########"
$CTL service stop 2>&1 | tail -3
sleep 2
pidof mihomo >/dev/null && kill -9 $(pidof mihomo)
sleep 1
echo "pid=$(pidof mihomo || echo none)"

echo "########## 2. 字符设备失败路径（必须在 rmmod 之前）##########"
if lsmod | grep -q kdnsguard; then
	$T/chrneg /dev/kdnsguard | tee $OUT/chrneg.txt
	echo "chrneg rc=$?"
else
	echo "模块已不在，跳过 chrneg"
fi

echo "########## 3. 交还所有权 ##########"
$T/kdgctl disable 2>&1 | tail -3
$T/kdgctl 2>&1 | grep ownership

echo "########## 4. 原二进制 ##########"
if [ -f $OUT/mihomo.orig ]; then
	cp -a $OUT/mihomo.orig $BIN
	chown root:net_admin $BIN
	chmod 6755 $BIN
	chcon u:object_r:app_data_file:s0 $BIN 2>/dev/null
	echo "bin md5=$(md5sum $BIN | awk '{print $1}')  orig=$(md5sum $OUT/mihomo.orig | awk '{print $1}')"
else
	echo "没有备份核心，跳过二进制还原"
fi

echo "########## 5. 原配置 ##########"
if [ -f $OUT/startup-config.orig ]; then
	cp -a $OUT/startup-config.orig $CFG
	echo "cfg md5=$(md5sum $CFG | awk '{print $1}')  orig=$(md5sum $OUT/startup-config.orig | awk '{print $1}')"
	grep -nE 'enhanced-mode|backend:|dns-mode:' $CFG | head
else
	echo "没有备份配置，跳过配置还原"
fi

echo "########## 6. 卸模块 ##########"
if command -v timeout >/dev/null; then
	timeout 15 rmmod kdnsguard
else
	/data/adb/ksu/bin/busybox timeout 15 rmmod kdnsguard
fi
rmmod kdnsguard 2>/dev/null
lsmod | grep kdns && echo '!!! 模块还在' || echo '模块未加载'
echo "kdg_pool 线程=$(ps -A | grep -c '\[kdg_pool\]')"

echo "########## 7. 终态 ##########"
echo "modules=$(lsmod | wc -l)"
echo "warn=$(dmesg | grep -cE 'BUG:|WARNING:|Oops|CFI failure|Internal error')"
echo "private_dns=$(settings get global private_dns_mode)"
echo "ddl=$(cat /proc/oplus_scheduler/sched_assist/sched_ddl_enabled 2>/dev/null)"
echo "zram=$(cat /sys/block/zram0/comp_algorithm 2>/dev/null)"
echo "su=$(id)"
$CTL status 2>&1 | head -6
echo "RESTORE_OK"
