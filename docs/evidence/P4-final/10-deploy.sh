#!/system/bin/sh
# 部署：停核心 → 换二进制 → 换配置 → 加载模块 → 启动。
# 任一步失败立刻回滚到进入本脚本前的状态。
set -e
B=/data/user/0/com.boxproxy.box/files/box
BIN=$B/bin/mihomo
CFG=$B/run/state/startup-config
T=/data/local/tmp
OUT=$T/kdg-final
CTL=$B/bin/boxctl
NEW=$T/mihomo-kdgp4final
KO=$T/kdnsguard.ko
NEWCFG=$T/startup-kernel.yaml

rollback() {
	echo "!!! 回滚：$1"
	$CTL service stop >/dev/null 2>&1 || true
	sleep 1
	if [ -f $OUT/mihomo.orig ]; then
		cp -a $OUT/mihomo.orig $BIN
		chown root:net_admin $BIN
		chmod 6755 $BIN
		chcon u:object_r:app_data_file:s0 $BIN 2>/dev/null || true
	fi
	if [ -f $OUT/startup-config.orig ]; then
		cp -a $OUT/startup-config.orig $CFG
	fi
	$T/kdgctl disable >/dev/null 2>&1 || true
	rmmod kdnsguard 2>/dev/null || true
	echo "回滚完成"
	exit 1
}

echo "########## 1. 备份 ##########"
cp -a $BIN $OUT/mihomo.orig
cp -a $CFG $OUT/startup-config.orig
echo "bin=$(md5sum $OUT/mihomo.orig | awk '{print $1}')"
echo "cfg=$(md5sum $OUT/startup-config.orig | awk '{print $1}')"

echo "########## 2. 停核心（进程在跑时 cp 会 Text file busy）##########"
$CTL service stop 2>&1 | tail -3 || true
sleep 2
pidof mihomo && rollback "停核心后进程还在" || echo "mihomo 已停"

echo "########## 3. 原子替换核心 ##########"
cp $NEW $BIN.new || rollback "拷新核心失败"
chown root:net_admin $BIN.new
chmod 6755 $BIN.new
chcon u:object_r:app_data_file:s0 $BIN.new
mv $BIN.new $BIN
echo "新核心 md5=$(md5sum $BIN | awk '{print $1}')"
$BIN -v 2>&1 | head -2

echo "########## 4. 换配置 ##########"
cp $NEWCFG $CFG
chmod 600 $CFG
echo "新配置 md5=$(md5sum $CFG | awk '{print $1}')"
grep -nE 'enhanced-mode|backend:|kernel-|dns-mode:' $CFG | head

echo "########## 5. 加载模块 ##########"
rmmod kdnsguard 2>/dev/null || true
dmesg -c >/dev/null 2>&1 || true
insmod $KO allow_intercept=1 || rollback "insmod 失败"
# major 从刚写下的那条日志读，不写死 440
MAJOR=$(dmesg | sed -n 's/.*\/dev\/kdnsguard 已注册（major \([0-9]*\).*/\1/p' | tail -1)
echo "major=$MAJOR"
[ -n "$MAJOR" ] || rollback "读不到 major"
rm -f /dev/kdnsguard
mknod /dev/kdnsguard c $MAJOR 0
chmod 660 /dev/kdnsguard
echo "node=$(ls -l /dev/kdnsguard)"

echo "########## 6. 启动核心 ##########"
$CTL service start 2>&1 | tail -4
# 等进程起来 + 内核 COMMIT
i=0
while [ $i -lt 30 ]; do
	pidof mihomo >/dev/null && break
	sleep 1
	i=$((i+1))
done
echo "mihomo pid=$(pidof mihomo)"
[ -n "$(pidof mihomo)" ] || rollback "核心没起来"

# 等 kernel backend 日志
i=0
while [ $i -lt 20 ]; do
	grep -q 'kernel DNS backend active' $B/run/mihomo.log 2>/dev/null && break
	sleep 1
	i=$((i+1))
done
echo "--- mihomo 后端判定 ---"
grep -aE 'kernel DNS backend|kernel dns|falling back|fake-ip' $B/run/mihomo.log | tail -10
echo "--- 内核 health ---"
$T/kdgctl 2>&1 | grep -E 'ownership|listener_ready|client_ifaces|doh_|nat_|map_|pool_' | head -40
echo "DEPLOY_OK"
