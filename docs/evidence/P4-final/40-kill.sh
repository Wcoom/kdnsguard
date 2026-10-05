#!/system/bin/sh
# SIGKILL mihomo：内核应继续应答 53；boxctl restart 应走 EBUSY 回收。
B=/data/user/0/com.boxproxy.box/files/box
T=/data/local/tmp
OUT=$T/kdg-final
NP=$T/netprobe
CTL=$B/bin/boxctl

echo "########## 0. kill 前 ##########"
echo "pid=$(pidof mihomo)"
$T/kdgctl 2>&1 | grep ownership
$NP udp 223.5.5.5 example.com | tee $OUT/kill-before.txt

echo
echo "########## 1. SIGKILL ##########"
kill -9 $(pidof mihomo) 2>/dev/null || true
sleep 1
echo "pid-after-kill=$(pidof mihomo || echo none)"
echo "--- 内核仍应答？ ---"
$NP udp 223.5.5.5 example.com | tee $OUT/kill-during.txt
$T/kdgctl 2>&1 | grep -E 'ownership|listener_ready'

echo
echo "########## 2. boxctl restart（应 EBUSY 回收）##########"
$CTL service restart 2>&1 | tail -4
i=0
while [ $i -lt 25 ]; do
	pidof mihomo >/dev/null && break
	sleep 1
	i=$((i+1))
done
echo "pid=$(pidof mihomo)"
sleep 8
echo "--- mihomo 日志（应见 reclaim / active）---"
grep -aE 'kernel DNS backend|reclaim|ownership held|falling back' $B/run/mihomo.log | tail -8
$T/kdgctl 2>&1 | grep -E 'ownership|listener_ready|doh_ok'
$NP udp 223.5.5.5 example.com | tee $OUT/kill-after.txt
echo "KILL_OK"
