#!/system/bin/sh
# 设备上立刻启用常驻（install.sh 推完资产后调用）。
set +e
KDG=/data/adb/kdnsguard
B=/data/user/0/com.boxproxy.box/files/box
CFG=$B/run/state/startup-config
STATE=$(dirname "$CFG")
BB=/data/adb/ksu/bin/busybox

echo "enabled flag"
touch "$KDG/enabled"
settings put global private_dns_mode off

echo "apply"
sh "$KDG/apply.sh"
echo "apply rc=$?"

echo "loop"
sh "$KDG/loop.sh" &

sleep 8
echo "pid=$(pidof mihomo || echo none)"
echo "--- mihomo 后端 ---"
grep -a "kernel DNS backend" "$B/run/mihomo.log" | tail -5
echo "--- kdgctl ---"
"$KDG/kdgctl" 2>&1 | grep -E "ownership|listener_ready|doh_ok|pool_connects|doh_queries" | head
echo "--- yaml ---"
grep -n "backend:" "$CFG" | head
grep -n "dns-mode:" "$CFG" | head
grep -n "enhanced-mode:" "$CFG" | head
echo "--- lsmod ---"
lsmod | grep kdns || echo none
echo "--- node ---"
ls -l /dev/kdnsguard
echo "--- inotifyd ---"
ps -A | grep inotifyd | grep -v grep
echo "ENABLE_DONE"
