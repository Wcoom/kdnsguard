#!/system/bin/sh
# 窗口开始：只记录，不改任何东西。
B=/data/user/0/com.boxproxy.box/files/box
T=/data/local/tmp
OUT=$T/kdg-final
mkdir -p $OUT
BB=/data/adb/ksu/bin/busybox

{
echo "### time $(date) uptime=$(cut -d' ' -f1 /proc/uptime)"
echo "### uname"; uname -a
echo "### kernel build"; cat /proc/version
echo "### private_dns"; settings get global private_dns_mode; settings get global private_dns_specifier
echo "### modules"; lsmod | wc -l; lsmod | grep kdns || echo 'kdnsguard 未加载'
echo "### /dev/kdnsguard"; ls -l /dev/kdnsguard 2>/dev/null || echo none
echo "### ddl"; cat /proc/oplus_scheduler/sched_assist/sched_ddl_enabled 2>/dev/null
echo "### zram"; cat /sys/block/zram0/comp_algorithm 2>/dev/null
echo "### su"; su -c id
echo "### mihomo bin"; ls -laZ $B/bin/mihomo; md5sum $B/bin/mihomo
echo "### startup-config"; ls -la $B/run/state/startup-config; md5sum $B/run/state/startup-config
echo "### boxctl status"; $B/bin/boxctl status 2>&1 | head -8
echo "### pidof mihomo"; pidof mihomo || echo stopped
echo "### dmesg warn"; dmesg | grep -cE 'BUG:|WARNING:|Oops|CFI failure|Internal error'
echo "### iptables owner match?"
iptables -t mangle -C OUTPUT -p udp --dport 53 -m owner --uid-owner 0 -j REJECT 2>/dev/null
echo "owner-check-rc=$?"
# 探测能否插入（立刻删）
iptables -t mangle -I OUTPUT 1 -p udp --dport 53 -m owner --uid-owner 0 -j REJECT -m comment --comment kdgfinal-probe 2>$OUT/ipt-owner.err
echo "owner-insert-rc=$?"
iptables -t mangle -D OUTPUT -p udp --dport 53 -m owner --uid-owner 0 -j REJECT -m comment --comment kdgfinal-probe 2>/dev/null
echo "### iptables nat 53/1053"
iptables -t nat -S 2>/dev/null | grep -E '53|1053|dns' | head
iptables -t mangle -S 2>/dev/null | grep -E '53|1053|dns' | head
echo "### ss 53/1053/9090"
ss -lntp 2>/dev/null | grep -E ':53 |:1053 |:9090 ' | head
echo "### rndis"
ip -o -4 addr show rndis0 2>/dev/null
echo "### kdgctl present"; ls -l $T/kdgctl $T/kdg_root.pem $T/netprobe $T/chrneg 2>/dev/null
} > $OUT/preflight.txt 2>&1
cat $OUT/preflight.txt
echo "WROTE $OUT/preflight.txt"
