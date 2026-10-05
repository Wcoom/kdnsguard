#!/system/bin/sh
# 接管矩阵：App 53 / 字符设备 / 反查 / 无明文旁路。
B=/data/user/0/com.boxproxy.box/files/box
T=/data/local/tmp
OUT=$T/kdg-final
NP=$T/netprobe
BB=/data/adb/ksu/bin/busybox

echo "########## A. 内核健康 ##########"
$T/kdgctl 2>&1 | tee $OUT/health-a.txt | grep -E 'ownership|listener_ready|doh_|nat_|map_|pool_|h2_'

echo
echo "########## B. App 视角 UDP/TCP IPv4（peer 必须是真实 DNS IP，不是 127.x）##########"
$NP udp 223.5.5.5 example.com | tee $OUT/np-udp4.txt
$NP tcp 223.5.5.5 example.com | tee $OUT/np-tcp4.txt
$NP udp 8.8.8.8 github.com | tee $OUT/np-udp4b.txt

echo
echo "########## C. App 视角 IPv6（当前 eBPF ipv6-mode=off，走 LOCAL_OUT NAT）##########"
$NP udp 2001:4860:4860::8888 example.com | tee $OUT/np-udp6.txt
$NP tcp 2001:4860:4860::8888 example.com | tee $OUT/np-tcp6.txt

echo
echo "########## D. 字符设备查询（mihomo 内部走同一条）##########"
for d in example.com www.baidu.com github.com; do
	printf '%-16s ' "$d"
	$T/kdgctl query "$d" 2>&1 | sed -n 's/^  A \(.*\)$/\1/p' | tr '\n' ' '
	echo
done
$T/kdgctl 2>&1 | grep -E 'doh_queries|doh_ok|pool_connects|pool_reused|map_entries' | tee $OUT/health-d.txt

echo
echo "########## E. IP-only 连接反查（enhancer 路径）##########"
IP=$($T/kdgctl query example.com 2>&1 | sed -n 's/^  A \(.*\)$/\1/p' | head -1)
echo "example.com A=$IP"
HITS0=$($T/kdgctl 2>&1 | sed -n 's/.*map_hits=\([0-9]*\).*/\1/p')
[ -z "$HITS0" ] && HITS0=0
# busybox nc 连纯 IP：mihomo 日志应出现 --> example.com
$BB timeout 3 $BB nc "$IP" 443 >/dev/null 2>&1 || true
sleep 1
HITS1=$($T/kdgctl 2>&1 | sed -n 's/.*map_hits=\([0-9]*\).*/\1/p')
echo "map_hits $HITS0 -> $HITS1"
grep -a "--> example.com" $B/run/mihomo.log | tail -3

echo
echo "########## F. 无明文 UDP 53 旁路（114/8.8.8.8 的 conntrack）##########"
# 系统 resolver 默认上游是 114.114.114.114 / 8.8.8.8。
# Invalid() 写反时，节点解析会打到这两处。
grep -E '114\.114\.114\.114|8\.8\.8\.8' /proc/net/nf_conntrack | grep dport=53 | head
echo "conntrack-114/8.8-dport53=$(grep -cE 'dport=53.*(114\.114\.114\.114|8\.8\.8\.8)|(114\.114\.114\.114|8\.8\.8\.8).*dport=53' /proc/net/nf_conntrack)"

echo
echo "########## G. DoH 上游 443 的 socket 归属（应无 mihomo 用户态）##########"
ss -tnp 2>/dev/null | grep ':443' | grep -i mihomo | head
echo "mihomo-owned-443=$(ss -tnp 2>/dev/null | grep ':443' | grep -ci mihomo)"
# 内核直达上游：conntrack 里应有 49.234.186.103:443 且无 users
echo "--- 上游 49.234.186.103:443 ---"
grep '49.234.186.103' /proc/net/nf_conntrack | grep dport=443 | head -3

echo
echo "########## H. 1053 不应再有用户态 DNS 监听 ##########"
ss -lnup 2>/dev/null | grep ':1053 ' || echo '1053 无 UDP 监听（预期）'
ss -lntp 2>/dev/null | grep ':1053 ' || echo '1053 无 TCP 监听（预期）'

echo
echo "########## I. conntrack 反向映射（本机 LOCAL_OUT）##########"
grep 'dport=53' /proc/net/nf_conntrack | grep -E '127\.0\.0\.1|::1' | head -6

echo
echo "########## J. 告警 ##########"
echo "告警=$(dmesg | grep -cE 'BUG:|WARNING:|Oops|CFI failure|Internal error')"
echo "MATRIX_OK"
