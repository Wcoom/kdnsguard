#!/system/bin/sh
# 故障注入：屏蔽 DoH 上游 IP，查询必须 SERVFAIL，不得回落运营商。
T=/data/local/tmp
OUT=$T/kdg-final
NP=$T/netprobe
UP=49.234.186.103

echo "########## 0. 注入前基线 ##########"
$NP udp 223.5.5.5 example.com | tee $OUT/inj-before.txt

echo
echo "########## 1. REJECT 上游 ##########"
iptables -I OUTPUT 1 -d $UP -j REJECT
echo "rule in=$(iptables -L OUTPUT -n --line-numbers | grep -c $UP)"

echo
echo "########## 2. App 查询应 SERVFAIL ~1s ##########"
# netprobe 打印 rcode / elapsed
$NP udp 223.5.5.5 should-fail.example | tee $OUT/inj-udp.txt
$NP tcp 223.5.5.5 should-fail.example | tee $OUT/inj-tcp.txt

echo
echo "########## 3. 字符设备同样失败 ##########"
$T/kdgctl query should-fail.example 2>&1 | tee $OUT/inj-chr.txt | head -20

echo
echo "########## 4. 无运营商回落：不应出现新的 53 外发到非上游 ##########"
# 若回落，会出现到 114/8.8/223.5.5.5 的 *成功* 应答。这里只看 conntrack 新增。
grep -E 'dport=53' /proc/net/nf_conntrack | grep -vE '127\.0\.0\.1|::1|10\.' | head

echo
echo "########## 5. 解除注入 ##########"
iptables -D OUTPUT -d $UP -j REJECT
echo "rule left=$(iptables -L OUTPUT -n | grep -c $UP)"
sleep 1
$NP udp 223.5.5.5 example.com | tee $OUT/inj-after.txt
echo "INJECT_OK"
