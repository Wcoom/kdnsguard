#!/system/bin/sh
T=/data/local/tmp
OUT=$T/kdg-final
echo "########## uid-0 规则计数（mihomo 内部 Lookup 期间）##########"
iptables -t mangle -L OUTPUT -v -n | grep kdgfinal-owner | tee $OUT/owner-counters-1.txt
echo "########## conntrack 114/8.8 dport=53 ##########"
grep -E 'dport=53' /proc/net/nf_conntrack | grep -E '114\.114\.114\.114|8\.8\.8\.8' | tee $OUT/owner-ct.txt | head
echo "########## 拆除 ##########"
iptables -t mangle -D OUTPUT -p udp --dport 53 -m owner --uid-owner 0 -j REJECT --reject-with icmp-port-unreachable -m comment --comment kdgfinal-owner 2>/dev/null || true
iptables -t mangle -D OUTPUT -p tcp --dport 53 -m owner --uid-owner 0 -j REJECT --reject-with tcp-reset -m comment --comment kdgfinal-owner 2>/dev/null || true
# 再兜一次按 comment 扫
iptables -t mangle -S OUTPUT | grep kdgfinal-owner && echo '!!! 规则残留' || echo '规则已清'
echo "OWNER_DISARMED"
