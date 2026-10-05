#!/system/bin/sh
# 证明 mihomo 内部 Lookup 走字符设备、不走明文 UDP 53。
# 手段：mangle OUTPUT 拦 uid=0 的 dport=53（mihomo 是 root）。
# 内核 socket 没有 uid，不受这条规则影响；chardev 查询也不走 53。
# Invalid() 若仍写反，节点解析会打到 114/8.8 并被 REJECT，延迟测试失败。
T=/data/local/tmp
OUT=$T/kdg-final
NP=$T/netprobe

echo "########## 插入 uid-0 dport-53 REJECT ##########"
iptables -t mangle -I OUTPUT 1 -p udp --dport 53 -m owner --uid-owner 0 -j REJECT --reject-with icmp-port-unreachable -m comment --comment kdgfinal-owner
iptables -t mangle -I OUTPUT 1 -p tcp --dport 53 -m owner --uid-owner 0 -j REJECT --reject-with tcp-reset -m comment --comment kdgfinal-owner
echo "rules:"
iptables -t mangle -L OUTPUT -n --line-numbers | grep kdgfinal-owner

echo
echo "########## App 查询仍应成功（NAT 改写发生在 mangle 之后？）##########"
# mangle OUTPUT 在 NAT 之前。本机 App 的 UDP 53 若 uid≠0 不受影响。
# netprobe 以 root 跑，会被这条规则拦住 —— 这正好说明规则生效。
# 所以 App 视角改用非 root：这里只记 netprobe 被拦（证明规则活着），
# 真正的「mihomo 内部 Lookup」由笔记本侧 curl /delay 验证。
echo "--- netprobe as root（预期失败，证明规则活着）---"
$NP udp 223.5.5.5 example.com | tee $OUT/owner-root-np.txt || true

echo
echo "########## 计数器清零点 ##########"
iptables -t mangle -L OUTPUT -v -n | grep kdgfinal-owner | tee $OUT/owner-counters-0.txt
echo "OWNER_ARMED"
