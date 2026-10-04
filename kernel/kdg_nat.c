/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_nat.c —— DNS 53 流量的 Netfilter/NAT 接管点。
 *
 * 为什么必须走 nf_nat_ipv4_register_fn 而不是自己 nf_register_net_hook()
 * 后在 hook 里调一次 nf_nat_setup_info()：方案 §5.2 明确禁止后者。读本树
 * net/netfilter/nf_nat_core.c:nf_nat_inet_fn() 可以看清原因——
 *
 *   - nf_nat_ipv4_register_fn() 把你的 ops 插进 **nat 核心自己的 hook**
 *     （nf_nat_ipv4_local_fn / _pre_routing 等）的 priv->entries 里；
 *   - nf_nat_inet_fn() 只对 IP_CT_NEW 的连接遍历这些内层 ops，任一内层 ops
 *     建立了 NAT（nf_nat_initialized() 转真）就 goto do_nat →
 *     nf_nat_packet()，由**nat 核心**完成改写、并借 conntrack 建立反向转换；
 *   - 若你只是在一个普通 HOOK 里自己调 setup_info，改写会生效，但既绕过了
 *     nf_nat_initialized 的记账，也拿不到 nat 核心的 null-binding / oif 变更
 *     处理，回包方向的行为与 iptables/nftables 的 NAT 不一致。
 *
 * 本阶段的开关策略（P3）：`intercept_enabled` 默认 **0**。为 0 时 hook 只做
 * 计数统计后立刻 NF_ACCEPT，对系统**零行为影响**；置 1 的唯一路径是 genl 的
 * ownership 事务（PREPARE → COMMIT），且模块必须以 `allow_intercept=1` 加载。
 *
 * 两条路径的所有权不同，必须分开处理：
 *   - **LOCAL_OUT**（本机进程查询）—— 改写到 loopback，由 loopback listener 应答；
 *   - **PREROUTING**（热点/共享网络客户端的转发查询）—— 改成**入接口自己的
 *     地址**，因此只在「该接口上已建好 listener」时才接管（见 kdg_listener.c
 *     的客户端入口表）。名单外的接口一律放行，避免手机在运营商网络上的地址
 *     变成开放解析器（方案 §5.2）。
 */
#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/inetdevice.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_redirect.h>
#include <net/net_namespace.h>
#include <net/ip.h>
#include <net/ipv6.h>

#include "kdg.h"

/* 传输层头前 4 字节在 UDP/TCP/SCTP/DCCP 上都是「源端口, 目的端口」，
 * 因此取端口不必先判协议——少一次分支，也少一处协议表遗漏的风险。 */
struct kdg_ports {
	__be16 sport;
	__be16 dport;
};

static bool kdg_get_ports(const struct sk_buff *skb, unsigned int off,
			  struct kdg_ports *out)
{
	struct kdg_ports tmp;
	const struct kdg_ports *p;

	/*
	 * ⚠️ 必须用**返回值**，不能用 tmp。
	 *
	 * skb_header_pointer() 的契约是：头部线性（快路径）时直接返回
	 * skb->data + off，**根本不会写 buffer**；只有数据跨页（慢路径）时
	 * 才把内容拷进 buffer 并返回 &buffer。写成
	 *     skb_header_pointer(skb, off, sizeof(tmp), &tmp);
	 *     *out = tmp;
	 * 会在最常见的快路径上读到**未初始化的栈内存**——实测表现为端口恒为 0
	 * （栈上恰好是零），而不是崩溃，因此极具迷惑性。参见
	 * include/linux/skbuff.h 中该函数对 `buffer` 参数的实际使用。
	 */
	p = skb_header_pointer(skb, off, sizeof(tmp), &tmp);
	if (!p)
		return false;
	*out = *p;
	return true;
}

/* kdg_classify_dns() 的返回值。刻意不用 bool：源端口 53 是需要**单独计数**
 * 而不是「顺带接管」的情形，历史上正是把它并进 bool 判据埋下一个反射面。 */
#define KDG_DNS_QUERY		1
#define KDG_DNS_SPORT53		2

/*
 * 判断本包是否是「明文 DNS 查询」。
 *
 * 只认 UDP/TCP。DoT(853)/DoQ(853) 与 DoH(443) 不在此列——方案 §11 明确：
 * 非 53 的加密 DNS 不能靠 payload 猜测来识别，只能靠精确目标限制或接口协作。
 *
 * ⚠️ 判据是**目的端口** 53，不是「源或目的端口」。
 *
 * 早期版本写的是 `dport == 53 || sport == 53`，看似能顺手覆盖回包方向，
 * 实际是个缺陷：回包由 conntrack 的反向映射负责，根本不会走到这里
 * （nf_nat_inet_fn 只对 IP_CT_NEW/RELATED 且未 NAT 初始化的连接遍历内层
 * ops，见 net/netfilter/nf_nat_core.c）。而放宽到 sport 会让**新**的
 * 源端口 53 报文（伪造源、DNS NOTIFY、反射放大）也进接管判定，在
 * PREROUTING 上就是给外部送了一个反射面。源端口 53 只计数，不接管。
 */
static int kdg_classify_dns(const struct sk_buff *skb, u8 pf,
			    struct kdg_ports *ports)
{
	unsigned int thoff;

	switch (pf) {
	case NFPROTO_IPV4: {
		const struct iphdr *iph = ip_hdr(skb);

		if (iph->protocol != IPPROTO_UDP &&
		    iph->protocol != IPPROTO_TCP)
			return 0;
		/* ihl 由对端控制，先验证下界再乘 4，避免 0 或 <5 造成
		 * 偏移算错。netfilter 此前已 pskb_may_pull 过基础头部。 */
		if (iph->ihl < 5)
			return 0;
		thoff = (unsigned int)iph->ihl * 4;
		break;
	}
	case NFPROTO_IPV6: {
		const struct ipv6hdr *iph6 = ipv6_hdr(skb);

		if (iph6->nexthdr != IPPROTO_UDP &&
		    iph6->nexthdr != IPPROTO_TCP)
			return 0;
		thoff = sizeof(struct ipv6hdr);
		break;
	}
	default:
		return 0;
	}

	if (!kdg_get_ports(skb, thoff, ports))
		return 0;

	if (ports->dport == htons(53))
		return KDG_DNS_QUERY;
	if (ports->sport == htons(53))
		return KDG_DNS_SPORT53;
	return 0;
}

/*
 * PREROUTING 路径的准入。返回 true 表示「这个入接口的 53 由本项目接管」。
 *
 * 三重判据缺一不可：
 *  1. 入接口在客户端入口表里（模块参数 client_ifaces 白名单 + listener 已建成）；
 *  2. 该接口的**这个地址族**上确实有 listener（上面已解释 IPv6 的 scope 问题）；
 *  3. IPv6 目的地址是全局 scope —— 链路本地目的地会让 nf_nat_redirect_ipv6
 *     选到接口的链路本地地址，而那里没有 listener。
 *
 * 任何一条不满足都返回 false，调用方 **NF_ACCEPT**：宁可少接管，也不能
 * 改写到没人听的地方（那等于静默丢客户端的 DNS）。
 */
bool kdg_v6_addr_is_global(const u8 *addr16)
{
	/* 拷进对齐的局部量再问：调用方传进来的可能是裸字节数组。头文件的
	 * 注释解释了为什么判据是「scope 掩码为 0」而不是比较 SCOPE_GLOBAL。 */
	struct in6_addr a;

	memcpy(&a, addr16, sizeof(a));
	return !(ipv6_addr_type(&a) & IPV6_ADDR_SCOPE_MASK);
}

static bool kdg_prerouting_allowed(const struct sk_buff *skb,
				   const struct nf_hook_state *state)
{
	u32 caps;

	if (!state->in)
		return false;
	caps = kdg_listener_client_caps(state->net, state->in);
	if (!caps)
		return false;

	if (state->pf == NFPROTO_IPV4)
		return caps & KDG_CLI_CAP_V4;

	if (state->pf == NFPROTO_IPV6) {
		const struct ipv6hdr *iph6 = ipv6_hdr(skb);

		if (!(caps & KDG_CLI_CAP_V6))
			return false;
		/* 链路本地等窄 scope 的目的地会被 nf_nat_redirect_ipv6 选到
		 * 接口的链路本地地址，而那里没有 listener ⇒ 必须放行。 */
		if (!kdg_v6_addr_is_global((const u8 *)&iph6->daddr))
			return false;
		return true;
	}
	return false;
}

/*
 * NAT 内层 hook。运行在 nat 核心的 hook 上下文里，**不可睡眠**：
 * 这里不取任何可变锁、不分配内存、不做名字解析。全部工作只有原子计数
 * 与一次 nf_nat_redirect_*（该函数本身即为 hook 上下文设计）。
 */
static unsigned int kdg_nat_hook(void *priv, struct sk_buff *skb,
				 const struct nf_hook_state *state)
{
	struct kdg_netns *ns = kdg_netns_of(state->net);
	struct kdg_ports ports;
	struct nf_nat_range2 range;
	int kind;

	if (!ns)
		return NF_ACCEPT;

	/* 无条件计数：这是判断「hook 到底有没有挂在报文路径上」的唯一可靠
	 * 依据。区分 hook_calls（进来了）与 seen（判定为 DNS）能让
	 * 「没挂上」与「挂上了但判定错」两种故障立刻分开。 */
	atomic64_inc(&ns->nat.hook_calls);

	/* 受 debug 参数控制的有限打印（默认关，最多 8 条）。
	 * 排障时无价：能直接看到 hook 眼里的 pf / 协议 / 端口，
	 * 而不是靠推理猜谓词为什么没匹配。 */
	if (unlikely(READ_ONCE(kdg_debug)) &&
	    atomic64_inc_return(&ns->nat.debug_printed) <= 8) {
		struct kdg_ports dbg = { 0 };
		unsigned int dthoff = 0;
		bool dgot = false;

		if (state->pf == NFPROTO_IPV4) {
			const struct iphdr *iph = ip_hdr(skb);

			pr_info("hook[v4]: len=%u netoff=%u ihl=%u proto=%u\n",
				skb->len, skb_network_offset(skb),
				(unsigned int)iph->ihl, iph->protocol);
			if (iph->ihl >= 5) {
				dthoff = skb_network_offset(skb) +
					 (unsigned int)iph->ihl * 4;
				dgot = kdg_get_ports(skb, dthoff, &dbg);
			}
		} else if (state->pf == NFPROTO_IPV6) {
			const struct ipv6hdr *iph6 = ipv6_hdr(skb);

			pr_info("hook[v6]: len=%u netoff=%u nexthdr=%u\n",
				skb->len, skb_network_offset(skb),
				(unsigned int)iph6->nexthdr);
			dthoff = skb_network_offset(skb) +
				 sizeof(struct ipv6hdr);
			dgot = kdg_get_ports(skb, dthoff, &dbg);
		} else {
			pr_info("hook[?]: pf=%u\n", state->pf);
		}
		if (dgot)
			pr_info("  thoff=%u sport=%u dport=%u (host order)\n",
				dthoff, ntohs(dbg.sport), ntohs(dbg.dport));
		else
			pr_info("  thoff=%u 端口读取失败\n", dthoff);

		/* 原始字节是最有力的证据：谓词不匹配时，直接看 hook 眼里的
		 * 报文长什么样，胜过任何推理。 */
		pr_info("  headlen=%u data=%pK\n", skb_headlen(skb), skb->data);
		print_hex_dump(KERN_INFO, "  pkt: ", DUMP_PREFIX_OFFSET, 16, 1,
			       skb->data,
			       min_t(unsigned int, skb_headlen(skb), 48), true);
	}

	kind = kdg_classify_dns(skb, state->pf, &ports);
	if (kind == 0)
		return NF_ACCEPT;
	if (kind == KDG_DNS_SPORT53) {
		/* 新连接的源端口 53：只记账，不接管。 */
		atomic64_inc(&ns->nat.sport53);
		return NF_ACCEPT;
	}

	atomic64_inc(&ns->nat.seen);

	/* 转发路径（热点/共享网络客户端）只接管白名单入接口。 */
	if (state->hook == NF_INET_PRE_ROUTING) {
		atomic64_inc(&ns->nat.fwd_seen);
		if (!kdg_prerouting_allowed(skb, state)) {
			atomic64_inc(&ns->nat.fwd_bypassed);
			return NF_ACCEPT;
		}
	}

	/* 未启用接管：只观察，绝不改写。 */
	if (!READ_ONCE(kdg_cfg.intercept_enabled)) {
		atomic64_inc(&ns->nat.bypassed);
		return NF_ACCEPT;
	}

	/* 本模块自身发往上游 DoH 的连接不能被自己截获（§5.3 防循环）。
	 * 上游走 443，天然不匹配 53，故此处无需特判；真正需要的 socket
	 * 身份登记与 eBPF 旁路集合在 P3 与 dns/transport 阶段加入。 */

	memset(&range, 0, sizeof(range));
	range.flags = NF_NAT_RANGE_PROTO_SPECIFIED;
	range.min_proto.all = htons(READ_ONCE(kdg_cfg.listen_port));
	range.max_proto.all = htons(READ_ONCE(kdg_cfg.listen_port));

	atomic64_inc(&ns->nat.redirected);

	/* LOCAL_OUT 走 loopback，PREROUTING 走入接口本地地址——这正是
	 * nf_nat_redirect_* 内部按 hooknum 分支处理的语义，也是方案 §5.2
	 * 「不能把所有 PREROUTING 流量简单 DNAT 到 loopback」的落点。 */
	if (state->pf == NFPROTO_IPV4)
		return nf_nat_redirect_ipv4(skb, &range, state->hook);
	return nf_nat_redirect_ipv6(skb, &range, state->hook);
}

/* 每个 (family, hooknum) 组合都需要一个独立的 ops —— nf_nat_*_register_fn
 * 按 ops->hooknum 匹配到 nat 核心对应位置的 entries 里，一个 ops 只能挂一处。
 * 这些结构体必须静态生存期：注册后指针被 nat 核心持有。 */
static struct nf_hook_ops kdg_nat_ops_v4[] = {
	{
		.hook		= kdg_nat_hook,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_LOCAL_OUT,
		.priority	= NF_IP_PRI_NAT_DST,
	},
	{
		.hook		= kdg_nat_hook,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority	= NF_IP_PRI_NAT_DST,
	},
};

static struct nf_hook_ops kdg_nat_ops_v6[] = {
	{
		.hook		= kdg_nat_hook,
		.pf		= NFPROTO_IPV6,
		.hooknum	= NF_INET_LOCAL_OUT,
		.priority	= NF_IP6_PRI_NAT_DST,
	},
	{
		.hook		= kdg_nat_hook,
		.pf		= NFPROTO_IPV6,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority	= NF_IP6_PRI_NAT_DST,
	},
};

int kdg_nat_register(struct net *net)
{
	struct kdg_netns *ns = kdg_netns_of(net);
	unsigned int i;
	int ret;

	if (!ns)
		return -ENOENT;

	for (i = 0; i < ARRAY_SIZE(kdg_nat_ops_v4); i++) {
		ret = nf_nat_ipv4_register_fn(net, &kdg_nat_ops_v4[i]);
		if (ret) {
			pr_err("IPv4 NAT hook %u 注册失败: %d\n", i, ret);
			while (i--)
				nf_nat_ipv4_unregister_fn(net,
							  &kdg_nat_ops_v4[i]);
			return ret;
		}
	}
	ns->nat_registered_v4 = true;

	for (i = 0; i < ARRAY_SIZE(kdg_nat_ops_v6); i++) {
		ret = nf_nat_ipv6_register_fn(net, &kdg_nat_ops_v6[i]);
		if (ret) {
			pr_err("IPv6 NAT hook %u 注册失败: %d\n", i, ret);
			while (i--)
				nf_nat_ipv6_unregister_fn(net,
							  &kdg_nat_ops_v6[i]);
			for (i = 0; i < ARRAY_SIZE(kdg_nat_ops_v4); i++)
				nf_nat_ipv4_unregister_fn(net,
							  &kdg_nat_ops_v4[i]);
			ns->nat_registered_v4 = false;
			return ret;
		}
	}
	ns->nat_registered_v6 = true;

	pr_info("NAT hook 已注册（IPv4+IPv6，LOCAL_OUT + PREROUTING）\n");
	return 0;
}

void kdg_nat_unregister(struct net *net)
{
	struct kdg_netns *ns = kdg_netns_of(net);
	unsigned int i;

	if (!ns)
		return;

	/* 逆序注销。nf_nat_*_unregister_fn 内部经 nf_unregister_net_hooks()
	 * 完成 RCU 同步，返回后不会再有新的 hook 调用进入。 */
	if (ns->nat_registered_v6) {
		for (i = ARRAY_SIZE(kdg_nat_ops_v6); i-- > 0;)
			nf_nat_ipv6_unregister_fn(net, &kdg_nat_ops_v6[i]);
		ns->nat_registered_v6 = false;
	}
	if (ns->nat_registered_v4) {
		for (i = ARRAY_SIZE(kdg_nat_ops_v4); i-- > 0;)
			nf_nat_ipv4_unregister_fn(net, &kdg_nat_ops_v4[i]);
		ns->nat_registered_v4 = false;
	}

	/*
	 * 必须显式同步。`nf_nat_*_unregister_fn()` 内部走的是
	 * nf_hook_entries_delete_raw()（见 net/netfilter/core.c），**它不做
	 * 任何 RCU 同步**——只是把条目从数组里摘掉。也就是说本函数返回时，
	 * 另一个 CPU 上可能仍有 kdg_nat_hook 正在执行；若此时模块被卸载，
	 * 那就是执行已释放的模块代码。
	 *
	 * nf_hook_slow() 的调用点在 rcu_read_lock() 内，因此一个 RCU 宽限期
	 * 足以覆盖所有在途 hook。synchronize_net() 是 synchronize_rcu() 的
	 * 超集（额外等 netdev 通知链），这里用它更保守。
	 */
	synchronize_net();
}

/*
 * 能力位。诚实申报是硬要求：GET_HEALTH/CAPS 不得宣称尚未实现的能力
 * （方案 §16 要求 H3 在验收前 capability 恒为 false）。
 */
u32 kdg_nat_capability_bits(void)
{
	u32 bits = KDG_CAP_IPV4 | KDG_CAP_IPV6;

	/* 双栈 UDP/TCP 接管链路已具备；DoH 传输层尚未落地（P1 未完成），
	 * 因此 H1/H2/H3、域名映射、负缓存、FakeIP 一律不申报。 */
	return bits;
}
