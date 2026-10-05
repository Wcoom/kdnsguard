/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_edns.c —— 加密 DNS（DoT/DoQ/DoH/DoH3）的「封锁并逼回落」。
 *
 * 内核解不开 App 自带的加密 DNS：它校验的是真实上游的证书，我们没有对应
 * 私钥。可行且诚实的做法是**让加密通道连不上**，App 按其回落逻辑改走系统
 * 解析器（明文 53），再由 kdg_nat.c 接到内核解析。方案 §11 的边界因此是：
 *
 *   - 853/TCP（DoT）、853/UDP（DoQ）：端口精确匹配，一律拒绝；
 *   - 443/TCP（DoH）、443/UDP（DoH3）：只对**已知公共解析器 IP 名单**拒绝。
 *     443 上无法靠 payload 判断是不是 DNS，名单外的私有 DoH 拦不住。
 *
 * 拒绝方式决定回落速度：TCP 回 RST、UDP 回 ICMP 端口不可达，客户端立即
 * 得到 ECONNREFUSED；静默丢包会让 App 等到自己的超时（数秒到数十秒）。
 *
 * 豁免：内核自己建的 socket（sk_kern_sock，含 kdnsguard 上游 DoH 连接）
 * 永不拦截 —— 否则上游一旦解析到名单内 IP，内核自己就断了（§5.3 防循环）。
 *
 * 生效条件与 NAT 接管同源：intercept_enabled 为真（ownership 已 COMMIT）且
 * 模块参数 edns_block=1。未接管时本 hook 只计数、立即放行。
 */
#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/seqlock.h>
#include <linux/string.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <net/netfilter/ipv4/nf_reject.h>
#include <net/netfilter/ipv6/nf_reject.h>
#include <net/net_namespace.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/sock.h>

#include "kdg.h"

#define KDG_EDNS_MAX	64

/* 名单只在参数写入时变动，hook 每包读 —— seqlock 让读侧无锁、无原子写。 */
static DEFINE_SEQLOCK(kdg_edns_lock);
static __be32 kdg_edns_v4[KDG_EDNS_MAX];
static struct in6_addr kdg_edns_v6[KDG_EDNS_MAX];
static unsigned int kdg_edns_n4, kdg_edns_n6;

static bool kdg_edns_block = true;
module_param_named(edns_block, kdg_edns_block, bool, 0644);
MODULE_PARM_DESC(edns_block, "接管期间拒绝 853 与名单内 443（逼加密 DNS 回落）");

/* 默认名单：主流公共 DoH/DoT 解析器的任播地址。可经 edns_ips 整体替换。 */
static char kdg_edns_default[] =
	"8.8.8.8,8.8.4.4,1.1.1.1,1.0.0.1,9.9.9.9,149.112.112.112,"
	"208.67.222.222,208.67.220.220,94.140.14.14,94.140.15.15,"
	"223.5.5.5,223.6.6.6,1.12.12.12,120.53.53.53,119.29.29.29,"
	"185.222.222.222,45.11.45.11,101.101.101.101,76.76.2.0,76.76.10.0,"
	"2001:4860:4860::8888,2001:4860:4860::8844,"
	"2606:4700:4700::1111,2606:4700:4700::1001,2620:fe::fe,2620:fe::9,"
	"2400:3200::1,2400:3200:baba::1,2402:4e00::,2a10:50c0::ad1:ff";

/* 解析逗号分隔的地址串并整体替换名单。任一项非法则整串拒绝（不做半截
 * 生效），名单保持原样。 */
static int kdg_edns_parse(const char *s)
{
	__be32 v4[KDG_EDNS_MAX];
	static struct in6_addr v6[KDG_EDNS_MAX];	/* 1 KiB，不放栈上 */
	static DEFINE_MUTEX(parse_mu);			/* 保护上面的 static 缓冲 */
	unsigned int n4 = 0, n6 = 0;
	const char *p = s, *end;
	char tok[INET6_ADDRSTRLEN];
	size_t len;
	int ret = 0;

	mutex_lock(&parse_mu);
	while (*p) {
		end = strchrnul(p, ',');
		len = end - p;
		while (len && (p[len - 1] == '\n' || p[len - 1] == ' '))
			len--;
		if (len) {
			if (len >= sizeof(tok)) {
				ret = -EINVAL;
				goto out;
			}
			memcpy(tok, p, len);
			tok[len] = '\0';
			if (strchr(tok, ':')) {
				if (n6 >= KDG_EDNS_MAX ||
				    !in6_pton(tok, -1, v6[n6].s6_addr, -1, NULL)) {
					ret = -EINVAL;
					goto out;
				}
				n6++;
			} else {
				if (n4 >= KDG_EDNS_MAX ||
				    !in4_pton(tok, -1, (u8 *)&v4[n4], -1, NULL)) {
					ret = -EINVAL;
					goto out;
				}
				n4++;
			}
		}
		p = *end ? end + 1 : end;
	}

	write_seqlock_bh(&kdg_edns_lock);
	memcpy(kdg_edns_v4, v4, n4 * sizeof(v4[0]));
	memcpy(kdg_edns_v6, v6, n6 * sizeof(v6[0]));
	kdg_edns_n4 = n4;
	kdg_edns_n6 = n6;
	write_sequnlock_bh(&kdg_edns_lock);
	pr_info("加密 DNS 名单：IPv4 %u 条，IPv6 %u 条\n", n4, n6);
out:
	mutex_unlock(&parse_mu);
	return ret;
}

static int kdg_edns_ips_set(const char *val, const struct kernel_param *kp)
{
	return kdg_edns_parse(val);
}

static int kdg_edns_ips_get(char *buf, const struct kernel_param *kp)
{
	unsigned int seq, i, n4, n6;
	int len;

	do {
		seq = read_seqbegin(&kdg_edns_lock);
		n4 = kdg_edns_n4;
		n6 = kdg_edns_n6;
		len = 0;
		for (i = 0; i < n4; i++)
			len += scnprintf(buf + len, PAGE_SIZE - len, "%pI4,",
					 &kdg_edns_v4[i]);
		for (i = 0; i < n6; i++)
			len += scnprintf(buf + len, PAGE_SIZE - len, "%pI6c,",
					 &kdg_edns_v6[i]);
	} while (read_seqretry(&kdg_edns_lock, seq));
	if (len)
		buf[len - 1] = '\n';
	return len;
}

static const struct kernel_param_ops kdg_edns_ips_ops = {
	.set = kdg_edns_ips_set,
	.get = kdg_edns_ips_get,
};
module_param_cb(edns_ips, &kdg_edns_ips_ops, NULL, 0644);
MODULE_PARM_DESC(edns_ips, "443 上要拒绝的公共 DoH 解析器地址（逗号分隔，整体替换）");

static bool kdg_edns_v4_listed(__be32 a)
{
	unsigned int seq, i;
	bool hit;

	do {
		seq = read_seqbegin(&kdg_edns_lock);
		hit = false;
		for (i = 0; i < kdg_edns_n4; i++)
			if (kdg_edns_v4[i] == a) {
				hit = true;
				break;
			}
	} while (read_seqretry(&kdg_edns_lock, seq));
	return hit;
}

static bool kdg_edns_v6_listed(const struct in6_addr *a)
{
	unsigned int seq, i;
	bool hit;

	do {
		seq = read_seqbegin(&kdg_edns_lock);
		hit = false;
		for (i = 0; i < kdg_edns_n6; i++)
			if (ipv6_addr_equal(&kdg_edns_v6[i], a)) {
				hit = true;
				break;
			}
	} while (read_seqretry(&kdg_edns_lock, seq));
	return hit;
}

/* 判定结果：0 放行；KDG_EDNS_DOT 端口 853；KDG_EDNS_DOH 名单内 443。 */
#define KDG_EDNS_DOT	1
#define KDG_EDNS_DOH	2

static int kdg_edns_classify(const struct sk_buff *skb, u8 pf, u8 *l4)
{
	const __be16 *pp;
	__be16 ports[2];
	unsigned int thoff;
	u16 dport;

	if (pf == NFPROTO_IPV4) {
		const struct iphdr *iph = ip_hdr(skb);

		if (iph->ihl < 5 || ip_is_fragment(iph))
			return 0;
		*l4 = iph->protocol;
		thoff = skb_network_offset(skb) + iph->ihl * 4;
	} else {
		*l4 = ipv6_hdr(skb)->nexthdr;
		thoff = skb_network_offset(skb) + sizeof(struct ipv6hdr);
	}
	if (*l4 != IPPROTO_TCP && *l4 != IPPROTO_UDP)
		return 0;

	/* 返回值才是数据位置，见 kdg_nat.c 对 skb_header_pointer 的说明。 */
	pp = skb_header_pointer(skb, thoff, sizeof(ports), ports);
	if (!pp)
		return 0;
	dport = ntohs(pp[1]);

	if (dport == 853)
		return KDG_EDNS_DOT;
	if (dport != 443)
		return 0;
	if (pf == NFPROTO_IPV4)
		return kdg_edns_v4_listed(ip_hdr(skb)->daddr) ? KDG_EDNS_DOH : 0;
	return kdg_edns_v6_listed(&ipv6_hdr(skb)->daddr) ? KDG_EDNS_DOH : 0;
}

static unsigned int kdg_edns_hook(void *priv, struct sk_buff *skb,
				  const struct nf_hook_state *state)
{
	struct kdg_netns *ns;
	struct sock *sk = skb->sk;
	int kind;
	u8 l4;

	if (!READ_ONCE(kdg_cfg.intercept_enabled) || !READ_ONCE(kdg_edns_block))
		return NF_ACCEPT;
	/* 内核自建 socket（含本模块上游连接）永不拦截。 */
	if (sk && sk_fullsock(sk) && sk->sk_kern_sock)
		return NF_ACCEPT;

	kind = kdg_edns_classify(skb, state->pf, &l4);
	if (!kind)
		return NF_ACCEPT;

	ns = kdg_netns_of(state->net);
	if (ns)
		atomic64_inc(kind == KDG_EDNS_DOT ? &ns->nat.edns_dot :
						    &ns->nat.edns_doh);

	/* 主动拒绝，让客户端立刻失败并回落，而不是等超时。 */
	if (state->pf == NFPROTO_IPV4) {
		if (l4 == IPPROTO_TCP)
			nf_send_reset(state->net, sk, skb, state->hook);
		else
			nf_send_unreach(skb, ICMP_PORT_UNREACH, state->hook);
	} else {
		if (l4 == IPPROTO_TCP)
			nf_send_reset6(state->net, sk, skb, state->hook);
		else
			nf_send_unreach6(state->net, skb, ICMPV6_PORT_UNREACH,
					 state->hook);
	}
	return NF_DROP;
}

/* LOCAL_OUT 覆盖本机 App；FORWARD 覆盖热点客户端。filter 优先级，与
 * iptables REJECT 同位。 */
static const struct nf_hook_ops kdg_edns_ops[] = {
	{ .hook = kdg_edns_hook, .pf = NFPROTO_IPV4,
	  .hooknum = NF_INET_LOCAL_OUT, .priority = NF_IP_PRI_FILTER },
	{ .hook = kdg_edns_hook, .pf = NFPROTO_IPV4,
	  .hooknum = NF_INET_FORWARD, .priority = NF_IP_PRI_FILTER },
	{ .hook = kdg_edns_hook, .pf = NFPROTO_IPV6,
	  .hooknum = NF_INET_LOCAL_OUT, .priority = NF_IP6_PRI_FILTER },
	{ .hook = kdg_edns_hook, .pf = NFPROTO_IPV6,
	  .hooknum = NF_INET_FORWARD, .priority = NF_IP6_PRI_FILTER },
};

int kdg_edns_register(struct net *net)
{
	struct kdg_netns *ns = kdg_netns_of(net);
	int ret;

	if (!ns)
		return -ENOENT;
	ret = nf_register_net_hooks(net, kdg_edns_ops, ARRAY_SIZE(kdg_edns_ops));
	if (!ret)
		ns->edns_registered = true;
	return ret;
}

void kdg_edns_unregister(struct net *net)
{
	struct kdg_netns *ns = kdg_netns_of(net);

	if (!ns || !ns->edns_registered)
		return;
	nf_unregister_net_hooks(net, kdg_edns_ops, ARRAY_SIZE(kdg_edns_ops));
	ns->edns_registered = false;
	/* 注销只摘条目，旧 hook 数组经 RCU 延迟释放；与 kdg_nat.c 同理，
	 * 显式等宽限期，保证模块卸载时没有 CPU 还在执行本 hook。 */
	synchronize_net();
}

int kdg_edns_init(void)
{
	return kdg_edns_parse(kdg_edns_default);
}