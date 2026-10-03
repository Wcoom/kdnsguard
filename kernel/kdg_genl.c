/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_genl.c —— 管理面：Generic Netlink 族 "KDNSGUARD"（方案 §14.1）。
 *
 * 纪律（全部来自方案 §14，违反任何一条都会变成安全问题）：
 *  - 管理面**不承载高频 DNS 正文**，那走字符设备（§14.2）。这里只有
 *    配置事务与状态查询。
 *  - 所有变更命令要求 CAP_NET_ADMIN：普通 App 不得换上游。
 *  - 不输出完整上游 URI，也不输出查询域名。本阶段尚无可泄漏的内容，
 *    但 GET_HEALTH 只给计数与状态，结构上就不给泄漏留位置。
 *  - CAPS 如实申报。未实现的能力**不置位**，调用方不得据此推断可用
 *    （§16 明确要求 H3 在验收前恒为 false）。
 */
#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/slab.h>
#include <net/genetlink.h>
#include <net/net_namespace.h>

#include "kdg.h"
#include "kdg_tls.h"
#include "kdg_doh.h"
#include "kdg_cache_tab.h"
#include "kdg_resolve.h"
#include "kdg_sflight.h"
#include "kdg_quota.h"

/* 骨架阶段的安全闸：即使有人拿到 CAP_NET_ADMIN 并调用 ENABLE_INTERCEPT，
 * 只要模块不是以 allow_intercept=1 加载的，就拒绝启用。理由是本阶段
 * **还没有**本地 DNS 监听者，一旦启用接管，53 端口流量会被改写到
 * 127.0.0.1:1054 而无人应答 —— 等于把手机的 DNS 打断。
 * 这是「分阶段推进、每步都有退出条件」的落地（§16 P3 之前不该能开）。 */
extern bool kdg_allow_intercept;

/* 处理函数先声明，让 ops 数组与 family 结构体能先定义；处理函数体内要用
 * kdg_genl_family 构造回包，形成相互引用，前置声明是标准解法。 */
static int kdg_genl_caps(struct sk_buff *skb, struct genl_info *info);
static int kdg_genl_health(struct sk_buff *skb, struct genl_info *info);
static int kdg_genl_enable(struct sk_buff *skb, struct genl_info *info);
static int kdg_genl_disable(struct sk_buff *skb, struct genl_info *info);
static int kdg_genl_set_trust(struct sk_buff *skb, struct genl_info *info);

static const struct genl_ops kdg_genl_ops[] = {
	{
		.cmd		= KDG_CMD_CAPS,
		.doit		= kdg_genl_caps,
		/* CAPS 不限权限：系统桥需要在不提权的情况下问「支持什么」。 */
		.validate	= GENL_DONT_VALIDATE_STRICT |
				  GENL_DONT_VALIDATE_DUMP,
	},
	{
		.cmd		= KDG_CMD_GET_HEALTH,
		.doit		= kdg_genl_health,
		.flags		= GENL_ADMIN_PERM,
		.validate	= GENL_DONT_VALIDATE_STRICT |
				  GENL_DONT_VALIDATE_DUMP,
	},
	{
		.cmd		= KDG_CMD_ENABLE_INTERCEPT,
		.doit		= kdg_genl_enable,
		.flags		= GENL_ADMIN_PERM,
		.validate	= GENL_DONT_VALIDATE_STRICT |
				  GENL_DONT_VALIDATE_DUMP,
	},
	{
		.cmd		= KDG_CMD_SET_TRUST,
		.doit		= kdg_genl_set_trust,
		.flags		= GENL_ADMIN_PERM,
		.validate	= GENL_DONT_VALIDATE_STRICT |
				  GENL_DONT_VALIDATE_DUMP,
	},
	{
		.cmd		= KDG_CMD_DISABLE_INTERCEPT,
		.doit		= kdg_genl_disable,
		.flags		= GENL_ADMIN_PERM,
		.validate	= GENL_DONT_VALIDATE_STRICT |
				  GENL_DONT_VALIDATE_DUMP,
	},
};

/* 属性策略。TRUST_MATERIAL 给到 16 KiB 上限：一张 PEM 证书约 1.5–2 KiB，
 * 一个常见的 CA bundle 在几十张的量级，16 KiB 足以分批喂入而不会让一次
 * 分配过大（方案 §7.4 的内存纪律同样适用于控制面）。 */
static const struct nla_policy kdg_genl_policy[KDG_A_MAX + 1] = {
	[KDG_A_ABI_VERSION]	= { .type = NLA_U16 },
	[KDG_A_TRUST_MATERIAL]	= { .type = NLA_BINARY, .len = 16384 },
	[KDG_A_GENERATION]	= { .type = NLA_U32 },
	[KDG_A_READINESS]	= { .type = NLA_U32 },
	[KDG_A_ERRNO]		= { .type = NLA_S32 },
};

static struct genl_family kdg_genl_family = {
	.name		= KDG_GENL_NAME,
	.version	= KDG_GENL_VERSION,
	.maxattr	= KDG_A_MAX,
	.module		= THIS_MODULE,
	.ops		= kdg_genl_ops,
	.n_ops		= ARRAY_SIZE(kdg_genl_ops),
	/* 本族不使用任何内核内部保留 cmd；显式声明而不是留 0，避免
	 * 将来新增 cmd 时与内核保留区间悄悄相撞。 */
	.resv_start_op	= __KDG_CMD_MAX,
	.policy		= kdg_genl_policy,
};

static int kdg_genl_caps(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg;
	void *hdr;

	msg = nlmsg_new(64, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put_reply(msg, info, &kdg_genl_family, 0, KDG_CMD_CAPS);
	if (!hdr) {
		nlmsg_free(msg);
		return -EMSGSIZE;
	}

	if (nla_put_u16(msg, KDG_A_ABI_VERSION, KDG_ABI_VERSION) ||
	    nla_put_u32(msg, KDG_A_CAPABILITY_BITS, kdg_nat_capability_bits())) {
		nlmsg_free(msg);
		return -EMSGSIZE;
	}

	genlmsg_end(msg, hdr);
	return genlmsg_reply(msg, info);
}

static int kdg_genl_health(struct sk_buff *skb, struct genl_info *info)
{
	struct kdg_netns *ns = kdg_netns_of(genl_info_net(info));
	struct sk_buff *msg;
	struct nlattr *nest;
	void *hdr;

	if (!ns)
		return -ENOENT;

	msg = nlmsg_new(192, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put_reply(msg, info, &kdg_genl_family, 0,
				KDG_CMD_GET_HEALTH);
	if (!hdr)
		goto nla_failure;

	if (nla_put_u16(msg, KDG_A_ABI_VERSION, KDG_ABI_VERSION) ||
	    nla_put_u32(msg, KDG_A_GENERATION, READ_ONCE(kdg_cfg.generation)))
		goto nla_failure;

	nest = nla_nest_start(msg, KDG_A_HEALTH);
	if (!nest)
		goto nla_failure;

	/* 所有权如实上报：§10.1 要求把「已由内核策略接管」显式反映出去，
	 * 而不是让设置页停留在 strict 却实际查了别的账户。 */
	if (nla_put_u32(msg, KDG_HA_OWNERSHIP,
			READ_ONCE(kdg_cfg.intercept_enabled) ? KDG_OWN_ACTIVE
							     : KDG_OWN_NONE) ||
	    nla_put_u8(msg, KDG_HA_UPSTREAM_OK, 0) ||
	    nla_put_u32(msg, KDG_HA_CONSECUTIVE_FAILURES, 0) ||
	    nla_put_u32(msg, KDG_HA_BACKOFF_UNTIL_MS, 0) ||
	    /* 传输层未落地前，上游恒为「未验证」而不是「正常」——不假报。 */
	    nla_put_s32(msg, KDG_HA_LAST_ERRNO, -ENOTCONN) ||
	    nla_put_u64_64bit(msg, KDG_HA_NAT_SEEN,
			      atomic64_read(&ns->nat.seen), KDG_HA_UNSPEC) ||
	    nla_put_u64_64bit(msg, KDG_HA_NAT_REDIRECTED,
			      atomic64_read(&ns->nat.redirected),
			      KDG_HA_UNSPEC) ||
	    nla_put_u64_64bit(msg, KDG_HA_NAT_BYPASSED,
			      atomic64_read(&ns->nat.bypassed),
			      KDG_HA_UNSPEC) ||
	    nla_put_u64_64bit(msg, KDG_HA_NAT_HOOK_CALLS,
			      atomic64_read(&ns->nat.hook_calls),
			      KDG_HA_UNSPEC)) {
		nla_nest_cancel(msg, nest);
		goto nla_failure;
	}

	{
		struct kdg_doh_stats ds;
		struct kdg_cache_stats cs;
		struct kdg_resolve_stats rs;
		struct kdg_sflight_stats fs;
		struct kdg_quota_stats qs;

		kdg_doh_get_stats(&ds);
		kdg_cache_stats(&cs);
		kdg_resolve_get_stats(&rs);
		kdg_sflight_stats(&fs);
		kdg_quota_stats(&qs);
		if (nla_put_u32(msg, KDG_HA_CA_COUNT, kdg_tls_ca_count()) ||
		    nla_put_u64_64bit(msg, KDG_HA_DOH_QUERIES, ds.queries,
				      KDG_HA_UNSPEC) ||
		    nla_put_u64_64bit(msg, KDG_HA_DOH_OK, ds.ok,
				      KDG_HA_UNSPEC) ||
		    nla_put_u32(msg, KDG_HA_DOH_LAST_STATUS,
				ds.last_http_status) ||
		    nla_put_u32(msg, KDG_HA_DOH_LAST_RTT_MS,
				ds.last_rtt_ms) ||
		    nla_put_u64_64bit(msg, KDG_HA_CACHE_HITS, cs.hits,
				      KDG_HA_UNSPEC) ||
		    nla_put_u64_64bit(msg, KDG_HA_CACHE_MISSES, cs.misses,
				      KDG_HA_UNSPEC) ||
		    nla_put_u64_64bit(msg, KDG_HA_CACHE_STALE, cs.stale,
				      KDG_HA_UNSPEC) ||
		    nla_put_u64_64bit(msg, KDG_HA_CACHE_EVICTIONS,
				      cs.evictions, KDG_HA_UNSPEC) ||
		    nla_put_u32(msg, KDG_HA_CACHE_ENTRIES, cs.entries) ||
		    nla_put_u32(msg, KDG_HA_CACHE_MEM_BYTES, cs.mem_bytes) ||
		    nla_put_u64_64bit(msg, KDG_HA_RESOLVE_CACHE, rs.from_cache,
				      KDG_HA_UNSPEC) ||
		    nla_put_u64_64bit(msg, KDG_HA_RESOLVE_UPSTREAM,
				      rs.from_upstream, KDG_HA_UNSPEC) ||
		    nla_put_u64_64bit(msg, KDG_HA_RESOLVE_JOINED,
				      rs.from_joined, KDG_HA_UNSPEC) ||
		    nla_put_u64_64bit(msg, KDG_HA_RESOLVE_CACHE_PUT,
				      rs.cache_put_ok, KDG_HA_UNSPEC) ||
		    nla_put_u32(msg, KDG_HA_SF_INFLIGHT, fs.inflight) ||
		    nla_put_u32(msg, KDG_HA_SF_WAITERS, fs.waiters) ||
		    nla_put_u64_64bit(msg, KDG_HA_SF_REJECTED,
				      fs.rejected_full, KDG_HA_UNSPEC) ||
		    nla_put_u64_64bit(msg, KDG_HA_QUOTA_ALLOWED, qs.allowed,
				      KDG_HA_UNSPEC) ||
		    nla_put_u64_64bit(msg, KDG_HA_QUOTA_DENIED, qs.denied,
				      KDG_HA_UNSPEC) ||
		    nla_put_u32(msg, KDG_HA_QUOTA_BUCKETS, qs.buckets_used)) {
			nla_nest_cancel(msg, nest);
			goto nla_failure;
		}
	}
	nla_nest_end(msg, nest);

	genlmsg_end(msg, hdr);
	return genlmsg_reply(msg, info);

nla_failure:
	nlmsg_free(msg);
	return -EMSGSIZE;
}

/*
 * 启停接管。两者都要求 CAP_NET_ADMIN，且启用还要求模块以
 * allow_intercept=1 加载 —— 原因见文件头。
 */
static int kdg_genl_set_intercept(bool enable)
{
	if (enable && !READ_ONCE(kdg_allow_intercept)) {
		pr_warn_ratelimited("ENABLE_INTERCEPT 被拒绝：模块未以 allow_intercept=1 加载\n");
		return -EPERM;
	}

	/* generation 单调递增：方案 §5.1 要求「切换期间宁可返回短时明确失败，
	 * 也不能出现两个 DNS 处理器串联」。旧 generation 的在途请求由调用方
	 * 自行作废，内核侧不做隐式迁移。 */
	WRITE_ONCE(kdg_cfg.intercept_enabled, enable);
	WRITE_ONCE(kdg_cfg.generation, READ_ONCE(kdg_cfg.generation) + 1);

	pr_info("接管状态 -> %s (generation=%u)\n",
		enable ? "启用" : "停用", READ_ONCE(kdg_cfg.generation));
	return 0;
}

/*
 * 加载上游信任锚（方案 §6.2「受保护的初始化接口」）。
 * 要求 CAP_NET_ADMIN：能换信任锚就能把上游换成任何人，这正是
 * 方案 §14.1 说的「普通 App 不得换上游」。
 */
static int kdg_genl_set_trust(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg;
	void *hdr;
	const void *data;
	size_t len;
	int added, ret;

	if (!info->attrs[KDG_A_TRUST_MATERIAL])
		return -EINVAL;

	data = nla_data(info->attrs[KDG_A_TRUST_MATERIAL]);
	len = nla_len(info->attrs[KDG_A_TRUST_MATERIAL]);
	if (len == 0)
		return -EINVAL;

	/* 受 debug 参数控制的首字节转储。曾用来定位「工具缓冲区越界导致
	 * PEM 被污染」——内核侧只看到 INVALID_FORMAT，看原始字节两分钟定位。 */
	if (unlikely(READ_ONCE(kdg_debug))) {
		const u8 *p = data;

		pr_info("信任锚入参 %zu 字节，首 24: %02x %02x %02x %02x %02x %02x %02x %02x"
			" %02x %02x %02x %02x %02x %02x %02x %02x"
			" %02x %02x %02x %02x %02x %02x %02x %02x\n",
			len, p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
			p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15],
			p[16], p[17], p[18], p[19], p[20], p[21], p[22], p[23]);
	}

	added = kdg_tls_add_ca(data, len);
	if (added < 0) {
		pr_warn("信任锚加载失败: %d\n", added);
		return added;
	}

	pr_info("信任锚加载：本次 %d 张，累计 %u 张\n", added,
		kdg_tls_ca_count());

	msg = nlmsg_new(64, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put_reply(msg, info, &kdg_genl_family, 0,
				KDG_CMD_SET_TRUST);
	if (!hdr) {
		nlmsg_free(msg);
		return -EMSGSIZE;
	}

	ret = 0;
	if (nla_put_u32(msg, KDG_A_CA_ADDED, (u32)added) ||
	    nla_put_u32(msg, KDG_A_CA_TOTAL, kdg_tls_ca_count())) {
		nlmsg_free(msg);
		return -EMSGSIZE;
	}

	genlmsg_end(msg, hdr);
	return genlmsg_reply(msg, info);
}

static int kdg_genl_enable(struct sk_buff *skb, struct genl_info *info)
{
	return kdg_genl_set_intercept(true);
}

static int kdg_genl_disable(struct sk_buff *skb, struct genl_info *info)
{
	return kdg_genl_set_intercept(false);
}

int kdg_genl_init(void)
{
	return genl_register_family(&kdg_genl_family);
}

void kdg_genl_exit(void)
{
	genl_unregister_family(&kdg_genl_family);
}
