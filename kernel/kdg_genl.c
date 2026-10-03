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
		.cmd		= KDG_CMD_DISABLE_INTERCEPT,
		.doit		= kdg_genl_disable,
		.flags		= GENL_ADMIN_PERM,
		.validate	= GENL_DONT_VALIDATE_STRICT |
				  GENL_DONT_VALIDATE_DUMP,
	},
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
