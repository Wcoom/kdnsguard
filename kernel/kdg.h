/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg.h —— kdnsguard 内核侧内部头（不对用户空间暴露）。
 *
 * 本文件只放模块内部共享的东西：per-netns 状态、全局开关、诊断计数。
 * UAPI 一律走 <uapi/kdnsguard.h>，不在这里重复定义。
 */
#ifndef _KDG_H
#define _KDG_H

#include <linux/types.h>
#include <linux/net.h>
#include <linux/atomic.h>

#include "uapi/kdnsguard.h"

#define KDG_MOD_NAME		"kdnsguard"
#define KDG_MOD_DESC		"Global kernel-space DNS takeover (DoH upstream)"

/* ⚠️ 各 .c 文件的 pr_fmt 必须写 KBUILD_MODNAME（由 kbuild 用 -D 预定义，
 * 任何 include 之前就存在），**不要**写 KDG_MOD_NAME：本头文件的 include
 * 时机排在 linux/module.h 之后，而后者链条里的 gfp.h/ratelimit.h 已经在用
 * pr_warn()，那时 KDG_MOD_NAME 尚未定义，展开成「标识符后跟字符串字面量」
 * 的语法错误，且报错位置落在内核头里，极具误导性。KDG_MOD_NAME 只用于
 * 描述性文本。 */

/* 内核默认查询 deadline（毫秒）。方案 §7.4 建议初值 3 秒。 */
#define KDG_DEFAULT_DEADLINE_MS	3000

/* 本地监听端口。方案 §5.2 的候选是 127.0.0.1:1054 —— 选 1054 而不是 53，
 * 是为了避开任何可能存在的用户态 DNS 监听者，也便于用 ss 一眼分辨。 */
#define KDG_DEFAULT_LISTEN_PORT	1054

/* 上游 bootstrap 端点（方案 §6.1）。首版编入设备配置，不做运行时下发；
 * 后续变更必须经受授权的系统调用方通过事务接口提交。 */
#define KDG_BOOTSTRAP_IPV4	"49.234.186.103"
#define KDG_UPSTREAM_HOST	"d6382545.6.00p.net"
#define KDG_UPSTREAM_PATH	"/gd/h596382545"
#define KDG_UPSTREAM_PORT	443

/* ── NAT 观察计数（per-netns） ────────────────────────────────────────── */
struct kdg_nat_stats {
	atomic64_t hook_calls;	/* hook 被调用的**总次数**（任何报文，任何协议） */
	atomic64_t seen;	/* 其中判定为明文 DNS（53 端口）的 */
	atomic64_t redirected;	/* 真正调用了 redirect 的 */
	atomic64_t bypassed;	/* 命中但按策略放行的 */
	atomic64_t dropped;
	atomic64_t debug_printed;	/* 已打印的诊断条数（debug 参数用） */
};

/* ── per-netns 状态 ───────────────────────────────────────────────────── */
struct kdg_netns {
	struct kdg_nat_stats nat;
	bool nat_registered_v4;
	bool nat_registered_v6;
	bool degraded;		/* 注册失败过；GET_HEALTH 如实上报 */
	/* 域名 -> IP 映射表、缓存、在途表在后续阶段加入，此处留位。 */
};

/* 全局（所有 netns 共享）只读配置。写路径必须经受权的事务接口，
 * 见方案 §14.1；本阶段先由模块参数提供，仅用于开发验证。 */
struct kdg_config_snapshot {
	u32 generation;
	bool intercept_enabled;
	u16 listen_port;
	u32 default_deadline_ms;
};

extern struct kdg_config_snapshot kdg_cfg;

/* debug 开关（模块参数，默认关）。开启后 NAT hook 会为最早的若干次调用
 * 打印 pf/协议/端口，用于定位「hook 挂了但谓词不匹配」这类问题。 */
extern bool kdg_debug;

/* kdg_main.c */
int kdg_netns_id(void);
struct kdg_netns *kdg_netns_of(struct net *net);

/* kdg_nat.c */
int kdg_nat_register(struct net *net);
void kdg_nat_unregister(struct net *net);
u32 kdg_nat_capability_bits(void);

/* kdg_genl.c */
int kdg_genl_init(void);
void kdg_genl_exit(void);

#endif /* _KDG_H */
