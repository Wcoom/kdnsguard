/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_quota.h —— 每调用方配额（方案 §7.3「每调用方 token bucket」）。
 *
 * 要解决的问题：一个跑飞的 App 不该把整机的 DNS 能力吃光 —— 它既会挤占
 * 别人的解析，也会把模块的内存配额（在途对象、waiter、缓存）拖到上限。
 * 方案 §7.3 的措辞是「队列使用按 UID/策略视图的公平调度与每调用方
 * token bucket」「全局队列满时返回 EAGAIN」。
 *
 * ⚠️ 本期形态的如实说明：当前是**同步模型**（一次查询在调用方的进程上下文里
 * 阻塞跑完），因此**没有队列**可以谈公平调度。本期落地的是方案里可落地的那
 * 一半 —— 每调用方 token bucket 的**准入控制**：超额直接 -EAGAIN，而不是
 * 排队。真正的「公平队列」要等 P3 引入异步请求队列与 worker 池。
 *
 * 身份来源：调用方的**有效 UID**，取自内核凭据（`current_fsuid()`），
 * **不信任请求里自报的任何身份** —— 方案 §7.2/§14.2 都点名了这一点。
 */
#ifndef _KDG_QUOTA_H
#define _KDG_QUOTA_H

#include <linux/types.h>

/* 桶数量。取 256：Android 上的活跃调用方是几十的量级，
 * 256 足以让实际参与配额的身份基本不冲突。 */
#define KDG_QUOTA_BUCKETS	256

int  kdg_quota_init(void);
void kdg_quota_exit(void);

/*
 * 为一个调用方扣一次配额。
 * 返回 0（放行）或 -EAGAIN（超额）。
 *
 * timeout 语义：本函数不阻塞、不排队 —— 「超过配额就明确失败」正是方案
 * §7.3 要的（「不让一款随机域名 App 阻塞整机」）。
 */
int kdg_quota_charge(u32 uid);

struct kdg_quota_stats {
	u64 allowed;
	u64 denied;
	u32 buckets_used;
	u32 rate_per_sec;	/* 当前生效参数（1 秒补多少个 token） */
	u32 burst;		/* 桶容量 */
};
void kdg_quota_stats(struct kdg_quota_stats *out);

/* 清空所有桶（用于配置变更后立即生效，避免旧的令牌残留）。 */
void kdg_quota_reset(void);

#endif /* _KDG_QUOTA_H */
