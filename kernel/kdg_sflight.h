/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_sflight.h —— 同名查询合并（方案 §7.2 / §7.3 的 singleflight）。
 *
 * 语义：同一个合并键上同时到达的 N 个请求，只产生**一次**上游查询，
 * 其余 N-1 个挂在该次查询上等待结果。方案 §7.3 的验收口径是
 * 「同键 100 次请求只产生一次正常上游查询，挂载 100 个有界 waiter」。
 *
 * ⚠️ 当前实现的一个**如实边界**：owner 一旦进入上游查询（阻塞在
 * kernel_sendmsg/kernel_recvmsg 里），就无法中途撤销，因此方案 §7.3 的
 * 「所有 waiter 均取消才考虑取消上游」在本期**不成立** —— waiter 可以
 * 超时或被信号打断而脱离，但 owner 会把这次查询跑完（结果照样进缓存，
 * 不浪费）。要做到撤销上游需要异步请求队列，那是 P3 的工作。
 * 本期真正拿到手的收益是：N 个 waiter 不会各自发起一次 TLS 握手。
 *
 * 内存纪律（方案 §7.4「单查询 waiter 128」）：每个键的 waiter 数有上限，
 * 超过即拒绝加入（返回 -EAGAIN），而不是无界挂载。
 */
#ifndef _KDG_SFLIGHT_H
#define _KDG_SFLIGHT_H

#include <linux/types.h>

#include "kdg_cache.h"

/* 方案 §7.4：单查询 waiter 上限 128；在途不同查询 256、全局硬上限 1024。 */
#define KDG_SF_MAX_WAITERS	128
#define KDG_SF_MAX_FLIGHTS	1024

struct kdg_flight;

/* begin 的返回值 */
#define KDG_SF_OWNER	1	/* 本调用方负责发起上游查询 */
#define KDG_SF_WAIT	0	/* 已有在途查询，应调 wait 等结果 */

int  kdg_sflight_init(void);
void kdg_sflight_exit(void);

/*
 * 声明参与某个键的合并。返回 KDG_SF_OWNER 或 KDG_SF_WAIT（均 >= 0），
 * 或负 errno（-EAGAIN 表示该键的 waiter 已满，-ENOMEM）。
 *
 * 无论哪种结果，**成功时 *out 都带一个引用**，用完必须 kdg_sflight_release()。
 * 上限错误必须直接返回，不得绕过配额发起独立上游请求。
 */
int kdg_sflight_begin(const struct kdg_cache_key *key, struct kdg_flight **out);

/*
 * 等 owner 的结果，并把响应复制进 out。
 * timeout_ms 为本次等待的上限（调用方自己的 deadline，方案 §7.3
 * 「每个 waiter 保存独立 deadline」）。
 * 返回 0 或负 errno：-ETIMEDOUT（超时）、-ERESTARTSYS（被信号打断）、
 * 或 owner 上游查询本身的错误码。
 */
int kdg_sflight_wait(struct kdg_flight *f, u32 timeout_ms,
		     u8 *out, size_t cap, size_t *outlen);

/*
 * owner 发布结果（status==0 时 resp/resp_len 有效）。
 * 发布后该键立刻从合并表移除：后来的请求不该再挂到一个已完成的查询上，
 * 它们应当去命中的是缓存（owner 会先把结果写进缓存）。
 */
void kdg_sflight_publish(struct kdg_flight *f, int status,
			 const u8 *resp, size_t resp_len);

/* 释放一个引用。最后一个引用负责回收。 */
void kdg_sflight_release(struct kdg_flight *f);

struct kdg_sflight_stats {
	u32 inflight;		/* 当前在途查询数 */
	u32 waiters;		/* 当前挂载的 waiter 数 */
	u64 joined;		/* 累计「搭车」次数 */
	u64 owned;		/* 累计「发起上游」次数 */
	u64 rejected_full;	/* 因 waiter 满被拒的次数 */
	u64 timeouts;		/* waiter 超时次数 */
};
void kdg_sflight_stats(struct kdg_sflight_stats *out);

#endif /* _KDG_SFLIGHT_H */
