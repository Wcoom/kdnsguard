/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_pool.h —— 上游 DoH 持久连接池（方案 §6.3）。
 *
 * 这个模块存在的理由可以一句话说完：**把 TCP+TLS 握手从「每次查询」降到
 * 「每条连接一次」**。
 *
 * P6 第一轮实测把代价量化了出来（`docs/P6-measurements.md`）：旧实现每查询
 * 建一条 TCP+TLS 连接、用完即关，于是在并发 64 时 p50 冲到 14 秒、159 条
 * 查询要跑 77 秒，随机 1000 条的 CPU 时间是用户态基线的 707 倍。而这些 CPU
 * 与时间几乎全部花在握手（密码学 + 多个往返）上，与解析本身无关。
 *
 * 方案 §6.3 的要求就落在这里：
 *  - **每网络一条按需连接**：连接在第一次查询时建立，此后复用；
 *  - **32 个活跃流，按对端 SETTINGS 可增至 64**：见 KDG_POOL_STREAMS_*；
 *  - **空闲 60–180 秒关闭、无保活**：见 KDG_POOL_IDLE_MS；
 *  - **单一执行者**：一条连接的全部 TLS/HTTP2 调用都在一个内核线程上完成，
 *    调用方只通过队列进入（见下）。
 *
 * ── 并发模型（本文件最需要理解的一件事）────────────────────────────────
 *
 * 旧实现把方案里的「单一执行者」直译成一把全局互斥锁，串行化了**所有**查询。
 * 那是「正确但退化」的版本：H2 的多路复用完全没被用上，因为每个查询都独占
 * 一条连接。
 *
 * 这里换成方案原文描述的那个模型 —— **一个驱动线程 + 一个请求队列**：
 *
 *   调用方（进程上下文 / listener kthread）
 *        │  只做三件事：取槽、入队、等自己的完成
 *        ▼
 *   [ g_pool.lock 保护的槽位表 + pending 链 ]
 *        │
 *        ▼
 *   驱动线程（唯一触碰 socket / mbedTLS / nghttp2 的线程）
 *        建连 → 提交队列里的流 → read/mem_recv/send 循环 → 结算
 *
 * 关键收益不是「快一点」，而是**调用方永远不会阻塞在协议栈上**：握手、收包、
 * 重传全在驱动线程里，调用方只是睡在自己的 completion 上。因此并发 64 与
 * 并发 1 对驱动线程而言没有区别 —— 64 条流在同一条连接上并行。
 *
 * ── 槽位生命周期（第二需要理解的事）────────────────────────────────────
 *
 * `struct kdg_pool_req` 是调用方与驱动线程之间**唯一**的共享对象，它的状态
 * 迁移全部在 g_pool.lock 下进行：
 *
 *   FREE ──调用方 alloc──▶ QUEUED ──驱动 pump──▶ INFLIGHT
 *                            │                      │
 *                            └────── 终态 ──────────┘
 *                                     ▼
 *                                   DONE ──调用方/驱动──▶ FREE
 *
 * 两条容易写错的地方，这里用结构本身消除掉：
 *
 *  1. **INFLIGHT → DONE 要求 `st.done && !st.in_flight`**。`in_flight` 只由
 *     nghttp2 的 on_stream_close 回调清掉 —— 也就是说「协议栈已经彻底忘掉
 *     这条流」是归还槽位的**前提**。否则槽位被 `memset` 复用后，nghttp2 会
 *     往新请求的收集结构里写旧流的数据（串台）。
 *  2. **谁释放谁**：正常路径由调用方读完成果后释放；调用方超时离开的槽位
 *     带 `abandoned` 标记，由驱动线程负责收尾与释放。两边都只在锁内改
 *     `abandoned`，所以不会双重释放、也不会泄漏。
 */
#ifndef _KDG_POOL_H
#define _KDG_POOL_H

#include "kdg_base.h"
#include "kdg_doh.h"

/*
 * 初始化槽位表。**不建线程** —— 驱动线程在第一次查询时懒启动（方案 §9.3
 * 「无请求时 worker 睡眠」的延伸：一个从没查过上游的模块不该有常驻线程）。
 * 由 kdg_main.c 在 init 阶段调用；失败即模块加载失败。
 */
int kdg_pool_init(void);

/*
 * 完成一次上游查询（经连接池）。
 *
 * 与 kdg_doh_query 的区别：本函数**只走 H2**。对端 ALPN 没协商出 h2 时返回
 * -EPROTONOSUPPORT，由 kdg_doh.c 回落到 H1 兼容路径（方案 §6.4）——「不支持
 * h2」与「上游坏了」是两件事，只有前者该回落。
 *
 * 返回值与 kdg_doh_query 一致（0 或负 errno）。
 */
int kdg_pool_query(const struct kdg_doh_cfg *cfg,
		   const u8 *qwire, size_t qlen,
		   u8 *rwire, size_t *rlen);

/* 停止驱动线程并拆掉连接。由模块 exit 在**所有调用方都已退出之后**调用
 * （kdg_chardev_exit / kdg_listener_stop 已经保证了这一点）。幂等。 */
void kdg_pool_shutdown(void);

struct kdg_pool_stats {
	u64 queries;		/* 进入池的查询数 */
	u64 connects;		/* 建立过的连接数（TCP + TLS + H2 会话） */
	u64 reused;		/* 复用既有连接完成的查询数 —— 池化的直接证据 */
	u64 idle_closes;	/* 因空闲被主动关闭的连接数 */
	u64 conn_errors;	/* 连接级失败次数（连带失败在途流） */
	u64 upstream_timeouts;	/* 因超过 deadline 被取消的流 */
	u64 wait_timeouts;	/* 调用方等过自己的上限仍无结果（不该发生） */
	u64 rejected;		/* 槽位满，明确拒绝 */
	u64 h1_fallbacks;	/* 对端不支持 h2，交回 H1 路径 */
	u64 stream_resets_sent;
	u32 inflight;		/* 当前在途流数 */
	u32 queued;		/* 当前排队待提交的请求数 */
	u32 stream_limit;	/* 当前生效的并发流上限 */
	u32 slots_used;
	u32 slots_max;
	u8  connected;		/* 连接当前是否可用 */
};
void kdg_pool_get_stats(struct kdg_pool_stats *out);

#endif /* _KDG_POOL_H */
