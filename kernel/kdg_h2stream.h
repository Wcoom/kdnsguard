/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_h2stream.h —— 一条 H2 流的收集状态。
 *
 * 单独成一个头文件、且**只依赖 kdg_base.h**，理由是它要被两个层次同时使用：
 *  - `kdg_h2.c`（协议栈，拉 mbedTLS）；
 *  - `kdg_pool.c`（连接池策略，**不碰 mbedTLS/nghttp2**）。
 * 把它留在 kdg_h2.h 里会让池层被迫把整条 TLS 头文件链拖进来，从而没法在
 * 宿主上用 gcc + ASan 跑并发测试 —— 而池层恰恰是并发正确性最需要被测的地方。
 *
 * 所有权约定：除 `done`/`err` 之外，本结构的字段只由**驱动者**（调用
 * nghttp2_session_feed 的那个线程）写；调用方只在自己的完成信号返回之后读。
 * 没有别的线程碰它 —— 这是方案 §6.3「单一执行者」在数据结构上的体现。
 */
#ifndef _KDG_H2STREAM_H
#define _KDG_H2STREAM_H

#include "kdg_base.h"

struct kdg_h2_stream {
	u8	       *resp;		/* 由调用方提供的响应缓冲 */
	size_t		resp_cap;
	size_t		resp_len;	/* 已写入字节数 */
	u32		status;		/* :status，0 表示未收到 */
	bool		status_seen;
	bool		ct_ok;		/* content-type 是 application/dns-message */
	bool		done;		/* 到达终态（正常或错误） */
	int		err;		/* 首个错误（负 errno），0 表示无 */
	u32		stream_close_err;	/* RST_STREAM 的 error_code */
	/* 请求正文的消费游标。由提交时重置、由 data provider 回调推进；
	 * 调用方**不要**碰这三个字段。 */
	const u8       *body;
	size_t		body_len;
	size_t		body_off;
	/* 驱动者私有：该流当前是否仍被协议栈持有。**只有 nghttp2 的
	 * on_stream_close 回调（或整个会话被销毁时）才能清掉它** ——
	 * kdg_pool.c 靠它判断「槽位可不可以被复用」。 */
	bool		in_flight;
};

#endif /* _KDG_H2STREAM_H */
