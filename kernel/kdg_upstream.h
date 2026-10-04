/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_upstream.h —— **一条**到上游 DoH 端点的连接（TCP + TLS + H2 会话）。
 *
 * 为什么把它从连接池里分出来：池里有两件性质完全不同的事 ——
 *   ① **策略**：槽位表、排队、超期取消、空闲关闭、谁在等谁（kdg_pool.c）；
 *   ② **连接**：建连、握手、收发、协议状态（本文件）。
 * 混在一起时，池层会被迫把整条 mbedTLS/nghttp2 头文件链拖进来，于是它就没法
 * 在宿主上用 gcc + ASan 跑并发测试 —— 而并发正确性正是池层最需要被测的东西。
 * 分开之后池层只认一个不透明句柄，宿主测试给它一个替身就能跑。
 *
 * 一个 `struct kdg_upstream` 的全部方法都**只能在同一个线程上调用**
 * （「单一执行者」，方案 §6.2）。本层不做任何加锁：线程安全由调用方
 * 用「一个驱动线程」这条更强的性质保证，而不是靠锁去修补。
 */
#ifndef _KDG_UPSTREAM_H
#define _KDG_UPSTREAM_H

#include "kdg_base.h"
#include "kdg_h2stream.h"
#include "kdg_doh.h"

struct kdg_upstream;

/*
 * 读滴答（毫秒）。**它不是失败判据**：`kdg_upstream_read` 在到期时返回
 * -EAGAIN（「这一轮没有数据」），而不是错误。
 *
 * 为什么要有它：驱动线程既是收包的、也是出队的 —— 它得定期回来提交新入队的
 * 请求、取消超期的流。若一次读阻塞整个 deadline，那些事在三秒里都做不了。
 * 250 ms 是「几乎不影响吞吐」与「取消够及时」之间的折中：响应一到就立刻
 * 返回，这个值只在**没数据**时起作用。池层的超期扫描精度也由它决定。
 */
#define KDG_UPSTREAM_TICK_MS	250

/* 方案 §6.3：「32 个活跃流，按对端 SETTINGS 可增至 64」。
 * 「增至」是有条件的：只有对端**确实声明过** SETTINGS 之后才按它的值放宽 ——
 * nghttp2 把未声明的 max_concurrent_streams 预置成 RFC 默认的 100，单看那个
 * 值分不清「对端说了 100」与「对端还什么都没说」。 */
#define KDG_UPSTREAM_STREAMS_INIT	32
#define KDG_UPSTREAM_STREAMS_MAX	64

/*
 * 建立连接：TCP 连接 → TLS 握手（含证书链与主机名校验）→ ALPN 协商 → H2 会话。
 * deadline_ms 同时用作握手期单次收发的上限与后续的默认超时。
 *
 * 返回 0，或负 errno。其中两个**必须区分开**：
 *   -EPROTONOSUPPORT  对端 ALPN 不是 h2（方案 §6.4：该走 H1 兼容路径）
 *   其它负值          上游真的坏了（不可达、证书不通过、协议错）
 * 调用方按这个区分决定「回落」还是「失败」—— 拿一次性的 H1 连接去重试一个
 * 已经坏了的上游，只会把一次失败变成两次。
 */
int  kdg_upstream_open(struct kdg_upstream **out, const struct kdg_doh_cfg *cfg,
		       u32 deadline_ms);
void kdg_upstream_close(struct kdg_upstream *u);

/* 提交一条 POST 流。*stream_id 回填流号（取消时要用）。 */
int  kdg_upstream_submit(struct kdg_upstream *u, const u8 *body, size_t len,
			 struct kdg_h2_stream *st, int32_t *stream_id);

/*
 * 读一批并喂进协议栈（会同步触发回调，写各流的收集结构）。
 * 返回**读到的字节数**（>0）；
 *   -EAGAIN  滴答到期、暂无数据（正常）
 *   -EIO     对端关闭或 TLS/协议层错误（连接已不可用）
 */
int  kdg_upstream_read(struct kdg_upstream *u, u8 *buf, size_t cap);

/* 把待发帧刷到 TLS（SETTINGS ACK、WINDOW_UPDATE、请求帧、RST_STREAM…）。
 * 返回 0 或负 errno。 */
int  kdg_upstream_flush(struct kdg_upstream *u);

/* 取消一条流（调用方超时，或请求被放弃）。 */
void kdg_upstream_reset_stream(struct kdg_upstream *u, int32_t stream_id);

/* 连接是否已不可用（GOAWAY、协议错、TLS 错）。不可用之后不得再提交新流。 */
bool kdg_upstream_dead(const struct kdg_upstream *u);
int  kdg_upstream_err(const struct kdg_upstream *u);

/*
 * 当前生效的并发流上限：对端 SETTINGS 声明前用 32，声明后取它的值并截到 64
 * （方案 §6.3「32 个活跃流，按对端 SETTINGS 可增至 64」）。
 */
u32  kdg_upstream_stream_limit(const struct kdg_upstream *u);

#endif /* _KDG_UPSTREAM_H */
