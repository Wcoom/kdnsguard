/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_h2.h —— 内核态 HTTP/2 **会话**（方案 §6.3）。
 *
 * 与上一版的区别（这是一次有意的形态转换）：
 *  - 旧版是 `kdg_h2_doh_request()` —— 「建会话 → 发一个请求 → 收完 → 销毁会话」，
 *    每个查询一条连接。它证明了 H2 链路能通，但把 H2 最值钱的能力（多路复用）
 *    整个丢掉了：实测并发 64 时 p50 14 秒、170 次查询要 77 秒，全部花在
 *    TCP+TLS 握手上。
 *  - 新版只暴露**会话**：建一次、提交多条流、由一个驱动者用 mem_recv 推进、
 *    最后释放。连接的生命周期上移到 kdg_pool.c。
 *
 * 本层刻意**不碰 socket，也不碰超时**：
 *  - 读写都经调用方传进来的 `struct kdg_tls *`（send 回调直接用它的 write）；
 *  - 喂给 mem_recv 的字节由调用方从 TLS 读出来后交进来；
 *  - 「什么时候放弃」是连接级的决策，属 kdg_pool.c。
 * 这样本层就是纯粹的协议状态机，没有 I/O 策略混在里面。
 *
 * 方案 §6.3 的几条要求在这里落地：
 *  - 「关闭 server push」：nghttp2 作为客户端在初始 SETTINGS 里就置
 *    ENABLE_PUSH=0（这是它的既有行为）
 *  - 「限制 header list / HPACK 内存」：把自己的 SETTINGS_MAX_HEADER_LIST_SIZE
 *    告诉对端（见 KDG_H2_MAX_HEADER_BYTES）
 *  - 「正确处理 SETTINGS、WINDOW_UPDATE、GOAWAY 和 RST_STREAM」：由 nghttp2
 *    自身处理，本层只把终态如实上报 —— GOAWAY 记成会话级错误（连接不可再用），
 *    RST_STREAM / 流错误记成**该流**的错误（其余流不受影响）
 *
 * 与 H1 的关系（方案 §6.4）：H1 是兼容路径。服务端 ALPN 没协商出 h2 时由
 * kdg_doh.c 回落到它，本层不参与。
 */
#ifndef _KDG_H2_H
#define _KDG_H2_H

#include "kdg_base.h"
#include "kdg_h2stream.h"
/* 需要在实现里驱动 mbedTLS 会话，但**头文件只用到指针** —— 因此这里只
 * 前置声明，把 mbedTLS 的完整定义留给 kdg_h2.c。这样 kdg_pool.c 通过
 * kdg_h2stream.h 拿到流状态时不会连带拖进整条 TLS 头文件链。 */
struct kdg_tls;

/* 单条响应正文的硬上限。与 UAPI 的报文上限一致；超出即拒绝而不是截断 ——
 * 截断的 DNS 响应会被上层的 wire 校验当成畸形报文，不如在这里明确失败。 */
#define KDG_H2_MAX_BODY		KDG_MAX_WIRE_MSG

/* 单次会话允许的接收头字节数（HPACK 解压后的累计）。防 header 洪泛。 */
#define KDG_H2_MAX_HEADER_BYTES	16384

struct kdg_h2_session;

/* 建会话。tls 必须已完成握手且 ALPN 协商为 h2。hostname/path 用于构造
 * :authority 与 :path，**建会话时就被拷贝进会话对象**，调用方不必保证它们
 * 之后仍然有效。返回 0 或负 errno。 */
int  kdg_h2_session_new(struct kdg_h2_session **out, struct kdg_tls *tls,
			const char *hostname, const char *path);
void kdg_h2_session_free(struct kdg_h2_session *s);

/* 提交一条 POST 请求（正文是 DNS wire 报文，RFC 8484 §4.1）。
 * *stream_id 回填分配到的流号。返回 0 或负 errno。
 * 注意：请求**还没发出去**，写完必须调 kdg_h2_session_flush()。 */
int  kdg_h2_session_submit(struct kdg_h2_session *s,
			   const u8 *body, size_t len,
			   struct kdg_h2_stream *st, int32_t *stream_id);

/* 把收到的字节喂进协议栈（会同步触发回调，写 st 的字段）。 */
int  kdg_h2_session_feed(struct kdg_h2_session *s, const u8 *buf, size_t len);

/* 把待发帧刷到 TLS（含 SETTINGS ACK / WINDOW_UPDATE / PING ACK / 请求帧）。 */
int  kdg_h2_session_flush(struct kdg_h2_session *s);

/* 主动取消一条流（调用方超时或连接级失败时用）。 */
void kdg_h2_session_reset_stream(struct kdg_h2_session *s, int32_t stream_id);

/* 会话是否已不可用（收到 GOAWAY，或出现过致命的协议错误）。 */
bool kdg_h2_session_dead(const struct kdg_h2_session *s);
int  kdg_h2_session_err(const struct kdg_h2_session *s);

/* 对端声明的并发流上限。**在收到对端 SETTINGS 之前返回 0**，调用方据此
 * 区分「还没协商」与「对端真的声明了很小的值」。 */
u32  kdg_h2_session_peer_max_streams(const struct kdg_h2_session *s);
bool kdg_h2_session_peer_settings_seen(const struct kdg_h2_session *s);

struct kdg_h2_stats {
	u64 sessions;		/* 建立过的会话数（= 连接数） */
	u64 requests;		/* 提交过的流数 */
	u64 ok;
	u64 failed;
	u64 proto_errors;	/* nghttp2 层错误 */
	u64 stream_resets;
	u64 non_200;
	u64 goaways;
	u32 last_nghttp2_err;
	u32 last_status;
};
void kdg_h2_get_stats(struct kdg_h2_stats *out);

#endif /* _KDG_H2_H */
