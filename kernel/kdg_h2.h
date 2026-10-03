/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_h2.h —— 内核态 HTTP/2 DoH 客户端（方案 §6.3）。
 *
 * 复用内核自带的 nghttp2（third_party/nghttp2，已编入模块），只做三件事：
 *   1. 建会话、注册回调、把它的 send 回调接到底层的 TLS 会话上
 *   2. 提交一次 POST 请求（正文是 DNS wire 报文，RFC 8484 §4.1）
 *   3. 用 mem_recv 驱动收包，把响应头与正文收集出来
 *
 * 方案 §6.3 的几条要求在本文件落地：
 *  - 「关闭 server push」：会话选项里显式关掉
 *  - 「限制 header list / HPACK 内存、帧处理预算、DATA 累计长度」：见常量与
 *    SETTINGS/选项设置
 *  - 「正确处理 SETTINGS、WINDOW_UPDATE、GOAWAY 和 RST_STREAM」：由 nghttp2
 *    自身处理，我们只把终态（stream close / GOAWAY）如实上报为错误
 *  - 「请求拒绝、连接关闭与可重试条件分别处理」：本层把 stream error 与
 *    连接级错误都变成不同的负 errno
 *
 * 与 H1 的关系：方案 §6.4 说 H1 是「先导与兼容路径」。本层的存在不取消 H1 ——
 * kdg_doh.c 按 ALPN 协商结果选择走哪一条；服务端不支持 h2 时自动回落到 H1。
 */
#ifndef _KDG_H2_H
#define _KDG_H2_H

#include "kdg_base.h"
#include "kdg_tls.h"

/* 响应正文的硬上限。与 UAPI 的报文上限一致；超出即拒绝而不是截断 ——
 * 截断的 DNS 响应会被上层的 wire 校验当成畸形报文，不如在这里明确失败。 */
#define KDG_H2_MAX_BODY		KDG_MAX_WIRE_MSG

/* 单次会话允许的接收头字节数（HPACK 解压后的累计）。防 header 洪泛。 */
#define KDG_H2_MAX_HEADER_BYTES	16384

/*
 * 用已握手的 TLS 会话提交一次 DoH 请求。
 * hostname/path 用于构造 :authority 与 :path。
 * 返回 0 或负 errno：
 *   -EMSGSIZE  响应正文超出 KDG_H2_MAX_BODY，或头部超出上限
 *   -EBADMSG   协议层错误（stream reset、GOAWAY、nghttp2 报错）
 *   -ETIMEDOUT 底层读超时
 *   -EPROTO    服务端返回非 200
 */
int kdg_h2_doh_request(struct kdg_tls *tls, const char *hostname,
		       const char *path,
		       const u8 *body, size_t body_len,
		       u8 *resp, size_t resp_cap, size_t *resp_len);

struct kdg_h2_stats {
	u64 sessions;
	u64 requests;
	u64 ok;
	u64 failed;
	u64 proto_errors;	/* nghttp2 层错误 */
	u64 stream_resets;
	u64 non_200;
	u32 last_nghttp2_err;
	u32 last_status;
};
void kdg_h2_get_stats(struct kdg_h2_stats *out);

#endif /* _KDG_H2_H */
