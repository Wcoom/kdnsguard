/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_doh.h —— DoH 上游查询（传输选择层）。
 *
 * 本文件定义的是**对外契约与上游端点描述**，不是某一种传输的实现：
 *  - 主线走 H2 持久连接池（`kdg_pool.c`，方案 §6.3）；
 *  - 对端不支持 h2 时回落到一次性的 HTTP/1.1（`kdg_doh.c`，方案 §6.4）。
 * 两条路径由 kdg_doh_query 按 ALPN 协商结果选择，调用方（编排层）不感知。
 *
 * POST 是方案 §6.3 指定的请求格式（RFC 8484 §4.1）。
 */
#ifndef _KDG_DOH_H
#define _KDG_DOH_H

#include "kdg_base.h"

/* 请求/响应缓冲上限。编排层（kdg_resolve.c）也要用，故上移到头文件。 */
#define KDG_DOH_REQ_MAX	(KDG_MAX_WIRE_MSG + 512)
#define KDG_DOH_RX_MAX	(8192 + KDG_MAX_WIRE_MSG)

/* 上游端点描述。字符串均为 NUL 结尾。 */
struct kdg_doh_cfg {
	char	hostname[256];	/* SNI 与证书主机名校验 */
	char	path[256];	/* DoH URI path */
	u32	ip_be;		/* bootstrap IPv4，网络字节序 */
	u16	port_be;	/* 端口，网络字节序 */
	u32	deadline_ms;
	/* 优先试 HTTP/3（QUIC）；失败或未启用则回落 H2。由模块参数控制。 */
	bool	allow_h3;
};

/* 用编入设备的默认端点填充 cfg（方案 §6.1）。 */
void kdg_doh_default_cfg(struct kdg_doh_cfg *cfg);

/*
 * 完成一次 DoH 查询（自动选择传输）。
 *  - qwire/qlen：DNS 查询报文（wire 格式）
 *  - rwire：接收缓冲区；*rlen 传入容量、返回实际响应长度
 * 返回 0 或负 errno。错误码的区分：
 *   -ETIMEDOUT  网络层超时
 *   -EACCES     TLS 证书验证失败
 *   -EIO        TLS/HTTP 层错误（握手失败、状态码非 200、Content-Type 不符）
 *   -EMSGSIZE   响应超出 rwire 容量
 *   -EAGAIN     上游未配置（信任锚为空），或连接池槽位已满
 *   -EPROTO     上游返回非 200（仅 H2 路径会返回它）
 */
int kdg_doh_query(const struct kdg_doh_cfg *cfg,
		  const u8 *qwire, size_t qlen,
		  u8 *rwire, size_t *rlen);

/* 最近一次查询的诊断摘要（供 GET_HEALTH 使用，**不含主机名与查询域名**）。 */
struct kdg_doh_stats {
	u64 queries;
	u64 ok;
	u64 net_fail;
	u64 tls_fail;
	u64 http_fail;
	u64 h1_fallbacks;	/* 对端 ALPN 不是 h2、走了兼容路径的次数 */
	u32 last_errno;
	u32 last_http_status;
	u32 last_rtt_ms;
};
void kdg_doh_get_stats(struct kdg_doh_stats *out);

#endif /* _KDG_DOH_H */
