/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_doh.h —— DoH 上游查询（HTTP/1.1 over TLS）。
 *
 * 本阶段形态（P1）：
 *  - **一次查询一条连接**。方案 §6.4 的持久连接池是 P2 的目标；P1 要证明的
 *    是「不改全局网络、经证书验证完成一次 DoH 查询」这条链路本身能通。
 *  - POST（方案 §6.3 指定的请求格式）。注意方案 §2.4 记录的是 GET 已验证、
 *    POST 待测 —— 端点对 POST 的支持情况由本次真机验证给出结论。
 *  - 全程在可睡眠上下文执行，由 kdg_tls_lock() 串行化（见 kdg_tls.h）。
 */
#ifndef _KDG_DOH_H
#define _KDG_DOH_H

#include "kdg_base.h"
#include "kdg_tls.h"

/* 上游端点描述。字符串均为 NUL 结尾。 */
struct kdg_doh_cfg {
	char	hostname[256];	/* SNI 与证书主机名校验 */
	char	path[256];	/* DoH URI path */
	u32	ip_be;		/* bootstrap IPv4，网络字节序 */
	u16	port_be;	/* 端口，网络字节序 */
	u32	deadline_ms;
};

/* 用编入设备的默认端点填充 cfg（方案 §6.1）。 */
void kdg_doh_default_cfg(struct kdg_doh_cfg *cfg);

/*
 * 完成一次 DoH 查询。
 *  - qwire/qlen：DNS 查询报文（wire 格式）
 *  - rwire：接收缓冲区；*rlen 传入容量、返回实际响应长度
 * 返回 0 或负 errno。错误码的区分：
 *   -ETIMEDOUT  网络层超时
 *   -EACCES     TLS 证书验证失败
 *   -EIO        TLS/HTTP 层错误（握手失败、状态码非 200、Content-Type 不符）
 *   -EMSGSIZE   响应超出 rwire 容量
 *   -EAGAIN     上游未配置（信任锚为空）
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
	u32 last_errno;
	u32 last_http_status;
	u32 last_rtt_ms;
};
void kdg_doh_get_stats(struct kdg_doh_stats *out);

#endif /* _KDG_DOH_H */
