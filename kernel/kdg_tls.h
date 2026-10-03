/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_tls.h —— 内核态 TLS 客户端会话（mbedTLS 驱动）。
 *
 * 与方案 §6.2 逐条对应：
 *  - 「用完整 TLS API，不能只含 wolfCrypt 的 cryptonly 模式」→ 现换选 mbedTLS，
 *    同理使用其完整 SSL 栈而非只取密码学原语。
 *  - 「在可睡眠的 kernel worker 上驱动握手与 I/O」→ 本层的所有入口都要求
 *    可睡眠上下文；send/recv 回调直接接 kdg_sock 的阻塞实现。
 *  - 「TLS 对象使用单一执行者驱动；并发客户端通过请求队列进入，避免多个
 *    worker 同时操作同一 TLS 状态」→ 本阶段用一把模块级互斥锁**串行化**
 *    整个会话，这正是「单执行者」的直译。P2 引入请求队列后，锁的粒度可以
 *    收细到 RNG 与共享 CA，但语义不变。
 *  - 「ALPN 提供 h2、http/1.1」→ 本阶段**只提供 http/1.1**。原因：H2 客户端
 *    尚未移植，若此刻在 ALPN 里宣告 h2，服务端会选中它，而我们无法构造合法
 *    的 HTTP/2 帧 —— 那会得到一条看似连上、实际不可用的连接。等 P2 的 H2
 *    就绪后再加入。这是「不宣称尚未实现的能力」在同一条链路上的落地。
 *  - 「不关闭证书验证，不因直连 IP 而遗漏 SNI」→ 认证模式固定为
 *    VERIFY_REQUIRED，且 set_bio 之后立刻 set_hostname。
 *  - 「默认不开 FIPS 全局随机数替换」→ 不调用任何 fips 入口。
 */
#ifndef _KDG_TLS_H
#define _KDG_TLS_H

#include "kdg_base.h"

#include <mbedtls/build_info.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509_crt.h>
/* MBEDTLS_ERR_NET_* 定义在 net_sockets.h 的**特性守卫之前**，因此即使
 * MBEDTLS_NET_C 已关闭（我们自备 socket 层），这些错误码依然可用。 */
#include <mbedtls/net_sockets.h>
#include <mbedtls/error.h>

#include "kdg_sock.h"

struct kdg_tls {
	mbedtls_ssl_context	ssl;
	mbedtls_ssl_config	conf;
	struct kdg_sock	       *sock;
	/* 最近的网络层 errno，用于把 mbedTLS 的笼统 NET 错误还原成具体原因。 */
	int			last_net_errno;
	u32			verify_flags;
	bool			handshaken;
};

/* ── 模块级生命周期 ────────────────────────────────────────────────────
 * 全局的熵源与 DRBG 只建一次；每会话共享。（MBEDTLS_THREADING_C 已关闭，
 * 因此对它们的并发访问由 kdg_tls_lock 串行化 —— 见实现文件。） */
int  kdg_tls_global_init(void);
void kdg_tls_global_exit(void);

/* ── 全局串行化 ────────────────────────────────────────────────────────
 * 见文件头「单一执行者」一条。DoH 层在一次完整查询的外围持有它：
 * 从建连、握手、请求、响应到关连接，全程独占。
 * 为什么粒度这么粗：mbedTLS 的 DRBG 与 CA 链是模块级共享状态，而
 * MBEDTLS_THREADING_C 已关闭（内核态里让库自己加锁不合适），
 * 因此只能由调用方保证不并发进入。P2 引入请求队列后粒度可收细。 */
void kdg_tls_lock(void);
void kdg_tls_unlock(void);

/* ── 信任锚（CA） ──────────────────────────────────────────────────────
 * 方案 §6.2：「CA/证书验证材料通过受保护的初始化接口加载进内核」。
 * 对应 UAPI 的 KDG_A_TRUST_MATERIAL。接受 PEM 或 DER；PEM 里可以有多张证书。
 * 加载是**追加**语义：可以分批喂入根证书与中间证书。
 * 返回解析成功的证书张数（>0）或负 errno。 */
int  kdg_tls_add_ca(const u8 *data, size_t len);

/* 当前已加载的信任锚张数（0 表示未配置，此时任何握手都会因无法验证而失败）。 */
unsigned int kdg_tls_ca_count(void);

/* 清空信任锚。 */
void kdg_tls_clear_ca(void);

/* ── 会话 ────────────────────────────────────────────────────────────── */

/* 在已连接的 socket 上建立 TLS 会话。hostname 用于 SNI 与证书主机名校验；
 * mbedTLS 会自行复制一份，调用方不必保证其生命期。 */
int  kdg_tls_session_open(struct kdg_tls *t, struct kdg_sock *sock,
			  const char *hostname);

/* 执行握手（含证书链校验与主机名校验）。 */
int  kdg_tls_handshake(struct kdg_tls *t);

/* 读写。返回实际字节数，或负 errno。 */
int  kdg_tls_write(struct kdg_tls *t, const void *buf, size_t len);
int  kdg_tls_read(struct kdg_tls *t, void *buf, size_t len);

/* 协商出来的 ALPN 协议名（如 "http/1.1"），未协商则为 NULL。 */
const char *kdg_tls_alpn(const struct kdg_tls *t);

/* 关闭并释放会话资源。幂等。 */
void kdg_tls_session_close(struct kdg_tls *t);

/* 把 mbedTLS 的负错误码转成可读短串（**不含主机名或 URI**，见方案 §14.1）。 */
const char *kdg_tls_strerror(int err);

#endif /* _KDG_TLS_H */
