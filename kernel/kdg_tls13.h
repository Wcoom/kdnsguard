/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_tls13.h —— 给 QUIC 用的 TLS 1.3 客户端握手引擎（RFC 8446 + RFC 9001 §4）。
 *
 * mbedTLS 3.6 没有 QUIC 接口：它只会把握手消息装进 TLS 记录层，不会按
 * 加密级别交出消息与密钥。QUIC 需要的恰恰是后者 —— 握手消息走 CRYPTO 帧，
 * 密钥由 QUIC 自己拿去保护包。所以本引擎**只处理握手消息本身**：
 *
 *   输入：某加密级别上按序到达的握手字节（kdg_tls13_recv）
 *   输出：某加密级别上要发出的握手字节（tx[level]）+ 各级流量密钥
 *
 * 密码学全部用 mbedTLS 原语（SHA-256、HKDF、X25519、x509、pk）。
 * 只协商一种组合：X25519 + TLS_AES_128_GCM_SHA256 / TLS_CHACHA20_POLY1305_SHA256，
 * 签名接受 ecdsa_secp256r1_sha256 与 rsa_pss_rsae_sha256。
 * 不支持 HelloRetryRequest（只发 X25519 key_share，对端要别的组就失败）、
 * PSK/0-RTT、客户端证书。这些不支持项都以明确错误码失败，绝不静默降级。
 *
 * 不持锁、不睡眠；随机数与信任锚由调用方注入，因此宿主可测。
 */
#ifndef _KDG_TLS13_H
#define _KDG_TLS13_H

#include "kdg_quic_crypto.h"
#include <mbedtls/sha256.h>
#include <mbedtls/x509_crt.h>

enum kdg_tls13_level {
	KDG_LVL_INITIAL = 0,
	KDG_LVL_HANDSHAKE,
	KDG_LVL_APP,
	KDG_LVL_COUNT,
};

enum kdg_tls13_state {
	KDG_T13_START = 0,
	KDG_T13_WAIT_SH,
	KDG_T13_WAIT_EE,
	KDG_T13_WAIT_CERT,
	KDG_T13_WAIT_CV,
	KDG_T13_WAIT_FIN,
	KDG_T13_DONE,
	KDG_T13_FAILED,
};

#define KDG_T13_RXBUF	16384	/* 一条握手消息的上限（证书链） */
#define KDG_T13_TXBUF	1024
#define KDG_T13_TP_MAX	256	/* 传输参数编码上限 */

typedef int (*kdg_rng_fn)(void *ctx, unsigned char *out, size_t len);

struct kdg_tls13 {
	enum kdg_tls13_state state;
	int err;			/* 失败原因（负 errno），state=FAILED 时有效 */
	u8 alert;			/* 要报给对端的 TLS alert（QUIC 映射为 0x100+alert） */

	/* 注入 */
	kdg_rng_fn rng;
	void *rng_ctx;
	const mbedtls_x509_crt *ca;	/* 信任锚；为 NULL 则拒绝握手 */
	char host[256];
	const char *alpn;		/* 例如 "h3"；对端必须选中它 */
	u8 tp[KDG_T13_TP_MAX];		/* 本端 QUIC 传输参数（已编码） */
	size_t tp_len;

	/* 握手状态 */
	mbedtls_sha256_context transcript;
	u8 x_priv[32];
	u8 x_pub[32];
	u16 suite;			/* 0x1301 或 0x1303 */
	enum kdg_quic_suite qsuite;
	u8 hs_secret[32];		/* Handshake Secret（派生主密钥用） */
	u8 c_hs[32], s_hs[32];		/* client/server handshake traffic secret */
	u8 c_ap[32], s_ap[32];		/* client/server application traffic secret */
	bool keys_hs, keys_ap;		/* 对应级别密钥已可取 */
	mbedtls_x509_crt *peer;		/* Certificate 消息解出的链 */

	/* 对端传输参数（原样保存，由 QUIC 层解析） */
	u8 peer_tp[KDG_T13_TP_MAX];
	size_t peer_tp_len;
	bool peer_tp_seen;

	/* 每级接收重组缓冲：CRYPTO 帧按偏移交付后，调用方顺序调用 recv */
	u8 *rx[KDG_LVL_COUNT];
	size_t rx_len[KDG_LVL_COUNT];

	/* 每级待发送字节；调用方取走后把 tx_len 清零 */
	u8 tx[KDG_LVL_COUNT][KDG_T13_TXBUF];
	size_t tx_len[KDG_LVL_COUNT];
};

/* rx 缓冲由引擎分配（内核 kvmalloc，宿主 malloc），fini 释放。 */
int kdg_tls13_init(struct kdg_tls13 *t, const char *host, const char *alpn,
		   const u8 *tp, size_t tp_len, const mbedtls_x509_crt *ca,
		   kdg_rng_fn rng, void *rng_ctx);
void kdg_tls13_fini(struct kdg_tls13 *t);

/* 生成 ClientHello，放进 tx[INITIAL]。 */
int kdg_tls13_start(struct kdg_tls13 *t);

/* 交付某级别上按序到达的握手字节。返回 0 或负 errno（同时 state=FAILED）。 */
int kdg_tls13_recv(struct kdg_tls13 *t, enum kdg_tls13_level lvl,
		   const u8 *data, size_t len);

/* 取某级别某方向的 QUIC 密钥（lvl 为 HANDSHAKE 或 APP）。 */
int kdg_tls13_quic_keys(const struct kdg_tls13 *t, enum kdg_tls13_level lvl,
			bool client, struct kdg_quic_keys *out);

#endif