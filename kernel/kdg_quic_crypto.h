/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_quic_crypto.h —— QUIC 包保护（RFC 9001 §5）。
 *
 * 只做纯计算：HKDF-Expand-Label、Initial 密钥派生、AEAD 加解密、头部保护。
 * 不持锁、不分配内存、不碰 socket，因此与 kdg_wire.c 一样双态可编译，
 * 宿主上用 RFC 9001 附录 A 的官方向量逐字节核对。
 *
 * 支持的套件：TLS_AES_128_GCM_SHA256（Initial 强制）与
 * TLS_CHACHA20_POLY1305_SHA256（与现有 H2 上游协商结果一致）。
 */
#ifndef _KDG_QUIC_CRYPTO_H
#define _KDG_QUIC_CRYPTO_H

#include "kdg_base.h"
#ifdef __KERNEL__
/* mbedTLS 的内核 shim 会引入 timekeeping.h，它要求 timespec64/ktime_t 已声明。 */
#include <linux/ktime.h>
#endif
#include <mbedtls/gcm.h>
#include <mbedtls/chachapoly.h>
#include <mbedtls/aes.h>

#define KDG_QUIC_V1		0x00000001u
#define KDG_QUIC_SECRET_LEN	32	/* 两个套件都是 SHA-256 */
#define KDG_QUIC_IV_LEN		12
#define KDG_QUIC_TAG_LEN	16
#define KDG_QUIC_HP_SAMPLE	16
#define KDG_QUIC_MAX_CID	20

enum kdg_quic_suite {
	KDG_QUIC_AES128GCM = 0,
	KDG_QUIC_CHACHA20,
};

/* 一个方向、一个加密级别的保护上下文。 */
struct kdg_quic_keys {
	enum kdg_quic_suite suite;
	bool ready;
	u8 secret[KDG_QUIC_SECRET_LEN];	/* 保留以便 1-RTT 密钥更新 */
	u8 key[32];			/* AES-128 用前 16 字节 */
	u8 iv[KDG_QUIC_IV_LEN];
	u8 hp[32];
	union {
		mbedtls_gcm_context gcm;
		mbedtls_chachapoly_context cp;
	} aead;
	mbedtls_aes_context hp_aes;	/* 仅 AES 套件使用 */
};

/* RFC 8446 §7.1 HKDF-Expand-Label（SHA-256），label 不含 "tls13 " 前缀。 */
int kdg_quic_hkdf_expand_label(const u8 *secret, size_t secret_len,
			       const char *label, const u8 *ctx, size_t ctx_len,
			       u8 *out, size_t out_len);

/* 由 secret 派生 key/iv/hp 并初始化 AEAD 与 HP 上下文。 */
int kdg_quic_keys_from_secret(struct kdg_quic_keys *k, enum kdg_quic_suite s,
			      const u8 *secret);
void kdg_quic_keys_free(struct kdg_quic_keys *k);

/* 由客户端选择的原始 DCID 派生 Initial 两个方向的密钥（RFC 9001 §5.2）。 */
/* RFC 9001 §5.8 Retry 完整性标签：AAD 是整包（含标签前的全部字节）。 */
int kdg_quic_retry_tag(const u8 *odcid, size_t odcid_len, const u8 *pkt,
		       size_t pkt_len, u8 tag[KDG_QUIC_TAG_LEN]);

int kdg_quic_initial_keys(const u8 *dcid, size_t dcid_len,
			  struct kdg_quic_keys *client,
			  struct kdg_quic_keys *server);

/*
 * 原地加密一个包。buf[0..hdr_len) 是已写好的明文头（含按 pn_len 编码的
 * 包号，位于 buf[pn_off..pn_off+pn_len)），buf[hdr_len..hdr_len+pt_len)
 * 是载荷；调用方须在其后预留 KDG_QUIC_TAG_LEN 字节。
 * 加密载荷、附标签、再施加头部保护。成功返回包总长。
 */
int kdg_quic_protect(struct kdg_quic_keys *k, u64 pn, u8 *buf,
		     size_t pn_off, size_t pn_len, size_t hdr_len,
		     size_t pt_len, size_t cap);

/*
 * 原地解密一个包。pn_off 是包号字段起点（头部保护尚未去除），pkt_len
 * 是本包在数据报中的长度（长头包取 Length 字段推出的值）。largest_pn
 * 用于从截断包号恢复完整包号（RFC 9000 附录 A.3），无已收包时传 -1。
 * 成功返回明文载荷长度，并输出 *pn 与 *hdr_len（明文起点）。
 * 失败返回 -EBADMSG/-EINVAL，此后 buf 内容未定义（重试须先拷贝整包）。
 */
int kdg_quic_unprotect(struct kdg_quic_keys *k, u8 *buf, size_t pn_off,
		       size_t pkt_len, s64 largest_pn, u64 *pn,
		       size_t *hdr_len);

#endif
