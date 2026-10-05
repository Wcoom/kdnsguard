// SPDX-License-Identifier: GPL-2.0
/*
 * kdg_tls13.c —— QUIC 用 TLS 1.3 客户端握手引擎，双态可编译。
 * 接口与边界见 kdg_tls13.h。
 */
#include "kdg_tls13.h"

#ifdef __KERNEL__
#include <linux/slab.h>
#include <linux/mm.h>
#define kdg_t13_alloc(n)	kvzalloc((n), GFP_KERNEL)
#define kdg_t13_free(p)		kvfree(p)
#else
#include <errno.h>
#include <stdlib.h>
#define kdg_t13_alloc(n)	calloc(1, (n))
#define kdg_t13_free(p)		free(p)
#endif

#include <mbedtls/ecp.h>
#include <mbedtls/md.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform_util.h>

/* 握手消息类型（RFC 8446 §4） */
#define HS_CLIENT_HELLO		1
#define HS_SERVER_HELLO		2
#define HS_NEW_SESSION_TICKET	4
#define HS_ENCRYPTED_EXTS	8
#define HS_CERTIFICATE		11
#define HS_CERT_VERIFY		15
#define HS_FINISHED		20

/* 扩展 */
#define EXT_SERVER_NAME		0
#define EXT_SUPPORTED_GROUPS	10
#define EXT_SIG_ALGS		13
#define EXT_ALPN		16
#define EXT_SUPPORTED_VERSIONS	43
#define EXT_KEY_SHARE		51
#define EXT_QUIC_TP		57

#define GROUP_X25519		0x001d
#define SIG_ECDSA_P256_SHA256	0x0403
#define SIG_RSA_PSS_RSAE_SHA256	0x0804

/* TLS alert（RFC 8446 §6.2），QUIC 用 CONNECTION_CLOSE 0x100+alert 上报 */
#define AL_UNEXPECTED_MESSAGE	10
#define AL_HANDSHAKE_FAILURE	40
#define AL_BAD_CERTIFICATE	42
#define AL_ILLEGAL_PARAMETER	47
#define AL_DECODE_ERROR		50
#define AL_DECRYPT_ERROR	51
#define AL_PROTOCOL_VERSION	70
#define AL_INTERNAL_ERROR	80
#define AL_MISSING_EXTENSION	109
#define AL_NO_APP_PROTOCOL	120

static int t13_fail(struct kdg_tls13 *t, int err, u8 alert)
{
	t->state = KDG_T13_FAILED;
	t->err = err;
	t->alert = alert;
	return err;
}

/* ── 有界读取器：所有对端输入都经它，越界一律 decode_error ─────────── */
struct rd {
	const u8 *p;
	size_t n;
	bool bad;
};

static u32 rd_u(struct rd *r, size_t w)
{
	u32 v = 0;
	size_t i;

	if (r->bad || r->n < w) {
		r->bad = true;
		return 0;
	}
	for (i = 0; i < w; i++)
		v = v << 8 | r->p[i];
	r->p += w;
	r->n -= w;
	return v;
}

/* 取一个长度前缀为 w 字节的子块 */
static struct rd rd_sub(struct rd *r, size_t w)
{
	struct rd s = { .bad = true };
	u32 len = rd_u(r, w);

	if (r->bad || r->n < len) {
		r->bad = true;
		return s;
	}
	s.p = r->p;
	s.n = len;
	s.bad = false;
	r->p += len;
	r->n -= len;
	return s;
}

/* ── 写入器 ────────────────────────────────────────────────────────── */
struct wr {
	u8 *p;
	size_t n, cap;
	bool bad;
};

static void wr_u(struct wr *w, u32 v, size_t width)
{
	size_t i;

	if (w->bad || w->cap - w->n < width) {
		w->bad = true;
		return;
	}
	for (i = 0; i < width; i++)
		w->p[w->n + i] = (u8)(v >> (8 * (width - 1 - i)));
	w->n += width;
}

static void wr_b(struct wr *w, const void *b, size_t len)
{
	if (w->bad || w->cap - w->n < len) {
		w->bad = true;
		return;
	}
	memcpy(w->p + w->n, b, len);
	w->n += len;
}

/* 开一个 width 字节长度前缀，返回其位置；wr_end 回填长度。 */
static size_t wr_begin(struct wr *w, size_t width)
{
	size_t at = w->n;

	wr_u(w, 0, width);
	return at;
}

static void wr_end(struct wr *w, size_t at, size_t width)
{
	size_t len = w->n - at - width, i;

	if (w->bad || len >> (8 * width)) {
		w->bad = true;
		return;
	}
	for (i = 0; i < width; i++)
		w->p[at + i] = (u8)(len >> (8 * (width - 1 - i)));
}

/* ── 转录哈希与密钥调度（RFC 8446 §7.1） ─────────────────────────── */
static int t13_hash_now(struct kdg_tls13 *t, u8 out[32])
{
	mbedtls_sha256_context c;
	int ret;

	/* 克隆再 finish：运行中的转录不能被结束。 */
	mbedtls_sha256_init(&c);
	mbedtls_sha256_clone(&c, &t->transcript);
	ret = mbedtls_sha256_finish(&c, out);
	mbedtls_sha256_free(&c);
	return ret ? -EIO : 0;
}

static int t13_extract(const u8 *salt, size_t slen, const u8 *ikm, size_t ilen,
		       u8 out[32])
{
	return mbedtls_hkdf_extract(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
				    salt, slen, ikm, ilen, out) ? -EIO : 0;
}

/* Derive-Secret(secret, label, transcript_hash) */
static int t13_derive(const u8 secret[32], const char *label,
		      const u8 hash[32], u8 out[32])
{
	return kdg_quic_hkdf_expand_label(secret, 32, label, hash, 32, out, 32);
}

/* ── X25519（mbedtls 对 Montgomery 曲线的 read/write_key 即 RFC 7748 小端） ── */
static int t13_x25519_gen(struct kdg_tls13 *t)
{
	mbedtls_ecp_keypair kp;
	size_t olen;
	int ret;

	mbedtls_ecp_keypair_init(&kp);
	ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_CURVE25519, &kp, t->rng,
				  t->rng_ctx);
	if (!ret)
		ret = mbedtls_ecp_write_key_ext(&kp, &olen, t->x_priv,
						sizeof(t->x_priv));
	if (!ret && olen != 32)
		ret = -1;
	if (!ret)
		ret = mbedtls_ecp_write_public_key(&kp, MBEDTLS_ECP_PF_UNCOMPRESSED,
						   &olen, t->x_pub,
						   sizeof(t->x_pub));
	if (!ret && olen != 32)
		ret = -1;
	mbedtls_ecp_keypair_free(&kp);
	return ret ? -EIO : 0;
}

static int t13_x25519_shared(struct kdg_tls13 *t, const u8 peer[32],
			     u8 out[32])
{
	/* 只用公开 API（mbedtls_ecp_export），不开 MBEDTLS_ALLOW_PRIVATE_ACCESS。 */
	mbedtls_ecp_keypair kp;
	mbedtls_ecp_group grp;
	mbedtls_mpi d;
	mbedtls_ecp_point pub, q, z;
	size_t olen;
	int ret;

	mbedtls_ecp_keypair_init(&kp);
	mbedtls_ecp_group_init(&grp);
	mbedtls_mpi_init(&d);
	mbedtls_ecp_point_init(&pub);
	mbedtls_ecp_point_init(&q);
	mbedtls_ecp_point_init(&z);
	ret = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_CURVE25519, &kp, t->x_priv, 32);
	if (!ret)
		ret = mbedtls_ecp_export(&kp, &grp, &d, &pub);
	if (!ret)
		ret = mbedtls_ecp_point_read_binary(&grp, &q, peer, 32);
	if (!ret)
		ret = mbedtls_ecp_mul(&grp, &z, &d, &q, t->rng, t->rng_ctx);
	if (!ret)
		ret = mbedtls_ecp_point_write_binary(&grp, &z,
						     MBEDTLS_ECP_PF_UNCOMPRESSED,
						     &olen, out, 32);
	if (!ret && olen != 32)
		ret = -1;
	mbedtls_ecp_point_free(&q);
	mbedtls_ecp_point_free(&z);
	mbedtls_ecp_point_free(&pub);
	mbedtls_mpi_free(&d);
	mbedtls_ecp_group_free(&grp);
	mbedtls_ecp_keypair_free(&kp);
	if (ret)
		return -EIO;
	/* RFC 8446 §7.4.2：共享秘密全零（对端给了小阶点）必须中止。 */
	{
		u8 acc = 0;
		int i;

		for (i = 0; i < 32; i++)
			acc |= out[i];
		if (!acc)
			return -EPROTO;
	}
	return 0;
}

/* 把一条完整握手消息记入转录并放进某级发送缓冲。 */
static int t13_emit(struct kdg_tls13 *t, enum kdg_tls13_level lvl,
		    const u8 *msg, size_t len)
{
	if (KDG_T13_TXBUF - t->tx_len[lvl] < len)
		return -ENOSPC;
	if (mbedtls_sha256_update(&t->transcript, msg, len))
		return -EIO;
	memcpy(t->tx[lvl] + t->tx_len[lvl], msg, len);
	t->tx_len[lvl] += len;
	return 0;
}

int kdg_tls13_start(struct kdg_tls13 *t)
{
	u8 msg[KDG_T13_TXBUF], rnd[32];
	struct wr w = { .p = msg, .cap = sizeof(msg) };
	size_t body, exts, e, l, hl = strlen(t->host), al = strlen(t->alpn);
	int ret;

	if (t->state != KDG_T13_START)
		return -EINVAL;
	ret = t13_x25519_gen(t);
	if (!ret && t->rng(t->rng_ctx, rnd, sizeof(rnd)))
		ret = -EIO;
	if (ret)
		return t13_fail(t, ret, AL_INTERNAL_ERROR);

	wr_u(&w, HS_CLIENT_HELLO, 1);
	body = wr_begin(&w, 3);
	wr_u(&w, 0x0303, 2);			/* legacy_version */
	wr_b(&w, rnd, 32);
	wr_u(&w, 0, 1);				/* legacy_session_id：QUIC 必须为空 */
	wr_u(&w, 4, 2);				/* cipher_suites */
	wr_u(&w, 0x1301, 2);
	wr_u(&w, 0x1303, 2);
	wr_u(&w, 1, 1);				/* legacy_compression_methods */
	wr_u(&w, 0, 1);

	exts = wr_begin(&w, 2);

	wr_u(&w, EXT_SERVER_NAME, 2);
	e = wr_begin(&w, 2);
	l = wr_begin(&w, 2);
	wr_u(&w, 0, 1);				/* host_name */
	wr_u(&w, hl, 2);
	wr_b(&w, t->host, hl);
	wr_end(&w, l, 2);
	wr_end(&w, e, 2);

	wr_u(&w, EXT_SUPPORTED_GROUPS, 2);
	wr_u(&w, 4, 2);
	wr_u(&w, 2, 2);
	wr_u(&w, GROUP_X25519, 2);

	wr_u(&w, EXT_SIG_ALGS, 2);
	wr_u(&w, 6, 2);
	wr_u(&w, 4, 2);
	wr_u(&w, SIG_ECDSA_P256_SHA256, 2);
	wr_u(&w, SIG_RSA_PSS_RSAE_SHA256, 2);

	wr_u(&w, EXT_SUPPORTED_VERSIONS, 2);
	wr_u(&w, 3, 2);
	wr_u(&w, 2, 1);
	wr_u(&w, 0x0304, 2);

	wr_u(&w, EXT_KEY_SHARE, 2);
	wr_u(&w, 2 + 4 + 32, 2);
	wr_u(&w, 4 + 32, 2);
	wr_u(&w, GROUP_X25519, 2);
	wr_u(&w, 32, 2);
	wr_b(&w, t->x_pub, 32);

	wr_u(&w, EXT_ALPN, 2);
	wr_u(&w, al + 3, 2);
	wr_u(&w, al + 1, 2);
	wr_u(&w, al, 1);
	wr_b(&w, t->alpn, al);

	wr_u(&w, EXT_QUIC_TP, 2);
	wr_u(&w, t->tp_len, 2);
	wr_b(&w, t->tp, t->tp_len);

	wr_end(&w, exts, 2);
	wr_end(&w, body, 3);
	mbedtls_platform_zeroize(rnd, sizeof(rnd));
	if (w.bad)
		return t13_fail(t, -ENOSPC, AL_INTERNAL_ERROR);

	ret = t13_emit(t, KDG_LVL_INITIAL, msg, w.n);
	if (ret)
		return t13_fail(t, ret, AL_INTERNAL_ERROR);
	t->state = KDG_T13_WAIT_SH;
	return 0;
}

/* RFC 8446 §4.1.3：HelloRetryRequest 的 random 是 SHA-256("HelloRetryRequest")。 */
static const u8 t13_hrr_random[32] = {
	0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c,
	0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb,
	0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
};

/* body 不含 4 字节消息头；msg/mlen 是含头的整条消息（记转录用）。 */
static int t13_on_server_hello(struct kdg_tls13 *t, const u8 *msg, size_t mlen)
{
	struct rd r = { .p = msg + 4, .n = mlen - 4 }, sid, ex;
	const u8 *rnd, *peer_pub = NULL;
	u8 shared[32], early[32], derived[32], hash[32], zeros[32] = { 0 };
	u16 ver = 0;
	int ret;

	rd_u(&r, 2);				/* legacy_version */
	rnd = r.p;
	if (r.n < 32)
		return t13_fail(t, -EBADMSG, AL_DECODE_ERROR);
	r.p += 32;
	r.n -= 32;
	sid = rd_sub(&r, 1);
	t->suite = (u16)rd_u(&r, 2);
	if (rd_u(&r, 1) != 0)
		return t13_fail(t, -EBADMSG, AL_ILLEGAL_PARAMETER);
	ex = rd_sub(&r, 2);
	if (r.bad || r.n || sid.bad)
		return t13_fail(t, -EBADMSG, AL_DECODE_ERROR);
	if (sid.n != 0)		/* 我们发的是空 session_id，必须原样回显 */
		return t13_fail(t, -EBADMSG, AL_ILLEGAL_PARAMETER);
	if (!memcmp(rnd, t13_hrr_random, 32))
		/* 只发了 X25519 key_share；对端要别的组 ⇒ 明确失败而不是重试。 */
		return t13_fail(t, -EPROTONOSUPPORT, AL_HANDSHAKE_FAILURE);
	if (t->suite == 0x1301)
		t->qsuite = KDG_QUIC_AES128GCM;
	else if (t->suite == 0x1303)
		t->qsuite = KDG_QUIC_CHACHA20;
	else
		return t13_fail(t, -EBADMSG, AL_ILLEGAL_PARAMETER);

	while (ex.n && !ex.bad) {
		u16 type = (u16)rd_u(&ex, 2);
		struct rd d = rd_sub(&ex, 2);

		if (d.bad)
			break;
		if (type == EXT_SUPPORTED_VERSIONS) {
			ver = (u16)rd_u(&d, 2);
		} else if (type == EXT_KEY_SHARE) {
			if (rd_u(&d, 2) != GROUP_X25519 || rd_u(&d, 2) != 32 ||
			    d.n != 32)
				return t13_fail(t, -EBADMSG, AL_ILLEGAL_PARAMETER);
			peer_pub = d.p;
		} else {
			/* ServerHello 只允许这两种扩展（RFC 8446 §4.2 表格） */
			return t13_fail(t, -EBADMSG, AL_UNEXPECTED_MESSAGE);
		}
	}
	if (ex.bad)
		return t13_fail(t, -EBADMSG, AL_DECODE_ERROR);
	if (ver != 0x0304)
		return t13_fail(t, -EPROTONOSUPPORT, AL_PROTOCOL_VERSION);
	if (!peer_pub)
		return t13_fail(t, -EBADMSG, AL_MISSING_EXTENSION);

	if (mbedtls_sha256_update(&t->transcript, msg, mlen))
		return t13_fail(t, -EIO, AL_INTERNAL_ERROR);

	ret = t13_x25519_shared(t, peer_pub, shared);
	if (ret)
		return t13_fail(t, ret, AL_ILLEGAL_PARAMETER);

	/* early = Extract(0, 0)；derived = Derive(early, "derived", H(""))；
	 * hs = Extract(derived, shared)。H("") 即空转录的 SHA-256。 */
	{
		static const u8 empty_hash[32] = {
			0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
			0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
			0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
			0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
		};

		ret = t13_extract(NULL, 0, zeros, 32, early);
		if (!ret)
			ret = t13_derive(early, "derived", empty_hash, derived);
	}
	if (!ret)
		ret = t13_extract(derived, 32, shared, 32, t->hs_secret);
	if (!ret)
		ret = t13_hash_now(t, hash);
	if (!ret)
		ret = t13_derive(t->hs_secret, "c hs traffic", hash, t->c_hs);
	if (!ret)
		ret = t13_derive(t->hs_secret, "s hs traffic", hash, t->s_hs);
	mbedtls_platform_zeroize(shared, sizeof(shared));
	mbedtls_platform_zeroize(early, sizeof(early));
	mbedtls_platform_zeroize(derived, sizeof(derived));
	mbedtls_platform_zeroize(t->x_priv, sizeof(t->x_priv));
	if (ret)
		return t13_fail(t, ret, AL_INTERNAL_ERROR);
	t->keys_hs = true;
	t->state = KDG_T13_WAIT_EE;
	return 0;
}

static int t13_on_ee(struct kdg_tls13 *t, const u8 *msg, size_t mlen)
{
	struct rd r = { .p = msg + 4, .n = mlen - 4 }, ex;
	bool alpn_ok = false;

	ex = rd_sub(&r, 2);
	if (r.bad || r.n)
		return t13_fail(t, -EBADMSG, AL_DECODE_ERROR);
	while (ex.n && !ex.bad) {
		u16 type = (u16)rd_u(&ex, 2);
		struct rd d = rd_sub(&ex, 2);

		if (d.bad)
			break;
		if (type == EXT_ALPN) {
			struct rd list = rd_sub(&d, 2);
			struct rd name = rd_sub(&list, 1);

			/* 服务器只能选一个，且必须是我们提供的那个 */
			if (list.bad || name.bad || list.n ||
			    name.n != strlen(t->alpn) ||
			    memcmp(name.p, t->alpn, name.n))
				return t13_fail(t, -EBADMSG,
						AL_ILLEGAL_PARAMETER);
			alpn_ok = true;
		} else if (type == EXT_QUIC_TP) {
			if (d.n > sizeof(t->peer_tp))
				return t13_fail(t, -EMSGSIZE,
						AL_ILLEGAL_PARAMETER);
			memcpy(t->peer_tp, d.p, d.n);
			t->peer_tp_len = d.n;
			t->peer_tp_seen = true;
		}
		/* 其余扩展（server_name 空回显等）忽略 */
	}
	if (ex.bad)
		return t13_fail(t, -EBADMSG, AL_DECODE_ERROR);
	/* RFC 9001 §8.1/§8.2：无 ALPN 必须以 no_application_protocol 失败，
	 * 缺传输参数必须以 missing_extension 失败。 */
	if (!alpn_ok)
		return t13_fail(t, -EBADMSG, AL_NO_APP_PROTOCOL);
	if (!t->peer_tp_seen)
		return t13_fail(t, -EBADMSG, AL_MISSING_EXTENSION);
	if (mbedtls_sha256_update(&t->transcript, msg, mlen))
		return t13_fail(t, -EIO, AL_INTERNAL_ERROR);
	t->state = KDG_T13_WAIT_CERT;
	return 0;
}

static int t13_on_cert(struct kdg_tls13 *t, const u8 *msg, size_t mlen)
{
	struct rd r = { .p = msg + 4, .n = mlen - 4 }, ctx, list;
	u32 flags = 0;
	int ret;

	ctx = rd_sub(&r, 1);
	list = rd_sub(&r, 3);
	if (r.bad || r.n || ctx.n)	/* 服务器证书的 request_context 必须为空 */
		return t13_fail(t, -EBADMSG, AL_DECODE_ERROR);
	if (!list.n)
		return t13_fail(t, -EBADMSG, AL_BAD_CERTIFICATE);

	t->peer = kdg_t13_alloc(sizeof(*t->peer));
	if (!t->peer)
		return t13_fail(t, -ENOMEM, AL_INTERNAL_ERROR);
	mbedtls_x509_crt_init(t->peer);
	while (list.n && !list.bad) {
		struct rd der = rd_sub(&list, 3);
		struct rd cex = rd_sub(&list, 2);

		if (der.bad || cex.bad)
			break;
		if (mbedtls_x509_crt_parse_der(t->peer, der.p, der.n))
			return t13_fail(t, -EBADMSG, AL_BAD_CERTIFICATE);
	}
	if (list.bad)
		return t13_fail(t, -EBADMSG, AL_DECODE_ERROR);

	if (!t->ca)
		return t13_fail(t, -EKEYREJECTED, AL_BAD_CERTIFICATE);
	ret = mbedtls_x509_crt_verify(t->peer, (mbedtls_x509_crt *)t->ca, NULL,
				      t->host, &flags, NULL, NULL);
	if (ret || flags)
		return t13_fail(t, -EKEYREJECTED, AL_BAD_CERTIFICATE);

	if (mbedtls_sha256_update(&t->transcript, msg, mlen))
		return t13_fail(t, -EIO, AL_INTERNAL_ERROR);
	t->state = KDG_T13_WAIT_CV;
	return 0;
}

static int t13_on_cv(struct kdg_tls13 *t, const u8 *msg, size_t mlen)
{
	static const char ctx[] = "TLS 1.3, server CertificateVerify";
	struct rd r = { .p = msg + 4, .n = mlen - 4 }, sig;
	u8 content[64 + sizeof(ctx) + 32], hash[32], dig[32];
	u16 alg;
	int ret;

	alg = (u16)rd_u(&r, 2);
	sig = rd_sub(&r, 2);
	if (r.bad || r.n || sig.bad)
		return t13_fail(t, -EBADMSG, AL_DECODE_ERROR);

	/* RFC 8446 §4.4.3：64 个 0x20 ‖ 上下文串 ‖ 0x00 ‖ 转录哈希 */
	if (t13_hash_now(t, hash))
		return t13_fail(t, -EIO, AL_INTERNAL_ERROR);
	memset(content, 0x20, 64);
	memcpy(content + 64, ctx, sizeof(ctx));	/* sizeof 含结尾 0x00 */
	memcpy(content + 64 + sizeof(ctx), hash, 32);
	if (mbedtls_sha256(content, sizeof(content), dig, 0))
		return t13_fail(t, -EIO, AL_INTERNAL_ERROR);

	if (alg == SIG_ECDSA_P256_SHA256) {
		if (!mbedtls_pk_can_do(&t->peer->pk, MBEDTLS_PK_ECDSA))
			return t13_fail(t, -EBADMSG, AL_ILLEGAL_PARAMETER);
		ret = mbedtls_pk_verify(&t->peer->pk, MBEDTLS_MD_SHA256, dig,
					32, sig.p, sig.n);
	} else if (alg == SIG_RSA_PSS_RSAE_SHA256) {
		mbedtls_pk_rsassa_pss_options o = {
			.mgf1_hash_id = MBEDTLS_MD_SHA256,
			.expected_salt_len = 32,
		};

		if (!mbedtls_pk_can_do(&t->peer->pk, MBEDTLS_PK_RSA))
			return t13_fail(t, -EBADMSG, AL_ILLEGAL_PARAMETER);
		ret = mbedtls_pk_verify_ext(MBEDTLS_PK_RSASSA_PSS, &o,
					    &t->peer->pk, MBEDTLS_MD_SHA256,
					    dig, 32, sig.p, sig.n);
	} else {
		return t13_fail(t, -EBADMSG, AL_ILLEGAL_PARAMETER);
	}
	if (ret)
		return t13_fail(t, -EKEYREJECTED, AL_DECRYPT_ERROR);

	if (mbedtls_sha256_update(&t->transcript, msg, mlen))
		return t13_fail(t, -EIO, AL_INTERNAL_ERROR);
	t->state = KDG_T13_WAIT_FIN;
	return 0;
}

/* finished_key = HKDF-Expand-Label(base, "finished", "", 32)；
 * verify_data = HMAC(finished_key, transcript_hash) */
static int t13_finished_mac(const u8 base[32], const u8 hash[32], u8 out[32])
{
	u8 fk[32];
	int ret;

	ret = kdg_quic_hkdf_expand_label(base, 32, "finished", NULL, 0, fk, 32);
	if (!ret &&
	    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), fk,
			    32, hash, 32, out))
		ret = -EIO;
	mbedtls_platform_zeroize(fk, sizeof(fk));
	return ret;
}

/* 常数时间比较：verify_data 不能因提前返回而泄露匹配前缀长度。 */
static bool t13_ct_eq(const u8 *a, const u8 *b, size_t n)
{
	u8 acc = 0;
	size_t i;

	for (i = 0; i < n; i++)
		acc |= a[i] ^ b[i];
	return acc == 0;
}

static int t13_on_fin(struct kdg_tls13 *t, const u8 *msg, size_t mlen)
{
	u8 hash[32], want[32], derived[32], master[32], zeros[32] = { 0 };
	u8 cfin[4 + 32];
	int ret;

	if (mlen != 4 + 32)
		return t13_fail(t, -EBADMSG, AL_DECODE_ERROR);
	if (t13_hash_now(t, hash) || t13_finished_mac(t->s_hs, hash, want))
		return t13_fail(t, -EIO, AL_INTERNAL_ERROR);
	if (!t13_ct_eq(want, msg + 4, 32))
		return t13_fail(t, -EKEYREJECTED, AL_DECRYPT_ERROR);
	if (mbedtls_sha256_update(&t->transcript, msg, mlen))
		return t13_fail(t, -EIO, AL_INTERNAL_ERROR);

	/* 应用流量密钥基于「到服务器 Finished 为止」的转录（RFC 8446 §7.1） */
	{
		static const u8 empty_hash[32] = {
			0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
			0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
			0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
			0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
		};

		ret = t13_derive(t->hs_secret, "derived", empty_hash, derived);
	}
	if (!ret)
		ret = t13_extract(derived, 32, zeros, 32, master);
	if (!ret)
		ret = t13_hash_now(t, hash);
	if (!ret)
		ret = t13_derive(master, "c ap traffic", hash, t->c_ap);
	if (!ret)
		ret = t13_derive(master, "s ap traffic", hash, t->s_ap);

	/* 客户端 Finished：MAC 覆盖到服务器 Finished 为止的转录 */
	if (!ret)
		ret = t13_finished_mac(t->c_hs, hash, cfin + 4);
	mbedtls_platform_zeroize(derived, sizeof(derived));
	mbedtls_platform_zeroize(master, sizeof(master));
	if (ret)
		return t13_fail(t, ret, AL_INTERNAL_ERROR);
	cfin[0] = HS_FINISHED;
	cfin[1] = 0;
	cfin[2] = 0;
	cfin[3] = 32;
	ret = t13_emit(t, KDG_LVL_HANDSHAKE, cfin, sizeof(cfin));
	if (ret)
		return t13_fail(t, ret, AL_INTERNAL_ERROR);

	t->keys_ap = true;
	t->state = KDG_T13_DONE;
	return 0;
}

/* 一条完整握手消息按状态分派。级别不符即 unexpected_message。 */
static int t13_dispatch(struct kdg_tls13 *t, enum kdg_tls13_level lvl,
			const u8 *msg, size_t mlen)
{
	u8 type = msg[0];

	switch (t->state) {
	case KDG_T13_WAIT_SH:
		if (lvl != KDG_LVL_INITIAL || type != HS_SERVER_HELLO)
			break;
		return t13_on_server_hello(t, msg, mlen);
	case KDG_T13_WAIT_EE:
		if (lvl != KDG_LVL_HANDSHAKE || type != HS_ENCRYPTED_EXTS)
			break;
		return t13_on_ee(t, msg, mlen);
	case KDG_T13_WAIT_CERT:
		if (lvl != KDG_LVL_HANDSHAKE || type != HS_CERTIFICATE)
			break;
		return t13_on_cert(t, msg, mlen);
	case KDG_T13_WAIT_CV:
		if (lvl != KDG_LVL_HANDSHAKE || type != HS_CERT_VERIFY)
			break;
		return t13_on_cv(t, msg, mlen);
	case KDG_T13_WAIT_FIN:
		if (lvl != KDG_LVL_HANDSHAKE || type != HS_FINISHED)
			break;
		return t13_on_fin(t, msg, mlen);
	case KDG_T13_DONE:
		/* 握手后服务器可在 1-RTT 级发 NewSessionTicket；我们不做恢复，丢弃。 */
		if (lvl == KDG_LVL_APP && type == HS_NEW_SESSION_TICKET)
			return 0;
		break;
	default:
		break;
	}
	return t13_fail(t, -EBADMSG, AL_UNEXPECTED_MESSAGE);
}

int kdg_tls13_recv(struct kdg_tls13 *t, enum kdg_tls13_level lvl,
		   const u8 *data, size_t len)
{
	size_t off = 0, mlen;
	int ret;

	if (t->state == KDG_T13_FAILED)
		return t->err;
	if (lvl >= KDG_LVL_COUNT || !t->rx[lvl])
		return t13_fail(t, -EINVAL, AL_INTERNAL_ERROR);
	if (KDG_T13_RXBUF - t->rx_len[lvl] < len)
		return t13_fail(t, -EMSGSIZE, AL_DECODE_ERROR);
	memcpy(t->rx[lvl] + t->rx_len[lvl], data, len);
	t->rx_len[lvl] += len;

	/* 逐条取完整消息；剩下的半截留在缓冲里等下一批 CRYPTO 数据。 */
	while (t->rx_len[lvl] - off >= 4) {
		const u8 *m = t->rx[lvl] + off;

		mlen = 4 + ((size_t)m[1] << 16 | (size_t)m[2] << 8 | m[3]);
		if (mlen > KDG_T13_RXBUF)
			return t13_fail(t, -EMSGSIZE, AL_DECODE_ERROR);
		if (t->rx_len[lvl] - off < mlen)
			break;
		ret = t13_dispatch(t, lvl, m, mlen);
		if (ret)
			return ret;
		off += mlen;
	}
	if (off) {
		memmove(t->rx[lvl], t->rx[lvl] + off, t->rx_len[lvl] - off);
		t->rx_len[lvl] -= off;
	}
	return 0;
}

int kdg_tls13_quic_keys(const struct kdg_tls13 *t, enum kdg_tls13_level lvl,
			bool client, struct kdg_quic_keys *out)
{
	const u8 *sec;

	if (lvl == KDG_LVL_HANDSHAKE && t->keys_hs)
		sec = client ? t->c_hs : t->s_hs;
	else if (lvl == KDG_LVL_APP && t->keys_ap)
		sec = client ? t->c_ap : t->s_ap;
	else
		return -EAGAIN;
	return kdg_quic_keys_from_secret(out, t->qsuite, sec);
}

int kdg_tls13_init(struct kdg_tls13 *t, const char *host, const char *alpn,
		   const u8 *tp, size_t tp_len, const mbedtls_x509_crt *ca,
		   kdg_rng_fn rng, void *rng_ctx)
{
	size_t hl = strlen(host);
	int i;

	memset(t, 0, sizeof(*t));
	if (!hl || hl >= sizeof(t->host) || !alpn || !*alpn ||
	    strlen(alpn) > 255 || tp_len > sizeof(t->tp) || !rng)
		return -EINVAL;
	memcpy(t->host, host, hl + 1);
	t->alpn = alpn;
	memcpy(t->tp, tp, tp_len);
	t->tp_len = tp_len;
	t->ca = ca;
	t->rng = rng;
	t->rng_ctx = rng_ctx;
	mbedtls_sha256_init(&t->transcript);
	if (mbedtls_sha256_starts(&t->transcript, 0))
		return -EIO;
	for (i = 0; i < KDG_LVL_COUNT; i++) {
		t->rx[i] = kdg_t13_alloc(KDG_T13_RXBUF);
		if (!t->rx[i]) {
			kdg_tls13_fini(t);
			return -ENOMEM;
		}
	}
	return 0;
}

void kdg_tls13_fini(struct kdg_tls13 *t)
{
	int i;

	for (i = 0; i < KDG_LVL_COUNT; i++)
		kdg_t13_free(t->rx[i]);
	if (t->peer) {
		mbedtls_x509_crt_free(t->peer);
		kdg_t13_free(t->peer);
	}
	mbedtls_sha256_free(&t->transcript);
	mbedtls_platform_zeroize(t, sizeof(*t));
}