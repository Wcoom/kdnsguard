// SPDX-License-Identifier: GPL-2.0
/*
 * test_tls13.c —— kdg_tls13 与 OpenSSL 3.5 的 QUIC-TLS 服务端互通测试。
 *
 * OpenSSL 3.5 提供给第三方 QUIC 栈的 SSL_set_quic_tls_cbs()：握手消息按
 * 加密级别经回调进出，不走 TLS 记录层 —— 与 QUIC 的用法完全一致。于是能在
 * 一个进程里让两端直接对喂握手字节，并逐字节比较双方算出的流量密钥。
 *
 * 用法：test_tls13 <ca.pem> <leaf.pem> <leaf.key> <wrong-ca.pem>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/random.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/core_dispatch.h>

#include "kdg_tls13.h"
#include <psa/crypto.h>

static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static int host_rng(void *ctx, unsigned char *out, size_t len)
{
	(void)ctx;
	return getrandom(out, len, 0) == (ssize_t)len ? 0 : -1;
}

/* OpenSSL 一侧的状态。级别编号统一用 kdg_tls13_level。 */
struct srv {
	SSL *ssl;
	int wlvl, rlvl;			/* OpenSSL 当前写/读级别 */
	unsigned char out[3][8192];	/* OpenSSL 发出的握手字节，按级别 */
	size_t out_len[3];
	unsigned char in[3][8192];	/* 喂给 OpenSSL 的握手字节，按级别 */
	size_t in_len[3], in_off[3];
	unsigned char sec[3][2][32];	/* [级别][0=读 1=写] */
	unsigned char peer_tp[256];
	size_t peer_tp_len;
	int alert;
};

static int lvl_of(uint32_t prot)
{
	return prot == OSSL_RECORD_PROTECTION_LEVEL_HANDSHAKE ? KDG_LVL_HANDSHAKE :
	       prot == OSSL_RECORD_PROTECTION_LEVEL_APPLICATION ? KDG_LVL_APP :
	       KDG_LVL_INITIAL;
}

static int cb_send(SSL *s, const unsigned char *buf, size_t len,
		   size_t *consumed, void *arg)
{
	struct srv *v = arg;

	(void)s;
	if (v->out_len[v->wlvl] + len > sizeof(v->out[0]))
		return 0;
	memcpy(v->out[v->wlvl] + v->out_len[v->wlvl], buf, len);
	v->out_len[v->wlvl] += len;
	*consumed = len;
	return 1;
}

static int cb_recv(SSL *s, const unsigned char **buf, size_t *n, void *arg)
{
	struct srv *v = arg;
	int l = v->rlvl;

	(void)s;
	*buf = v->in[l] + v->in_off[l];
	*n = v->in_len[l] - v->in_off[l];
	return 1;
}

static int cb_release(SSL *s, size_t n, void *arg)
{
	struct srv *v = arg;

	(void)s;
	v->in_off[v->rlvl] += n;
	return 1;
}

/* direction：0 = 读，1 = 写。拿到某级密钥即意味着 OpenSSL 切换到该级。 */
static int cb_secret(SSL *s, uint32_t prot, int dir,
		     const unsigned char *sec, size_t len, void *arg)
{
	struct srv *v = arg;
	int l = lvl_of(prot);

	(void)s;
	if (len != 32 || l == KDG_LVL_INITIAL)
		return 1;
	memcpy(v->sec[l][dir], sec, 32);
	if (dir)
		v->wlvl = l;
	else
		v->rlvl = l;
	return 1;
}

static int cb_tp(SSL *s, const unsigned char *p, size_t n, void *arg)
{
	struct srv *v = arg;

	(void)s;
	if (n > sizeof(v->peer_tp))
		return 0;
	memcpy(v->peer_tp, p, n);
	v->peer_tp_len = n;
	return 1;
}

static int cb_alert(SSL *s, unsigned char code, void *arg)
{
	struct srv *v = arg;

	(void)s;
	v->alert = code;
	return 1;
}

static const OSSL_DISPATCH qtdis[] = {
	{ OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND, (void (*)(void))cb_send },
	{ OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD, (void (*)(void))cb_recv },
	{ OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD, (void (*)(void))cb_release },
	{ OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET, (void (*)(void))cb_secret },
	{ OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS, (void (*)(void))cb_tp },
	{ OSSL_FUNC_SSL_QUIC_TLS_ALERT, (void (*)(void))cb_alert },
	OSSL_DISPATCH_END
};

static int alpn_select(SSL *s, const unsigned char **out, unsigned char *outlen,
		       const unsigned char *in, unsigned int inlen, void *arg)
{
	const char *want = arg;
	unsigned int i = 0;

	(void)s;
	while (i < inlen) {
		unsigned int l = in[i];

		if (l == strlen(want) && i + 1 + l <= inlen &&
		    !memcmp(in + i + 1, want, l)) {
			*out = in + i + 1;
			*outlen = (unsigned char)l;
			return SSL_TLSEXT_ERR_OK;
		}
		i += 1 + l;
	}
	return SSL_TLSEXT_ERR_ALERT_FATAL;
}

struct opts {
	const char *host;		/* 客户端校验的主机名 */
	const char *srv_alpn;		/* 服务器愿意选的 ALPN */
	const char *groups;		/* 服务器支持的组 */
	int tamper_fin;			/* 篡改服务器 Finished 的最后一字节 */
	const mbedtls_x509_crt *ca;
	const char *suites;		/* 服务器 TLS 1.3 套件；NULL 为默认 */
};

static const char *cert_path, *key_path;
static int last_srv_alert;

/* 跑一次握手，返回客户端最终状态；ok 时核对双方密钥一致。 */
static int run(const struct opts *o, struct kdg_tls13 *t)
{
	static const unsigned char ctp[] = { 0x04, 0x02, 0x40, 0x64 };	/* initial_max_data=100 */
	static const unsigned char stp[] = { 0x01, 0x02, 0x67, 0x10 };	/* max_idle_timeout=10000 */
	struct srv *v = calloc(1, sizeof(*v));
	SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
	int rounds, ret, l;

	SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
	if (SSL_CTX_use_certificate_chain_file(ctx, cert_path) != 1 ||
	    SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) != 1) {
		printf("证书加载失败\n");
		exit(2);
	}
	SSL_CTX_set_alpn_select_cb(ctx, alpn_select, (void *)o->srv_alpn);
	SSL_CTX_set1_groups_list(ctx, o->groups);
	if (o->suites)
		SSL_CTX_set_ciphersuites(ctx, o->suites);
	v->ssl = SSL_new(ctx);
	SSL_set_accept_state(v->ssl);
	SSL_set_quic_tls_cbs(v->ssl, qtdis, v);
	SSL_set_quic_tls_transport_params(v->ssl, stp, sizeof(stp));

	ret = kdg_tls13_init(t, o->host, "h3", ctp, sizeof(ctp), o->ca,
			     host_rng, NULL);
	CHECK(ret == 0);
	ret = kdg_tls13_start(t);
	CHECK(ret == 0);

	for (rounds = 0; rounds < 8; rounds++) {
		/* 客户端 → 服务器 */
		for (l = 0; l < 3; l++) {
			memcpy(v->in[l] + v->in_len[l], t->tx[l], t->tx_len[l]);
			v->in_len[l] += t->tx_len[l];
			t->tx_len[l] = 0;
		}
		SSL_do_handshake(v->ssl);
		/* 服务器 → 客户端 */
		for (l = 0; l < 3; l++) {
			if (!v->out_len[l])
				continue;
			if (o->tamper_fin && l == KDG_LVL_HANDSHAKE)
				v->out[l][v->out_len[l] - 1] ^= 1;
			kdg_tls13_recv(t, l, v->out[l], v->out_len[l]);
			v->out_len[l] = 0;
		}
		if (t->state == KDG_T13_FAILED ||
		    (t->state == KDG_T13_DONE && SSL_is_init_finished(v->ssl)))
			break;
	}

	if (t->state == KDG_T13_DONE) {
		/* 双方必须算出同一组密钥：服务器的写 = 客户端的 s_*，反之亦然 */
		CHECK(!memcmp(v->sec[KDG_LVL_HANDSHAKE][1], t->s_hs, 32));
		CHECK(!memcmp(v->sec[KDG_LVL_HANDSHAKE][0], t->c_hs, 32));
		CHECK(!memcmp(v->sec[KDG_LVL_APP][1], t->s_ap, 32));
		CHECK(!memcmp(v->sec[KDG_LVL_APP][0], t->c_ap, 32));
		CHECK(SSL_is_init_finished(v->ssl));
		CHECK(v->peer_tp_len == sizeof(ctp) && !memcmp(v->peer_tp, ctp, sizeof(ctp)));
		CHECK(t->peer_tp_len == sizeof(stp) && !memcmp(t->peer_tp, stp, sizeof(stp)));
	}
	ret = t->state;
	last_srv_alert = v->alert;
	SSL_free(v->ssl);
	SSL_CTX_free(ctx);
	free(v);
	return ret;
}

static void load_ca(mbedtls_x509_crt *c, const char *path)
{
	static char buf[16384];
	FILE *f = fopen(path, "rb");
	size_t n = f ? fread(buf, 1, sizeof(buf) - 1, f) : 0;

	if (f)
		fclose(f);
	buf[n] = 0;	/* PEM 解析要求含结尾 NUL 的长度 */
	mbedtls_x509_crt_init(c);
	if (!n || mbedtls_x509_crt_parse(c, (const unsigned char *)buf, n + 1)) {
		printf("CA 加载失败 %s\n", path);
		exit(2);
	}
}

int main(int argc, char **argv)
{
	mbedtls_x509_crt ca, wrong;
	struct kdg_tls13 t;
	struct opts o;
	int st;

	if (argc != 5)
		return 2;
	cert_path = argv[2];
	key_path = argv[3];
	load_ca(&ca, argv[1]);
	load_ca(&wrong, argv[4]);
	psa_crypto_init();

	/* 1. 正常握手：AES-128-GCM */
	o = (struct opts){ "kdg-test.invalid", "h3", "X25519", 0, &ca, NULL };
	st = run(&o, &t);
	CHECK(st == KDG_T13_DONE);
	CHECK(t.suite == 0x1301 || t.suite == 0x1303);
	printf("  正常握手：state=%d suite=0x%04x\n", st, t.suite);
	kdg_tls13_fini(&t);

	/* 1b. ChaCha20-Poly1305（真实上游协商出的套件） */
	o.suites = "TLS_CHACHA20_POLY1305_SHA256";
	st = run(&o, &t);
	CHECK(st == KDG_T13_DONE && t.suite == 0x1303);
	{
		struct kdg_quic_keys k;

		CHECK(kdg_tls13_quic_keys(&t, KDG_LVL_APP, true, &k) == 0);
		CHECK(k.suite == KDG_QUIC_CHACHA20);
		kdg_quic_keys_free(&k);
	}
	printf("  ChaCha20：state=%d suite=0x%04x\n", st, t.suite);
	kdg_tls13_fini(&t);
	o.suites = NULL;

	/* 2. 主机名不符 */
	o.host = "evil.invalid";
	st = run(&o, &t);
	CHECK(st == KDG_T13_FAILED && t.err == -EKEYREJECTED);
	kdg_tls13_fini(&t);
	o.host = "kdg-test.invalid";

	/* 3. 信任锚不符 */
	o.ca = &wrong;
	st = run(&o, &t);
	CHECK(st == KDG_T13_FAILED && t.err == -EKEYREJECTED);
	kdg_tls13_fini(&t);
	o.ca = &ca;

	/* 4. 服务器不选 h3 */
	o.srv_alpn = "h2";
	st = run(&o, &t);
	/* OpenSSL 的 QUIC-TLS 在服务端拒绝时只走 alert 回调、不发字节 */
	CHECK(st != KDG_T13_DONE && last_srv_alert == 120);
	kdg_tls13_fini(&t);
	o.srv_alpn = "h3";

	/* 5. 服务器只要 P-256 ⇒ HRR ⇒ 明确失败 */
	o.groups = "P-256";
	st = run(&o, &t);
	/* 客户端只列 X25519 ⇒ 无共同组 ⇒ 服务器直接 handshake_failure，不发 HRR */
	CHECK(st != KDG_T13_DONE && last_srv_alert == 40);
	kdg_tls13_fini(&t);
	o.groups = "X25519";

	/* 5b. 手工构造 HelloRetryRequest，直接喂给引擎 */
	{
		static const unsigned char tp1[] = { 0x04, 0x02, 0x40, 0x64 };
		unsigned char hrr[4 + 2 + 32 + 1 + 2 + 1 + 2 + 6] = { 2, 0, 0, 0 };
		unsigned char *p = hrr + 4;
		static const unsigned char rnd[32] = {
			0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c,
			0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb,
			0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c };

		*p++ = 3; *p++ = 3;
		memcpy(p, rnd, 32); p += 32;
		*p++ = 0;			/* session_id */
		*p++ = 0x13; *p++ = 0x01;
		*p++ = 0;			/* compression */
		*p++ = 0; *p++ = 6;		/* extensions */
		*p++ = 0; *p++ = 43; *p++ = 0; *p++ = 2; *p++ = 3; *p++ = 4;
		hrr[3] = (unsigned char)(p - hrr - 4);
		CHECK(kdg_tls13_init(&t, "kdg-test.invalid", "h3", tp1, sizeof(tp1),
				     &ca, host_rng, NULL) == 0);
		CHECK(kdg_tls13_start(&t) == 0);
		CHECK(kdg_tls13_recv(&t, KDG_LVL_INITIAL, hrr, p - hrr) == -EPROTONOSUPPORT);
		CHECK(t.state == KDG_T13_FAILED && t.alert == 40);
		kdg_tls13_fini(&t);
	}

	/* 5c. 截断与超长输入：分片喂 ServerHello 头，越界长度必须拒绝 */
	{
		static const unsigned char tp1[] = { 0x04, 0x02, 0x40, 0x64 };
		unsigned char bad[4] = { 2, 0xff, 0xff, 0xff };

		CHECK(kdg_tls13_init(&t, "kdg-test.invalid", "h3", tp1, sizeof(tp1),
				     &ca, host_rng, NULL) == 0);
		CHECK(kdg_tls13_start(&t) == 0);
		CHECK(kdg_tls13_recv(&t, KDG_LVL_INITIAL, bad, 2) == 0);	/* 半截头：等待 */
		CHECK(kdg_tls13_recv(&t, KDG_LVL_INITIAL, bad + 2, 2) == -EMSGSIZE);
		kdg_tls13_fini(&t);
	}

	/* 6. 篡改服务器 Finished */
	o.tamper_fin = 1;
	st = run(&o, &t);
	CHECK(st == KDG_T13_FAILED);
	kdg_tls13_fini(&t);

	mbedtls_x509_crt_free(&ca);
	mbedtls_x509_crt_free(&wrong);
	printf("test_tls13: %s（失败 %d）\n", fails ? "FAIL" : "PASS", fails);
	return fails ? 1 : 0;
}
