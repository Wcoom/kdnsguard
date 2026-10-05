// SPDX-License-Identifier: GPL-2.0
/*
 * test_quic_crypto.c —— kdg_quic_crypto.c 的宿主测试。
 *
 * 向量来源：RFC 9001 附录 A.1（Initial 密钥派生）与 A.5（ChaCha20-Poly1305
 * 短头包）。另加 AES 往返、篡改、包号恢复（RFC 9000 附录 A.3 示例）。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "kdg_quic_crypto.h"

static int fails;

#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static void unhex(const char *h, u8 *out, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		sscanf(h + 2 * i, "%2hhx", &out[i]);
}

static int eqhex(const u8 *b, const char *h)
{
	u8 x[256];
	size_t n = strlen(h) / 2;

	unhex(h, x, n);
	return memcmp(b, x, n) == 0;
}

static void test_initial(void)
{
	u8 dcid[8];
	struct kdg_quic_keys c, s;

	unhex("8394c8f03e515708", dcid, 8);
	CHECK(kdg_quic_initial_keys(dcid, 8, &c, &s) == 0);
	CHECK(eqhex(c.secret, "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"));
	CHECK(eqhex(c.key, "1f369613dd76d5467730efcbe3b1a22d"));
	CHECK(eqhex(c.iv, "fa044b2f42a3fd3b46fb255c"));
	CHECK(eqhex(c.hp, "9f50449e04a0e810283a1e9933adedd2"));
	CHECK(eqhex(s.secret, "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b"));
	CHECK(eqhex(s.key, "cf3a5331653c364c88f0f379b6067e37"));
	CHECK(eqhex(s.iv, "0ac1493ca1905853b0bba03e"));
	CHECK(eqhex(s.hp, "c206b8d9b9f0f37644430b490eeaa314"));

	/* AES 长头往返：客户端加密、对端用同一组密钥解密；再验篡改被拒。 */
	{
		u8 pkt[128] = { 0 }, orig[128];
		size_t pn_off = 18, hl = 22, pl = 40, hdr;
		u64 pn;
		int n, m;

		pkt[0] = 0xc3;	/* 长头 Initial，pn_len=4 */
		memcpy(pkt + 1, "\x00\x00\x00\x01", 4);
		pkt[5] = 8;
		memcpy(pkt + 6, dcid, 8);
		pkt[14] = 0;	/* SCID 长度 0 */
		pkt[15] = 0;	/* token 长度 0 */
		pkt[16] = 0x40 | ((pl + 4 + 16) >> 8);
		pkt[17] = (u8)(pl + 4 + 16);
		pkt[18] = 0; pkt[19] = 0; pkt[20] = 0; pkt[21] = 2;
		memset(pkt + hl, 0x06, pl);
		memcpy(orig, pkt, sizeof(pkt));
		n = kdg_quic_protect(&c, 2, pkt, pn_off, 4, hl, pl, sizeof(pkt));
		CHECK(n == (int)(hl + pl + 16));
		CHECK(memcmp(pkt, orig, hl) != 0);	/* 头部保护确实改了头 */

		m = kdg_quic_unprotect(&c, pkt, pn_off, n, -1, &pn, &hdr);
		CHECK(m == (int)pl && pn == 2 && hdr == hl);
		CHECK(memcmp(pkt, orig, hl + pl) == 0);

		n = kdg_quic_protect(&c, 2, pkt, pn_off, 4, hl, pl, sizeof(pkt));
		memcpy(orig, pkt, n);
		pkt[hl + 3] ^= 1;
		CHECK(kdg_quic_unprotect(&c, pkt, pn_off, n, -1, &pn, &hdr) == -EBADMSG);
		/* 失败后 buf 未定义：从副本恢复后，原密钥仍能正确解开 */
		memcpy(pkt, orig, n);
		CHECK(kdg_quic_unprotect(&c, pkt, pn_off, n, -1, &pn, &hdr) == (int)pl && pn == 2);
		/* 用对端方向的密钥必然认证失败 */
		memcpy(pkt, orig, n);
		CHECK(kdg_quic_unprotect(&s, pkt, pn_off, n, -1, &pn, &hdr) < 0);
		/* 容量不足、样本越界都必须拒绝 */
		CHECK(kdg_quic_protect(&c, 2, pkt, pn_off, 4, hl, pl, hl + pl) == -EINVAL);
		CHECK(kdg_quic_protect(&c, 2, pkt, pn_off, 1, pn_off + 1, 0, sizeof(pkt)) == -EINVAL);
	}
	kdg_quic_keys_free(&c);
	kdg_quic_keys_free(&s);
}

/* RFC 9001 A.5 */
static void test_chacha_short(void)
{
	u8 secret[32], pkt[64];
	struct kdg_quic_keys k;
	u64 pn;
	size_t hdr;
	int n;

	unhex("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b",
	      secret, 32);
	CHECK(kdg_quic_keys_from_secret(&k, KDG_QUIC_CHACHA20, secret) == 0);
	CHECK(eqhex(k.key, "c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"));
	CHECK(eqhex(k.iv, "e0459b3474bdd0e44a41c144"));
	CHECK(eqhex(k.hp, "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4"));

	memset(pkt, 0, sizeof(pkt));
	pkt[0] = 0x42; pkt[1] = 0x00; pkt[2] = 0xbf; pkt[3] = 0xf4;
	pkt[4] = 0x01;	/* PING */
	n = kdg_quic_protect(&k, 654360564ULL, pkt, 1, 3, 4, 1, sizeof(pkt));
	CHECK(n == 21);
	CHECK(eqhex(pkt, "4cfe4189655e5cd55c41f69080575d7999c25a5bfb"));

	n = kdg_quic_unprotect(&k, pkt, 1, 21, 654360563LL, &pn, &hdr);
	CHECK(n == 1 && hdr == 4 && pn == 654360564ULL && pkt[4] == 0x01);
	kdg_quic_keys_free(&k);
}

int main(void)
{
	test_initial();
	test_chacha_short();
	printf("test_quic_crypto: %s（失败 %d）\n", fails ? "FAIL" : "PASS", fails);
	return fails ? 1 : 0;
}