// SPDX-License-Identifier: GPL-2.0
/*
 * test_qpack.c —— kdg_qpack 的宿主测试。
 *
 * 三条独立证据：
 *   1. RFC 7541 C.4.1 的官方向量（Huffman 表的真源核对）；
 *   2. 交叉验证——用生成表里的**符号表**另写一个参考编码器（另一条代码路径），
 *      编码后交由被测解码器解回，覆盖全部字节值与长度边界；
 *   3. 字段段：静态索引 / 名引用字面量 / 字面量名 / Huffman 值，以及
 *      动态表引用、Post-Base、RIC>0、填充违规必须被拒。
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include "kdg_qpack.h"
#include "kdg_qpack_huff_table.h"

static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

/* 参考编码器（RFC 7541 §5.2）：用符号表，末尾补 1 至字节边界。 */
static size_t ref_huff_encode(const u8 *in, size_t n, u8 *out, size_t cap)
{
	size_t o = 0, i;
	/* ⚠️ 必须 64 位：残留位最多 7，再加最长 30 位的码，32 位累加器会溢出
	 * （第一版就是 u32，于是长码字节的交叉验证全红——是测试的缺陷，不是解码器的）。 */
	u64 acc = 0;
	unsigned bits = 0;

	for (i = 0; i < n; i++) {
		unsigned nb = kdg_huff_sym[in[i]].nbits;
		u64 code = (u64)(kdg_huff_sym[in[i]].code >> (32 - nb));

		acc = (acc << nb) | code;
		bits += nb;
		while (bits >= 8) {
			if (o >= cap)
				return 0;
			out[o++] = (u8)(acc >> (bits - 8));
			bits -= 8;
			acc &= bits ? ((u64)1 << bits) - 1 : 0;
		}
	}
	if (bits) {
		if (o >= cap)
			return 0;
		acc = (acc << (8 - bits)) | (((u64)1 << (8 - bits)) - 1);
		out[o++] = (u8)acc;
	}
	return o;
}

static void test_rfc_vector(void)
{
	/* RFC 7541 C.4.1：Huffman("www.example.com") */
	static const u8 enc[] = { 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b,
				  0xa0, 0xab, 0x90, 0xf4, 0xff };
	u8 out[64];
	size_t n = 0;

	CHECK(kdg_qpack_huff_decode(enc, sizeof(enc), out, sizeof(out), &n) == 0);
	CHECK(n == 15 && !memcmp(out, "www.example.com", 15));
}

static void test_cross_check(void)
{
	u8 plain[300], enc[1300], dec[300];	/* 最坏 30 位/字节 ⇒ 256 字节要 960 */
	size_t len, n, got;
	unsigned seed = 987654321, i;

	/* 全部字节值 */
	for (i = 0; i < 256; i++)
		plain[i] = (u8)i;
	for (len = 0; len <= 256; len += 1) {
		n = ref_huff_encode(plain, len, enc, sizeof(enc));
		CHECK(n > 0 || len == 0);
		if (!n && len)
			continue;
		got = 0;
		CHECK(kdg_qpack_huff_decode(enc, n, dec, sizeof(dec), &got) == 0);
		CHECK(got == len && !memcmp(dec, plain, len));
	}
	/* 随机串：混入会触发长码的字节 */
	for (i = 0; i < 2000; i++) {
		unsigned k;

		len = (unsigned)rand_r(&seed) % 200;
		for (k = 0; k < len; k++)
			plain[k] = (u8)rand_r(&seed);
		n = ref_huff_encode(plain, len, enc, sizeof(enc));
		got = 0;
		CHECK(kdg_qpack_huff_decode(enc, n, dec, sizeof(dec), &got) == 0);
		CHECK(got == len && !memcmp(dec, plain, len));
	}
}

static void test_huff_rejects(void)
{
	u8 plain[8] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h' };
	u8 enc[64], out[64];
	size_t n, got;

	/* 输出缓冲太小必须报错，而不是截断后返回成功 */
	n = ref_huff_encode(plain, sizeof(plain), enc, sizeof(enc));
	CHECK(kdg_qpack_huff_decode(enc, n, out, 3, &got) == -ENOSPC);

	/* 填充超过 7 位：手工构造 0xff × 3 后接一个非 1 的填充位 */
	{
		u8 bad[4] = { 0x00, 0x00, 0x00, 0x00 };

		/* 全 0 的 4 字节：路径不会停在叶子上，且填充不是全 1 → 必须拒 */
		CHECK(kdg_qpack_huff_decode(bad, sizeof(bad), out, sizeof(out),
					    &got) == -EBADMSG);
	}
	/* EOS 符号出现在流里 → 必须拒。EOS 是 30 个 1，用符号表拼出来。 */
	{
		u8 eos[4];
		size_t elen = ref_huff_encode(plain, 0, eos, sizeof(eos));

		(void)elen;
		/* 直接构造 30 个 1 位：0xff 0xff 0xff 0xfc */
		eos[0] = 0xff; eos[1] = 0xff; eos[2] = 0xff; eos[3] = 0xfc;
		CHECK(kdg_qpack_huff_decode(eos, 4, out, sizeof(out), &got) == -EBADMSG);
	}
}

static void test_field_section(void)
{
	u8 buf[1024], enc[256];
	struct kdg_qpack_dec d;
	struct kdg_qpack_field f[16];
	const struct kdg_qpack_field *p;
	size_t n = 0, i;

	/* 手工构造一个字段段：
	 *   前缀 00 00
	 *   0xC0|25        索引 :status 200
	 *   0x50 + "dns.example"   名引用(:authority) 字面量值
	 *   0x20 + "x-test" + "v"  字面量名
	 *   0x51 + Huffman("/dns-query")  名引用(:path) + Huffman 值
	 */
	enc[n++] = 0x00;
	enc[n++] = 0x00;
	enc[n++] = 0xc0 | 25;
	enc[n++] = 0x50;
	enc[n++] = (u8)strlen("dns.example");
	memcpy(enc + n, "dns.example", strlen("dns.example"));
	n += strlen("dns.example");
	/* 字面量名：0x20 | 3 位长度前缀（H 位是 0x08，长度 ≤7 时占一个字节） */
	enc[n++] = 0x20 | (u8)strlen("x-test");
	memcpy(enc + n, "x-test", strlen("x-test"));
	n += strlen("x-test");
	enc[n++] = 1;
	enc[n++] = 'v';
	{
		u8 h[32];
		size_t hn = ref_huff_encode((const u8 *)"/dns-query", 10, h, sizeof(h));

		enc[n++] = 0x51;
		enc[n++] = 0x80 | (u8)hn;	/* H=1 */
		memcpy(enc + n, h, hn);
		n += hn;
	}

	kdg_qpack_dec_init(&d, buf, sizeof(buf));
	CHECK(kdg_qpack_decode(&d, enc, n, f, 16) == 0);
	CHECK(d.nfields == 4);
	p = kdg_qpack_find(f, d.nfields, ":status");
	CHECK(p && p->val_len == 3 && !memcmp(p->val, "200", 3));
	p = kdg_qpack_find(f, d.nfields, ":authority");
	CHECK(p && p->val_len == 11 && !memcmp(p->val, "dns.example", 11));
	p = kdg_qpack_find(f, d.nfields, "x-test");
	CHECK(p && p->val_len == 1 && p->val[0] == 'v');
	p = kdg_qpack_find(f, d.nfields, ":path");
	CHECK(p && p->val_len == 10 && !memcmp(p->val, "/dns-query", 10));

	/* 动态表引用必须拒（我们申报容量 0） */
	{
		u8 dyn[4] = { 0x00, 0x00, 0x80 | 5, 0x00 };
		u8 dyn2[4] = { 0x00, 0x00, 0x40 | 3, 0x00 };	/* T=0：动态表名引用 */

		kdg_qpack_dec_init(&d, buf, sizeof(buf));
		CHECK(kdg_qpack_decode(&d, dyn, 3, f, 16) == -EOPNOTSUPP);
		CHECK(kdg_qpack_decode(&d, dyn2, 3, f, 16) == -EOPNOTSUPP);
	}
	/* RIC > 0 与 Post-Base 必须拒 */
	{
		u8 ric[3] = { 0x05, 0x00, 0xc0 | 25 };
		u8 pb[3] = { 0x00, 0x00, 0x10 };

		kdg_qpack_dec_init(&d, buf, sizeof(buf));
		CHECK(kdg_qpack_decode(&d, ric, 3, f, 16) == -EOPNOTSUPP);
		CHECK(kdg_qpack_decode(&d, pb, 3, f, 16) == -EOPNOTSUPP);
	}
	/* 截断：声明的字符串长度超出现有字节时必须拒（确定性的中段截断） */
	{
		u8 cut[6] = { 0x00, 0x00, 0x50, 0x0b, 'a', 'b' };	/* 声明 11 字节只给 2 个 */

		kdg_qpack_dec_init(&d, buf, sizeof(buf));
		CHECK(kdg_qpack_decode(&d, cut, sizeof(cut), f, 16) == -EBADMSG);
		/* 头部前缀本身被截断也要拒 */
		CHECK(kdg_qpack_decode(&d, cut, 1, f, 16) == -EBADMSG);
	}
	/* 字段数上限 */
	kdg_qpack_dec_init(&d, buf, sizeof(buf));
	CHECK(kdg_qpack_decode(&d, enc, n, f, 2) == -ENOSPC);
	(void)i;
}

static void test_request_round_trip(void)
{
	static const char *auth = "d6382545.6.00p.net";
	static const char *path = "/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB";
	static const char *acc = "application/dns-message";
	u8 enc[256], buf[1024];
	struct kdg_qpack_dec d;
	struct kdg_qpack_field f[16];
	const struct kdg_qpack_field *p;
	int n;

	n = kdg_qpack_encode_post(enc, sizeof(enc), auth, path);
	CHECK(n > 0);
	kdg_qpack_dec_init(&d, buf, sizeof(buf));
	CHECK(kdg_qpack_decode(&d, enc, (size_t)n, f, 16) == 0);
	CHECK(d.nfields == 5);
	p = kdg_qpack_find(f, d.nfields, ":method");
	CHECK(p && p->val_len == 3 && !memcmp(p->val, "GET", 3));
	p = kdg_qpack_find(f, d.nfields, ":scheme");
	CHECK(p && p->val_len == 5 && !memcmp(p->val, "https", 5));
	p = kdg_qpack_find(f, d.nfields, ":authority");
	CHECK(p && p->val_len == strlen(auth) && !memcmp(p->val, auth, p->val_len));
	p = kdg_qpack_find(f, d.nfields, ":path");
	CHECK(p && p->val_len == strlen(path) && !memcmp(p->val, path, p->val_len));
	p = kdg_qpack_find(f, d.nfields, "accept");
	CHECK(p && p->val_len == strlen(acc) && !memcmp(p->val, acc, p->val_len));
}

int main(void)
{
	srand(1);
	test_rfc_vector();
	test_cross_check();
	test_huff_rejects();
	test_field_section();
	test_request_round_trip();
	printf("test_qpack: %s（失败 %d）\n", fails ? "FAIL" : "PASS", fails);
	return fails ? 1 : 0;
}
