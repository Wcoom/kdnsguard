// SPDX-License-Identifier: GPL-2.0
/* test_quic_frame.c —— varint（RFC 9000 附录 A.1 示例）、帧解析、ACK 区间、传输参数。 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "kdg_quic_frame.h"

static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static void test_varint(void)
{
	static const struct { const u8 b[8]; size_t n; u64 v; } vec[] = {
		{ { 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c }, 8, 151288809941952652ULL },
		{ { 0x9d, 0x7f, 0x3e, 0x7d }, 4, 494878333 },
		{ { 0x7b, 0xbd }, 2, 15293 },
		{ { 0x25 }, 1, 37 },
		{ { 0x40, 0x25 }, 2, 37 },	/* 非最短编码也合法 */
	};
	size_t i;
	u8 out[8];

	for (i = 0; i < ARRAY_SIZE(vec); i++) {
		struct kdg_qrd r = { .p = vec[i].b, .n = vec[i].n };

		CHECK(kdg_qv_get(&r) == vec[i].v && !r.bad && r.n == 0);
	}
	/* 编码按最短形式 */
	CHECK(kdg_qv_put(out, 8, 151288809941952652ULL) == 8 && !memcmp(out, vec[0].b, 8));
	CHECK(kdg_qv_put(out, 8, 15293) == 2 && !memcmp(out, vec[2].b, 2));
	CHECK(kdg_qv_put(out, 8, KDG_QV_MAX + 1) == 0);
	CHECK(kdg_qv_put(out, 1, 64) == 0);
	{
		struct kdg_qrd r = { .p = vec[0].b, .n = 3 };	/* 截断 */

		kdg_qv_get(&r);
		CHECK(r.bad);
	}
}

static void test_frames(void)
{
	/* ACK largest=10 delay=0 count=1 first=2 gap=1 range=3：区间 [8,10] [2,5] */
	static const u8 ack[] = { 0x02, 10, 0, 1, 2, 1, 3 };
	static const u8 crypto[] = { 0x06, 0, 3, 'a', 'b', 'c' };
	/* STREAM 0x0b = LEN|FIN，id=0 len=2；再接一个无 LEN 位（0x0c=OFF）的帧吃到包尾 */
	static const u8 streams[] = { 0x00, 0x00, 0x0b, 0, 2, 'h', 'i',
				      0x0c, 4, 5, 'x', 'y', 'z' };
	struct kdg_qrd r;
	struct kdg_qframe f;
	struct kdg_qack_it it;
	u64 lo, hi;

	r = (struct kdg_qrd){ .p = ack, .n = sizeof(ack) };
	CHECK(kdg_qframe_next(&r, &f) == 0 && f.type == QF_ACK && f.u.ack.largest == 10);
	kdg_qack_begin(&it, &f);
	CHECK(kdg_qack_next(&it, &lo, &hi) == 0 && lo == 8 && hi == 10);
	CHECK(kdg_qack_next(&it, &lo, &hi) == 0 && lo == 2 && hi == 5);
	CHECK(kdg_qack_next(&it, &lo, &hi) == -EAGAIN);
	CHECK(kdg_qframe_next(&r, &f) == -EAGAIN);

	/* first_range > largest 必须拒绝；gap 让区间下溢必须拒绝 */
	{
		static const u8 bad1[] = { 0x02, 3, 0, 0, 4 };
		static const u8 bad2[] = { 0x02, 3, 0, 1, 1, 5, 0 };

		r = (struct kdg_qrd){ .p = bad1, .n = sizeof(bad1) };
		CHECK(kdg_qframe_next(&r, &f) == -EBADMSG);
		r = (struct kdg_qrd){ .p = bad2, .n = sizeof(bad2) };
		CHECK(kdg_qframe_next(&r, &f) == 0);
		kdg_qack_begin(&it, &f);
		CHECK(kdg_qack_next(&it, &lo, &hi) == 0);
		CHECK(kdg_qack_next(&it, &lo, &hi) == -EBADMSG);
	}

	r = (struct kdg_qrd){ .p = crypto, .n = sizeof(crypto) };
	CHECK(kdg_qframe_next(&r, &f) == 0 && f.type == QF_CRYPTO &&
	      f.u.crypto.len == 3 && !memcmp(f.u.crypto.data, "abc", 3));

	r = (struct kdg_qrd){ .p = streams, .n = sizeof(streams) };
	CHECK(kdg_qframe_next(&r, &f) == 0 && f.type == QF_STREAM &&
	      f.u.stream.fin && f.u.stream.len == 2 && f.u.stream.off == 0);
	CHECK(kdg_qframe_next(&r, &f) == 0 && f.type == QF_STREAM &&
	      f.u.stream.id == 4 && f.u.stream.off == 5 && f.u.stream.len == 3 &&
	      !f.u.stream.fin);
	CHECK(kdg_qframe_next(&r, &f) == -EAGAIN);

	/* 长度越界、未知帧类型 */
	{
		static const u8 over[] = { 0x06, 0, 9, 'a' };
		static const u8 unk[] = { 0x21 };

		r = (struct kdg_qrd){ .p = over, .n = sizeof(over) };
		CHECK(kdg_qframe_next(&r, &f) == -EBADMSG);
		r = (struct kdg_qrd){ .p = unk, .n = sizeof(unk) };
		CHECK(kdg_qframe_next(&r, &f) == -EPROTO);
	}
}

static void test_tp(void)
{
	struct kdg_qtp a, b;
	u8 buf[256], scid[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	int n;

	kdg_qtp_defaults(&a);
	a.max_idle_timeout = 30000;
	a.initial_max_data = 1 << 20;
	a.initial_max_stream_data_bidi_local = 1 << 18;
	a.initial_max_streams_uni = 3;
	n = kdg_qtp_encode_client(&a, scid, 8, buf, sizeof(buf));
	CHECK(n > 0);
	/* 客户端参数缺 orig_dcid ⇒ 按服务器参数解析必须拒绝（§7.3） */
	CHECK(kdg_qtp_parse(buf, n, &b) == -EBADMSG);
	/* 补上 orig_dcid 后可解析，字段往返一致 */
	buf[n++] = 0x00;
	buf[n++] = 4;
	memcpy(buf + n, "\xaa\xbb\xcc\xdd", 4);
	n += 4;
	CHECK(kdg_qtp_parse(buf, n, &b) == 0);
	CHECK(b.max_idle_timeout == 30000 && b.initial_max_data == (1 << 20) &&
	      b.initial_max_stream_data_bidi_local == (1 << 18) &&
	      b.initial_max_streams_uni == 3 && b.init_scid_len == 8 &&
	      !memcmp(b.init_scid, scid, 8) && b.orig_dcid_len == 4);
	/* 重复参数必须拒绝 */
	buf[n++] = 0x00;
	buf[n++] = 1;
	buf[n++] = 0xee;
	CHECK(kdg_qtp_parse(buf, n, &b) == -EBADMSG);
}

int main(void)
{
	test_varint();
	test_frames();
	test_tp();
	printf("test_quic_frame: %s（失败 %d）\n", fails ? "FAIL" : "PASS", fails);
	return fails ? 1 : 0;
}