// SPDX-License-Identifier: GPL-2.0
/*
 * test_h3_frames.c —— H3 帧解析的离线负例（不联网）。
 * 覆盖：跨 chunk 拆分的帧、DATA 先于 HEADERS、体超限、控制流上出现数据帧、
 * 控制流 FIN、未知帧必须忽略、GOAWAY 解析、截断的帧头。
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include "kdg_h3.h"

static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

/* 造一个响应：HEADERS(:status 200) + DATA(n 字节) */
static size_t mk_resp(u8 *out, const u8 *body, size_t blen)
{
	size_t n = 0;
	u8 fs[8];
	int fl;

	fl = 0;
	fs[fl++] = 0x00;			/* RIC */
	fs[fl++] = 0x00;			/* Delta Base */
	fs[fl++] = 0xc0 | 25;			/* :status 200 */
	out[n++] = H3F_HEADERS;
	out[n++] = (u8)fl;
	memcpy(out + n, fs, (size_t)fl);
	n += (size_t)fl;
	out[n++] = H3F_DATA;
	out[n++] = (u8)blen;
	memcpy(out + n, body, blen);
	n += blen;
	return n;
}

int main(void)
{
	u8 buf[256], resp[256];
	u8 body[16];
	struct kdg_h3 *h = calloc(1, sizeof(*h));
	struct kdg_h3_req r;

	memset(body, 0xab, sizeof(body));
	body[0] = 0x12; body[1] = 0x34;
	body[6] = 0; body[7] = 1;		/* ANCOUNT=1 */

	/* 1. 一次喂完 */
	memset(&r, 0, sizeof(r));
	{
		size_t n = mk_resp(resp, body, sizeof(body));

		CHECK(kdg_h3_feed(h, &r, resp, n, true) == 0);
		CHECK(r.state == H3R_DONE && r.status == 200);
		CHECK(r.body_len == sizeof(body) && r.body[0] == 0x12);
	}

	/* 2. 逐字节喂：跨 chunk 的帧必须能拼起来 */
	memset(&r, 0, sizeof(r));
	{
		size_t n = mk_resp(resp, body, sizeof(body)), i;

		for (i = 0; i < n; i++) {
			int rc = kdg_h3_feed(h, &r, resp + i, 1, i + 1 == n);

			CHECK(rc == 0);
		}
		CHECK(r.state == H3R_DONE && r.body_len == sizeof(body));
	}

	/* 3. DATA 先于 HEADERS */
	memset(&r, 0, sizeof(r));
	{
		u8 bad[4] = { H3F_DATA, 2, 0xaa, 0xbb };	/* 长度正好 4 */

		CHECK(kdg_h3_feed(h, &r, bad, sizeof(bad), false) ==
		      -H3E_FRAME_UNEXPECTED);
	}

	/* 4. 体超限：声明一个 100000 字节的 DATA 帧（> 64 KiB 上限） */
	memset(&r, 0, sizeof(r));
	{
		u8 big[5] = { H3F_HEADERS, 3, 0x00, 0x00, 0xc0 | 25 };
		/* DATA + 4 字节 varint 长度 100000 */
		u8 dh[5] = { H3F_DATA, 0x80, 0x01, 0x86, 0xa0 };

		CHECK(kdg_h3_feed(h, &r, big, sizeof(big), false) == 0);
		CHECK(kdg_h3_feed(h, &r, dh, sizeof(dh), false) == 0);
		{
			u8 chunk[512];
			int rc = 0, i;

			memset(chunk, 0, sizeof(chunk));
			for (i = 0; i < 200 && !rc; i++)
				rc = kdg_h3_feed(h, &r, chunk, sizeof(chunk), false);
			CHECK(rc == -H3E_EXCESSIVE_LOAD);
		}
	}

	/* 5. 帧头被截断就 FIN */
	memset(&r, 0, sizeof(r));
	{
		u8 part[3] = { H3F_HEADERS, 0x40 };	/* 长度 varint 只给一半 */

		CHECK(kdg_h3_feed(h, &r, part, 2, true) == -H3E_FRAME_ERROR);
	}

	/* 6. 未知帧类型必须被忽略（RFC 9114 §9），随后正常帧仍要解析 */
	memset(&r, 0, sizeof(r));
	{
		size_t n = mk_resp(resp, body, sizeof(body));
		u8 seq[300];
		size_t o = 0;

		seq[o++] = 0x21;			/* 未知帧类型 0x21 */
		seq[o++] = 3;
		seq[o++] = 1; seq[o++] = 2; seq[o++] = 3;
		memcpy(seq + o, resp, n);
		o += n;
		CHECK(kdg_h3_feed(h, &r, seq, o, true) == 0);
		CHECK(r.state == H3R_DONE && r.status == 200);
	}

	/* 7. 控制流：SETTINGS 可接受，GOAWAY 解析出 stream id，DATA 必须拒 */
	{
		struct kdg_h3_req c;

		memset(&c, 0, sizeof(c));
		c.is_control = true;
		{
			/* 长度必须按实际数据长度传：多给的零字节会被解析成 DATA 帧 */
			u8 st[4] = { H3F_SETTINGS, 2, 0x01, 0x00 };

			CHECK(kdg_h3_feed(h, &c, st, sizeof(st), false) == 0);
		}
		{
			u8 go[3] = { H3F_GOAWAY, 1, 0x04 };

			CHECK(kdg_h3_feed(h, &c, go, sizeof(go), false) == 0);
			CHECK(h->goaway_seen && h->goaway_id == 4);
		}
		{
			u8 d[3] = { H3F_DATA, 1, 0x00 };

			CHECK(kdg_h3_feed(h, &c, d, sizeof(d), false) ==
			      -H3E_FRAME_UNEXPECTED);
		}
		/* 控制流不得 FIN */
		memset(&c, 0, sizeof(c));
		c.is_control = true;
		CHECK(kdg_h3_feed(h, &c, NULL, 0, true) == -H3E_CLOSED_CRITICAL);
		/* 控制流上的推送帧必须拒 */
		memset(&c, 0, sizeof(c));
		c.is_control = true;
		{
			u8 pp[3] = { H3F_PUSH_PROMISE, 1, 0x00 };

			CHECK(kdg_h3_feed(h, &c, pp, sizeof(pp), false) ==
			      -H3E_FRAME_UNEXPECTED);
		}
	}

	/* 8. 响应流上的 PUSH_PROMISE 必须拒（我们 MAX_PUSH_ID=0） */
	memset(&r, 0, sizeof(r));
	{
		u8 pp[5] = { H3F_HEADERS, 3, 0x00, 0x00, 0xc0 | 25 };

		CHECK(kdg_h3_feed(h, &r, pp, sizeof(pp), false) == 0);
		{
			u8 push[3] = { H3F_PUSH_PROMISE, 1, 0x00 };

			/* §7.2.5：MAX_PUSH_ID=0 时收到推送是 ID_ERROR，不是帧错误 */
			CHECK(kdg_h3_feed(h, &r, push, sizeof(push), false) ==
			      -H3E_ID_ERROR);
		}
	}

	free(h);
	(void)buf;
	printf("test_h3_frames: %s（失败 %d）\n", fails ? "FAIL" : "PASS", fails);
	return fails ? 1 : 0;
}
