/* SPDX-License-Identifier: GPL-2.0 */
/*
 * test_http.c —— kdg_http 的宿主侧语料测试。
 *
 * 与 test_wire.c 同样的理由：本树 CONFIG_KUNIT=m，设备构建里跑不了 KUnit，
 * 而 HTTP 分帧的风险全在边界条件上（缺 CRLF、长度撒谎、chunked 越界、
 * 冒号前空白走私、重复 Content-Length）。
 */
#include <stdio.h>
#include <string.h>

#include "kdg_http.h"

static int g_pass, g_fail;

#define T(cond, name) do {						\
	if (cond) {							\
		g_pass++;						\
	} else {							\
		g_fail++;						\
		printf("  FAIL %-50s (line %d)\n", name, __LINE__);	\
	}								\
} while (0)

#define TEQ(expr, want, name) do {					\
	long _g = (long)(expr), _w = (long)(want);			\
	if (_g == _w) {							\
		g_pass++;						\
	} else {							\
		g_fail++;						\
		printf("  FAIL %-50s got=%ld want=%ld (line %d)\n",	\
		       name, _g, _w, __LINE__);				\
	}								\
} while (0)

static void test_head_ok(void)
{
	static const char resp[] =
		"HTTP/1.1 200 OK\r\n"
		"Server: nginx\r\n"
		"Content-Type: application/dns-message\r\n"
		"Content-Length: 45\r\n"
		"Connection: close\r\n"
		"\r\n";
	struct kdg_http_response r;
	const u8 *v;
	size_t vlen;

	puts("[响应头 · 正常路径]");

	TEQ(kdg_http_parse_response_head((const u8 *)resp, sizeof(resp) - 1, &r),
	    KDG_H_OK, "解析成功");
	TEQ(r.status, 200, "状态码 200");
	T(r.http11, "HTTP/1.1");
	TEQ(r.nheaders, 4, "头数量");
	T(r.ctype_is_dns, "Content-Type 被识别为 dns-message");
	T(r.has_content_length, "有 Content-Length");
	TEQ(r.content_length, 45, "Content-Length 值");
	T(r.connection_close, "Connection: close");
	TEQ(r.hdr_end, sizeof(resp) - 1, "hdr_end 指向正文起点");

	/* 头名大小写不敏感 */
	TEQ(kdg_http_header_get((const u8 *)resp, r.hdr_end,
				"content-length", &v, &vlen),
	    KDG_H_OK, "小写查头名");
	TEQ(vlen, 2, "值长度");
	T(memcmp(v, "45", 2) == 0, "值内容");
	TEQ(kdg_http_header_get((const u8 *)resp, r.hdr_end, "CONTENT-TYPE",
				&v, &vlen),
	    KDG_H_OK, "全大写查头名");
	TEQ(kdg_http_header_get((const u8 *)resp, r.hdr_end, "x-nope",
				&v, &vlen),
	    KDG_H_ENOENT, "不存在的头");
	TEQ(kdg_http_count_header((const u8 *)resp, r.hdr_end,
				  "content-length"), 1, "计数");
}

static void test_head_reject(void)
{
	struct kdg_http_response r;
	static const char need_more[] = "HTTP/1.1 200 OK\r\nContent-Len";
	static const char bare_lf[] = "HTTP/1.1 200 OK\nContent-Length: 5\n\n";
	static const char bad_ver[] = "HTTP/0.9 200 OK\r\n\r\n";
	static const char bad_ver2[] = "HTTP/2 200 OK\r\n\r\n";
	static const char short_status[] = "HTTP/1.1 20 OK\r\n\r\n";
	static const char alpha_status[] = "HTTP/1.1 2O0 OK\r\n\r\n";
	static const char long_status[] = "HTTP/1.1 2000 OK\r\n\r\n";
	static const char ws_colon[] =
		"HTTP/1.1 200 OK\r\nContent-Length : 5\r\n\r\n";
	static const char bad_clen[] =
		"HTTP/1.1 200 OK\r\nContent-Length: 5x\r\n\r\n";
	static const char bad_te[] =
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n";
	static const char no_colon[] = "HTTP/1.1 200 OK\r\nBrokenHeader\r\n\r\n";

	puts("[响应头 · 拒绝路径]");

	TEQ(kdg_http_parse_response_head((const u8 *)need_more,
					 sizeof(need_more) - 1, &r),
	    KDG_H_NEED_MORE, "头部未收全 → NEED_MORE");

	/* 裸 \n\n 不是合法 HTTP 分帧：接受它等于放宽协议 */
	TEQ(kdg_http_parse_response_head((const u8 *)bare_lf,
					 sizeof(bare_lf) - 1, &r),
	    KDG_H_NEED_MORE, "裸 LF 分帧不被接受");

	TEQ(kdg_http_parse_response_head((const u8 *)bad_ver,
					 sizeof(bad_ver) - 1, &r),
	    KDG_H_EVERSION, "HTTP/0.9 被拒绝");
	TEQ(kdg_http_parse_response_head((const u8 *)bad_ver2,
					 sizeof(bad_ver2) - 1, &r),
	    KDG_H_EVERSION, "HTTP/2 被拒绝");
	TEQ(kdg_http_parse_response_head((const u8 *)short_status,
					 sizeof(short_status) - 1, &r),
	    KDG_H_ESTATUS, "状态码不足 3 位");
	TEQ(kdg_http_parse_response_head((const u8 *)alpha_status,
					 sizeof(alpha_status) - 1, &r),
	    KDG_H_ESTATUS, "状态码含字母");
	/* 关键：不能把 "2000" 读成 200 —— 那是请求走私的经典手法 */
	TEQ(kdg_http_parse_response_head((const u8 *)long_status,
					 sizeof(long_status) - 1, &r),
	    KDG_H_ESTATUS, "状态码 2000 不被读成 200");
	TEQ(kdg_http_parse_response_head((const u8 *)ws_colon,
					 sizeof(ws_colon) - 1, &r),
	    KDG_H_EFORMAT, "冒号前空白被拒绝");
	TEQ(kdg_http_parse_response_head((const u8 *)bad_clen,
					 sizeof(bad_clen) - 1, &r),
	    KDG_H_EFORMAT, "非数字 Content-Length 被拒绝");
	TEQ(kdg_http_parse_response_head((const u8 *)bad_te,
					 sizeof(bad_te) - 1, &r),
	    KDG_H_EFORMAT, "非 chunked 的 Transfer-Encoding 被拒绝");
	TEQ(kdg_http_parse_response_head((const u8 *)no_colon,
					 sizeof(no_colon) - 1, &r),
	    KDG_H_EFORMAT, "无冒号的头行被拒绝");
}

static void test_duplicate_headers(void)
{
	static const char dup[] =
		"HTTP/1.1 200 OK\r\n"
		"Content-Length: 5\r\n"
		"Content-Length: 9\r\n"
		"\r\n";
	struct kdg_http_response r;

	puts("[响应头 · 重复字段]");

	/* 解析器本身不拒绝重复（那是上层策略），但必须能如实数出来 ——
	 * 重复的 Content-Length 是请求走私的经典载体，调用方要能发现它。 */
	TEQ(kdg_http_parse_response_head((const u8 *)dup, sizeof(dup) - 1, &r),
	    KDG_H_OK, "重复 Content-Length 可解析");
	TEQ(kdg_http_count_header((const u8 *)dup, r.hdr_end, "content-length"),
	    2, "数出 2 处");
}

static void test_chunked(void)
{
	u8 out[256];
	size_t olen;

	puts("[chunked 解码]");

	{
		static const char c[] = "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";

		TEQ(kdg_http_chunk_decode((const u8 *)c, sizeof(c) - 1,
					  out, sizeof(out), &olen),
		    KDG_H_OK, "基本 chunked");
		TEQ(olen, 11, "长度");
		T(memcmp(out, "hello world", 11) == 0, "内容");
	}

	{
		/* 大小写十六进制 + 扩展参数 */
		static const char c[] =
			"B;foo=bar\r\nhello world\r\n0\r\n\r\n";

		TEQ(kdg_http_chunk_decode((const u8 *)c, sizeof(c) - 1,
					  out, sizeof(out), &olen),
		    KDG_H_OK, "带 chunk-ext 的 chunked");
		TEQ(olen, 11, "长度");
	}

	{
		/* 带 trailer 的收尾 */
		static const char c[] =
			"5\r\nhello\r\n0\r\nX-Trailer: v\r\n\r\n";

		TEQ(kdg_http_chunk_decode((const u8 *)c, sizeof(c) - 1,
					  out, sizeof(out), &olen),
		    KDG_H_OK, "带 trailer 的 chunked");
		TEQ(olen, 5, "trailer 不计入正文");
	}

	{
		/* 数据未到齐 */
		static const char c[] = "5\r\nhel";

		TEQ(kdg_http_chunk_decode((const u8 *)c, sizeof(c) - 1,
					  out, sizeof(out), &olen),
		    KDG_H_NEED_MORE, "半个 chunk → NEED_MORE");
	}

	{
		/* 输出容量不足必须报错而不是截断 —— 截断的 DNS 响应会被
		 * 上层当成合法报文去解析。 */
		static const char c[] = "10\r\n0123456789abcdef\r\n0\r\n\r\n";

		TEQ(kdg_http_chunk_decode((const u8 *)c, sizeof(c) - 1,
					  out, 8, &olen),
		    KDG_H_ENOSPC, "输出不足 → ENOSPC");
	}

	{
		/* 块长度与后续 CRLF 不符 */
		static const char c[] = "5\r\nhelloXX\r\n0\r\n\r\n";

		TEQ(kdg_http_chunk_decode((const u8 *)c, sizeof(c) - 1,
					  out, sizeof(out), &olen),
		    KDG_H_EFORMAT, "块后缺 CRLF 被拒绝");
	}

	{
		/* 非法十六进制 */
		static const char c[] = "zz\r\nhello\r\n0\r\n\r\n";

		TEQ(kdg_http_chunk_decode((const u8 *)c, sizeof(c) - 1,
					  out, sizeof(out), &olen),
		    KDG_H_EFORMAT, "非法块长度被拒绝");
	}
}

static void test_invariants(void)
{
	static const char resp[] =
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: application/dns-message\r\n"
		"Content-Length: 32\r\n"
		"\r\n";
	struct kdg_http_response r;
	unsigned int seed = 987654321u;
	int i;

	puts("[结构性不变量 · 截断前缀与随机流]");

	/* 任何长度前缀都不允许崩或越界 */
	for (i = 0; i <= (int)(sizeof(resp) - 1) + 8; i++) {
		int rc = kdg_http_parse_response_head((const u8 *)resp,
						      (size_t)i, &r);

		if (rc > KDG_H_NEED_MORE && rc != KDG_H_OK) {
			g_fail++;
			printf("  FAIL 前缀 %d 返回非预期码 %d\n", i, rc);
		}
	}
	g_pass++;

	/* 随机字节流：不得挂死、不得越界 */
	for (i = 0; i < 20000; i++) {
		u8 rnd[128];
		size_t len;
		unsigned int j;

		seed = seed * 1103515245u + 12345u;
		len = seed % sizeof(rnd);
		for (j = 0; j < len; j++) {
			seed = seed * 1103515245u + 12345u;
			rnd[j] = (u8)(seed >> 16);
		}
		(void)kdg_http_parse_response_head(rnd, len, &r);
	}
	g_pass++;
}

int main(void)
{
	puts("=== kdg_http 语料测试 ===");

	test_head_ok();
	test_head_reject();
	test_duplicate_headers();
	test_chunked();
	test_invariants();

	printf("\n=== 通过 %d / 失败 %d ===\n", g_pass, g_fail);
	return g_fail ? 1 : 0;
}
