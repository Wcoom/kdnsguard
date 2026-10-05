// SPDX-License-Identifier: GPL-2.0
/*
 * test_h3.c —— 端到端：向真实上游发一个 DoH POST 查询，走完整 H3 栈
 * （QUIC 握手 → 控制流 → QPACK 编码请求 → HEADERS/DATA 响应 → 解开 DNS 报文）。
 *
 * 这是第 3、4 两步合起来最有说服力的验收：任何一环不对（Initial 密钥、
 * 传输参数、QPACK 静态表、:status 解码、DATA 重组）都会在这里露出来。
 *
 * 用法：test_h3 [主机:端口] [路径] [CA 文件]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/random.h>

#include "kdg_h3.h"

static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static u64 now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (u64)ts.tv_sec * 1000 + (u64)ts.tv_nsec / 1000000;
}

static int host_rng(void *ctx, unsigned char *out, size_t len)
{
	(void)ctx;
	return getrandom(out, len, 0) == (ssize_t)len ? 0 : -1;
}

static int load_ca(mbedtls_x509_crt *c, const char *path)
{
	static char buf[1 << 20];
	FILE *f = fopen(path, "rb");
	size_t n = f ? fread(buf, 1, sizeof(buf) - 1, f) : 0;

	if (f)
		fclose(f);
	if (!n)
		return -1;
	buf[n] = 0;
	mbedtls_x509_crt_init(c);
	return mbedtls_x509_crt_parse(c, (const unsigned char *)buf, n + 1);
}

/* 造一个 A 查询：example.com */
static size_t build_query(u8 *q, u16 id)
{
	static const char *name = "example.com";
	size_t n = 0, i;
	const char *p;

	q[n++] = (u8)(id >> 8);
	q[n++] = (u8)id;
	q[n++] = 0x01; q[n++] = 0x00;		/* RD */
	q[n++] = 0; q[n++] = 1;			/* qdcount */
	q[n++] = 0; q[n++] = 0;
	q[n++] = 0; q[n++] = 0;
	q[n++] = 0; q[n++] = 0;
	for (p = name; *p; ) {
		const char *dot = strchr(p, '.');
		size_t l = dot ? (size_t)(dot - p) : strlen(p);

		q[n++] = (u8)l;
		for (i = 0; i < l; i++)
			q[n++] = (u8)p[i];
		p += l + (dot ? 1 : 0);
	}
	q[n++] = 0;
	q[n++] = 0; q[n++] = 1;			/* A */
	q[n++] = 0; q[n++] = 1;			/* IN */
	return n;
}

int main(int argc, char **argv)
{
	const char *hp = argc > 1 ? argv[1] : "d6382545.6.00p.net:443";
	const char *path = argc > 2 ? argv[2] : "/gd/h596382545";
	const char *capath = argc > 3 ? argv[3] : "/etc/ssl/certs/ca-certificates.crt";
	char host[256];
	int port = 443, fd, i;
	struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_DGRAM };
	struct addrinfo *res = NULL;
	mbedtls_x509_crt ca;
	struct kdg_qtp tp;
	struct kdg_h3 *h;
	u8 query[512];
	size_t qlen;
	u64 t0;
	int slot = -1;
	bool done = false;

	setvbuf(stdout, NULL, _IONBF, 0);
	snprintf(host, sizeof(host), "%s", hp);
	{
		char *colon = strrchr(host, ':');

		if (colon) {
			*colon = 0;
			port = atoi(colon + 1);
		}
	}
	if (load_ca(&ca, capath)) {
		printf("CA 加载失败：%s\n", capath);
		return 2;
	}
	{
		char ps[8];

		snprintf(ps, sizeof(ps), "%d", port);
		if (getaddrinfo(host, ps, &hints, &res) || !res) {
			printf("解析失败：%s\n", host);
			return 2;
		}
	}
	fd = socket(res->ai_family, SOCK_DGRAM, 0);
	if (connect(fd, res->ai_addr, res->ai_addrlen)) {
		perror("connect");
		return 2;
	}

	kdg_qtp_defaults(&tp);
	tp.max_idle_timeout = 10000;
	tp.initial_max_data = 1 << 20;
	tp.initial_max_stream_data_bidi_local = 1 << 16;
	tp.initial_max_stream_data_bidi_remote = 1 << 16;
	tp.initial_max_stream_data_uni = 1 << 16;
	tp.initial_max_streams_bidi = 16;
	tp.initial_max_streams_uni = 16;

	h = calloc(1, sizeof(*h));
	if (kdg_h3_init(h, host, "h3", &tp, &ca, host_rng, NULL, now_ms())) {
		printf("H3 初始化失败\n");
		return 1;
	}
	printf("H3 → %s:%d%s\n", host, port, path);

	qlen = build_query(query, 0x1234);
	t0 = now_ms();
	while (now_ms() - t0 < 15000) {
		u8 pkt[2048];
		size_t n;
		u64 now = now_ms(), timer;

		if (slot < 0 && kdg_h3_ready(h)) {
			slot = kdg_h3_post(h, path, query, qlen);
			printf("  握手完成 %llums，请求槽位=%d\n",
			       (unsigned long long)(now - t0), slot);
		}
		n = kdg_h3_send(h, pkt, sizeof(pkt), now);
		if (n)
			send(fd, pkt, n, 0);
		for (i = 0; i < 8; i++) {
			ssize_t r = recv(fd, pkt, sizeof(pkt), MSG_DONTWAIT);

			if (r <= 0)
				break;
			kdg_h3_recv(h, pkt, (size_t)r, now_ms());
			n = kdg_h3_send(h, pkt, sizeof(pkt), now_ms());
			if (n)
				send(fd, pkt, n, 0);
		}
		if (slot >= 0) {
			struct kdg_h3_req *r = kdg_h3_req_at(h, (size_t)slot);

			if (r && r->state == H3R_DONE) {
				printf("  响应：status=%d body=%zu 字节（%llums）\n",
				       r->status, r->body_len,
				       (unsigned long long)(now_ms() - t0));
				CHECK(r->status == 200);
				CHECK(r->body_len >= 12);
				CHECK(r->body[0] == 0x12 && r->body[1] == 0x34);
				{
					unsigned an = (unsigned)(r->body[6] << 8) |
						      r->body[7];

					printf("  DNS 应答：ANCOUNT=%u\n", an);
					CHECK(an >= 1);
				}
				done = true;
				break;
			}
			if (r && r->state == H3R_FAILED) {
				printf("  请求失败：err=%d（H3 错误码取负）\n", r->err);
				fails++;
				break;
			}
		}
		if (h->qc.state >= QC_CLOSING) {
			printf("  连接关闭：state=%d err=%llu app=%d\n",
			       (int)h->qc.state, (unsigned long long)h->qc.err,
			       h->qc.err_app);
			break;
		}
		/* 走到这里说明还没完成，继续；循环末尾统一检查 */
		timer = kdg_h3_next_timer(h);
		if (timer && now >= timer)
			kdg_h3_timeout(h, now);
		usleep(1000);
	}

	/* 连接被关掉却没有拿到完整响应 = 失败，不能算通过 */
	if (!done) {
		printf("  未能拿到完整响应（slot=%d state=%d）\n", slot,
		       (int)h->qc.state);
		fails++;
	}
	kdg_h3_fini(h);
	free(h);
	mbedtls_x509_crt_free(&ca);
	freeaddrinfo(res);
	close(fd);
	printf("test_h3: %s（失败 %d）\n", fails ? "FAIL" : "PASS", fails);
	return fails ? 1 : 0;
}
