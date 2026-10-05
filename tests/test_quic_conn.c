// SPDX-License-Identifier: GPL-2.0
/*
 * test_quic_conn.c —— kdg_quic_conn 对真实 QUIC 服务器（默认上游 DoH 端点）
 * 的联通测试。验证：握手走完、两级密钥就位、传输参数被采纳、流可开可写。
 *
 * 用真服务器而不是本地桩：Initial 密钥派生、证书验证、Retry 处理、包合并、
 * 传输参数语义都要和真实实现对齐，桩测不出这些。
 *
 * 用法：test_quic_conn [主机:端口] [CA 文件]
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

#include "kdg_quic_conn.h"

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

int main(int argc, char **argv)
{
	const char *hp = argc > 1 ? argv[1] : "d6382545.6.00p.net:443";
	const char *capath = argc > 2 ? argv[2] : "/etc/ssl/certs/ca-certificates.crt";
	char host[256];
	int port = 443, fd, i;
	struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_DGRAM };
	struct addrinfo *res = NULL;
	mbedtls_x509_crt ca;
	struct kdg_qtp tp;
	struct kdg_qc *c;
	u64 t0, last_rx = 0;
	int got = 0;

	setvbuf(stdout, NULL, _IONBF, 0);	/* LeakSanitizer 走 _exit，不冲刷缓冲 */
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
		char portstr[8];

		snprintf(portstr, sizeof(portstr), "%d", port);
		if (getaddrinfo(host, portstr, &hints, &res) || !res) {
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

	c = calloc(1, sizeof(*c));
	if (kdg_qc_init(c, host, "h3", &tp, &ca, host_rng, NULL, now_ms())) {
		printf("初始化失败\n");
		return 1;
	}
	printf("连接到 %s:%d\n", host, port);

	t0 = now_ms();
	while (now_ms() - t0 < 15000) {
		unsigned char pkt[2048];
		size_t n;
		u64 now = now_ms();
		u64 timer;

		n = kdg_qc_send(c, pkt, sizeof(pkt), now);
		if (n) {
			if (send(fd, pkt, n, 0) < 0) {
				perror("send");
				break;
			}
		}
		for (i = 0; i < 8; i++) {
			ssize_t r = recv(fd, pkt, sizeof(pkt), MSG_DONTWAIT);

			if (r <= 0)
				break;
			got++;
			last_rx = now_ms();
			kdg_qc_recv(c, pkt, (size_t)r, last_rx);
			/* 内核路径是「收一个包立刻回」；这里照做以便握手尽快推进 */
			n = kdg_qc_send(c, pkt, sizeof(pkt), now_ms());
			if (n)
				send(fd, pkt, n, 0);
			if (c->state >= QC_ESTABLISHED)
				break;
		}
		if (c->state >= QC_ESTABLISHED || c->state == QC_CLOSED)
			break;
		timer = kdg_qc_next_timer(c);
		if (timer && now >= timer)
			kdg_qc_timeout(c, now);
		usleep(2000);
	}

	printf("状态=%d 收到包=%d 耗时=%llums\n", (int)c->state, got,
	       (unsigned long long)(now_ms() - t0));
	if (c->state == QC_HANDSHAKING || c->state == QC_CLOSED) {
		printf("握手未完成（err=%llu app=%d）\n", (unsigned long long)c->err,
		       c->err_app);
		fails++;
	}
	if (c->state >= QC_ESTABLISHED) {
		s64 id;

		CHECK(c->tls.state == KDG_T13_DONE);
		CHECK(c->peer_tp_ok);
		CHECK(c->sp[QS_HANDSHAKE].tx.ready && c->sp[QS_HANDSHAKE].rx.ready);
		CHECK(c->sp[QS_APP].tx.ready && c->sp[QS_APP].rx.ready);
		CHECK(c->sp[QS_INITIAL].discarded);
		printf("  服务器传输参数：max_data=%llu streams_bidi=%llu idle=%llums\n",
		       (unsigned long long)c->peer.initial_max_data,
		       (unsigned long long)c->peer.initial_max_streams_bidi,
		       (unsigned long long)c->peer.max_idle_timeout);
		id = kdg_qc_stream_open(c, false);
		CHECK(id >= 0);
		printf("  已开双向流 id=%lld；发一个请求首字节\n", (long long)id);
		CHECK(kdg_qc_stream_write(c, (u64)id, (const u8 *)"x", 1, false) == 0);
		/* 把流数据发出去（不验 H3 语义，那是第 4 步） */
		{
			unsigned char pkt[2048];
			size_t n = kdg_qc_send(c, pkt, sizeof(pkt), now_ms());

			if (n)
				send(fd, pkt, n, 0);
			CHECK(n > 0);
		}
	}

	kdg_qc_fini(c);
	mbedtls_x509_crt_free(&ca);
	free(c);
	freeaddrinfo(res);
	close(fd);
	printf("test_quic_conn: %s（失败 %d）\n", fails ? "FAIL" : "PASS", fails);
	return fails ? 1 : 0;
}
