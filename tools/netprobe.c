/* SPDX-License-Identifier: GPL-2.0 */
/* 有界 DNS 路径探针，仅请求显式指定的测试域名。 */
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "kdg_wire.h"

static long long now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void show_addr(int fd, bool peer)
{
	struct sockaddr_storage ss;
	socklen_t len = sizeof(ss);
	char text[INET6_ADDRSTRLEN];
	int ret = peer ? getpeername(fd, (struct sockaddr *)&ss, &len)
		       : getsockname(fd, (struct sockaddr *)&ss, &len);
	if (ret) {
		printf("%s errno=%d\n", peer ? "peer" : "local", errno);
		return;
	}
	if (ss.ss_family == AF_INET) {
		struct sockaddr_in *s = (void *)&ss;
		inet_ntop(AF_INET, &s->sin_addr, text, sizeof(text));
		printf("%s=%s:%u\n", peer ? "peer" : "local", text, ntohs(s->sin_port));
	} else {
		struct sockaddr_in6 *s = (void *)&ss;
		inet_ntop(AF_INET6, &s->sin6_addr, text, sizeof(text));
		printf("%s=[%s]:%u\n", peer ? "peer" : "local", text, ntohs(s->sin6_port));
	}
}

static int read_exact(int fd, void *buf, size_t len, long long deadline)
{
	size_t off = 0;
	while (off < len) {
		struct pollfd p = { .fd = fd, .events = POLLIN };
		long long remaining = deadline - now_ms();
		ssize_t n;
		if (remaining <= 0 || poll(&p, 1, (int)remaining) <= 0)
			return -ETIMEDOUT;
		n = recv(fd, (char *)buf + off, len - off, 0);
		if (n <= 0)
			return n ? -errno : -ECONNRESET;
		off += (size_t)n;
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct sockaddr_storage ss = { 0 };
	struct kdg_dname name;
	struct kdg_summary summary;
	struct timeval timeout = { .tv_sec = 3 };
	const char *domain = argc > 3 ? argv[3] : "example.com";
	unsigned char query[512] = { 0x4b, 0x44, 1, 0, 0, 1 };
	unsigned char response[65535], prefix[2];
	socklen_t salen;
	bool tcp, connected;
	size_t qlen;
	int fd, family, ret;
	ssize_t n;
	long long deadline;

	if (argc < 3 || (strcmp(argv[1], "tcp") && strcmp(argv[1], "udp") &&
			strcmp(argv[1], "sendto"))) {
		fprintf(stderr, "usage: netprobe tcp|udp|sendto numeric-IP [test-domain] [uid]\n");
		return 2;
	}
	if (argc > 4) {
		char *end;
		unsigned long uid = strtoul(argv[4], &end, 10);
		if (!argv[4][0] || *end || uid > 0xffffffffUL ||
		    setgid((gid_t)uid) || setuid((uid_t)uid)) {
			fprintf(stderr, "cannot select test uid\n");
			return 2;
		}
	}
	family = strchr(argv[2], ':') ? AF_INET6 : AF_INET;
	if (family == AF_INET) {
		struct sockaddr_in *s = (void *)&ss;
		s->sin_family = AF_INET;
		s->sin_port = htons(53);
		ret = inet_pton(family, argv[2], &s->sin_addr);
		salen = sizeof(*s);
	} else {
		struct sockaddr_in6 *s = (void *)&ss;
		s->sin6_family = AF_INET6;
		s->sin6_port = htons(53);
		ret = inet_pton(family, argv[2], &s->sin6_addr);
		salen = sizeof(*s);
	}
	if (ret != 1 || kdg_wire_dname_from_text(domain, strlen(domain), &name))
		return 2;
	memcpy(query + 12, name.wire, name.len);
	qlen = 12 + name.len;
	query[qlen++] = 0; query[qlen++] = 1;
	query[qlen++] = 0; query[qlen++] = 1;
	tcp = !strcmp(argv[1], "tcp");
	connected = strcmp(argv[1], "sendto") != 0;
	fd = socket(family, tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
	if (fd < 0) { perror("socket"); return 1; }
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
	printf("uid=%u mode=%s target=%s:53\n", (unsigned)getuid(), argv[1], argv[2]);
	if (connected) {
		if (connect(fd, (struct sockaddr *)&ss, salen)) {
			perror("connect"); close(fd); return 1;
		}
		show_addr(fd, true);
	}
	deadline = now_ms() + 3000;
	if (tcp) {
		unsigned char framed[514];
		size_t off = 0;
		framed[0] = (unsigned char)(qlen >> 8);
		framed[1] = (unsigned char)qlen;
		memcpy(framed + 2, query, qlen);
		while (off < qlen + 2) {
			n = send(fd, framed + off, qlen + 2 - off, MSG_NOSIGNAL);
			if (n <= 0) { perror("send"); close(fd); return 1; }
			off += (size_t)n;
		}
		ret = read_exact(fd, prefix, 2, deadline);
		n = ((unsigned)prefix[0] << 8) | prefix[1];
		if (!ret)
			ret = read_exact(fd, response, (size_t)n, deadline);
	} else {
		n = sendto(fd, query, qlen, MSG_NOSIGNAL,
			   connected ? NULL : (struct sockaddr *)&ss,
			   connected ? 0 : salen);
		if (n != (ssize_t)qlen) { perror("sendto"); close(fd); return 1; }
		salen = sizeof(ss);
		n = recvfrom(fd, response, sizeof(response), 0, (struct sockaddr *)&ss, &salen);
		ret = n < 0 ? -errno : 0;
	}
	show_addr(fd, false);
	close(fd);
	if (ret) {
		printf("response error=%d\n", ret);
		return 1;
	}
	ret = kdg_wire_match_response(query, qlen, response, (size_t)n, &summary);
	printf("bytes=%zd match=%d rcode=%u answers=%u elapsed_ms=%lld\n",
	       n, ret, ret ? 0 : summary.rcode, ret ? 0 : summary.ancount,
	       now_ms() - (deadline - 3000));
	return ret ? 1 : 0;
}
