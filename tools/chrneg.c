// SPDX-License-Identifier: GPL-2.0
/*
 * chrneg —— /dev/kdnsguard 失败路径的真机反向探针。
 *
 * 为什么要有它：kdg_chr_write/read 的每条失败路径都必须与 kdg_op_enter()
 * 配对 kdg_op_exit()。漏一次，kdg_active_ops 就停在 >0，
 * kdg_chardev_exit() 永久等待，rmmod 卡死；另一类写法会在没拿到的 mutex
 * 上 unlock。宿主测试没有字符设备，正向查询也走不到这些分支 ——
 * 所以必须在真机上故意把每条拒绝路径各打很多次，然后看 rmmod 能不能回来。
 *
 * 每个用例重复 N 次：泄漏是累加的，打一次可能看不出来。
 * 本程序只发「必然被拒」的请求，不触发任何上游查询。
 */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "uapi/kdnsguard.h"

#define N 64

static int fails;

static void expect(const char *what, ssize_t got, int want_errno)
{
	int e = errno;

	if (got >= 0 || e != want_errno) {
		fprintf(stderr, "  FAIL %-28s 期望 -%d，得到 ret=%zd errno=%d\n",
			what, want_errno, got, got < 0 ? e : 0);
		fails++;
	}
}

static void fill(struct kdg_req_v1 *r, uint32_t total, uint32_t qlen)
{
	memset(r, 0, sizeof(*r));
	r->abi_version = KDG_ABI_VERSION;
	r->opcode = KDG_OP_QUERY;
	r->total_len = total;
	r->request_cookie = 0x6b64676e6567ULL;
	r->query_len = qlen;
}

int main(int argc, char **argv)
{
	const char *dev = argc > 1 ? argv[1] : "/dev/kdnsguard";
	unsigned char buf[sizeof(struct kdg_req_v1) + 32];
	struct kdg_req_v1 *r = (struct kdg_req_v1 *)buf;
	int fd, i;

	fd = open(dev, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		perror("open");
		return 2;
	}

	for (i = 0; i < N; i++) {
		/* write 失败路径 */
		expect("短写（count < 头）", write(fd, buf, 4), EMSGSIZE);

		fill(r, sizeof(buf), 12);
		expect("pwrite 偏移≠0", pwrite(fd, buf, sizeof(buf), 8), ESPIPE);

		fill(r, sizeof(buf), 12);
		r->abi_version = KDG_ABI_VERSION + 7;
		expect("ABI 版本不符", write(fd, buf, sizeof(buf)), EPROTO);

		fill(r, sizeof(buf), 12);
		r->opcode = 0x7f;
		expect("未知 opcode", write(fd, buf, sizeof(buf)), EOPNOTSUPP);

		fill(r, sizeof(buf) + 1, 12);
		expect("total_len 与 count 不符", write(fd, buf, sizeof(buf)), EMSGSIZE);

		fill(r, sizeof(buf), 12);
		r->reserved0 = 1;
		expect("reserved0 非零", write(fd, buf, sizeof(buf)), EINVAL);

		fill(r, sizeof(buf), 0);
		expect("query_len = 0", write(fd, buf, sizeof(buf)), EMSGSIZE);

		fill(r, sizeof(buf), 12);
		r->expected_generation = 0xfffffff0u;
		expect("过期 generation", write(fd, buf, sizeof(buf)), ESTALE);

		/* read 失败路径 */
		expect("pread 偏移≠0", pread(fd, buf, sizeof(buf), 8), ESPIPE);
		expect("无待取响应", read(fd, buf, sizeof(buf)), EAGAIN);
	}

	close(fd);
	printf("chrneg: %d 个用例 × %d 次，失败 %d\n", 10, N, fails);
	return fails ? 1 : 0;
}
