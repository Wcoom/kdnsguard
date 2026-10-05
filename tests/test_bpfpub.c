// SPDX-License-Identifier: GPL-2.0
/* test_bpfpub.c —— 域名哈希与 BPF 表结构的宿主测试（发布路径是内核态，宿主退化为桩）。 */
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "kdg_bpfpub.h"

static int fails;
#define CHECK(c) do { if (!(c)) { printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

int main(void)
{
	/* FNV-1a 64 的已知值：对 "" 是 offset basis；对 "a" 有标准值 */
	CHECK(kdg_bpf_domain_hash((const u8 *)"", 0) == 0xcbf29ce484222325ULL);
	CHECK(kdg_bpf_domain_hash((const u8 *)"a", 1) == 0xaf63dc4c8601ec8cULL);
	CHECK(kdg_bpf_domain_hash((const u8 *)"foobar", 6) == 0x85944171f73967e8ULL);

	/* 大小写不敏感：这是"规则域名算同一个哈希"的前提 */
	CHECK(kdg_bpf_domain_hash((const u8 *)"Example.COM", 11) ==
	      kdg_bpf_domain_hash((const u8 *)"example.com", 11));

	/* key/value 布局：用户空间按同一布局建表，大小不符时挂接必须被拒 */
	CHECK(sizeof(struct kdg_bpf_key) == 20);
	CHECK(sizeof(struct kdg_bpf_val) == 16);
	CHECK(kdg_bpfpub_key_size() == 20 && kdg_bpfpub_val_size() == 16);

	/* 宿主下发布不落地 */
	CHECK(!kdg_bpfpub_active());
	CHECK(kdg_bpfpub_published() == 0);
	kdg_bpfpub_publish(KDG_BPF_AF_INET, (const u8 *)"\x01\x02\x03\x04", 4,
			   123, 1000, KDG_BPF_F_UPSTREAM);
	CHECK(kdg_bpfpub_published() == 0);

	printf("test_bpfpub: %s（失败 %d）\n", fails ? "FAIL" : "PASS", fails);
	return fails ? 1 : 0;
}
