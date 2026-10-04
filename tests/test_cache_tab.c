/* SPDX-License-Identifier: GPL-2.0 */
/* 直接编译内核存储层，覆盖锁外引用与预算失败的交错。 */
#include <stdio.h>
#include "host_kernel.h"
#include "../kernel/kdg_cache_tab.c"

static size_t response(u8 *msg)
{
	const u8 wire[] = {
		0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0,
		1, 'a', 0, 0, 1, 0, 1,
		0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 10, 0, 4,
		192, 0, 2, 1
	};
	memcpy(msg, wire, sizeof(wire));
	return sizeof(wire);
}

int main(void)
{
	struct kdg_cache_key key = { .qname = { 1, 'a', 0 }, .qname_len = 3,
		.qtype = 1, .qclass = 1 };
	struct kdg_cache_tmpl view, replacement;
	struct kdg_cache_stats before, after;
	void *pin, *other;
	u8 msg[64];
	size_t len = response(msg);

	assert(kdg_cache_tab_init() == 0);
	assert(kdg_cache_put(&key, msg, len, 100, 1000) == 0);
	assert(kdg_cache_get(&key, 200, &view, &pin) == 0);
	/* 第二个调用者遇到到期，不能释放第一个调用者还持有的载荷。 */
	assert(kdg_cache_get(&key, 1100, &replacement, &other) == -ESTALE);
	assert(memcmp(view.msg, msg, len) == 0);
	kdg_cache_stats(&after);
	assert(after.entries == 0);
	kdg_cache_unpin(pin);
	assert(kdg_cache_put(&key, msg, len, 2000, 1000) == 0);
	assert(kdg_cache_get(&key, 2001, &view, &pin) == 0);
	/* flush 必须立刻摘索引，同时允许原 pin 正常完成。 */
	kdg_cache_flush(0);
	assert(kdg_cache_get(&key, 2002, &replacement, &other) == -ENOENT);
	assert(memcmp(view.msg, msg, len) == 0);
	kdg_cache_unpin(pin);
	/* 替换被钉住的条目，新查询只能拿到新模板。 */
	assert(kdg_cache_put(&key, msg, len, 3000, 1000) == 0);
	assert(kdg_cache_get(&key, 3001, &view, &pin) == 0);
	msg[len - 1] = 2;
	assert(kdg_cache_put(&key, msg, len, 3002, 1000) == 0);
	assert(kdg_cache_get(&key, 3003, &replacement, &other) == 0);
	assert(view.msg[len - 1] == 1 && replacement.msg[len - 1] == 2);
	kdg_cache_unpin(pin);
	/* 固定预算低于新增载荷，所有候选被 pin：必须拒绝且不越界。 */
	kdg_cache_stats(&before);
	g_cache->mem_max = before.mem_bytes;
	key.qname[1] = 'b';
	assert(kdg_cache_put(&key, msg, len, 3004, 1000) == -ENOSPC);
	kdg_cache_stats(&after);
	assert(after.mem_bytes == before.mem_bytes);
	assert(after.mem_bytes <= after.mem_max_bytes);
	kdg_cache_unpin(other);
	kdg_cache_tab_exit();
	puts("cache_tab: 引用到期 / flush / 替换 / 固定预算回归全部通过");
	return 0;
}
