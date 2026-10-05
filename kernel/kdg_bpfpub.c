// SPDX-License-Identifier: GPL-2.0
/*
 * kdg_bpfpub.c —— 见头文件的说明。本文件是**双态**的：宿主构建（unit test）
 * 下整个实现退化成不落地的桩，因为 bpf_map_get 这类符号在宿主上不存在。
 */
#include "kdg_bpfpub.h"

#ifdef __KERNEL__

#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/bpf.h>
#include <linux/slab.h>

static DEFINE_MUTEX(kdg_bpfpub_mu);
static struct bpf_map *kdg_bpfpub_map;
static u64 kdg_bpfpub_count;
static u64 kdg_bpfpub_dropped;

bool kdg_bpfpub_active(void)
{
	return READ_ONCE(kdg_bpfpub_map) != NULL;
}

u64 kdg_bpfpub_published(void)
{
	return READ_ONCE(kdg_bpfpub_count);
}

u32 kdg_bpfpub_key_size(void)
{
	return sizeof(struct kdg_bpf_key);
}

u32 kdg_bpfpub_val_size(void)
{
	return sizeof(struct kdg_bpf_val);
}

u64 kdg_bpf_domain_hash(const u8 *name, size_t len)
{
	u64 h = 0xcbf29ce484222325ULL;	/* FNV offset basis */
	size_t i;

	for (i = 0; i < len; i++) {
		u8 c = name[i];

		/* 域名大小写不敏感：统一到小写再哈希，否则 "Example.COM" 与
		 * "example.com" 会落到两个不同的哈希上。 */
		if (c >= 'A' && c <= 'Z')
			c = (u8)(c - 'A' + 'a');
		h ^= c;
		h *= 0x100000001b3ULL;	/* FNV prime */
	}
	return h;
}

int kdg_bpfpub_attach(int fd)
{
	struct bpf_map *map;
	int ret = 0;

	if (fd < 0) {
		kdg_bpfpub_detach();
		return 0;
	}
	/* 按**调用进程**的 fd 表取图 —— 必须在系统调用上下文里调用。 */
	map = bpf_map_get((u32)fd);
	if (IS_ERR(map))
		return PTR_ERR(map);

	/* 表类型与 key/value 大小必须完全对得上：宁可拒绝，也不要往一张布局
	 * 不同的表里写 —— 那会让 eBPF 侧读到错位的字段，且不报错。 */
	if (map->map_type != BPF_MAP_TYPE_HASH &&
	    map->map_type != BPF_MAP_TYPE_LRU_HASH) {
		ret = -EINVAL;
		goto out;
	}
	if (map->key_size != sizeof(struct kdg_bpf_key) ||
	    map->value_size != sizeof(struct kdg_bpf_val)) {
		ret = -EINVAL;
		goto out;
	}

	mutex_lock(&kdg_bpfpub_mu);
	if (kdg_bpfpub_map)
		bpf_map_put(kdg_bpfpub_map);
	kdg_bpfpub_map = map;
	map = NULL;		/* 所有权转移，别在下面 put 掉 */
	mutex_unlock(&kdg_bpfpub_mu);

	pr_info("BPF 发布表已挂接（key %u B / value %u B / type %d）\n",
		kdg_bpfpub_key_size(), kdg_bpfpub_val_size(),
		(int)kdg_bpfpub_map->map_type);
	return 0;
out:
	bpf_map_put(map);
	return ret;
}

void kdg_bpfpub_detach(void)
{
	struct bpf_map *map;

	mutex_lock(&kdg_bpfpub_mu);
	map = kdg_bpfpub_map;
	kdg_bpfpub_map = NULL;
	mutex_unlock(&kdg_bpfpub_mu);
	if (map)
		bpf_map_put(map);
}

void kdg_bpfpub_publish(u32 family, const u8 *addr, size_t addr_len,
			u64 domain_hash, u32 ttl_ms, u32 flags)
{
	struct kdg_bpf_key key;
	struct kdg_bpf_val val;
	struct bpf_map *map;
	int ret;

	if (!addr || (addr_len != 4 && addr_len != 16))
		return;
	map = READ_ONCE(kdg_bpfpub_map);
	if (!map)
		return;

	memset(&key, 0, sizeof(key));
	key.family = family;
	memcpy(key.addr, addr, addr_len);
	val.domain_hash = domain_hash;
	val.ttl_ms = ttl_ms;
	val.flags = flags | (family == KDG_BPF_AF_INET6 ? KDG_BPF_F_INET6 : 0);

	/* 直接走图自己的 update 回调：内核没有导出面向驱动的更新入口
	 * （bpf_map_update_value 是 static）。这里是常规的、带 kCFI 类型检查
	 * 的间接调用，不是「对 libc 取地址」那一类。 */
	ret = map->ops->map_update_elem(map, &key, &val, BPF_ANY);
	if (ret)
		WRITE_ONCE(kdg_bpfpub_dropped, kdg_bpfpub_dropped + 1);
	else
		WRITE_ONCE(kdg_bpfpub_count, kdg_bpfpub_count + 1);
}

#else /* 宿主构建：只保留哈希（可测），发布不落地 */

#include <errno.h>

u64 kdg_bpf_domain_hash(const u8 *name, size_t len)
{
	u64 h = 0xcbf29ce484222325ULL;
	size_t i;

	for (i = 0; i < len; i++) {
		u8 c = name[i];

		if (c >= 'A' && c <= 'Z')
			c = (u8)(c - 'A' + 'a');
		h ^= c;
		h *= 0x100000001b3ULL;
	}
	return h;
}

int kdg_bpfpub_attach(int fd) { (void)fd; return -EOPNOTSUPP; }
void kdg_bpfpub_detach(void) { }
bool kdg_bpfpub_active(void) { return false; }
u64 kdg_bpfpub_published(void) { return 0; }
u32 kdg_bpfpub_key_size(void) { return sizeof(struct kdg_bpf_key); }
u32 kdg_bpfpub_val_size(void) { return sizeof(struct kdg_bpf_val); }
void kdg_bpfpub_publish(u32 family, const u8 *addr, size_t addr_len,
			u64 domain_hash, u32 ttl_ms, u32 flags)
{
	(void)family; (void)addr; (void)addr_len;
	(void)domain_hash; (void)ttl_ms; (void)flags;
}

#endif /* __KERNEL__ */
