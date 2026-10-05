/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_bpfpub.h —— 把内核解析出的「地址 → 域名哈希」发布到用户空间提供的
 * BPF 哈希表里，供 eBPF 在包路径上直接匹配（不发起任何系统调用）。
 *
 * 为什么方向是「用户空间建表、内核填表」而不是「内核建表」：
 * 本内核是 6.6，**没有**内核内建图创建接口（bpf_map_create 是后来的版本才有），
 * 所以表只能由用户空间建好后把 fd 交过来。取 fd 用的是 bpf_map_get(ufd)，
 * 它按**当前进程**的 fd 表解析 —— 因此这一步必须发生在系统调用上下文里
 * （genl doit 正是这种上下文），不能放到池线程去做。
 *
 * 表结构（key/value 大小必须完全一致，否则挂接被拒，而不是「尽力而为」）：
 *   key   = struct kdg_bpf_key   （family + 16 字节地址）
 *   value = struct kdg_bpf_val   （域名哈希 + TTL + 标志）
 * 域名哈希用 FNV-1a 64 对小写、未压缩的 qname wire 形式计算 —— 用户空间
 * 要对规则域名算同一个哈希来匹配，所以算法必须写死在这里并且不随版本变。
 *
 * 内建形态（CONFIG_KDNSGUARD=y）下本功能可用；树外 LKM 形态下同样可用
 * （bpf_map_get/bpf_map_put 都是导出符号），但发布路径依赖内建时才有的
 * 目标文件，故按 CONFIG 收口。
 */
#ifndef _KDG_BPFPUB_H
#define _KDG_BPFPUB_H

#include "kdg_base.h"

#define KDG_BPF_ADDR_MAX	16
#define KDG_BPF_DOMAIN_MAX	255	/* 单标签 63 × 若干 + 根；够 DoH 用 */

/* 地址族常量：与内核 AF_INET/AF_INET6 取值一致，这里写死是为了让本文件
 * 在宿主（无 socket.h）与内核两种构建下都能用同一套常量。 */
#define KDG_BPF_AF_INET		2
#define KDG_BPF_AF_INET6	10

/* 标志位 */
#define KDG_BPF_F_UPSTREAM	(1u << 0)	/* 来自上游解析（非缓存命中） */
#define KDG_BPF_F_INET6		(1u << 1)	/* 地址是 IPv6 */

struct kdg_bpf_key {
	u32 family;			/* AF_INET / AF_INET6 */
	u8  addr[KDG_BPF_ADDR_MAX];
} __packed;

struct kdg_bpf_val {
	u64 domain_hash;		/* FNV-1a 64 */
	u32 ttl_ms;
	u32 flags;
} __packed;

/* FNV-1a 64：对**小写化**后的域名 wire 形式逐字节计算。 */
u64 kdg_bpf_domain_hash(const u8 *name, size_t len);

/*
 * 挂接/解绑。fd 来自调用者（-1 表示解绑）。
 * 成功返回 0；表类型或 key/value 大小不符返回 -EINVAL（不静默接受）。
 */
int kdg_bpfpub_attach(int fd);
void kdg_bpfpub_detach(void);
bool kdg_bpfpub_active(void);
u64 kdg_bpfpub_published(void);
u32 kdg_bpfpub_key_size(void);
u32 kdg_bpfpub_val_size(void);

/* 发布一条。family 用 AF_INET/AF_INET6；addr_len 为 4 或 16。无返回值：
 * 发布是旁路，失败只计数，绝不影响 DNS 应答本身。 */
void kdg_bpfpub_publish(u32 family, const u8 *addr, size_t addr_len,
			u64 domain_hash, u32 ttl_ms, u32 flags);

#endif
