/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_transport.h —— 上游 DoH 传输层的**接口**（实现留待 P1/P2）。
 *
 * 本文件存在的意义是把「内核 TLS 用什么库」这个决策**隔离在一处**，
 * 使得其余模块（缓存、合并、NAT、UAPI）不被它绑死。
 *
 * 决策背景（2026-10-03 核实，务必保留）：
 *   方案原文选 wolfSSL linuxkm。但 wolfSSL 的 LICENSING 给出的 GPLv2 例外
 *   是一份**封闭清单**（MariaDB、OpenVPN、U-Boot(Cisco) 等），**不含 Linux
 *   内核**；而 Linux 内核是 GPLv2-only、与 GPLv3 不兼容。也就是说在没有
 *   商业许可的前提下，wolfSSL 路线在**发布层面**走不通，不是技术问题。
 *   经用户裁决改用 **mbedTLS**：其 README 声明为
 *   "Apache-2.0 OR GPL-2.0-or-later" 双许可，按 GPL-2.0 使用与内核相容。
 *
 *   代价是 mbedTLS 没有现成的内核移植层（wolfSSL 的 linuxkm 正是那一层），
 *   P1 必须自己写：内存分配、时间源、熵源、threading alt、以及这里的
 *   send/recv 回调接到 kernel_sendmsg/kernel_recvmsg。
 *
 * 传输层实现的硬性契约（来自方案 §6.2 / §6.3 / §9.3）：
 *   1. 握手与 I/O 只能在**可睡眠的内核线程**上驱动。绝不允许在 Netfilter
 *      hook、spinlock、RCU 读侧临界区或关中断区调用本接口的任何函数。
 *   2. 证书验证不可关闭：完整链校验 + hostname 校验 + 有效期检查，且依赖
 *      可靠的系统时间。不得因为「直连 IP」而省略 SNI。
 *   3. 单一执行者驱动一个 TLS 对象，并发客户端通过请求队列进入 ——
 *      绝不让两个 worker 同时操作同一份 TLS 状态。
 *   4. ALPN 必须提供 h2 与 http/1.1。首期禁用 TLS 0-RTT。
 *   5. 所有受网络输入控制的缓冲走**有界堆分配**（64 KiB 级缓冲不得放内核栈），
 *      分配失败是正常错误路径。
 *   6. 失败即失败：上游不可达时返回错误，**绝不**回落明文 53（方案 §18）。
 */
#ifndef _KDG_TRANSPORT_H
#define _KDG_TRANSPORT_H

#include "kdg_base.h"

/* 单次查询的 wire 上限。与 UAPI 的 KDG_MAX_WIRE_MSG 一致。 */
#define KDG_UPSTREAM_MAX_WIRE	4096

/* 主机名与路径的上限。与 UAPI 的 KDG_MAX_TEXT 一致，两处数字必须一起改；
 * 这里独立定义是为了让本头文件不必依赖完整的 UAPI。 */
#define KDG_MAX_TEXT_SHORT	256

struct kdg_upstream;

/*
 * 传输实现的能力位。与 UAPI 的 KDG_CAP_DOH_* 一一对应，由实现如实申报，
 * 内核据其决定 CAPS 回包里置哪些位 —— 不得凭空置位。
 */
enum kdg_transport_kind {
	KDG_TRANSPORT_NONE	= 0,
	KDG_TRANSPORT_H1	= 1,	/* 先导与兼容路径（方案 §6.4） */
	KDG_TRANSPORT_H2	= 2,	/* 主线发布目标（方案 §6.3） */
	KDG_TRANSPORT_H3	= 3,	/* 实验阶段，验收前不得启用（§6.5） */
};

/*
 * 上游 profile：一次已提交的端点配置。对应方案 §6.1 的固定端点描述。
 * hostname/path 由 PREPARE_PROFILE 事务写入，不是编译期常量 ——
 * 这里给出默认值只是为了首版能直接跑通。
 */
struct kdg_upstream_profile {
	u32 generation;			/* 与全局 generation 对齐 */
	enum kdg_transport_kind kind;
	char hostname[KDG_MAX_TEXT_SHORT];	/* SNI 与 hostname 校验用 */
	char path[KDG_MAX_TEXT_SHORT];
	u8  bootstrap_ip[16];		/* 4（v4）或 16（v6）字节 */
	u8  bootstrap_ip_len;
	u16 port;
	bool allow_tls12;		/* 首版为 false，只走 TLS 1.3 */
};

/*
 * 传输操作表。所有函数在**可睡眠上下文**调用，可以阻塞、可以分配内存。
 *
 * 生命周期：open() 成功后才能 query()；close() 必须能对未 open 成功的
 * 对象安全调用（幂等）。实现者负责在 close() 里释放全部资源，并保证
 * 此后不再有任何回调进入。
 */
struct kdg_transport_ops {
	const char *name;
	enum kdg_transport_kind kind;

	/* 建立连接（含 TLS 握手与证书验证）。返回 0 或负 errno。 */
	int  (*open)(struct kdg_upstream *up);

	/* 关闭连接并释放资源。幂等，不得失败。 */
	void (*close)(struct kdg_upstream *up);

	/* 在已建立的连接上完成一次 DoH 查询。
	 * 入参与出参都用 DNS wire 格式；*resp_len 传入缓冲容量、返回实际长度。
	 * 返回 0 或负 errno（-ETIMEDOUT / -EBADMSG / -ECONNRESET ...）。 */
	int  (*query)(struct kdg_upstream *up,
		      const u8 *query, size_t query_len,
		      u8 *resp, size_t *resp_len);

	/* 连接是否仍然可用（不发起任何网络 I/O，只看本地状态）。 */
	bool (*is_live)(const struct kdg_upstream *up);
};

struct kdg_upstream {
	const struct kdg_transport_ops *ops;
	struct kdg_upstream_profile profile;
	/* 实现的私有状态。内核不解释，只透传。 */
	void *priv;
	/* 统计：仅计数，不含域名或 URI（方案 §14.1 的输出纪律）。 */
	u64 queries, failures, reconnects;
};

#endif /* _KDG_TRANSPORT_H */
