/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg.h —— kdnsguard 内核侧内部头（不对用户空间暴露）。
 *
 * 本文件只放模块内部共享的东西：per-netns 状态、全局开关、诊断计数。
 * UAPI 一律走 <uapi/kdnsguard.h>，不在这里重复定义。
 */
#ifndef _KDG_H
#define _KDG_H

#include <linux/types.h>
#include <linux/net.h>
#include <linux/atomic.h>

#include "uapi/kdnsguard.h"
#include "kdg_listener.h"
#include "kdg_map.h"

#define KDG_MOD_NAME		"kdnsguard"
#define KDG_MOD_DESC		"Global kernel-space DNS takeover (DoH upstream)"

/* ⚠️ 各 .c 文件的 pr_fmt 必须写 KBUILD_MODNAME（由 kbuild 用 -D 预定义，
 * 任何 include 之前就存在），**不要**写 KDG_MOD_NAME：本头文件的 include
 * 时机排在 linux/module.h 之后，而后者链条里的 gfp.h/ratelimit.h 已经在用
 * pr_warn()，那时 KDG_MOD_NAME 尚未定义，展开成「标识符后跟字符串字面量」
 * 的语法错误，且报错位置落在内核头里，极具误导性。KDG_MOD_NAME 只用于
 * 描述性文本。 */

/* 内核默认查询 deadline（毫秒）。方案 §7.4 建议初值 3 秒。 */
#define KDG_DEFAULT_DEADLINE_MS	3000

/* 本地监听端口。方案 §5.2 的候选是 127.0.0.1:1054 —— 选 1054 而不是 53，
 * 是为了避开任何可能存在的用户态 DNS 监听者，也便于用 ss 一眼分辨。 */
#define KDG_DEFAULT_LISTEN_PORT	1054

/* 上游 bootstrap 端点（方案 §6.1）。首版编入设备配置，不做运行时下发；
 * 后续变更必须经受授权的系统调用方通过事务接口提交。 */
#define KDG_BOOTSTRAP_IPV4	"49.234.186.103"
#define KDG_UPSTREAM_HOST	"d6382545.6.00p.net"
#define KDG_UPSTREAM_PATH	"/gd/h596382545"
#define KDG_UPSTREAM_PORT	443

/* 客户端入口（热点 / USB 共享 / AP）接口名长度。刻意写死 16 而不是引
 * <linux/netdevice.h> 的 IFNAMSIZ：本头被每个 .c 包含，为两个常量把
 * netdevice.h 整条 include 链拖进来不划算。kdg_listener.c 里有 static_assert
 * 钉住它与 IFNAMSIZ 相等。 */
#define KDG_IFNAME_LEN		16U

/* 同时维持 listener 的客户端入口接口数上限。热点通常只有一个入口（rndis0
 * 或 wlan1），给 4 是防御性上界 —— 每个入口 4 个 socket + 4 个 kthread，
 * 上界必须存在，否则「接口抖动 + 名字不断变」能无限吃线程。 */
#define KDG_MAX_CLIENT_IF	4

/* 一个已绑定的客户端入口。**只有真正绑定成功的接口才会进这张表**，NAT hook
 * 也**只**按这张表判定 PREROUTING 是否接管 —— 这样「还没建好 listener 就
 * 先接管」的窗口在构造上不存在（那会把热点客户端的 DNS 打进黑洞）。
 *
 * 地址存成裸字节而不是 struct in6_addr：本头不必为 16 个字节把 linux/in6.h
 * 拖进来。socket/task 指针只由 kdg_listener.c 读写。 */
struct kdg_client_iface {
	char name[KDG_IFNAME_LEN];
	bool listener_up;
	__be32 addr4;
	/* 写成 __be32[4] 而不是 u8[16]：ipv6_addr_type() 会按 s6_addr32 读，
	 * 4 字节对齐是它的事实前提。声明成 __be32 数组后对齐由类型保证。 */
	__be32 addr6[4];
	bool has4;
	bool has6;
	struct socket *udp4, *tcp4, *udp6, *tcp6;
	struct task_struct *udp4_task, *tcp4_task, *udp6_task, *tcp6_task;
};

/* ── NAT 观察计数（per-netns） ────────────────────────────────────────── */
struct kdg_nat_stats {
	atomic64_t hook_calls;	/* hook 被调用的**总次数**（任何报文，任何协议） */
	atomic64_t seen;	/* 其中判定为明文 DNS 查询（目的端口 53）的 */
	atomic64_t redirected;	/* 真正调用了 redirect 的 */
	atomic64_t bypassed;	/* 命中但按策略放行的 */
	atomic64_t dropped;
	atomic64_t debug_printed;	/* 已打印的诊断条数（debug 参数用） */
	atomic64_t fwd_seen;	/* 其中 PREROUTING（转发/共享网络）路径的 */
	atomic64_t fwd_bypassed;	/* 转发了但入口接口不在客户端入口表里 */
	atomic64_t sport53;	/* 源端口是 53 的新连接（**不**接管，仅计数） */
};

/* ── per-netns 状态 ───────────────────────────────────────────────────── */
struct kdg_netns {
	struct kdg_nat_stats nat;
	bool nat_registered_v4;
	bool nat_registered_v6;
	bool degraded;		/* 注册失败过；GET_HEALTH 如实上报 */
	/* 域名 -> IP 映射表、缓存、在途表在后续阶段加入，此处留位。 */
};

/* 全局（所有 netns 共享）只读配置。写路径必须经受权的事务接口，
 * 见方案 §14.1；本阶段先由模块参数提供，仅用于开发验证。 */
/* 前置声明：本头只用到指针，不必把 net_namespace.h / netdevice.h 的整条
 * include 链拖进每个 .c（那会显著放大编译依赖面）。 */
struct net;
struct net_device;

struct kdg_config_snapshot {
	u32 generation;
	u64 transaction_id;
	u32 ownership;
	u32 net_id;
	u32 ifindex;
	u64 network_epoch;
	u8 private_dns_mode;
	bool intercept_enabled;
	u16 listen_port;
	u32 default_deadline_ms;
};

extern struct kdg_config_snapshot kdg_cfg;

/* debug 开关（模块参数，默认关）。开启后 NAT hook 会为最早的若干次调用
 * 打印 pf/协议/端口，用于定位「hook 挂了但谓词不匹配」这类问题。 */
extern bool kdg_debug;

/* kdg_main.c */
int kdg_netns_id(void);
struct kdg_netns *kdg_netns_of(struct net *net);

/* kdg_nat.c */
int kdg_nat_register(struct net *net);
void kdg_nat_unregister(struct net *net);
u32 kdg_nat_capability_bits(void);

/*
 * 一个 IPv6 地址是否**全局** scope（参数是 16 字节裸地址）。
 *
 * ⚠️ 这里有个极易写错的约定，本函数存在的唯一理由就是把它集中到一处：
 * `__ipv6_addr_type()` 把 scope 编码在 bit16+（`IPV6_ADDR_SCOPE_TYPE(s) =
 * s << 16`），而 `ipv6_addr_type()` 只保留低 16 位 —— 于是**低字节里的
 * 0x00f0 区间承载的是「非全局」的类别位**（loopback 0x10 / link-local
 * 0x20 / site-local 0x40 / compatv4 0x80），全局单播恰好一位都不占。
 * 也就是说 **「与 IPV6_ADDR_SCOPE_MASK 相与为 0」才等价于「全局」**。
 *
 * `IPV6_ADDR_SCOPE_GLOBAL`(0x0e) 属于另一套编码，只能与
 * `ipv6_addr_src_scope()`（即 `__ipv6_addr_type() >> 16`）的结果比较，
 * **拿它去和 `ipv6_addr_type() & IPV6_ADDR_SCOPE_MASK` 比永远不相等**，
 * 会把所有全局地址都误判成非全局（最初就踩了这个坑：客户端入口的 IPv6
 * listener 一个都建不起来，日志上表现为「IPv4-only」，不容易当场看出）。
 * 参照 net/netfilter/nf_nat_redirect.c:nf_nat_redirect_ipv6_usable()，它
 * 也是用 `if (scope) {...}` 这个形式，即 scope==0 才是全局。
 */
bool kdg_v6_addr_is_global(const u8 *addr16);

/* kdg_listener.c */
int kdg_listener_prepare(void);
void kdg_listener_stop(void);
bool kdg_listener_ready(void);

/* 客户端入口表。NAT hook 在 PREROUTING 上按**名字**查它；只在 listener 真正
 * 绑定成功后才有条目，因此查询即为「可以安全改写到该接口地址」的判据。
 * hook 跑在 RCU 读侧、不可睡眠，故只做名字比较，不取 `struct net_device *`
 * 引用（那需要 dev_hold 与配套释放，收益为零）。
 *
 * 返回值是**按地址族**的能力位：bit0=该接口已绑 IPv4 listener，
 * bit1=已绑 IPv6 listener。必须分族，因为 nf_nat_redirect_* 在两个族下选
 * 地址的规则不同 —— IPv6 会按目的地址的 scope 挑地址，我们只绑了全局地址，
 * 若把一个链路本地目的地址也改写到该接口，那个端口上没人听，客户端 DNS
 * 会直接被打进黑洞。 */
#define KDG_CLI_CAP_V4		(1U << 0)
#define KDG_CLI_CAP_V6		(1U << 1)

extern struct kdg_client_iface kdg_client_ifaces[KDG_MAX_CLIENT_IF];
u32 kdg_listener_client_caps(struct net *net, const struct net_device *dev);

/* kdg_genl.c */
int kdg_genl_init(void);
void kdg_genl_exit(void);

/* kdg_mbedtls.c —— mbedTLS 平台适配层 */
int kdg_mbedtls_init(void);

/* kdg_tls.c —— 内核态 TLS 客户端 */
int kdg_tls_global_init(void);
void kdg_tls_global_exit(void);

/* kdg_psa_probe.c —— PSA 直探针（排障用，定位后可整体删除） */
void kdg_psa_probe(void);

/* kdg_cache_tab.c —— DNS 缓存存储层 */
int kdg_cache_tab_init(void);
void kdg_cache_tab_exit(void);

/* kdg_sflight.c —— 同名查询合并 */
int kdg_sflight_init(void);
void kdg_sflight_exit(void);

/* kdg_quota.c —— 每调用方配额 */
int kdg_quota_init(void);
void kdg_quota_exit(void);

/* kdg_chardev.c —— 查询面 /dev/kdnsguard */
int kdg_chardev_init(void);
void kdg_chardev_exit(void);

#endif /* _KDG_H */
