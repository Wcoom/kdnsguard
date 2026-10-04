/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdnsguard UAPI v1 —— 全内核 DNS 接管项目的用户空间接口。
 *
 * 设计纪律（对应方案 §14）：
 *  1. 这是**拟新增** UAPI，不是现有系统调用。落进内核 include/uapi 前，
 *     结构、字节序与兼容规则必须在本文件内冻结。
 *  2. 所有多字节字段为主机字节序（内核本地 ABI 惯例），宽度用固定类型，
 *     不用 __attribute__((packed))：ARM64 上非对齐访问有代价，改用**显式
 *     保留字段**把结构体钉成确定布局（每次加字段只能加在尾部保留区）。
 *  3. 上游路径含账户标识。stats 与普通日志**不得**输出完整 URI 或查询域名。
 *  4. 查询面（字符设备）与管理面（Generic Netlink）分离：管理面不承载
 *     高频 DNS 正文。
 */
#ifndef _UAPI_KDNSGUARD_H
#define _UAPI_KDNSGUARD_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <linux/types.h>	/* 宿主态由 tests/Makefile 提供替身头 */
#endif

/* ── ABI 版本 ────────────────────────────────────────────────────────────
 * 任何结构布局或语义变更都必须递增，且内核侧对未知版本一律显式拒绝
 * （KDG_ST_EABI），不做尽力而为的解析。
 */
#define KDG_ABI_VERSION		1

/* ── 通用上限 ────────────────────────────────────────────────────────────
 * KDG_MAX_WIRE_MSG 是首版单条 DNS 报文的硬上限。TCP 上 DNS 理论可达
 * 65535，但首版字符设备接口按方案 §14.2「不做共享内存 mmap 环形队列」，
 * 走 write/read 拷贝，4096 是一次 syscall 的合理界；超出返回
 * KDG_ST_EMSGSIZE 而不是截断。
 */
#define KDG_MAX_WIRE_MSG	4096
/* 查询面字符串（如 profile hostname / path）的最大字节数，含结尾 NUL。 */
#define KDG_MAX_TEXT		256

/* ── 管理面：Generic Netlink ──────────────────────────────────────────── */
#define KDG_GENL_NAME		"KDNSGUARD"
#define KDG_GENL_VERSION	1

enum kdg_genl_cmd {
	KDG_CMD_UNSPEC,
	KDG_CMD_CAPS,			/* 能力位：H1/H2/H3、双栈、映射、限额 */
	KDG_CMD_PREPARE_PROFILE,	/* 建立候选 profile，**不**抢占现有流量 */
	KDG_CMD_COMMIT_PROFILE,		/* 原子切换；旧在途按旧 generation 完成 */
	KDG_CMD_SET_NETWORK,		/* netId/iface/经验证路由信息/epoch */
	KDG_CMD_SET_PRIVATE_DNS_STATE,	/* 平台状态桥；不假报验证成功 */
	KDG_CMD_ENABLE_INTERCEPT,	/* 按 readiness 与所有权 generation 接管 */
	KDG_CMD_DISABLE_INTERCEPT,	/* 故障关闭或明确恢复原链路 */
	KDG_CMD_FLUSH_CACHE,
	KDG_CMD_RESET_TRANSPORT,
	KDG_CMD_GET_STATS,
	KDG_CMD_GET_HEALTH,
	/* 追加于尾部（尾部追加不破坏既有 ABI）。加载上游信任锚：
	 * 方案 §6.2「CA/证书验证材料通过受保护的初始化接口加载进内核」。
	 * 追加语义 —— 可以分批喂入根证书与中间证书。 */
	KDG_CMD_SET_TRUST,
	__KDG_CMD_MAX,
};
#define KDG_CMD_MAX (__KDG_CMD_MAX - 1)

enum kdg_genl_attr {
	KDG_A_UNSPEC,
	KDG_A_ABI_VERSION,		/* u16 */
	KDG_A_TRANSACTION_ID,		/* u64 */
	KDG_A_EXPECTED_GENERATION,	/* u32 */
	KDG_A_GENERATION,		/* u32 —— 输出 */
	KDG_A_NETID,			/* u32 */
	KDG_A_IFINDEX,			/* u32 */
	KDG_A_EPOCH,			/* u64 —— 网络 epoch，切换即变 */
	KDG_A_NETWORK_HANDLE,		/* u32 —— 内核签发的网络句柄 */
	KDG_A_CAPABILITY_BITS,		/* u32 —— CAPS 输出 */
	KDG_A_HOSTNAME,			/* NUL 结尾，≤ KDG_MAX_TEXT */
	KDG_A_PATH,			/* NUL 结尾，≤ KDG_MAX_TEXT */
	KDG_A_BOOTSTRAP_IP,		/* 4 或 16 字节裸地址 */
	KDG_A_TRUST_MATERIAL,		/* DER 或 PEM 的信任锚 */
	KDG_A_PRIVATE_DNS_MODE,		/* u8：见 enum kdg_private_dns_mode */
	KDG_A_READINESS,		/* u8：0=未就绪 1=就绪 */
	KDG_A_STATS,			/* 嵌套：见 kdg_stats_v1 */
	KDG_A_HEALTH,			/* 嵌套：见 kdg_health_v1 */
	KDG_A_ERRNO,			/* s32 —— 明确 errno，不用字符串 */
	/* 追加于尾部。SET_TRUST 的响应：本次成功加载的证书张数 / 累计张数。 */
	KDG_A_CA_ADDED,			/* u32 */
	KDG_A_CA_TOTAL,			/* u32 */
	/* P3 ownership transaction attributes, appended for ABI compatibility. */
	KDG_A_TRANSACTION_STATE,	/* u32: enum kdg_ownership */
	KDG_A_UPSTREAM_OK,		/* u8 */
	__KDG_A_MAX,
};
#define KDG_A_MAX (__KDG_A_MAX - 1)

/* KDG_A_HEALTH 的嵌套子属性。与 struct kdg_health_v1 表达同一组事实，
 * 但走 netlink 属性而非定长结构——两条通路各自自洽，不互相复制布局。 */
enum kdg_health_attr {
	KDG_HA_UNSPEC,
	KDG_HA_OWNERSHIP,		/* u32：enum kdg_ownership */
	KDG_HA_UPSTREAM_OK,		/* u8 */
	KDG_HA_CONSECUTIVE_FAILURES,	/* u32 */
	KDG_HA_BACKOFF_UNTIL_MS,	/* u32，0 表示未退避 */
	KDG_HA_LAST_ERRNO,		/* s32，0 表示无 */
	KDG_HA_NAT_SEEN,		/* u64：观察到的 53 端口报文数 */
	KDG_HA_NAT_REDIRECTED,		/* u64：实际改写的 */
	KDG_HA_NAT_BYPASSED,		/* u64：命中但按策略放行的 */
	/* 追加于尾部（尾部追加不破坏既有 ABI）。hook_calls - seen 就是
	 * 「进来了但没被判为 DNS」的量，是区分「hook 没挂上」与
	 * 「挂上了但判定错」的关键诊断量。 */
	KDG_HA_NAT_HOOK_CALLS,		/* u64：hook 被调用的总次数 */
	KDG_HA_CA_COUNT,		/* u32：已加载的信任锚张数 */
	KDG_HA_DOH_QUERIES,		/* u64：DoH 查询总数 */
	KDG_HA_DOH_OK,			/* u64：成功数 */
	KDG_HA_DOH_LAST_STATUS,		/* u32：最近一次 HTTP 状态码 */
	KDG_HA_DOH_LAST_RTT_MS,		/* u32：最近一次往返毫秒 */
	/* 缓存与编排统计（P2）。 */
	KDG_HA_CACHE_HITS,		/* u64 */
	KDG_HA_CACHE_MISSES,		/* u64 */
	KDG_HA_CACHE_STALE,		/* u64：命中但已过期而摘除 */
	KDG_HA_CACHE_EVICTIONS,		/* u64 */
	KDG_HA_CACHE_ENTRIES,		/* u32：当前有效条目 */
	KDG_HA_CACHE_MEM_BYTES,		/* u32：当前核算占用 */
	KDG_HA_RESOLVE_CACHE,		/* u64：由缓存满足的解析次数 */
	KDG_HA_RESOLVE_UPSTREAM,	/* u64：真正走上游的次数 */
	KDG_HA_RESOLVE_JOINED,		/* u64：搭车（同名合并）满足的解析次数 */
	KDG_HA_RESOLVE_CACHE_PUT,	/* u64：成功写入缓存的次数 */
	KDG_HA_SF_INFLIGHT,		/* u32：当前在途合并项 */
	KDG_HA_SF_WAITERS,		/* u32：当前挂载的 waiter */
	KDG_HA_SF_REJECTED,		/* u64：因上限被拒的合并 */
	KDG_HA_QUOTA_ALLOWED,		/* u64 */
	KDG_HA_QUOTA_DENIED,		/* u64：超额被拒 */
	KDG_HA_QUOTA_BUCKETS,		/* u32：已用的配额桶数 */
	/* HTTP/2（nghttp2）统计。 */
	KDG_HA_H2_SESSIONS,		/* u64 */
	KDG_HA_H2_REQUESTS,		/* u64 */
	KDG_HA_H2_OK,			/* u64 */
	KDG_HA_H2_PROTO_ERRORS,		/* u64：nghttp2 层错误 */
	KDG_HA_H2_STREAM_RESETS,	/* u64 */
	/* P3：PREROUTING（热点 / USB 共享 / AP 客户端）路径的独立计数。
	 * 与 LOCAL_OUT 分开计数是必要的：fwd_seen - seen 能立刻区分
	 * 「客户端流量根本没到 hook」与「到了但被入口白名单挡掉」。 */
	KDG_HA_NAT_FWD_SEEN,		/* u64：来源为转发路径且目的端口 53 */
	KDG_HA_NAT_FWD_BYPASSED,	/* u64：其中因入接口不在白名单/无 listener 放行 */
	KDG_HA_NAT_SPORT53,		/* u64：**新**连接的源端口 53（只计数，不接管）*/
	KDG_HA_CLIENT_IFACES,		/* u32：已建 listener 的客户端入口数 */
	KDG_HA_LISTENER_READY,		/* u8：loopback listener 是否就绪 */
	/* P4 第一步：IP ↔ 域名 关联表（方案 §12.2）。 */
	KDG_HA_MAP_ENTRIES,		/* u32：当前有效关联数 */
	KDG_HA_MAP_HITS,		/* u64 */
	KDG_HA_MAP_MISSES,		/* u64 */
	KDG_HA_MAP_EVICTIONS,		/* u32 */
	KDG_HA_MAP_REJECTED,		/* u32：超长名 / 歧义集合满 / 无槽位 */
	KDG_HA_MAP_MEM_BYTES,		/* u32 */
	__KDG_HA_MAX,
};
#define KDG_HA_MAX (__KDG_HA_MAX - 1)

/* CAPS 能力位。未置位即表示**不支持**，调用方不得据此推断可用。 */
#define KDG_CAP_IPV4			(1U << 0)
#define KDG_CAP_IPV6			(1U << 1)
#define KDG_CAP_UDP53			(1U << 2)
#define KDG_CAP_TCP53			(1U << 3)
#define KDG_CAP_DOH_H1			(1U << 4)
#define KDG_CAP_DOH_H2			(1U << 5)
#define KDG_CAP_DOH_H3			(1U << 6)	/* 实验；验收前恒为 0 */
#define KDG_CAP_DOMAIN_MAP		(1U << 7)
#define KDG_CAP_NEG_CACHE		(1U << 8)
#define KDG_CAP_FAKEIP			(1U << 9)	/* 首期恒为 0 */

/* 对应 Android Settings 的 private_dns_mode。内核**不**自行推断语义，
 * 只如实上报，避免方案 §10.1 禁止的「设置页报 strict 成功却查了别的账户」。 */
enum kdg_private_dns_mode {
	KDG_PDNS_OFF		= 0,
	KDG_PDNS_AUTOMATIC	= 1,
	KDG_PDNS_STRICT		= 2,
	KDG_PDNS_UNKNOWN	= 255,
};

/* 内核向系统桥报告的所有权状态。§10.1 要求把「已由内核策略接管」显式
 * 反映出去，而不是把 off 当成允许明文泄漏。 */
enum kdg_ownership {
	KDG_OWN_NONE		= 0,	/* 未接管，原链路在工作 */
	KDG_OWN_PREPARED	= 1,	/* 资源已备，尚未切换 */
	KDG_OWN_ACTIVE		= 2,	/* 本项目持有 53 所有权 */
	KDG_OWN_DEGRADED	= 3,	/* 接管中但上游不健康，严格模式返回错误 */
};

struct kdg_stats_v1 {
	__u64 queries_total;
	__u64 cache_hits;
	__u64 inflight_joined;		/* 同名合并命中次数 */
	__u64 upstream_queries;
	__u64 upstream_failures;
	__u64 retries;
	__u64 dropped_quota;		/* 因配额拒绝 */
	__u64 mem_bytes;		/* 当前动态内存占用 */
	__u32 inflight_current;
	__u32 cache_entries;
	__u32 latency_p50_us;
	__u32 latency_p95_us;
	__u32 generation;
	__u32 reserved0;		/* 保留：显式对齐，不可复用直至 ABI 递增 */
};

struct kdg_health_v1 {
	__u32 generation;
	__u32 ownership;		/* enum kdg_ownership */
	__u32 upstream_ok;		/* 最近一次验证是否成功 */
	__u32 consecutive_failures;
	__u32 backoff_until_ms;		/* 0 表示未退避 */
	__u32 last_errno;		/* 最近失败 errno，0 表示无 */
	__u32 reserved0[6];
};

/* ── MAP_LOOKUP 的响应体（方案 §12.2「映射查询接口」）──────────────────
 *
 * 方向只有**反查**：调用方拿一个连接的真实目的 IP 来问「它可能是哪些域名」。
 * 代理手上的输入就是 IP（DNS 挪进内核之后，它不再有 DNS 应答可看），所以
 * 这是它唯一能发起的查询；正查（域名→IP）本期没有消费者，不做。
 *
 * 请求形态不动 `struct kdg_req_v1`：opcode = KDG_OP_MAP_LOOKUP 时，
 * query_wire 就是**裸地址**（4 或 16 字节），query_len 即地址长度。
 * 响应体紧随 `struct kdg_resp_v1`，布局如下。
 */
#define KDG_MAP_MAX_ITEMS	4	/* 单个 IP 最多带回多少个候选域名 */

struct kdg_map_item_v1 {
	__u16 len;		/* 载荷字节数 */
	__u16 kind;		/* 0 = DNS 名（wire，未压缩）；4/16 = 裸地址 */
	__u32 ttl_ms;		/* 该候选还剩多少毫秒可用 */
	/* 载荷紧随其后，按 4 字节对齐补齐 */
};

struct kdg_map_result_v1 {
	__u32 profile_generation;	/* provenance：关联建立时的 profile 代际 */
	__u32 actual_network;		/* 本期恒 0 = init_net */
	__u32 count;			/* 实际带回的 item 数 */
	__u32 truncated;		/* 非 0 = 还有候选未装下，不要当成"就这几个" */
};

/* ── 查询面：受控字符设备 /dev/kdnsguard ──────────────────────────────── */
#define KDG_DEVICE_NAME		"kdnsguard"

enum kdg_ioctl_op {
	KDG_OP_QUERY		= 0,
	KDG_OP_CANCEL		= 1,
	KDG_OP_MAP_LOOKUP	= 2,
	KDG_OP_GET_HEALTH	= 3,
	__KDG_OP_MAX,
};

/* 响应状态。负值区间留给 errno 直通，正值区间是协议自有状态。 */
enum kdg_status {
	KDG_ST_OK		= 0,
	KDG_ST_EABI		= 1,	/* abi_version 不认识 */
	KDG_ST_EOP		= 2,	/* opcode 不认识 */
	KDG_ST_EMSGSIZE		= 3,	/* 长度越界或溢出 */
	KDG_ST_ECOOKIE		= 4,	/* cookie 重复或不属于本上下文 */
	KDG_ST_EGENERATION	= 5,	/* expected_generation 过旧 */
	KDG_ST_EPERM		= 6,	/* 调用方无权使用该 network */
	KDG_ST_ECANCELED	= 7,
	KDG_ST_ETIMEDOUT	= 8,
	KDG_ST_EBADWIRE		= 9,	/* 内核侧 DNS wire 校验失败 */
	KDG_ST_EAGAIN		= 10,	/* 全局队列满，有界拒绝 */
	KDG_ST_EUPSTREAM	= 11,	/* 上游不可达（严格模式不回落） */
};

/* 请求头。query_wire 紧随其后，长度 query_len，按 8 字节对齐补齐。
 * 用 Q_ 后缀强调这是「请求描述」而非完整的领域模型。 */
struct kdg_req_v1 {
	__u16 abi_version;		/* 必须 == KDG_ABI_VERSION */
	__u16 opcode;			/* enum kdg_ioctl_op */
	__u32 total_len;		/* 本次 write 的总字节数（含本头） */
	__u64 request_cookie;		/* 调用方自选，回包原样带回 */
	__u32 expected_generation;	/* 旧 generation 显式拒绝 */
	__u32 requested_network_handle;	/* 0 = 用调用方默认网络 */
	__u32 deadline_ms;		/* 0 = 用内核默认 3000 */
	__u32 query_len;		/* query_wire 字节数 */
	__u32 flags;
	__u32 reserved0;		/* 显式对齐，置 0 */
};

struct kdg_resp_v1 {
	__u16 abi_version;
	__u16 status;			/* enum kdg_status */
	__u32 errno_hint;		/* status 的负 errno 直通，便于调用方映射 */
	__u64 request_cookie;
	__u32 actual_network;		/* 实际使用的 network handle */
	__u32 generation;		/* 回包时的 generation */
	__u32 response_len;
	__u32 reserved0;
	/* response_wire 紧随其后，长度 response_len，按 8 字节对齐补齐。 */
};

/* 调用方凭据决定可用 network。内核**不**信任请求里自报的 UID —— 见方案
 * §7.2 与 §14.2。requested_network_handle 只是一个「申请」，内核按
 * caller 的 Android 网络权限裁决，不满足返回 KDG_ST_EPERM。 */
#define KDG_REQ_FLAG_WANT_NEG_CACHE	(1U << 0)
#define KDG_REQ_FLAG_NO_SHARE		(1U << 1)	/* 禁止在途合并 */
#define KDG_REQ_FLAG_RAW_ID		(1U << 2)	/* 保留调用方 DNS ID，不规范化 */
#define KDG_REQ_FLAG_MASK		(KDG_REQ_FLAG_WANT_NEG_CACHE | \
					 KDG_REQ_FLAG_NO_SHARE | \
					 KDG_REQ_FLAG_RAW_ID)

#endif /* _UAPI_KDNSGUARD_H */
