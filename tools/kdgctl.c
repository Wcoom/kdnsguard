/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdgctl.c —— kdnsguard 诊断客户端（freestanding aarch64 静态二进制）。
 *
 * 为什么是 freestanding：本机没有 aarch64 交叉 libc（aarch64-linux-gnu-gcc
 * 不存在），而设备是 Android/bionic。要在这台机器上产出能在设备上跑的可执行
 * 文件，最省事且零依赖的办法就是用内核树自带的 clang-19 + lld 直接编译一个
 * **不链接任何 libc、只发裸系统调用**的静态 ELF。这样：
 *   - 不依赖 NDK（本机 /opt/android-sdk 已不存在）；
 *   - 不依赖设备上的任何用户态库；
 *   - 二进制几十 KB，push 上去就能跑。
 *
 * 它同时验证了一件事：include/uapi/kdnsguard.h 是**真的能被用户态使用**的
 * —— 头文件写了不等于可用，必须有人真的 include 它并编过。
 *
 * 用法（设备上，需 root）:
 *   kdgctl             —— 探测族 + 打 CAPS
 *   kdgctl health      —— 探测族 + 打 GET_HEALTH
 *   kdgctl maplookup <ip> —— 反查该 IP 关联的域名（方案 §12.2）
 */
typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long  u64;
typedef signed int     s32;
typedef unsigned long  usize;

/* freestanding：没有 stdbool.h / string.h，自己补最小集。
 * 不引入 stdint.h 是因为本机没有 aarch64 交叉 libc，任何 libc 头都不可用。 */
typedef unsigned char  bool_;
typedef unsigned char  kdg_bool;
#define true  1
#define false 0

static void *memset(void *dst, int c, usize n)
{
	u8 *d = dst;
	usize i;

	for (i = 0; i < n; i++)
		d[i] = (u8)c;
	return dst;
}

#include "uapi/kdnsguard.h"

/* ── 裸系统调用 ───────────────────────────────────────────────────────── */

static long sys3(long n, long a, long b, long c)
{
	register long x8 __asm__("x8") = n;
	register long x0 __asm__("x0") = a;
	register long x1 __asm__("x1") = b;
	register long x2 __asm__("x2") = c;

	__asm__ volatile("svc #0"
			 : "+r"(x0)
			 : "r"(x1), "r"(x2), "r"(x8)
			 : "memory", "cc");
	return x0;
}

/* sendto/recvfrom 需要 6 个参数，aarch64 的调用约定用 x0..x5。 */
static long sys6(long n, long a, long b, long c, long d, long e, long f)
{
	register long x8 __asm__("x8") = n;
	register long x0 __asm__("x0") = a;
	register long x1 __asm__("x1") = b;
	register long x2 __asm__("x2") = c;
	register long x3 __asm__("x3") = d;
	register long x4 __asm__("x4") = e;
	register long x5 __asm__("x5") = f;

	__asm__ volatile("svc #0"
			 : "+r"(x0)
			 : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
			 : "memory", "cc");
	return x0;
}

#define SYS_write	64
#define SYS_exit	93
#define SYS_socket	198
#define SYS_bind	200
#define SYS_sendto	206
#define SYS_recvfrom	207
#define SYS_setsockopt	208

/* 给 netlink socket 装上接收超时：处理器若既不回包也不回 ACK，
 * recvfrom 会永久阻塞，诊断工具卡死比报错更难排查。 */
#define SOL_SOCKET_	1
#define SO_RCVTIMEO_	20

struct kdg_timeval {
	long tv_sec;
	long tv_usec;
};

static void set_recv_timeout(int fd, long seconds)
{
	struct kdg_timeval tv = { .tv_sec = seconds, .tv_usec = 0 };

	sys6(SYS_setsockopt, fd, SOL_SOCKET_, SO_RCVTIMEO_, (long)&tv,
	     sizeof(tv), 0);
}

/* ── 最小输出 ─────────────────────────────────────────────────────────── */

static usize slen(const char *s)
{
	usize n = 0;

	while (s[n])
		n++;
	return n;
}

/* freestanding：没有 libc，这两个是最小替身。 */
static void *memcpy_(void *d, const void *s, usize n)
{
	u8 *dd = (u8 *)d;
	const u8 *ss = (const u8 *)s;
	usize i;

	for (i = 0; i < n; i++)
		dd[i] = ss[i];
	return d;
}

static const char *str_chr(const char *s, char c)
{
	for (; *s; s++)
		if (*s == c)
			return s;
	return (const char *)0;
}

static void puts_(const char *s)
{
	sys3(SYS_write, 1, (long)s, (long)slen(s));
}

static void putnum(u64 v)
{
	char buf[24];
	int i = (int)sizeof(buf);

	buf[--i] = '\0';
	if (v == 0)
		buf[--i] = '0';
	while (v) {
		buf[--i] = (char)('0' + (v % 10));
		v /= 10;
	}
	puts_(&buf[i]);
}

/* 64 位版本：puthex 只打 8 个 nibble（历史用法是按 u32 调的）。 */
static void puthex64(u64 v)
{
	static const char hx[] = "0123456789abcdef";
	char buf[20];
	int i;

	buf[0] = '0';
	buf[1] = 'x';
	for (i = 0; i < 16; i++)
		buf[2 + i] = hx[(v >> ((15 - i) * 4)) & 0xf];
	buf[18] = '\0';
	puts_(buf);
}

static void puthex(u64 v)
{
	static const char hx[] = "0123456789abcdef";
	char buf[20];
	int i;

	buf[0] = '0';
	buf[1] = 'x';
	for (i = 0; i < 8; i++)
		buf[2 + i] = hx[(v >> ((7 - i) * 4)) & 0xf];
	buf[10] = '\0';
	puts_(buf);
}

void _start(void);

/* ── netlink 报文构造 ─────────────────────────────────────────────────── */

#define NLA_HDRLEN	4
#define NLA_ALIGN4(x)	(((x) + 3) & ~3u)

struct nlmsghdr {
	u32 nlmsg_len;
	u16 nlmsg_type;
	u16 nlmsg_flags;
	u32 nlmsg_seq;
	u32 nlmsg_pid;
};

struct genlmsghdr {
	u8 cmd;
	u8 version;
	u16 reserved;
};

struct nlattr {
	u16 nla_len;
	u16 nla_type;
};

struct sockaddr_nl {
	u16 nl_family;
	u16 nl_pad;
	u32 nl_pid;
	u32 nl_groups;
};

#define AF_NETLINK_		16
#define SOCK_RAW_		3
#define NETLINK_GENERIC_	16
#define NLM_F_REQUEST_		0x01
/* 必须带 ACK：PREPARE/COMMIT/DISABLE 的处理器只返回错误码、不构造回包，
 * 不带 ACK 时内核一个字节都不回，recvfrom 会永久阻塞（实测踩过）。 */
#define NLM_F_ACK_		0x04
#define GENL_ID_CTRL_		0x10

#define CTRL_CMD_GETFAMILY_	3
#define CTRL_ATTR_FAMILY_ID_	1
#define CTRL_ATTR_FAMILY_NAME_	2
#define CTRL_ATTR_VERSION_	3
#define CTRL_ATTR_OPS_		8

/*
 * 缓冲区必须容纳最大的 TRUST_MATERIAL（内核策略上限 16 KiB）加上报文头。
 * ⚠️ 这里曾写成 1024 字节，而一次 1598 字节的 PEM 就直接越界写 BSS ——
 * 表现为内核侧 PEM 解析失败（MBEDTLS_ERR_X509_INVALID_FORMAT），
 * 看起来像内核 bug 而实际是工具自己坏了。attr_put() 现在做边界检查，
 * 越界会明确报错而不是静默截断。
 */
static u8 txbuf[16 * 1024 + 512];
static u8 rxbuf[8192];

/* 溢出标志：attr_put 越界时置位，调用方据此放弃本次请求。 */
static int g_attr_overflow;

static void attr_put(u16 type, const void *data, usize len)
{
	usize off = ((struct nlmsghdr *)txbuf)->nlmsg_len;
	struct nlattr *a;

	if (off + NLA_ALIGN4(NLA_HDRLEN + len) > sizeof(txbuf)) {
		g_attr_overflow = 1;
		return;
	}
	a = (struct nlattr *)(txbuf + off);
	a->nla_type = type;
	a->nla_len = (u16)(NLA_HDRLEN + len);
	if (len) {
		u8 *p = txbuf + off + NLA_HDRLEN;
		const u8 *s = data;
		usize i;

		for (i = 0; i < len; i++)
			p[i] = s[i];
	}
	/* 尾部对齐到 4，并把补零写进 len —— 内核按 nla_len 取，多出的
	 * 对齐字节不属于任何属性，安全。 */
	((struct nlmsghdr *)txbuf)->nlmsg_len =
		(u32)(off + NLA_ALIGN4(NLA_HDRLEN + len));
}

/* 发一条 genl 请求，返回收到的字节数（<0 为错误）。 */
static long genl_xchg(u16 family, u8 cmd, u8 version)
{
	struct nlmsghdr *nh = (struct nlmsghdr *)txbuf;
	struct genlmsghdr *gh;
	struct sockaddr_nl dst;
	int fd;
	long n;

	nh->nlmsg_len = sizeof(*nh) + sizeof(*gh);
	nh->nlmsg_type = family;
	nh->nlmsg_flags = NLM_F_REQUEST_;
	nh->nlmsg_seq = 1;
	nh->nlmsg_pid = 0;

	gh = (struct genlmsghdr *)(txbuf + sizeof(*nh));
	gh->cmd = cmd;
	gh->version = version;
	gh->reserved = 0;

	fd = (int)sys3(SYS_socket, AF_NETLINK_, SOCK_RAW_, NETLINK_GENERIC_);
	if (fd < 0)
		return fd;

	dst.nl_family = AF_NETLINK_;
	dst.nl_pad = 0;
	dst.nl_pid = 0;		/* 内核 */
	dst.nl_groups = 0;

	if (sys3(SYS_bind, fd, (long)&dst, sizeof(dst)) < 0)
		return -2;

	if (sys6(SYS_sendto, fd, (long)txbuf, nh->nlmsg_len, 0, 0, 0) < 0)
		return -3;

	n = sys6(SYS_recvfrom, fd, (long)rxbuf, sizeof(rxbuf), 0, 0, 0);
	sys3(57 /* close */, fd, 0, 0);
	return n;
}

/* ── 响应解析 ─────────────────────────────────────────────────────────── */

static u16 resolve_family(u16 *version)
{
	struct nlmsghdr *nh = (struct nlmsghdr *)txbuf;
	struct genlmsghdr *gh;
	struct sockaddr_nl dst;
	const char name[] = KDG_GENL_NAME;
	u8 *p;
	u32 rem;
	u16 fam = 0;
	int fd;
	long n;

	nh->nlmsg_len = sizeof(*nh) + sizeof(*gh);
	nh->nlmsg_type = GENL_ID_CTRL_;
	nh->nlmsg_flags = NLM_F_REQUEST_;
	nh->nlmsg_seq = 1;
	nh->nlmsg_pid = 0;

	gh = (struct genlmsghdr *)(txbuf + sizeof(*nh));
	gh->cmd = CTRL_CMD_GETFAMILY_;
	gh->version = 1;
	gh->reserved = 0;
	attr_put(CTRL_ATTR_FAMILY_NAME_, name, sizeof(name));

	fd = (int)sys3(SYS_socket, AF_NETLINK_, SOCK_RAW_, NETLINK_GENERIC_);
	if (fd < 0)
		return 0;
	set_recv_timeout(fd, 5);
	dst.nl_family = AF_NETLINK_;
	dst.nl_pad = 0;
	dst.nl_pid = 0;
	dst.nl_groups = 0;
	if (sys3(SYS_bind, fd, (long)&dst, sizeof(dst)) < 0)
		return 0;
	if (sys6(SYS_sendto, fd, (long)txbuf, nh->nlmsg_len, 0, 0, 0) < 0)
		return 0;
	n = sys6(SYS_recvfrom, fd, (long)rxbuf, sizeof(rxbuf), 0, 0, 0);
	sys3(57, fd, 0, 0);
	if (n <= 0)
		return 0;

	nh = (struct nlmsghdr *)rxbuf;
	gh = (struct genlmsghdr *)(rxbuf + sizeof(*nh));
	p = (u8 *)gh + sizeof(*gh);
	rem = nh->nlmsg_len - (u32)(sizeof(*nh) + sizeof(*gh));

	while (rem >= NLA_HDRLEN) {
		struct nlattr *a = (struct nlattr *)p;
		u16 alen = a->nla_len;
		u16 atype = a->nla_type & 0x3fff;

		if (alen < NLA_HDRLEN || alen > rem)
			break;
		if (atype == CTRL_ATTR_FAMILY_ID_)
			fam = *(u16 *)(p + NLA_HDRLEN);
		else if (atype == CTRL_ATTR_VERSION_)
			*version = *(u8 *)(p + NLA_HDRLEN);
		p += NLA_ALIGN4(alen);
		rem -= NLA_ALIGN4(alen);
	}
	return fam;
}

#define NLA_F_NESTED_		0x8000
#define NLA_TYPE_MASK_		0x3fff

/*
 * GET_HEALTH 的嵌套属性名。没有这张表，回包只能打成「attr 25 len=8
 * 1234567」——数值对，但核对时得反复回查 uapi 头，容易看错行。
 * 名字只用于**本诊断工具**；内核侧不含任何字符串表。
 */
static const char *ha_name(u16 type)
{
	switch (type) {
	case KDG_HA_OWNERSHIP:			return "ownership";
	case KDG_HA_UPSTREAM_OK:		return "upstream_ok";
	case KDG_HA_CONSECUTIVE_FAILURES:	return "consec_fail";
	case KDG_HA_BACKOFF_UNTIL_MS:		return "backoff_ms";
	case KDG_HA_LAST_ERRNO:			return "last_errno";
	case KDG_HA_NAT_SEEN:			return "nat_seen";
	case KDG_HA_NAT_REDIRECTED:		return "nat_redirected";
	case KDG_HA_NAT_BYPASSED:		return "nat_bypassed";
	case KDG_HA_NAT_HOOK_CALLS:		return "nat_hook_calls";
	case KDG_HA_CA_COUNT:			return "ca_count";
	case KDG_HA_DOH_QUERIES:		return "doh_queries";
	case KDG_HA_DOH_OK:			return "doh_ok";
	case KDG_HA_DOH_LAST_STATUS:		return "doh_last_status";
	case KDG_HA_DOH_LAST_RTT_MS:		return "doh_last_rtt_ms";
	case KDG_HA_CACHE_HITS:			return "cache_hits";
	case KDG_HA_CACHE_MISSES:		return "cache_misses";
	case KDG_HA_CACHE_ENTRIES:		return "cache_entries";
	case KDG_HA_CACHE_MEM_BYTES:		return "cache_mem_bytes";
	case KDG_HA_RESOLVE_CACHE:		return "resolve_cache";
	case KDG_HA_RESOLVE_UPSTREAM:		return "resolve_upstream";
	case KDG_HA_RESOLVE_JOINED:		return "resolve_joined";
	case KDG_HA_SF_INFLIGHT:		return "sf_inflight";
	case KDG_HA_SF_WAITERS:			return "sf_waiters";
	case KDG_HA_QUOTA_ALLOWED:		return "quota_allowed";
	case KDG_HA_QUOTA_DENIED:		return "quota_denied";
	case KDG_HA_H2_SESSIONS:		return "h2_sessions";
	case KDG_HA_H2_REQUESTS:		return "h2_requests";
	case KDG_HA_H2_OK:			return "h2_ok";
	case KDG_HA_NAT_FWD_SEEN:		return "nat_fwd_seen";
	case KDG_HA_NAT_FWD_BYPASSED:		return "nat_fwd_bypassed";
	case KDG_HA_NAT_SPORT53:		return "nat_sport53";
	case KDG_HA_CLIENT_IFACES:		return "client_ifaces";
	case KDG_HA_LISTENER_READY:		return "listener_ready";
	case KDG_HA_MAP_ENTRIES:		return "map_entries";
	case KDG_HA_MAP_HITS:			return "map_hits";
	case KDG_HA_MAP_MISSES:			return "map_misses";
	case KDG_HA_MAP_EVICTIONS:		return "map_evictions";
	case KDG_HA_MAP_REJECTED:		return "map_rejected";
	case KDG_HA_MAP_MEM_BYTES:		return "map_mem_bytes";
	case KDG_HA_POOL_CONNECTS:		return "pool_connects";
	case KDG_HA_POOL_REUSED:		return "pool_reused";
	case KDG_HA_POOL_INFLIGHT:		return "pool_inflight";
	case KDG_HA_POOL_QUEUED:		return "pool_queued";
	case KDG_HA_POOL_STREAM_LIMIT:		return "pool_stream_limit";
	case KDG_HA_POOL_IDLE_CLOSES:		return "pool_idle_closes";
	case KDG_HA_POOL_CONN_ERRORS:		return "pool_conn_errors";
	case KDG_HA_POOL_UPSTREAM_TIMEOUTS:	return "pool_upstream_timeouts";
	case KDG_HA_POOL_REJECTED:		return "pool_rejected";
	case KDG_HA_POOL_H1_FALLBACKS:		return "pool_h1_fallbacks";
	case KDG_HA_POOL_SLOTS_USED:		return "pool_slots_used";
	case KDG_HA_POOL_SLOTS_MAX:		return "pool_slots_max";
	case KDG_HA_POOL_CONNECTED:		return "pool_connected";
	default:				return (const char *)0;
	}
}

/* 置位后 dump_attrs_at 在嵌套层打印上面的名字。全局标志而不是参数：
 * 该函数是纯诊断输出路径，为传一个调试开关改签名不划算。 */
static int g_dump_health_names;

/* 递归展开属性。深度上限 2 足够本 UAPI（顶层 + 一个嵌套块），
 * 设上限是刻意的：嵌套深度来自对端，不能让一个畸形回包把栈打穿。 */
static void dump_attrs_at(u8 *base, u32 len, int depth)
{
	u8 *p = base;
	u32 rem = len;

	while (rem >= NLA_HDRLEN && depth < 3) {
		struct nlattr *a = (struct nlattr *)p;
		u16 alen = a->nla_len;
		u16 raw = a->nla_type;
		u16 atype = raw & NLA_TYPE_MASK_;
		u16 plen;
		int i;

		if (alen < NLA_HDRLEN || alen > rem)
			break;
		plen = (u16)(alen - NLA_HDRLEN);

		for (i = 0; i < depth; i++)
			puts_("  ");
		puts_("attr ");
		putnum(atype);

		if (raw & NLA_F_NESTED_) {
			puts_(" [nested]\n");
			dump_attrs_at(p + NLA_HDRLEN, plen, depth + 1);
			p += NLA_ALIGN4(alen);
			rem -= NLA_ALIGN4(alen);
			continue;
		}

		if (depth > 0 && g_dump_health_names) {
			const char *nm = ha_name(atype);

			if (nm) {
				puts_(" ");
				puts_(nm);
			}
		}

		puts_(" len=");
		putnum(plen);
		puts_("  ");
		if (plen == 1) {
			putnum(*(u8 *)(p + NLA_HDRLEN));
		} else if (plen == 2) {
			putnum(*(u16 *)(p + NLA_HDRLEN));
		} else if (plen == 4) {
			putnum(*(u32 *)(p + NLA_HDRLEN));
			puts_(" (");
			puthex(*(u32 *)(p + NLA_HDRLEN));
			puts_(")");
		} else if (plen == 8) {
			putnum(*(u64 *)(p + NLA_HDRLEN));
		} else {
			puts_("<bin>");
		}
		puts_("\n");

		p += NLA_ALIGN4(alen);
		rem -= NLA_ALIGN4(alen);
	}
}

static void dump_attrs(const char *title)
{
	struct nlmsghdr *nh = (struct nlmsghdr *)rxbuf;
	struct genlmsghdr *gh;
	u8 *p;
	u32 rem;

	puts_(title);
	puts_("\n");
	gh = (struct genlmsghdr *)(rxbuf + sizeof(*nh));
	p = (u8 *)gh + sizeof(*gh);
	rem = nh->nlmsg_len - (u32)(sizeof(*nh) + sizeof(*gh));
	dump_attrs_at(p, rem, 0);
}


/* ── 进程入口参数 ─────────────────────────────────────────────────────
 * freestanding 程序没有 libc 的 _start 包装，得自己从栈上取 argc/argv。
 * aarch64 Linux 的进程入口约定：sp 指向 argc，紧接着是 argv[] 指针数组。 */
static long sys4(long n, long a, long b, long c, long d)
{
	register long x8 __asm__("x8") = n;
	register long x0 __asm__("x0") = a;
	register long x1 __asm__("x1") = b;
	register long x2 __asm__("x2") = c;
	register long x3 __asm__("x3") = d;

	__asm__ volatile("svc #0"
			 : "+r"(x0)
			 : "r"(x1), "r"(x2), "r"(x3), "r"(x8)
			 : "memory", "cc");
	return x0;
}


/*
 * ⚠️ 入口必须是 naked。
 *
 * 常规函数的序言（stp x29,x30,[sp,#-N]!）会在函数体执行**之前**就调整 sp，
 * 因此在普通函数里内联汇编读 sp 拿到的是该函数自己的栈帧，而不是进程的
 * 初始栈 —— 实测表现为 argc 恒为 0，子命令全被忽略、静默走默认路径。
 * __attribute__((naked)) 抑制序言生成，第一条指令即我们自己的汇编。
 *
 * 用 b（而非 bl）跳转：kdg_entry 以 exit() 收尾、永不返回，
 * 无需保存 x30（进程启动时它本就是未定义的）。
 */
__attribute__((naked)) void _start(void)
{
	__asm__ volatile(
		"mov x0, sp\n"
		"b   kdg_entry\n");
}

static int str_eq(const char *a, const char *b)
{
	while (*a && *b) {
		if (*a != *b)
			return 0;
		a++;
		b++;
	}
	return *a == *b;
}

/* ── 文件读取 ─────────────────────────────────────────────────────────── */

#define SYS_read	63
#define SYS_close	57
#define SYS_openat	56
#define AT_FDCWD_	(-100)
#define O_RDONLY_	0
/* 字符设备必须 O_RDWR：同一个 fd 上既 write（提交查询）又 read（取回响应）。
 * 曾写成 O_RDONLY，write 直接返回 EBADF。 */
#define O_RDWR_		2

static int read_file(const char *path, u8 *buf, usize cap, usize *outlen)
{
	long fd, n;

	/* 用 openat 而不是 open：aarch64 没有独立的 open 系统调用。 */
	fd = sys4(SYS_openat, AT_FDCWD_, (long)path, O_RDONLY_, 0);
	if (fd < 0)
		return (int)fd;

	n = sys3(SYS_read, fd, (long)buf, (long)cap);
	sys3(SYS_close, fd, 0, 0);
	if (n < 0)
		return (int)n;

	*outlen = (usize)n;
	return 0;
}

/* ── DNS 查询报文构造（本工具的测试载荷）────────────────────────────── */

static usize dn_encode(u8 *out, const char *name)
{
	usize o = 0;

	while (*name) {
		const char *p = name;
		usize l = 0;

		while (*p && *p != '.') {
			p++;
			l++;
		}
		if (l == 0 || l > 63)
			return 0;
		out[o++] = (u8)l;
		{
			usize i;

			for (i = 0; i < l; i++)
				out[o++] = (u8)name[i];
		}
		name = (*p == '.') ? p + 1 : p;
	}
	out[o++] = 0;
	return o;
}

static usize build_dns_query(u8 *out, const char *name, u16 qtype)
{
	usize n = 12;
	usize nl;

	out[0] = 0x12; out[1] = 0x34;	/* ID */
	out[2] = 0x01; out[3] = 0x00;	/* flags: RD */
	out[4] = 0x00; out[5] = 0x01;	/* qdcount = 1 */
	out[6] = 0; out[7] = 0; out[8] = 0; out[9] = 0;
	out[10] = 0; out[11] = 0;

	nl = dn_encode(out + n, name);
	if (nl == 0)
		return 0;
	n += nl;

	out[n++] = (u8)(qtype >> 8);
	out[n++] = (u8)(qtype & 0xff);
	out[n++] = 0;			/* qclass = IN */
	out[n++] = 1;
	return n;
}

/* ── 信任锚加载（Generic Netlink）────────────────────────────────────── */

static int cmd_trust(u16 fam, const char *path)
{
	static u8 file[16384];
	struct nlmsghdr *nh = (struct nlmsghdr *)txbuf;
	struct genlmsghdr *gh;
	struct sockaddr_nl dst;
	usize flen = 0;
	int fd;
	long n;
	int rc;

	rc = read_file(path, file, sizeof(file), &flen);
	if (rc) {
		puts_("读取文件失败: ");
		puts_(path);
		puts_("\n");
		return 1;
	}
	if (flen == 0) {
		puts_("文件为空\n");
		return 1;
	}

	nh->nlmsg_len = sizeof(*nh) + sizeof(*gh);
	nh->nlmsg_type = fam;
	nh->nlmsg_flags = NLM_F_REQUEST_;
	nh->nlmsg_seq = 2;
	nh->nlmsg_pid = 0;
	gh = (struct genlmsghdr *)(txbuf + sizeof(*nh));
	gh->cmd = KDG_CMD_SET_TRUST;
	gh->version = KDG_GENL_VERSION;
	gh->reserved = 0;
	g_attr_overflow = 0;
	attr_put(KDG_A_TRUST_MATERIAL, file, flen);
	if (g_attr_overflow) {
		puts_("内部错误：信任锚超出发送缓冲上限\n");
		return 1;
	}

	puts_("提交信任锚 ");
	putnum(flen);
	puts_(" 字节\n");

	fd = (int)sys3(SYS_socket, AF_NETLINK_, SOCK_RAW_, NETLINK_GENERIC_);
	if (fd < 0)
		return 1;
	dst.nl_family = AF_NETLINK_;
	dst.nl_pad = 0;
	dst.nl_pid = 0;
	dst.nl_groups = 0;
	if (sys3(SYS_bind, fd, (long)&dst, sizeof(dst)) < 0)
		return 1;
	if (sys6(SYS_sendto, fd, (long)txbuf, nh->nlmsg_len, 0, 0, 0) < 0)
		return 1;

	n = sys6(SYS_recvfrom, fd, (long)rxbuf, sizeof(rxbuf), 0, 0, 0);
	sys3(SYS_close, fd, 0, 0);
	if (n < 0)
		return 1;

	{
		struct nlmsghdr *rn = (struct nlmsghdr *)rxbuf;
		int err = rn->nlmsg_type == 2 /* NLMSG_ERROR */ &&
			  rn->nlmsg_len >= sizeof(*rn) + 4
			  ? *(int *)(rxbuf + sizeof(*rn)) : 0;
		if (err) {
			puts_("内核返回错误: ");
			putnum((u64)(-err));
			puts_("\n");
			return 1;
		}
	}

	dump_attrs("SET_TRUST 回包:");
	return 0;
}

/* ── 所有权事务（Generic Netlink）────────────────────────────────────── */

/* 发一条带属性的 genl 请求，返回内核错误码（0 表示成功）。 */
struct kdg_attr_ref {
	u16 type;
	const void *data;
	usize len;
};

static int genl_send_attrs(u16 fam, u8 cmd, const struct kdg_attr_ref *attrs,
			   unsigned int nattrs)
{
	struct nlmsghdr *nh = (struct nlmsghdr *)txbuf;
	struct genlmsghdr *gh;
	struct sockaddr_nl dst;
	unsigned int i;
	int fd;
	long n;

	nh->nlmsg_len = sizeof(*nh) + sizeof(*gh);
	nh->nlmsg_type = fam;
	nh->nlmsg_flags = NLM_F_REQUEST_ | NLM_F_ACK_;
	nh->nlmsg_seq = 3;
	nh->nlmsg_pid = 0;
	gh = (struct genlmsghdr *)(txbuf + sizeof(*nh));
	gh->cmd = cmd;
	gh->version = KDG_GENL_VERSION;
	gh->reserved = 0;

	g_attr_overflow = 0;
	for (i = 0; i < nattrs; i++)
		attr_put(attrs[i].type, attrs[i].data, attrs[i].len);
	if (g_attr_overflow) {
		puts_("内部错误：属性超出发送缓冲上限\n");
		return -1;
	}

	fd = (int)sys3(SYS_socket, AF_NETLINK_, SOCK_RAW_, NETLINK_GENERIC_);
	if (fd < 0)
		return -1;
	set_recv_timeout(fd, 10);
	dst.nl_family = AF_NETLINK_;
	dst.nl_pad = 0;
	dst.nl_pid = 0;
	dst.nl_groups = 0;
	if (sys3(SYS_bind, fd, (long)&dst, sizeof(dst)) < 0)
		return -1;
	if (sys6(SYS_sendto, fd, (long)txbuf, nh->nlmsg_len, 0, 0, 0) < 0)
		return -1;
	n = sys6(SYS_recvfrom, fd, (long)rxbuf, sizeof(rxbuf), 0, 0, 0);
	sys3(SYS_close, fd, 0, 0);
	if (n < 0)
		return -1;

	{
		struct nlmsghdr *rn = (struct nlmsghdr *)rxbuf;
		int err = rn->nlmsg_type == 2 /* NLMSG_ERROR */ &&
			  rn->nlmsg_len >= sizeof(*rn) + 4
			  ? *(int *)(rxbuf + sizeof(*rn)) : 0;
		return err;
	}
}

/* ── BPF 发布表：建表 / 挂接 / 回读 ──────────────────────────────────────
 *
 * 为什么这条验证路径放在 kdgctl 而不是等 mihomo：内核把「域名哈希 + TTL」
 * 发布进用户空间的 BPF 表，涉及三段（建表 / 挂接 / 回读）。放在一个不依赖
 * 任何第三方库的小工具里，一旦不通就能立刻分清是内核侧还是客户端侧。
 *
 * 表结构必须与内核里的 kdg_bpf_key / kdg_bpf_val 逐字节一致 —— 大小不符时
 * 挂接会被内核拒绝（而不是「尽力而为」写进一张错位的表）。
 */
#define SYS_bpf_		280	/* arm64 */
#define SYS_nanosleep_		101

#define BPF_MAP_CREATE_		0
#define BPF_MAP_LOOKUP_ELEM_	1
#define BPF_MAP_UPDATE_ELEM_	2
#define BPF_MAP_GET_NEXT_KEY_	4
#define BPF_MAP_TYPE_LRU_HASH_	9

struct bpf_attr_map_create {
	u32 map_type;
	u32 key_size;
	u32 value_size;
	u32 max_entries;
	u32 map_flags;
	u32 inner_map_fd;
	u32 numa_node;
	char map_name[16];
	u32 map_ifindex;
	u32 btf_fd;
	u32 btf_key_type_id;
	u32 btf_value_type_id;
	u32 btf_vmlinux_value_type_id;
	u64 map_extra;
};

struct bpf_attr_elem {
	u32 map_fd;
	u32 pad0;
	u64 key;
	u64 value;
	u64 flags;
};

struct bpf_attr_next {
	u32 map_fd;
	u32 pad0;
	u64 key;
	u64 next_key;
};

struct kdg_bpf_key_ {
	u32 family;
	u8  addr[16];
} __attribute__((packed));

struct kdg_bpf_val_ {
	u64 domain_hash;
	u32 ttl_ms;
	u32 flags;
} __attribute__((packed));

static void msleep_(u64 ms)
{
	struct { u64 s; u64 ns; } ts;

	ts.s = ms / 1000;
	ts.ns = (ms % 1000) * 1000000;
	sys3(SYS_nanosleep_, (long)&ts, 0, 0);
}

static int bpf_map_create_(u32 ksz, u32 vsz, u32 entries)
{
	struct bpf_attr_map_create a;

	memset(&a, 0, sizeof(a));
	a.map_type = BPF_MAP_TYPE_LRU_HASH_;
	a.key_size = ksz;
	a.value_size = vsz;
	a.max_entries = entries;
	return (int)sys3(SYS_bpf_, BPF_MAP_CREATE_, (long)&a, sizeof(a));
}

static int bpf_lookup_(int fd, const void *key, void *val)
{
	struct bpf_attr_elem a;

	memset(&a, 0, sizeof(a));
	a.map_fd = (u32)fd;
	a.key = (u64)(usize)key;
	a.value = (u64)(usize)val;
	return (int)sys3(SYS_bpf_, BPF_MAP_LOOKUP_ELEM_, (long)&a, sizeof(a));
}

static int bpf_update_(int fd, const void *key, const void *val)
{
	struct bpf_attr_elem a;

	memset(&a, 0, sizeof(a));
	a.map_fd = (u32)fd;
	a.key = (u64)(usize)key;
	a.value = (u64)(usize)val;
	return (int)sys3(SYS_bpf_, BPF_MAP_UPDATE_ELEM_, (long)&a, sizeof(a));
}

static int bpf_next_key_(int fd, const void *key, void *next)
{
	struct bpf_attr_next a;

	memset(&a, 0, sizeof(a));
	a.map_fd = (u32)fd;
	a.key = (u64)(usize)key;
	a.next_key = (u64)(usize)next;
	return (int)sys3(SYS_bpf_, BPF_MAP_GET_NEXT_KEY_, (long)&a, sizeof(a));
}

static void dump_bpf_entry(int fd, const struct kdg_bpf_key_ *k)
{
	struct kdg_bpf_val_ v;
	u32 n = k->family == 2 ? 4u : 16u;
	u32 i;

	if (bpf_lookup_(fd, k, &v)) {
		puts_("  <查不到>\n");
		return;
	}
	puts_(k->family == 2 ? "  v4 " : "  v6 ");
	for (i = 0; i < n; i++) {
		putnum(k->addr[i]);
		if (i + 1 < n)
			puts_(".");
	}
	puts_("  hash=");
	puthex64(v.domain_hash);
	puts_("  ttl_ms=");
	putnum(v.ttl_ms);
	puts_("  flags=");
	putnum(v.flags);
	puts_("\n");
}

/* 一次做完：建表 → 挂接 → 等待 → 回读。等待期间由外部脚本发起解析。 */
static int cmd_bpftest(u16 fam, int seconds)
{
	struct kdg_bpf_key_ key, nk;
	int fd, ret, i, total = 0;

	fd = bpf_map_create_(sizeof(struct kdg_bpf_key_),
			     sizeof(struct kdg_bpf_val_), 4096);
	if (fd < 0) {
		puts_("建表失败（bpf syscall 返回 ");
		putnum((u64)(-fd));
		puts_("）：内核是否开了 CONFIG_BPF_SYSCALL？\n");
		return 1;
	}
	puts_("已建表 fd=");
	putnum((u64)fd);
	puts_("（key ");
	putnum(sizeof(struct kdg_bpf_key_));
	puts_(" B / value ");
	putnum(sizeof(struct kdg_bpf_val_));
	puts_(" B）\n");

	{
		s32 fdattr = (s32)fd;
		struct kdg_attr_ref attrs[1];

		attrs[0].type = KDG_A_BPF_MAP_FD;
		attrs[0].data = &fdattr;
		attrs[0].len = sizeof(fdattr);
		ret = genl_send_attrs(fam, KDG_CMD_SET_BPF_MAP, attrs, 1);
		if (ret) {
			puts_("挂接失败（errno ");
			putnum((u64)(-ret));
			puts_("）\n");
			return 1;
		}
	}
	/* 自检：先自己写一条已知记录再读回。**这一步不能省** —— 没有它，表为空
	 * 时分不清是「内核没发布」还是「本工具的 bpf 系统调用封装有错」。 */
	{
		struct kdg_bpf_key_ tk;
		struct kdg_bpf_val_ tv;
		int rc;

		memset(&tk, 0, sizeof(tk));
		tk.family = 2;
		tk.addr[0] = 1; tk.addr[1] = 2; tk.addr[2] = 3; tk.addr[3] = 4;
		tv.domain_hash = 0xdeadbeefcafeULL;
		tv.ttl_ms = 1234;
		tv.flags = 0x5a;
		rc = bpf_update_(fd, &tk, &tv);
		puts_("自检写入返回 ");
		putnum((u64)(rc < 0 ? -rc : 0));
		puts_(rc ? "（失败）\n" : "\n");
		dump_bpf_entry(fd, &tk);
	}

	puts_("已挂接，等待解析结果");

	if (seconds <= 0)
		seconds = 10;
	for (i = 0; i < seconds; i++) {
		msleep_(1000);
		puts_(".");
	}
	puts_("\n");

	memset(&key, 0, sizeof(key));
	ret = bpf_next_key_(fd, 0, &key);
	while (ret == 0 && total < 64) {
		dump_bpf_entry(fd, &key);
		total++;
		memset(&nk, 0, sizeof(nk));
		if (bpf_next_key_(fd, &key, &nk))
			break;
		key = nk;
	}
	puts_("表内共 ");
	putnum((u64)total);
	puts_(" 条（最多打印 64 条）\n");
	return total > 0 ? 0 : 1;
}

/* 从 GET_HEALTH 回包里取 generation（顶层 KDG_A_GENERATION，u32）。 */
static u32 genl_read_generation(u16 fam)
{
	struct nlmsghdr *nh = (struct nlmsghdr *)txbuf;
	struct genlmsghdr *gh;
	struct sockaddr_nl dst;
	u8 *p;
	u32 rem, generation = 0;
	int fd;
	long n;

	nh->nlmsg_len = sizeof(*nh) + sizeof(*gh);
	nh->nlmsg_type = fam;
	nh->nlmsg_flags = NLM_F_REQUEST_;
	nh->nlmsg_seq = 4;
	nh->nlmsg_pid = 0;
	gh = (struct genlmsghdr *)(txbuf + sizeof(*nh));
	gh->cmd = KDG_CMD_GET_HEALTH;
	gh->version = KDG_GENL_VERSION;
	gh->reserved = 0;

	fd = (int)sys3(SYS_socket, AF_NETLINK_, SOCK_RAW_, NETLINK_GENERIC_);
	if (fd < 0)
		return 0;
	dst.nl_family = AF_NETLINK_;
	dst.nl_pad = 0;
	dst.nl_pid = 0;
	dst.nl_groups = 0;
	if (sys3(SYS_bind, fd, (long)&dst, sizeof(dst)) < 0)
		return 0;
	if (sys6(SYS_sendto, fd, (long)txbuf, nh->nlmsg_len, 0, 0, 0) < 0)
		return 0;
	n = sys6(SYS_recvfrom, fd, (long)rxbuf, sizeof(rxbuf), 0, 0, 0);
	sys3(SYS_close, fd, 0, 0);
	if (n <= 0)
		return 0;

	nh = (struct nlmsghdr *)rxbuf;
	gh = (struct genlmsghdr *)(rxbuf + sizeof(*nh));
	p = (u8 *)gh + sizeof(*gh);
	rem = nh->nlmsg_len - (u32)(sizeof(*nh) + sizeof(*gh));
	while (rem >= NLA_HDRLEN) {
		struct nlattr *a = (struct nlattr *)p;
		u16 alen = a->nla_len;
		u16 atype = a->nla_type & 0x3fff;

		if (alen < NLA_HDRLEN || alen > rem)
			break;
		if (atype == KDG_A_GENERATION && alen >= NLA_HDRLEN + 4)
			generation = *(u32 *)(p + NLA_HDRLEN);
		p += NLA_ALIGN4(alen);
		rem -= NLA_ALIGN4(alen);
	}
	return generation;
}

static int cmd_prepare(u16 fam, const char *tx_text)
{
	u64 tx = 0;
	unsigned int i;
	int err;

	for (i = 0; tx_text[i]; i++)
		tx = tx * 10 + (u64)(tx_text[i] - '0');
	if (tx == 0) {
		puts_("transaction id 不能为 0\n");
		return 1;
	}
	{
		const struct kdg_attr_ref attrs[] = {
			{ KDG_A_TRANSACTION_ID, &tx, sizeof(tx) },
		};

		err = genl_send_attrs(fam, KDG_CMD_PREPARE_PROFILE, attrs, 1);
	}
	if (err) {
		puts_("PREPARE 失败 errno=");
		putnum((u64)(-err));
		puts_("\n");
		return 1;
	}
	puts_("PREPARE 成功，generation=");
	putnum(genl_read_generation(fam));
	puts_("\n");
	return 0;
}

static int cmd_commit(u16 fam, const char *tx_text)
{
	u64 tx = 0;
	u32 expected, ready = 1;
	unsigned int i;
	int err;

	for (i = 0; tx_text[i]; i++)
		tx = tx * 10 + (u64)(tx_text[i] - '0');
	expected = genl_read_generation(fam);
	if (tx == 0 || expected == 0) {
		puts_("需要有效的 transaction id 与 generation\n");
		return 1;
	}
	{
		const struct kdg_attr_ref attrs[] = {
			{ KDG_A_TRANSACTION_ID, &tx, sizeof(tx) },
			{ KDG_A_EXPECTED_GENERATION, &expected, sizeof(expected) },
			{ KDG_A_READINESS, &ready, sizeof(ready) },
		};

		err = genl_send_attrs(fam, KDG_CMD_COMMIT_PROFILE, attrs, 3);
	}
	if (err) {
		puts_("COMMIT 失败 errno=");
		putnum((u64)(-err));
		puts_("\n");
		return 1;
	}
	puts_("COMMIT 成功，generation=");
	putnum(genl_read_generation(fam));
	puts_("\n");
	return 0;
}

static int cmd_disable(u16 fam)
{
	int err = genl_send_attrs(fam, KDG_CMD_DISABLE_INTERCEPT, (const void *)0, 0);

	if (err) {
		puts_("DISABLE 失败 errno=");
		putnum((u64)(-err));
		puts_("\n");
		return 1;
	}
	puts_("DISABLE 成功（ownership 已归还）\n");
	return 0;
}

/* ── 查询（字符设备）─────────────────────────────────────────────────── */

/* ── MAP_LOOKUP：IP → 候选域名集合（方案 §12.2）──────────────────────── */

static int hexval(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

/*
 * 极简地址解析：IPv4 "a.b.c.d" 与 IPv6（支持 `::` 压缩与尾部内嵌 IPv4）。
 * 刻意不追求 RFC 4291 的全部写法（不做 zone id、不接受混合大小写外的花活）
 * —— 这是诊断工具，能打出来的地址必须能查回去即可。
 */
static int parse_addr(const char *s, u8 *out, u32 *alen)
{
	u16 groups[8];
	int dcolon = -1, i;
	const char *p = s;

	if (!s || !s[0])
		return -1;

	if (!str_chr(s, ':')) {			/* IPv4 */
		u32 parts[4] = { 0, 0, 0, 0 };
		u32 val = 0;
		int n = 0, digits = 0;

		for (p = s; ; p++) {
			if (*p >= '0' && *p <= '9') {
				val = val * 10 + (u32)(*p - '0');
				if (val > 255 || ++digits > 3)
					return -1;
			} else if (*p == '.' || *p == 0) {
				if (!digits || n >= 4)
					return -1;
				parts[n++] = val;
				val = 0;
				digits = 0;
				if (!*p)
					break;
			} else {
				return -1;
			}
		}
		if (n != 4)
			return -1;
		for (i = 0; i < 4; i++)
			out[i] = (u8)parts[i];
		*alen = 4;
		return 0;
	}

	/* IPv6 */
	for (i = 0; i < 8; i++)
		groups[i] = 0xffff;
	i = 0;
	while (*p) {
		if (*p == ':') {
			if (p[1] == ':') {
				if (dcolon >= 0) return -1;
				dcolon = i;
				p += 2;
				if (!*p) break;
				continue;
			}
			return -1;
		}
		{
			u32 val = 0;
			int digits = 0, hv;

			while ((hv = hexval(*p)) >= 0) {
				val = (val << 4) | (u32)hv;
				digits++;
				p++;
				if (digits > 4) return -1;
			}
			if (!digits) return -1;
			if (i >= 8) return -1;
			groups[i++] = (u16)val;
		}
		if (*p == ':') {
			p++;
			if (!*p) return -1;	/* 结尾单冒号非法 */
			continue;
		}
		if (*p) return -1;
	}
	if (dcolon < 0 && i != 8) return -1;
	*alen = 16;
	{
		int head = dcolon < 0 ? i : dcolon;
		int tail = dcolon < 0 ? 0 : i - dcolon;
		int z;

		/* dcolon 之后的部分要右对齐到 groups[7] */
		for (z = 0; z < tail; z++)
			groups[8 - tail + z] = groups[head + z];
		for (z = head; z < 8 - tail; z++)
			groups[z] = 0;
		for (z = 0; z < 8; z++) {
			out[z * 2] = (u8)(groups[z] >> 8);
			out[z * 2 + 1] = (u8)groups[z];
		}
	}
	return 0;
}

/* 未压缩的 wire 域名 → 文本。返回写入的字符数（不含结尾 NUL）。 */
static usize dname_to_text(const u8 *w, usize len, char *buf, usize cap)
{
	usize p = 0, o = 0;

	while (p < len && w[p]) {
		usize l = w[p++];

		if (l > 63 || p + l > len) break;
		if (o) {
			if (o + 1 >= cap) break;
			buf[o++] = '.';
		}
		if (o + l >= cap) break;
		memcpy_(buf + o, w + p, l);
		o += l;
		p += l;
	}
	if (o >= cap) o = cap - 1;
	buf[o] = 0;
	return o;
}

static int cmd_maplookup(const char *ip_text)
{
	static u8 reqbuf[256 + 512];
	static u8 respbuf[8 + 1024];
	struct kdg_req_v1 *req = (struct kdg_req_v1 *)reqbuf;
	u8 addr[16];
	u32 alen = 0;
	long fd, wn, rn;
	char text[256];

	if (parse_addr(ip_text, addr, &alen)) {
		puts_("地址非法（IPv4 或 IPv6）\n");
		return 1;
	}

	memset(req, 0, sizeof(*req));
	req->abi_version = KDG_ABI_VERSION;
	req->opcode = KDG_OP_MAP_LOOKUP;
	req->total_len = (u32)(sizeof(*req) + alen);
	req->request_cookie = 0x2233445566778899ULL;
	req->query_len = alen;
	memcpy_(reqbuf + sizeof(*req), addr, alen);

	fd = sys4(SYS_openat, AT_FDCWD_, (long)"/dev/kdnsguard", O_RDWR_, 0);
	if (fd < 0) {
		puts_("打开 /dev/kdnsguard 失败（errno ");
		putnum((u64)(-fd));
		puts_("）\n");
		return 1;
	}
	wn = sys3(SYS_write, fd, (long)reqbuf, (long)req->total_len);
	if (wn < 0) {
		puts_("write 失败 errno=");
		putnum((u64)(-wn));
		puts_("\n");
		sys3(SYS_close, fd, 0, 0);
		return 1;
	}
	rn = sys3(SYS_read, fd, (long)respbuf, sizeof(respbuf));
	sys3(SYS_close, fd, 0, 0);
	if (rn < (long)sizeof(struct kdg_resp_v1)) {
		puts_("read 不足（");
		putnum((u64)rn);
		puts_(" 字节）\n");
		return 1;
	}

	{
		struct kdg_resp_v1 *r = (struct kdg_resp_v1 *)respbuf;
		usize off = sizeof(*r);
		struct kdg_map_result_v1 mh;
		u32 i;

		if (r->status != KDG_ST_OK) {
			puts_("MAP_LOOKUP 失败 status=");
			putnum(r->status);
			puts_(" errno=");
			putnum(r->errno_hint);
			puts_("\n");
			return 1;
		}
		if (r->response_len < sizeof(mh) ||
		    off + sizeof(mh) > (usize)rn) {
			puts_("响应体过短\n");
			return 1;
		}
		memcpy_(&mh, respbuf + off, sizeof(mh));
		off += sizeof(mh);

		puts_("映射: count=");
		putnum(mh.count);
		puts_(" truncated=");
		putnum(mh.truncated);
		puts_(" profile_gen=");
		putnum(mh.profile_generation);
		puts_("\n");
		if (!mh.count)
			puts_("（该 IP 没有已知关联）\n");

		for (i = 0; i < mh.count && i < KDG_MAP_MAX_ITEMS; i++) {
			struct kdg_map_item_v1 it;

			if (off + sizeof(it) > (usize)rn) break;
			memcpy_(&it, respbuf + off, sizeof(it));
			off += sizeof(it);
			if (off + it.len > (usize)rn) break;

			puts_("  [");
			putnum(i);
			puts_("] ttl_ms=");
			putnum(it.ttl_ms);
			puts_(" ");
			if (it.kind == 0) {
				dname_to_text(respbuf + off, it.len, text, sizeof(text));
				puts_(text);
			} else {
				puts_("<裸地址 kind=");
				putnum(it.kind);
				puts_(">");
			}
			puts_("\n");
			off += (usize)((it.len + 3u) & ~3u);
		}
	}
	return 0;
}

static int cmd_query(const char *name)
{
	static u8 reqbuf[256 + 512];
	static u8 respbuf[8 + 4096];
	struct kdg_req_v1 *req = (struct kdg_req_v1 *)reqbuf;
	usize qlen;
	long fd, wn, rn;
	usize total;

	qlen = build_dns_query(reqbuf + sizeof(*req), name, 1 /* A */);
	if (qlen == 0) {
		puts_("域名非法\n");
		return 1;
	}

	total = sizeof(*req) + qlen;
	memset(req, 0, sizeof(*req));
	req->abi_version = KDG_ABI_VERSION;
	req->opcode = KDG_OP_QUERY;
	req->total_len = (u32)total;
	req->request_cookie = 0x1122334455667788ULL;
	req->deadline_ms = 5000;
	req->query_len = (u32)qlen;

	fd = sys4(SYS_openat, AT_FDCWD_, (long)"/dev/kdnsguard", O_RDWR_, 0);
	if (fd < 0) {
		puts_("打开 /dev/kdnsguard 失败（errno ");
		putnum((u64)(-fd));
		puts_("）\n");
		return 1;
	}

	wn = sys3(SYS_write, fd, (long)reqbuf, (long)total);
	if (wn < 0) {
		puts_("write 失败 errno=");
		putnum((u64)(-wn));
		puts_("\n");
		sys3(SYS_close, fd, 0, 0);
		return 1;
	}

	rn = sys3(SYS_read, fd, (long)respbuf, sizeof(respbuf));
	sys3(SYS_close, fd, 0, 0);
	if (rn < (long)sizeof(struct kdg_resp_v1)) {
		puts_("read 不足（");
		putnum((u64)rn);
		puts_(" 字节）\n");
		return 1;
	}

	{
		struct kdg_resp_v1 *r = (struct kdg_resp_v1 *)respbuf;
		usize off = sizeof(*r);

		puts_("响应: status=");
		putnum(r->status);
		puts_(" errno=");
		putnum(r->errno_hint);
		puts_(" cookie=");
		puthex(r->request_cookie);
		puts_(" resp_len=");
		putnum(r->response_len);
		puts_("\n");

		if (r->status != KDG_ST_OK || r->response_len < 12) {
			puts_("查询未成功\n");
			return 1;
		}

		/* 极简 DNS 响应摘要：rcode / ancount / 前几条 A 记录。
		 * 完整校验是内核侧 kdg_wire.c 的职责，这里只为肉眼确认。 */
		{
			const u8 *w = respbuf + off;
			usize wl = r->response_len;
			unsigned int an, i;
			usize p;

			puts_("DNS: rcode=");
			putnum(w[3] & 0x0f);
			an = ((unsigned int)w[6] << 8) | w[7];
			puts_(" ancount=");
			putnum(an);
			puts_("\n");

			/* 跳过问题区 */
			p = 12;
			while (p < wl && w[p] != 0) {
				if ((w[p] & 0xc0) == 0xc0) { p += 2; break; }
				p += 1 + w[p];
			}
			if (p < wl && w[p] == 0)
				p += 1;
			p += 4;

			for (i = 0; i < an && p + 12 <= wl; i++) {
				unsigned int type, rdlen;

				if ((w[p] & 0xc0) == 0xc0) {
					p += 2;
				} else {
					while (p < wl && w[p] != 0)
						p += 1 + w[p];
					p += 1;
				}
				if (p + 10 > wl)
					break;
				type = ((unsigned int)w[p] << 8) | w[p + 1];
				rdlen = ((unsigned int)w[p + 8] << 8) | w[p + 9];
				p += 10;
				if (p + rdlen > wl)
					break;
				if (type == 1 && rdlen == 4) {
					puts_("  A ");
					putnum(w[p]);
					puts_(".");
					putnum(w[p + 1]);
					puts_(".");
					putnum(w[p + 2]);
					puts_(".");
					putnum(w[p + 3]);
					puts_("\n");
				}
				p += rdlen;
			}
		}
	}
	return 0;
}

void kdg_entry(long *sp)
{
	long argc = sp[0];
	char **argv = (char **)&sp[1];
	u16 version = 0;
	u16 fam;
	long n;

	fam = resolve_family(&version);
	if (!fam) {
		puts_("失败：Generic Netlink 族 \"");
		puts_(KDG_GENL_NAME);
		puts_("\" 不存在（模块未加载？）\n");
		sys3(SYS_exit, 1, 0, 0);
	}

	/* 带参数时按子命令派发；不带参数时打印诊断总览（保持原行为）。 */
	if (argc >= 2 && str_eq(argv[1], "trust")) {
		if (argc < 3) {
			puts_("用法: kdgctl trust <pem文件>\n");
			sys3(SYS_exit, 1, 0, 0);
		}
		sys3(SYS_exit, cmd_trust(fam, argv[2]), 0, 0);
	}
	if (argc >= 2 && str_eq(argv[1], "query")) {
		if (argc < 3) {
			puts_("用法: kdgctl query <域名>\n");
			sys3(SYS_exit, 1, 0, 0);
		}
		sys3(SYS_exit, cmd_query(argv[2]), 0, 0);
	}
	if (argc >= 2 && str_eq(argv[1], "prepare")) {
		if (argc < 3) {
			puts_("用法: kdgctl prepare <transaction-id>\n");
			sys3(SYS_exit, 1, 0, 0);
		}
		sys3(SYS_exit, cmd_prepare(fam, argv[2]), 0, 0);
	}
	if (argc >= 2 && str_eq(argv[1], "commit")) {
		if (argc < 3) {
			puts_("用法: kdgctl commit <transaction-id>\n");
			sys3(SYS_exit, 1, 0, 0);
		}
		sys3(SYS_exit, cmd_commit(fam, argv[2]), 0, 0);
	}
	if (argc >= 2 && str_eq(argv[1], "disable")) {
		sys3(SYS_exit, cmd_disable(fam), 0, 0);
	}
	if (argc >= 2 && str_eq(argv[1], "bpftest")) {
		int secs = 10;

		if (argc >= 3) {
			int k = 0;

			secs = 0;
			while (argv[2][k] >= '0' && argv[2][k] <= '9')
				secs = secs * 10 + (argv[2][k++] - '0');
		}
		sys3(SYS_exit, cmd_bpftest(fam, secs), 0, 0);
	}
	if (argc >= 2 && str_eq(argv[1], "maplookup")) {
		if (argc < 3) {
			puts_("用法: kdgctl maplookup <ipv4|ipv6>\n");
			sys3(SYS_exit, 1, 0, 0);
		}
		sys3(SYS_exit, cmd_maplookup(argv[2]), 0, 0);
	}

	puts_("族 ");
	puts_(KDG_GENL_NAME);
	puts_(" 存在：id=");
	putnum(fam);
	puts_(" version=");
	putnum(version);
	puts_("\n");

	n = genl_xchg(fam, KDG_CMD_CAPS, KDG_GENL_VERSION);
	if (n > 0)
		dump_attrs("CAPS 回包:");

	n = genl_xchg(fam, KDG_CMD_GET_HEALTH, KDG_GENL_VERSION);
	if (n > 0) {
		g_dump_health_names = 1;
		dump_attrs("GET_HEALTH 回包:");
		g_dump_health_names = 0;
	}

	sys3(SYS_exit, 0, 0, 0);
}
