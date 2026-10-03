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

/* ── 最小输出 ─────────────────────────────────────────────────────────── */

static usize slen(const char *s)
{
	usize n = 0;

	while (s[n])
		n++;
	return n;
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
#define GENL_ID_CTRL_		0x10

#define CTRL_CMD_GETFAMILY_	3
#define CTRL_ATTR_FAMILY_ID_	1
#define CTRL_ATTR_FAMILY_NAME_	2
#define CTRL_ATTR_VERSION_	3
#define CTRL_ATTR_OPS_		8

static u8 txbuf[1024];
static u8 rxbuf[8192];

static void attr_put(u16 type, const void *data, usize len)
{
	usize off = ((struct nlmsghdr *)txbuf)->nlmsg_len;
	struct nlattr *a = (struct nlattr *)(txbuf + off);

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

static void get_args(long *argc, char ***argv)
{
	long *sp;

	__asm__ volatile("mov %0, sp" : "=r"(sp));
	*argc = sp[0];
	*argv = (char **)(sp + 1);
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
	attr_put(KDG_A_TRUST_MATERIAL, file, flen);

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

/* ── 查询（字符设备）─────────────────────────────────────────────────── */

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

	fd = sys4(SYS_openat, AT_FDCWD_, (long)"/dev/kdnsguard", O_RDONLY_, 0);
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

void _start(void)
{
	long argc;
	char **argv;
	u16 version = 0;
	u16 fam;
	long n;

	get_args(&argc, &argv);

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
	if (n > 0)
		dump_attrs("GET_HEALTH 回包:");

	sys3(SYS_exit, 0, 0, 0);
}
