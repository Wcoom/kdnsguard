/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_listener.c —— loopback DNS listener for PREPARE/COMMIT.
 *
 * The listener is deliberately bound to 127.0.0.1/[::1]:1054. Port 53 remains
 * owned by the existing network until the NAT ownership transaction commits.
 * UDP and TCP share kdg_resolve(), so wire validation/cache/singleflight have
 * one implementation. All socket I/O runs in kthreads, never in a Netfilter hook.
 *
 * 两类监听 socket，地址选择**不是**可互换的：
 *
 *  - **loopback 组**（127.0.0.1 / ::1）：服务 LOCAL_OUT 路径。为什么必须绑
 *    loopback 而不是 0.0.0.0：REDIRECT 在 LOCAL_OUT 会把目的地址改写成
 *    127.0.0.1，conntrack 建立的反向映射期望「源 = 127.0.0.1:listen_port」。
 *    绑 0.0.0.0 的 socket 在回包时由路由选源地址（对端是本机地址 ⇒ 选到
 *    本机网卡地址），元组对不上 conntrack，回包会被当作新包丢掉。
 *
 *  - **客户端入口组**（热点 / USB 共享接口的地址）：服务 PREROUTING 路径。
 *    该路径下 nf_nat_redirect_* 把目的地址改写成**入接口自己的地址**
 *    （net/netfilter/nf_nat_redirect.c 按 hooknum 分支，LOCAL_OUT 才用
 *    127.0.0.1）。所以必须逐个绑定到接口地址上，回包才会以该接口地址为源
 *    —— 那正是 conntrack 反向元组期望的值。
 *
 * 客户端入口表只收录**绑定成功**的接口，NAT hook 也只按它判定是否接管
 * PREROUTING：宁可少接管一个接口，也不能「先接管、后建 listener」把热点
 * 客户端的 DNS 打进黑洞（nf_nat_redirect_* 找不到接口地址时返回 NF_DROP）。
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": listener: " fmt

#include <linux/delay.h>
#include <linux/if.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/inetdevice.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/string.h>
#include <linux/wait.h>
#include <net/addrconf.h>
#include <net/ipv6.h>
#include <net/sock.h>

#include "kdg.h"
#include "kdg_doh.h"
#include "kdg_resolve.h"
#include "kdg_wire.h"
#include "kdg_listener.h"

#define KDG_LISTEN_BACKLOG 16
#define KDG_LISTENER_RX_MAX KDG_MAX_WIRE_MSG

/* 模块参数里最多接受多少个候选接口名。真正同时维持 listener 的上限是
 * KDG_MAX_CLIENT_IF（更小）—— 候选表只是「哪些名字算客户端入口」的白名单，
 * 不必给每个候选都开线程。 */
#define KDG_MAX_CLIENT_CANDIDATES 16
#define KDG_CLIENT_NAME_MAX 32

/* 与 kdg.h 的 KDG_IFNAME_LEN 必须一致，否则名字比较会在编译期就对不上。 */
static_assert(KDG_IFNAME_LEN == IFNAMSIZ,
	      "KDG_IFNAME_LEN 必须等于 IFNAMSIZ");

struct kdg_listener {
	struct socket *udp4;
	struct socket *udp6;
	struct socket *tcp4;
	struct socket *tcp6;
	struct task_struct *udp4_task;
	struct task_struct *udp6_task;
	struct task_struct *tcp4_task;
	struct task_struct *tcp6_task;
	struct kdg_doh_cfg cfg;
	struct mutex lock;
	bool ready;
	bool stopping;
};

static struct kdg_listener g_listener;

/* 客户端入口表。NAT hook 在 RCU 读侧按 name 查它，因此：
 *  - 表本身静态生存期，不重新分配；
 *  - 条目内容只在 `listener_up` 的**最后一次**写入（true 在全部 socket 就绪
 *    之后、false 在全部 socket 释放之前）发布，且用 WRITE_ONCE/_once 配对，
 *    避免 hook 看到「已标记可用但 socket 还没建好」的中间态。 */
struct kdg_client_iface kdg_client_ifaces[KDG_MAX_CLIENT_IF];

/* 候选接口名（模块参数 client_ifaces 解析而来）。 */
static char g_client_names[KDG_MAX_CLIENT_CANDIDATES][KDG_CLIENT_NAME_MAX];
static unsigned int g_client_name_count;

static void kdg_listener_set_timeout(struct socket *sock, u32 ms)
{
	if (!sock || !sock->sk)
		return;
	sock->sk->sk_rcvtimeo = msecs_to_jiffies(ms);
	sock->sk->sk_sndtimeo = msecs_to_jiffies(ms);
}

/* ── 绑定 ─────────────────────────────────────────────────────────────── */

/*
 * 通用绑定：addr 为 NULL 表示 loopback，否则是 __be32（IPv4）或 16 字节
 * （IPv6）地址缓冲。端口一律取当前生效的 listen_port，**不要**回落到
 * KDG_DEFAULT_LISTEN_PORT —— NAT hook 改写用的是 kdg_cfg.listen_port，
 * 两者一旦不一致就是「把 DNS 改写到没人听的端口」。
 */
static int kdg_listener_bind(struct socket **out, int family, bool stream,
			     const void *addr)
{
	struct sockaddr_storage ss;
	struct socket *sock;
	u16 port = READ_ONCE(kdg_cfg.listen_port);
	int type = stream ? SOCK_STREAM : SOCK_DGRAM;
	int proto = stream ? IPPROTO_TCP : IPPROTO_UDP;
	int ret;

	*out = NULL;
	ret = sock_create_kern(&init_net, family, type, proto, &sock);
	if (ret)
		return ret;

	memset(&ss, 0, sizeof(ss));
	if (family == AF_INET) {
		struct sockaddr_in *s = (struct sockaddr_in *)&ss;

		s->sin_family = AF_INET;
		s->sin_port = htons(port);
		s->sin_addr.s_addr = addr ? *(const __be32 *)addr
					  : htonl(INADDR_LOOPBACK);
		ret = kernel_bind(sock, (struct sockaddr *)s, sizeof(*s));
	} else {
		struct sockaddr_in6 *s = (struct sockaddr_in6 *)&ss;

		s->sin6_family = AF_INET6;
		s->sin6_port = htons(port);
		if (addr)
			memcpy(&s->sin6_addr, addr, sizeof(s->sin6_addr));
		else
			s->sin6_addr = in6addr_loopback;
		ret = kernel_bind(sock, (struct sockaddr *)s, sizeof(*s));
	}
	if (!ret && stream)
		ret = kernel_listen(sock, KDG_LISTEN_BACKLOG);
	if (ret) {
		sock_release(sock);
		return ret;
	}
	kdg_listener_set_timeout(sock, READ_ONCE(kdg_cfg.default_deadline_ms));
	*out = sock;
	return 0;
}

static int kdg_listener_query(const struct kdg_doh_cfg *cfg,
			      const u8 *query, size_t qlen,
			      u8 *reply, size_t *reply_len)
{
	struct kdg_resolve_req req = {
		.cfg = cfg,
		.net_id = 0,
		.profile_gen = READ_ONCE(kdg_cfg.generation),
	};
	enum kdg_source source;

	return kdg_resolve(&req, query, qlen, reply, reply_len, &source);
}

/*
 * 把 resolve 的失败映射成 DNS rcode，并构造最小合规失败应答。
 *
 * 方案 §18（失败与退出策略）：严格模式下内核服务或上游失效时**返回
 * SERVFAIL/API 错误**，不回落运营商 DNS。这里就是「返回」的落点——
 * 早期实现走的是 `if (ret) return ret;`，即**静默丢包**，客户端只能等到
 * 自己的超时（真机实测 3 s+）且拿不到任何可区分信号，等价于把失败转嫁、
 * 而且掩盖了「确有失败」这一事实。
 *
 * 映射：
 *   - 内核侧 wire 校验失败  → FORMERR（这是「你发的不合法」，不是我们坏了）
 *   - 配额/队列满（-EAGAIN）→ SERVFAIL（§7.3 明确要求短时 SERVFAIL）
 *   - 其余（上游不可达、超时、TLS 失败…）→ SERVFAIL
 */
static u8 kdg_listener_rcode_for(int err)
{
	switch (err) {
	case -EBADMSG:			/* kdg_resolve 对坏 wire 的返回 */
	case -KDG_ST_EBADWIRE:		/* 迁移自字符设备侧的等价状态码 */
		return KDG_RCODE_FORMERR;
	case -KDG_ST_EOP:
	case -KDG_ST_EABI:
		return KDG_RCODE_NOTIMP;
	default:
		return KDG_RCODE_SERVFAIL;
	}
}

static bool kdg_listener_build_error(const u8 *query, size_t qlen, int err,
				     u8 *reply, size_t *reply_len)
{
	size_t len = 0;

	if (kdg_wire_make_error_response(query, qlen,
					 kdg_listener_rcode_for(err),
					 reply, *reply_len, &len))
		return false;
	*reply_len = len;
	return true;
}

static int kdg_listener_recv_udp(struct socket *sock, struct kdg_doh_cfg *cfg)
{
	u8 *query = kmalloc(KDG_LISTENER_RX_MAX, GFP_KERNEL);
	u8 *reply = kmalloc(KDG_LISTENER_RX_MAX, GFP_KERNEL);
	struct sockaddr_storage peer = { 0 };
	int peer_len = sizeof(peer);
	struct kvec in_vec = { .iov_base = query, .iov_len = KDG_LISTENER_RX_MAX };
	struct kvec out_vec = { .iov_base = reply, .iov_len = KDG_LISTENER_RX_MAX };
	struct msghdr in_msg = {
		.msg_name = &peer,
		.msg_namelen = peer_len,
	};
	struct msghdr out_msg = {
		.msg_name = &peer,
		.msg_namelen = peer_len,
	};
	size_t qlen, reply_len;
	int ret;

	if (!query || !reply) {
		kfree(query);
		kfree(reply);
		return -ENOMEM;
	}
	ret = kernel_recvmsg(sock, &in_msg, &in_vec, 1, KDG_LISTENER_RX_MAX, 0);
	peer_len = in_msg.msg_namelen;
	if (ret <= 0)
		goto out;
	qlen = (size_t)ret;

	reply_len = KDG_LISTENER_RX_MAX;
	ret = kdg_listener_query(cfg, query, qlen, reply, &reply_len);
	if (ret && !kdg_listener_build_error(query, qlen, ret, reply, &reply_len))
		goto out;

	out_vec.iov_len = reply_len;
	ret = kernel_sendmsg(sock, &out_msg, &out_vec, 1, reply_len);
out:
	kfree(query);
	kfree(reply);
	return ret;
}

/*
 * 从 recvmsg/accept 拿到的错误怎么处理。区分三类是必要的：
 *  - 正常唤醒类（超时、被信号打断）：立刻重试，不睡 —— 否则每个查询都要
 *    多付一次调度延迟；
 *  - socket 已经不可用（shutdown/关掉/连接断）：直接退出线程。这类错误
 *    会**持续**返回，继续循环就是 100% CPU 的忙等（本函数每轮还要
 *    kmalloc 两次，会连带制造内存churn）；
 *  - 其他未预期错误：睡一个短间隔再继续，把最坏情况的 CPU 占用钉在低位。
 */
enum kdg_rx_action {
	KDG_RX_RETRY,		/* 立刻重试 */
	KDG_RX_STOP,		/* 终止线程 */
	KDG_RX_BACKOFF,		/* 退避后重试 */
};

static enum kdg_rx_action kdg_rx_classify(int ret)
{
	switch (ret) {
	case -EINTR:
	case -ERESTARTSYS:
	case -EAGAIN:
	case -ETIMEDOUT:
		return KDG_RX_RETRY;
	case -ENOTCONN:
	case -ESHUTDOWN:
	case -EBADF:
	case -ECONNRESET:
	case -EPIPE:
		return KDG_RX_STOP;
	default:
		return KDG_RX_BACKOFF;
	}
}

static int kdg_listener_udp_thread(void *arg)
{
	struct socket *sock = arg;

	while (!kthread_should_stop()) {
		int ret = kdg_listener_recv_udp(sock, &g_listener.cfg);

		if (ret >= 0)
			continue;
		switch (kdg_rx_classify(ret)) {
		case KDG_RX_RETRY:
			break;
		case KDG_RX_STOP:
			goto out;
		case KDG_RX_BACKOFF:
			usleep_range(1000, 2000);
			break;
		}
	}
out:
	return 0;
}

static int kdg_listener_recv_exact(struct socket *sock, u8 *buf, size_t len)
{
	size_t off = 0;

	while (off < len) {
		struct kvec vec = { .iov_base = buf + off, .iov_len = len - off };
		struct msghdr msg = { 0 };
		int ret = kernel_recvmsg(sock, &msg, &vec, 1, len - off, 0);

		if (ret <= 0)
			return ret ? ret : -ECONNRESET;
		off += ret;
	}
	return 0;
}

static int kdg_listener_tcp_connection(struct socket *sock)
{
	u8 *query = kmalloc(KDG_LISTENER_RX_MAX, GFP_KERNEL);
	u8 *reply = kmalloc(KDG_LISTENER_RX_MAX, GFP_KERNEL);
	u8 prefix[2];
	struct kvec vec;
	struct msghdr msg = { 0 };
	size_t reply_len;
	int ret;

	if (!query || !reply) {
		ret = -ENOMEM;
		goto out;
	}
	ret = kdg_listener_recv_exact(sock, prefix, sizeof(prefix));
	if (ret)
		goto out;
	{
		u16 qlen = ((u16)prefix[0] << 8) | prefix[1];
		if (!qlen || qlen > KDG_LISTENER_RX_MAX) {
			ret = -EMSGSIZE;
			goto out;
		}
		ret = kdg_listener_recv_exact(sock, query, qlen);
		if (ret)
			goto out;
		reply_len = KDG_LISTENER_RX_MAX;
		ret = kdg_listener_query(&g_listener.cfg, query, qlen, reply,
					 &reply_len);
		/* 与 UDP 同理：失败要**回一个应答**（方案 §18），不能一断了之。 */
		if (ret && !kdg_listener_build_error(query, qlen, ret, reply,
						     &reply_len))
			goto out;
		if (reply_len > 0xffff) {
			ret = -EMSGSIZE;
			goto out;
		}
		prefix[0] = (u8)(reply_len >> 8);
		prefix[1] = (u8)reply_len;
		vec.iov_base = prefix;
		vec.iov_len = sizeof(prefix);
		ret = kernel_sendmsg(sock, &msg, &vec, 1, sizeof(prefix));
		if (ret != sizeof(prefix))
			goto out;
		vec.iov_base = reply;
		vec.iov_len = reply_len;
		ret = kernel_sendmsg(sock, &msg, &vec, 1, reply_len);
	}
out:
	kfree(query);
	kfree(reply);
	return ret;
}

static int kdg_listener_tcp_thread(void *arg)
{
	struct socket *listen = arg;

	while (!kthread_should_stop()) {
		struct socket *client = NULL;
		int ret = kernel_accept(listen, &client, 0);

		if (ret < 0) {
			switch (kdg_rx_classify(ret)) {
			case KDG_RX_RETRY:
				break;
			case KDG_RX_STOP:
				goto out;
			case KDG_RX_BACKOFF:
				usleep_range(1000, 2000);
				break;
			}
			continue;
		}
		kdg_listener_set_timeout(client, READ_ONCE(kdg_cfg.default_deadline_ms));
		kdg_listener_tcp_connection(client);
		kernel_sock_shutdown(client, SHUT_RDWR);
		sock_release(client);
	}
out:
	return 0;
}

static void kdg_listener_shutdown_socket(struct socket *sock)
{
	if (sock)
		kernel_sock_shutdown(sock, SHUT_RDWR);
}

static void kdg_listener_release_socket(struct socket **sock)
{
	if (*sock) {
		sock_release(*sock);
		*sock = NULL;
	}
}

bool kdg_listener_ready(void)
{
	return READ_ONCE(g_listener.ready);
}

/* ── 客户端入口（热点 / USB 共享）────────────────────────────────────────
 *
 * 为什么需要这一组：LOCAL_OUT 的 REDIRECT 目标是 loopback，PREROUTING 的
 * 目标却是**入接口自己的地址**。热点客户端的 53 是转发流量，只走 PREROUTING，
 * 所以必须有一份绑定在该接口地址上的 listener，否则改写到的地方没人应答
 * （更糟：nf_nat_redirect_* 在接口没有地址时直接 NF_DROP）。
 *
 * 生命周期完全由 netdev 通知链驱动 —— 地址出现即建、消失即拆。接口上的
 * 地址会随 DHCP 变化，所以「记住上一次绑的地址、变了就重绑」是必需逻辑，
 * 而不是优化。
 */

/* 已建 listener 的客户端入口数（诊断用；GET_HEALTH 上报）。 */
u32 kdg_listener_client_count(void)
{
	u32 n = 0;
	int i;

	for (i = 0; i < KDG_MAX_CLIENT_IF; i++)
		if (READ_ONCE(kdg_client_ifaces[i].listener_up))
			n++;
	return n;
}

u32 kdg_listener_client_caps(struct net *net, const struct net_device *dev)
{
	const char *name;
	int i;

	if (!dev || net != &init_net)
		return 0;
	name = dev->name;
	for (i = 0; i < KDG_MAX_CLIENT_IF; i++) {
		const struct kdg_client_iface *ci = &kdg_client_ifaces[i];
		u32 caps = 0;

		if (!READ_ONCE(ci->listener_up))
			continue;
		if (strncmp(ci->name, name, KDG_IFNAME_LEN) != 0)
			continue;
		if (ci->has4)
			caps |= KDG_CLI_CAP_V4;
		if (ci->has6)
			caps |= KDG_CLI_CAP_V6;
		return caps;
	}
	return 0;
}

static bool kdg_client_name_allowed(const char *name)
{
	unsigned int i;

	for (i = 0; i < g_client_name_count; i++)
		if (strncmp(g_client_names[i], name, KDG_CLIENT_NAME_MAX) == 0)
			return true;
	return false;
}

static struct kdg_client_iface *kdg_client_find(const char *name)
{
	int i;

	for (i = 0; i < KDG_MAX_CLIENT_IF; i++)
		if (kdg_client_ifaces[i].name[0] &&
		    strncmp(kdg_client_ifaces[i].name, name, KDG_IFNAME_LEN) == 0)
			return &kdg_client_ifaces[i];
	return NULL;
}

static struct kdg_client_iface *kdg_client_free_slot(void)
{
	int i;

	for (i = 0; i < KDG_MAX_CLIENT_IF; i++)
		if (!kdg_client_ifaces[i].name[0])
			return &kdg_client_ifaces[i];
	return NULL;
}

/*
 * 读取接口上「REDIRECT 会选中的那个地址」。必须与 nf_nat_redirect_* 的选择
 * 规则**逐字一致**，否则绑到的地址和改写到的地址对不上 —— 后果是客户端
 * 的查询被改写到没人监听的地址上（静默黑洞）。
 *
 * IPv4：nf_nat_redirect_ipv4 取 `ifa_list` 链首项。
 *
 * IPv6：⚠️ 规则比看上去绕，这里踩过一次。nf_nat_redirect_ipv6 取
 * `addr_list` 里**第一个通过 nf_nat_redirect_ipv6_usable() 的地址**，并且
 * **只在目的地不是全局 scope 时才追加 scope 匹配**
 * （`if (scope) { ... }`，而全局地址的 scope 值是 0）。也就是说：
 * **全局目的地 ⇒ 不做 scope 过滤 ⇒ 第一个可用地址可能正好是链路本地**。
 *
 * 所以这里也取「第一个可用地址」而不是「第一个全局地址」：只有当它**确实
 * 是全局**时才申报 KDG_CLI_CAP_V6（hook 侧本来也只接管全局目的地）。
 * 这样「绑定目标」与「改写目标」在构造上一致；不一致时宁可不接管。
 */
static void kdg_client_read_addrs(struct net_device *dev, struct kdg_client_iface *ci)
{
	struct in_device *in_dev;
	const struct in_ifaddr *ifa;
	struct inet6_dev *idev;
	const struct inet6_ifaddr *ifa6;

	memset(ci->addr6, 0, sizeof(ci->addr6));
	ci->addr4 = 0;
	ci->has4 = false;
	ci->has6 = false;

	rcu_read_lock();
	in_dev = __in_dev_get_rcu(dev);
	if (in_dev) {
		for (ifa = rcu_dereference(in_dev->ifa_list); ifa;
		     ifa = rcu_dereference(ifa->ifa_next)) {
			ci->addr4 = ifa->ifa_local;
			ci->has4 = true;
			break;
		}
	}

	idev = __in6_dev_get(dev);
	if (idev) {
		read_lock_bh(&idev->lock);
		list_for_each_entry(ifa6, &idev->addr_list, if_list) {
			/* 与 nf_nat_redirect_ipv6_usable() 同源的可用性判据。 */
			if ((ifa6->flags & IFA_F_TENTATIVE) &&
			    !(ifa6->flags & IFA_F_OPTIMISTIC))
				continue;
			if (ipv6_addr_type(&ifa6->addr) & IPV6_ADDR_MAPPED)
				continue;
			memcpy(ci->addr6, &ifa6->addr, sizeof(ci->addr6));
			ci->has6 = kdg_v6_addr_is_global((const u8 *)&ifa6->addr);
			break;
		}
		read_unlock_bh(&idev->lock);
	}
	if (unlikely(READ_ONCE(kdg_debug))) {
		struct in_ifaddr *dbg_ifa;
		int n = 0;

		if (in_dev)
			for (dbg_ifa = rcu_dereference(in_dev->ifa_list); dbg_ifa;
			     dbg_ifa = rcu_dereference(dbg_ifa->ifa_next))
				n++;
		pr_info("%s: read_addrs ip_ptr=%p in_dev_dev=%s dead=%d n_ifa=%d has4=%d has6=%d flags=0x%x\n",
			dev->name, rcu_dereference(dev->ip_ptr),
			(in_dev && in_dev->dev) ? in_dev->dev->name : "(null)",
			in_dev ? in_dev->dead : -1, n, ci->has4, ci->has6,
			dev->flags);
	}
	rcu_read_unlock();
}

static void kdg_client_release(struct kdg_client_iface *ci)
{
	struct task_struct *tasks[4];

	mutex_lock(&g_listener.lock);
	/* 先落 listener_up，再拆 socket。反过来的话 NAT hook 会在这个窗口里
	 * 把包改写到正在被 shutdown 的 socket 上。 */
	WRITE_ONCE(ci->listener_up, false);
	tasks[0] = ci->udp4_task;
	tasks[1] = ci->udp6_task;
	tasks[2] = ci->tcp4_task;
	tasks[3] = ci->tcp6_task;
	ci->udp4_task = NULL;
	ci->udp6_task = NULL;
	ci->tcp4_task = NULL;
	ci->tcp6_task = NULL;
	kdg_listener_shutdown_socket(ci->udp4);
	kdg_listener_shutdown_socket(ci->udp6);
	kdg_listener_shutdown_socket(ci->tcp4);
	kdg_listener_shutdown_socket(ci->tcp6);
	mutex_unlock(&g_listener.lock);

	{
		int i;

		for (i = 0; i < ARRAY_SIZE(tasks); i++)
			if (tasks[i] && !IS_ERR(tasks[i]))
				kthread_stop(tasks[i]);
	}

	mutex_lock(&g_listener.lock);
	kdg_listener_release_socket(&ci->udp4);
	kdg_listener_release_socket(&ci->udp6);
	kdg_listener_release_socket(&ci->tcp4);
	kdg_listener_release_socket(&ci->tcp6);
	ci->name[0] = '\0';
	ci->has4 = false;
	ci->has6 = false;
	mutex_unlock(&g_listener.lock);
}

/*
 * 在接口当前地址上建 listener。四个 socket 全部建成后才置 listener_up ——
 * 部分成功一律回滚，绝不发布「半可用」的条目。
 *
 * 调用方必须先确保该接口不在表中（sync 会先 release）。
 */
static int kdg_client_activate(struct net_device *dev)
{
	struct kdg_client_iface *ci;
	int ret;

	mutex_lock(&g_listener.lock);
	ci = kdg_client_free_slot();
	if (!ci) {
		mutex_unlock(&g_listener.lock);
		pr_warn("%s: 客户端入口槽位已满（上限 %d），本接口不接管\n",
			dev->name, KDG_MAX_CLIENT_IF);
		return -ENOSPC;
	}
	strscpy(ci->name, dev->name, sizeof(ci->name));
	mutex_unlock(&g_listener.lock);

	kdg_client_read_addrs(dev, ci);
	if (!ci->has4 && !ci->has6) {
		if (unlikely(READ_ONCE(kdg_debug)))
			pr_info("%s: 入口事件时接口还没有可用地址，跳过\n",
				dev->name);
		ci->name[0] = '\0';
		return -EADDRNOTAVAIL;
	}

	if (ci->has4) {
		ret = kdg_listener_bind(&ci->udp4, AF_INET, false, &ci->addr4);
		if (ret) {
			pr_warn("%s: UDP/IPv4 绑定失败 %d，本接口不接管\n",
				dev->name, ret);
			goto fail;
		}
		ret = kdg_listener_bind(&ci->tcp4, AF_INET, true, &ci->addr4);
		if (ret) {
			pr_warn("%s: TCP/IPv4 绑定失败 %d，本接口不接管\n",
				dev->name, ret);
			goto fail;
		}
	}
	if (ci->has6) {
		ret = kdg_listener_bind(&ci->udp6, AF_INET6, false, ci->addr6);
		if (ret) {
			pr_warn("%s: UDP/IPv6 绑定失败 %d，退回 IPv4-only\n",
				dev->name, ret);
			ci->has6 = false;
		} else {
			ret = kdg_listener_bind(&ci->tcp6, AF_INET6, true, ci->addr6);
			if (ret) {
				pr_warn("%s: TCP/IPv6 绑定失败 %d，退回 IPv4-only\n",
					dev->name, ret);
				kdg_listener_release_socket(&ci->udp6);
				ci->has6 = false;
			}
		}
	}

	/* kthread_run 对 NULL 入参会创建线程然后立刻崩，所以先判 socket。 */
	ci->udp4_task = ci->udp4 ? kthread_run(kdg_listener_udp_thread, ci->udp4,
					       "kdg-c-udp4") : NULL;
	ci->tcp4_task = ci->tcp4 ? kthread_run(kdg_listener_tcp_thread, ci->tcp4,
					       "kdg-c-tcp4") : NULL;
	ci->udp6_task = ci->udp6 ? kthread_run(kdg_listener_udp_thread, ci->udp6,
					       "kdg-c-udp6") : NULL;
	ci->tcp6_task = ci->tcp6 ? kthread_run(kdg_listener_tcp_thread, ci->tcp6,
					       "kdg-c-tcp6") : NULL;
	if (IS_ERR_OR_NULL(ci->udp4_task) || IS_ERR_OR_NULL(ci->tcp4_task) ||
	    (ci->udp6 && IS_ERR_OR_NULL(ci->udp6_task)) ||
	    (ci->tcp6 && IS_ERR_OR_NULL(ci->tcp6_task))) {
		ret = -ENOMEM;
		goto fail;
	}

	WRITE_ONCE(ci->listener_up, true);
	pr_info("%s: 客户端入口 listener 就绪（IPv4%s）\n", dev->name,
		ci->has6 ? "+IPv6" : "");
	return 0;

fail:
	kdg_client_release(ci);
	return ret;
}

/* 与真实 netdev 事件区分开的哨兵值，用于 PREPARE 时的首次全量扫描。 */
#define KDG_EV_SCAN		(~0UL)

static void kdg_client_sync(struct net_device *dev, unsigned long event)
{
	struct kdg_client_iface *ci, probe;

	if (!dev)
		return;

	if (unlikely(READ_ONCE(kdg_debug)) && kdg_client_name_allowed(dev->name))
		pr_info("%s: 入口事件 ev=%lu running=%d flags=0x%x dev=%p net=%p\n",
			dev->name, event, netif_running(dev), dev->flags, dev,
			dev_net(dev));

	/*
	 * 三条早退，缺任何一条都会出错：
	 *
	 *  - **只看 init_net**：通知链是全局的（所有 netns 都发），而
	 *    kdg_client_bind() 固定 `sock_create_kern(&init_net, ...)`。
	 *    容器/VPN 的 netns 里出现同名接口（默认名单里有 wlan0/usb0 这类
	 *    通用名）时会白占一个槽位、并在每次地址事件时打一条告警。
	 *    而 hook 侧本来就只认 init_net（见 kdg_listener_client_caps）。
	 *
	 *  - **拆机中直接返回**：kdg_listener_stop() 期间不能再建 listener，
	 *    否则建出来的那个不会被释放 —— 模块卸载后它还在跑模块代码，
	 *    就是模块镜像的 use-after-free。stop() 已在拿 rtnl 之后、动任何
	 *    socket 之前就把 stopping 立起来，这里是第二道闸。
	 *
	 *  - **名字/链路状态**：名单外或未 up 的接口不建，已建的要撤。
	 */
	if (dev_net(dev) != &init_net || READ_ONCE(g_listener.stopping))
		return;

	if (!kdg_client_name_allowed(dev->name) ||
	    !netif_running(dev) || !(dev->flags & IFF_UP)) {
		ci = kdg_client_find(dev->name);
		if (ci)
			kdg_client_release(ci);
		return;
	}

	/* 已在表中：地址没变就不动。Wi-Fi/蜂窝抖动会高频发 NETDEV_CHANGE，
	 * 每次都重建 socket 会让热点客户端在网络抖动期反复失去 DNS。 */
	ci = kdg_client_find(dev->name);
	if (ci) {
		memset(&probe, 0, sizeof(probe));
		kdg_client_read_addrs(dev, &probe);
		if (ci->has4 == probe.has4 && ci->has6 == probe.has6 &&
		    (!ci->has4 || ci->addr4 == probe.addr4) &&
		    (!ci->has6 || memcmp(ci->addr6, probe.addr6, 16) == 0))
			return;
		kdg_client_release(ci);
	}

	kdg_client_activate(dev);
}

static int kdg_client_netdev_event(struct notifier_block *nb,
				   unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);

	switch (event) {
	case NETDEV_UP:
	case NETDEV_CHANGE:
	case NETDEV_CHANGEADDR:
	case NETDEV_DOWN:
	case NETDEV_UNREGISTER:
		kdg_client_sync(dev, event);
		break;
	default:
		break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block g_client_notifier = {
	.notifier_call	= kdg_client_netdev_event,
};

/*
 * ⚠️ 为什么**必须**同时挂 inet/inet6 地址通知链：
 *
 * `netdev_chain` 只在**链路状态**变化时发事件。「接口已经 up 之后才配上
 * 地址」这条路径**不会**产生任何 netdev 事件 —— IPv4 侧地址插入走的是
 * `inet_insert_ifa()` 里的 `blocking_notifier_call_chain(&inetaddr_chain,
 * NETDEV_UP, ifa)`（net/ipv4/devinet.c），IPv6 侧同理走 inet6addr_chain。
 *
 * 这不是边角情形，恰恰是**热点/USB 共享的真实时序**：接口先被拉起
 * （NETDEV_UP，此刻还没有地址 ⇒ 我们正确地跳过），地址随后由 netd 配上
 * ——如果只听 netdev_chain，这个接口就永远不会被接管，而且**看起来一切
 * 正常**（只在连接建立时才暴露：客户端 DNS 超时）。首次实现就踩了这个坑。
 *
 * 这两个通知链都是 blocking notifier，回调在进程上下文、可睡眠，与
 * netdev 通知链的约束一致；内核在调用它们时持有 rtnl，所以回调里同样
 * **不能**再去拿 rtnl（kdg_client_sync 不碰 rtnl，全量扫描才拿）。
 */
static int kdg_inetaddr_event(struct notifier_block *nb, unsigned long event,
			      void *ptr)
{
	const struct in_ifaddr *ifa = ptr;

	if (ifa && ifa->ifa_dev && ifa->ifa_dev->dev)
		kdg_client_sync(ifa->ifa_dev->dev, event);
	return NOTIFY_DONE;
}

static int kdg_inet6addr_event(struct notifier_block *nb, unsigned long event,
			       void *ptr)
{
	const struct inet6_ifaddr *ifa = ptr;

	if (ifa && ifa->idev && ifa->idev->dev)
		kdg_client_sync(ifa->idev->dev, event);
	return NOTIFY_DONE;
}

static struct notifier_block g_client_inet_notifier = {
	.notifier_call	= kdg_inetaddr_event,
};

static struct notifier_block g_client_inet6_notifier = {
	.notifier_call	= kdg_inet6addr_event,
};

static bool g_client_notifier_registered;

static void kdg_client_scan_existing(void)
{
	struct net_device *dev;

	rtnl_lock();
	for_each_netdev(&init_net, dev)
		kdg_client_sync(dev, KDG_EV_SCAN);
	rtnl_unlock();
}

static void kdg_client_release_all(void)
{
	int i;

	for (i = 0; i < KDG_MAX_CLIENT_IF; i++)
		if (kdg_client_ifaces[i].name[0])
			kdg_client_release(&kdg_client_ifaces[i]);
}

/*
 * 解析模块参数 client_ifaces。空串表示**禁用**客户端入口接管（只用
 * loopback，热点客户端 DNS 走原链路）—— 这是有意的可关闭项，不是错误。
 * 名字过长/重复只告警并跳过，不让模块加载失败：一个拼错的接口名不该
 * 让整个 DNS 模块装不上。
 */
int kdg_listener_client_config(const char *spec)
{
	char buf[KDG_MAX_CLIENT_CANDIDATES * KDG_CLIENT_NAME_MAX];
	char *p, *tok;

	g_client_name_count = 0;
	if (!spec)
		return 0;

	strscpy(buf, spec, sizeof(buf));
	p = buf;
	while ((tok = strsep(&p, ",")) != NULL) {
		size_t len;

		/* 去掉首尾空白，允许 "rndis0, wlan0" 这种写法。 */
		while (*tok == ' ' || *tok == '\t')
			tok++;
		len = strlen(tok);
		while (len && (tok[len - 1] == ' ' || tok[len - 1] == '\t'))
			tok[--len] = '\0';
		if (!len)
			continue;
		if (len >= KDG_CLIENT_NAME_MAX) {
			pr_warn("client_ifaces: 名字过长已忽略: %s\n", tok);
			continue;
		}
		if (g_client_name_count >= KDG_MAX_CLIENT_CANDIDATES) {
			pr_warn("client_ifaces: 候选超过 %d 个，其余忽略\n",
				KDG_MAX_CLIENT_CANDIDATES);
			break;
		}
		strscpy(g_client_names[g_client_name_count++], tok,
			KDG_CLIENT_NAME_MAX);
	}
	return 0;
}

static int kdg_client_notifier_register(void)
{
	int ret;

	if (g_client_notifier_registered)
		return 0;
	ret = register_netdevice_notifier(&g_client_notifier);
	if (ret) {
		pr_err("netdev 通知链注册失败: %d（客户端入口不接管）\n", ret);
		return ret;
	}
	/* 地址链注册失败**不**回滚 netdev 链：链路事件仍能覆盖「先配地址、
	 * 后拉起接口」的时序，只是覆盖不全。如实记日志，让 GET_HEALTH 的
	 * client_ifaces 计数把差异暴露出来。 */
	ret = register_inetaddr_notifier(&g_client_inet_notifier);
	if (ret)
		pr_err("inetaddr 通知链注册失败: %d（接口 up 后再配 IPv4 地址将不被接管）\n",
		       ret);
	ret = register_inet6addr_notifier(&g_client_inet6_notifier);
	if (ret)
		pr_err("inet6addr 通知链注册失败: %d（接口 up 后再配 IPv6 地址将不被接管）\n",
		       ret);
	g_client_notifier_registered = true;
	return 0;
}

static void kdg_client_notifier_unregister(void)
{
	if (!g_client_notifier_registered)
		return;
	unregister_inet6addr_notifier(&g_client_inet6_notifier);
	unregister_inetaddr_notifier(&g_client_inet_notifier);
	unregister_netdevice_notifier(&g_client_notifier);
	g_client_notifier_registered = false;
}

static int kdg_listener_probe_upstream(void)
{
	static const u8 query[] = {
		0x4b, 0x44, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		0, 1, 0, 1,
	};
	struct kdg_doh_cfg cfg;
	u8 *reply;
	size_t reply_len = KDG_DOH_RX_MAX;
	int ret;

	if (!kdg_tls_ca_count())
		return -EAGAIN;
	reply = kmalloc(KDG_DOH_RX_MAX, GFP_KERNEL);
	if (!reply)
		return -ENOMEM;
	kdg_doh_default_cfg(&cfg);
	ret = kdg_doh_query(&cfg, query, sizeof(query), reply, &reply_len);
	if (!ret)
		ret = kdg_wire_match_response(query, sizeof(query), reply,
					      reply_len, &(struct kdg_summary){ 0 });
	kfree(reply);
	return ret;
}

int kdg_listener_prepare(void)
{
	int ret;

	/* 快路径：已就绪直接返回，不必先白跑一次上游探测。 */
	if (READ_ONCE(g_listener.ready))
		return 0;

	/*
	 * ⚠️ 上游探测**必须在 g_listener.lock 之外**做。
	 *
	 * 它是一次真实的 DoH 往返（DNS over TLS 握手 + 一次查询），实测
	 * 143–257 ms；上游异常时要跑满重试预算，接近 3 s 的 deadline。
	 * 而这个 mutex 现在也被 netdev/inetaddr 通知链的回调（经
	 * kdg_client_sync）持有 —— 那些回调是**持 rtnl** 进来的，也就是说
	 * 持锁做探测会把全局的 rtnl 一起按住几秒，全系统的路由/netlink
	 * 操作都被拖住，代价远大于本模块省下的一次探测。
	 *
	 * 代价是并发 PREPARE 可能各跑一次探测（重复的 DoH 查询，无害），
	 * 真正的状态机仍在锁内串行。
	 */
	ret = kdg_listener_probe_upstream();
	if (ret)
		return ret;

	mutex_lock(&g_listener.lock);
	if (g_listener.ready) {
		mutex_unlock(&g_listener.lock);
		return 0;
	}
	if (g_listener.stopping) {
		mutex_unlock(&g_listener.lock);
		return -ESHUTDOWN;
	}
	kdg_doh_default_cfg(&g_listener.cfg);
	ret = kdg_listener_bind(&g_listener.udp4, AF_INET, false, NULL);
	if (ret)
		goto fail;
	ret = kdg_listener_bind(&g_listener.udp6, AF_INET6, false, NULL);
	if (ret)
		goto fail;
	ret = kdg_listener_bind(&g_listener.tcp4, AF_INET, true, NULL);
	if (ret)
		goto fail;
	ret = kdg_listener_bind(&g_listener.tcp6, AF_INET6, true, NULL);
	if (ret)
		goto fail;
	g_listener.udp4_task = kthread_run(kdg_listener_udp_thread, g_listener.udp4,
					   "kdg-udp4");
	if (IS_ERR(g_listener.udp4_task)) {
		ret = PTR_ERR(g_listener.udp4_task);
		g_listener.udp4_task = NULL;
		goto fail;
	}
	g_listener.udp6_task = kthread_run(kdg_listener_udp_thread, g_listener.udp6,
					   "kdg-udp6");
	if (IS_ERR(g_listener.udp6_task)) {
		ret = PTR_ERR(g_listener.udp6_task);
		g_listener.udp6_task = NULL;
		goto fail;
	}
	g_listener.tcp4_task = kthread_run(kdg_listener_tcp_thread, g_listener.tcp4,
					   "kdg-tcp4");
	if (IS_ERR(g_listener.tcp4_task)) {
		ret = PTR_ERR(g_listener.tcp4_task);
		g_listener.tcp4_task = NULL;
		goto fail;
	}
	g_listener.tcp6_task = kthread_run(kdg_listener_tcp_thread, g_listener.tcp6,
					   "kdg-tcp6");
	if (IS_ERR(g_listener.tcp6_task)) {
		ret = PTR_ERR(g_listener.tcp6_task);
		g_listener.tcp6_task = NULL;
		goto fail;
	}
	/* 发布就绪前再查一次 stopping：stop() 的第一件事（在同一把锁内）就是
	 * 置位它。没有这一查，一个已经走到这里的 PREPARE 会在 DISABLE 已经把
	 * 状态机标记为停机之后仍然 `ready=true` 地返回成功，调用方据此
	 * COMMIT 就会把 53 改写到正在被拆掉的 listener 上。 */
	if (g_listener.stopping) {
		ret = -ESHUTDOWN;
		goto fail;
	}
	WRITE_ONCE(g_listener.ready, true);
	mutex_unlock(&g_listener.lock);
	pr_info("UDP/TCP loopback listener ready on port %u\n",
		READ_ONCE(kdg_cfg.listen_port));

	/* 客户端入口监听器**不是** PREPARE 成功的前提：热点没开、候选接口
	 * 不存在、槽位满了，都只意味着「这些接口的 53 不接管」，不该让整个
	 * PREPARE 失败而挡住 LOCAL_OUT 路径。失败一律降级 + 告警。 */
	kdg_client_notifier_register();
	kdg_client_scan_existing();
	return 0;
fail:
	g_listener.stopping = true;
	kdg_listener_shutdown_socket(g_listener.udp4);
	kdg_listener_shutdown_socket(g_listener.udp6);
	kdg_listener_shutdown_socket(g_listener.tcp4);
	kdg_listener_shutdown_socket(g_listener.tcp6);
	{
		struct task_struct *tasks[] = {
			g_listener.udp4_task, g_listener.udp6_task,
			g_listener.tcp4_task, g_listener.tcp6_task,
		};
		int i;
		g_listener.udp4_task = NULL;
		g_listener.udp6_task = NULL;
		g_listener.tcp4_task = NULL;
		g_listener.tcp6_task = NULL;
		mutex_unlock(&g_listener.lock);
		for (i = 0; i < ARRAY_SIZE(tasks); i++)
			if (tasks[i])
				kthread_stop(tasks[i]);
	}
	mutex_lock(&g_listener.lock);
	kdg_listener_release_socket(&g_listener.udp4);
	kdg_listener_release_socket(&g_listener.udp6);
	kdg_listener_release_socket(&g_listener.tcp4);
	kdg_listener_release_socket(&g_listener.tcp6);
	g_listener.stopping = false;
	mutex_unlock(&g_listener.lock);
	return ret;
}

void kdg_listener_stop(void)
{
	struct task_struct *tasks[4];
	int i;

	/*
	 * 两件事的顺序在这里是硬要求，反过来都有真实故障：
	 *
	 * 1) **先把 stopping 立起来、ready 落下去，再动任何 socket**。
	 *    之前是「先拆客户端 listener，再置 stopping/ready」，于是拆的过程中
	 *    `kdg_listener_ready()` 仍报 true：并发的 PREPARE 会走
	 *    `if (!kdg_listener_ready())` 的快路径、**不建 listener 就返回成功**，
	 *    紧接着 COMMIT 若也落在同一个窗口里就会打开接管 —— 而 listener 正在
	 *    被拆掉 ⇒ 53 全被改写到没人应答的端口，手机 DNS 直接断。
	 *
	 * 2) **先注销通知链，再拆客户端 listener**。注销本身就把在途回调等完
	 *    了：netdev 通知链的回调都在 rtnl 下跑，而
	 *    `unregister_netdevice_notifier()` 内部要取 rtnl（见
	 *    net/core/dev.c，**所以它必须留在我们自己不持 rtnl 的上下文里**）；
	 *    inet/inet6 地址链是 blocking notifier，注销要拿写锁，而回调持读锁。
	 *    两者返回后都不会再有回调进来，`write -> unregister -> release`
	 *    这个次序因此就是完整的互斥，**不需要再额外持 rtnl 去圈 release**
	 *    —— 那会把 rtnl 按住 kthread_stop 的时长（客户端线程可能正卡在一次
	 *    DoH 往返里，最长到 deadline），代价远大于收益。
	 *
	 *    另外 `kdg_client_sync()` 开头也查 stopping，是给「刚过检查就被
	 *    置位」的窄窗口兜的那一手。
	 */
	mutex_lock(&g_listener.lock);
	g_listener.stopping = true;
	WRITE_ONCE(g_listener.ready, false);
	mutex_unlock(&g_listener.lock);

	kdg_client_notifier_unregister();
	kdg_client_release_all();

	mutex_lock(&g_listener.lock);
	tasks[0] = g_listener.udp4_task;
	tasks[1] = g_listener.udp6_task;
	tasks[2] = g_listener.tcp4_task;
	tasks[3] = g_listener.tcp6_task;
	g_listener.udp4_task = NULL;
	g_listener.udp6_task = NULL;
	g_listener.tcp4_task = NULL;
	g_listener.tcp6_task = NULL;
	kdg_listener_shutdown_socket(g_listener.udp4);
	kdg_listener_shutdown_socket(g_listener.udp6);
	kdg_listener_shutdown_socket(g_listener.tcp4);
	kdg_listener_shutdown_socket(g_listener.tcp6);
	mutex_unlock(&g_listener.lock);
	for (i = 0; i < ARRAY_SIZE(tasks); i++)
		if (tasks[i] && !IS_ERR(tasks[i]))
			kthread_stop(tasks[i]);
	mutex_lock(&g_listener.lock);
	kdg_listener_release_socket(&g_listener.udp4);
	kdg_listener_release_socket(&g_listener.udp6);
	kdg_listener_release_socket(&g_listener.tcp4);
	kdg_listener_release_socket(&g_listener.tcp6);
	g_listener.stopping = false;
	mutex_unlock(&g_listener.lock);
}

	int kdg_listener_init_state(void)
{
	mutex_init(&g_listener.lock);
	return 0;
}

