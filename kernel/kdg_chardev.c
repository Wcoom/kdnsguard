/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_chardev.c —— 查询面：受控字符设备 /dev/kdnsguard（方案 §14.2）。
 *
 * 为什么查询不走 Generic Netlink：netlink 是**管理面**，承载配置事务与状态
 * 查询；DNS 正文是高频小块二进制，走 netlink 会让属性解析（对齐、拷贝、
 * 逐属性校验）成为每一次查询的固定开销。方案 §14.2 因此把查询面单列。
 *
 * 首期形态（有意从简，逐条对应方案 §14.2 的措辞）：
 *  - **不做共享内存 mmap 环形队列**。方案原文：「首期不做 mmap，减少内存
 *    生命周期与竞态」。故用 write/read/poll 的拷贝语义。
 *  - 一次 write 提交一条查询，**同步**完成（本层运行在进程上下文，可睡眠），
 *    结果留在下一个 read 里。取消（CANCEL）暂不实现 —— 同步语义下调用方
 *    自己超时返回即可；P2 引入异步队列时再加。
 *  - 每个打开的文件描述符绑定一份独立上下文（caller-bound context），
 *    互不干扰；close 时全部释放。
 *
 * 拒绝规则（方案 §14.2 点名要求）：
 *  - abi_version 不认识 → KDG_ST_EABI
 *  - opcode 不认识 → KDG_ST_EOP
 *  - 长度溢出或越界 → KDG_ST_EMSGSIZE
 *  - 未配置信任锚 → KDG_ST_EUPSTREAM（不是 EPERM：不是权限问题）
 */
#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/poll.h>
#include <linux/mutex.h>
#include <linux/cred.h>
#include <linux/uidgid.h>

#include "kdg.h"
#include "kdg_doh.h"
#include "kdg_resolve.h"
#include "kdg_quota.h"

struct kdg_file_ctx {
	struct mutex		lock;		/* 串行化同一 fd 上的 write/read */
	struct kdg_doh_cfg	cfg;
	u8		       *resp;		/* kdg_resp_v1 + response_wire */
	size_t			resp_len;
	size_t			resp_off;
	bool			have_resp;
};

static dev_t		kdg_devno;
static struct cdev	kdg_cdev;
static DEFINE_MUTEX(kdg_ops_lock);
static DECLARE_WAIT_QUEUE_HEAD(kdg_ops_wait);
static atomic_t kdg_active_ops = ATOMIC_INIT(0);
static bool kdg_stopping;

static bool kdg_op_enter(void)
{
	bool ok;

	mutex_lock(&kdg_ops_lock);
	ok = !kdg_stopping;
	if (ok)
		atomic_inc(&kdg_active_ops);
	mutex_unlock(&kdg_ops_lock);
	return ok;
}

static void kdg_op_exit(void)
{
	if (atomic_dec_and_test(&kdg_active_ops))
		wake_up_all(&kdg_ops_wait);
}

/* 前置声明：kdg_do_query 先用到它，定义在本节之后。 */
static int kdg_status_from_errno(int err);

/* ── 请求/响应编解码 ─────────────────────────────────────────────────── */

static int kdg_do_query(struct kdg_file_ctx *ctx, const struct kdg_req_v1 *req,
			const u8 *qwire, size_t qlen)
{
	u8 *rwire = NULL;
	size_t rlen = KDG_MAX_WIRE_MSG;
	struct kdg_resp_v1 hdr;
	int ret = 0, n;
	u32 generation = READ_ONCE(kdg_cfg.generation);

	rwire = kmalloc(KDG_MAX_WIRE_MSG, GFP_KERNEL);
	if (!rwire)
		return -ENOMEM;

	memset(&ctx->cfg, 0, sizeof(ctx->cfg));
	kdg_doh_default_cfg(&ctx->cfg);
	if (req->deadline_ms)
		ctx->cfg.deadline_ms = req->deadline_ms;

	/*
	 * 配额准入（方案 §7.3「每调用方 token bucket」）。
	 *
	 * 身份取自**内核凭据**而不是请求里自报的字段 —— 方案 §7.2/§14.2
	 * 都点名「不信任用户传入的 UID」。超额时明确失败（KDG_ST_EAGAIN）
	 * 而不是排队：同步模型下没有队列可排，而「不让一个跑飞的 App
	 * 阻塞整机」才是这条要求的本意。
	 */
	{
		u32 uid = from_kuid(&init_user_ns, current_fsuid());

		if (kdg_quota_charge(uid) != 0)
			ret = -EAGAIN;
	}

	if (ret == 0) {
		struct kdg_resolve_req rq = {
			.cfg = &ctx->cfg,
			/* P2 阶段还没有网络上下文输入面（方案 §5.3 的
			 * netId/fwmark 属 P3），故 net_id 恒为 0。
			 * profile_gen 取当前配置代际：换上游会递增它，
			 * 从而让旧代际的缓存自动失效。 */
			.net_id = 0,
			.profile_gen = generation,
		};
		enum kdg_source src;

		ret = kdg_resolve(&rq, qwire, qlen, rwire, &rlen, &src);
	}

	/* 响应头 + 正文一次分配：读路径只需一次 copy_to_user，
	 * 也避免两个缓冲各自的生命周期管理。 */
	ctx->resp_len = sizeof(hdr) + (ret ? 0 : rlen);
	ctx->resp = kmalloc(ctx->resp_len, GFP_KERNEL);
	if (!ctx->resp) {
		kfree(rwire);
		return -ENOMEM;
	}

	memset(&hdr, 0, sizeof(hdr));
	hdr.abi_version = KDG_ABI_VERSION;
	hdr.status = ret ? kdg_status_from_errno(ret) : KDG_ST_OK;
	hdr.errno_hint = ret ? (u32)(-ret) : 0;
	hdr.request_cookie = req->request_cookie;
	hdr.actual_network = 0;			/* P1 恒为 init_net */
	hdr.generation = generation;
	hdr.response_len = ret ? 0 : (u32)rlen;

	memcpy(ctx->resp, &hdr, sizeof(hdr));
	if (!ret && rlen)
		memcpy(ctx->resp + sizeof(hdr), rwire, rlen);

	ctx->resp_off = 0;
	ctx->have_resp = true;

	/* 对于「查询本身失败」的情形，我们仍然回一个完整的响应帧（带错误码），
	 * 而不是用 write 的返回值表达错误 —— 这样调用方只需处理一种返回路径。
	 * 因此这里总是返回写入的字节数。 */
	n = (int)req->total_len;
	kfree(rwire);
	return n;
}

static int kdg_status_from_errno(int err)
{
	switch (err) {
	case 0:			return KDG_ST_OK;
	case -EAGAIN:		return KDG_ST_EAGAIN;
	case -ETIMEDOUT:	return KDG_ST_ETIMEDOUT;
	case -EACCES:
	case -EPERM:		return KDG_ST_EPERM;
	case -EMSGSIZE:		return KDG_ST_EMSGSIZE;
	case -EBADMSG:
	case -EINVAL:		return KDG_ST_EBADWIRE;
	default:		return KDG_ST_EUPSTREAM;
	}
}

/* ── MAP_LOOKUP：IP → 候选域名集合（方案 §12.2）───────────────────────── */

#define KDG_ALIGN4(x)		(((x) + 3u) & ~3u)

/* 响应体的静态上界：头 + 4 个 item（各带一个最长域名）。有这个界才能用
 * 一次 kmalloc 交出整帧，不必边写边扩容。 */
#define KDG_MAP_BODY_MAX						\
	(sizeof(struct kdg_map_result_v1) +				\
	 KDG_MAP_MAX_ITEMS * (sizeof(struct kdg_map_item_v1) +		\
			      KDG_MAP_NAME_MAX + 4))

/*
 * 反查的实现。addr 是裸地址（4 或 16 字节）。
 *
 * 「没有关联」**不是错误**：调用方拿一个 IP 来问，正常的答案之一就是「不知道」。
 * 因此命中与未命中都走 KDG_ST_OK，靠 body 里的 count 区分 —— 若把未命中做成
 * 错误码，调用方就没法把「这个 IP 没记录」与「查询功能本身坏了」分开，而这两
 * 者的处置完全不同（前者回退到 SNI 嗅探，后者要报故障）。
 */
static int kdg_do_map_lookup(struct kdg_file_ctx *ctx,
			     const struct kdg_req_v1 *req,
			     const u8 *addr, size_t alen)
{
	struct kdg_map_result res;
	struct kdg_map_result_v1 mh;
	struct kdg_resp_v1 hdr;
	u8 *body = NULL;
	size_t body_len, off, total;
	u32 generation = READ_ONCE(kdg_cfg.generation);
	u8 i;
	int ret;

	if (alen != 4 && alen != 16)
		return -EINVAL;

	body = kmalloc(KDG_MAP_BODY_MAX, GFP_KERNEL);
	if (!body)
		return -ENOMEM;

	ret = kdg_map_lookup(0, generation, (u8)alen, addr,
			     KDG_MAP_MAX_ITEMS, &res);
	if (ret == -ENOENT) {
		memset(&res, 0, sizeof(res));
		res.profile_gen = generation;
		ret = 0;
	} else if (ret) {
		kfree(body);
		return ret;
	}

	memset(&mh, 0, sizeof(mh));
	mh.profile_generation = res.profile_gen;
	mh.actual_network = 0;			/* 本期恒 init_net */
	mh.count = res.count;
	mh.truncated = res.truncated ? 1 : 0;
	memcpy(body, &mh, sizeof(mh));
	off = sizeof(mh);

	for (i = 0; i < res.count; i++) {
		struct kdg_map_item_v1 it;

		/* count 已由 kdg_map_lookup 按 cap 限死，这里再判一次是为了让
		 * 「body 上界」这个假设在代码里显式可查，而不是靠远端不变式。 */
		if (off + sizeof(it) + KDG_ALIGN4(res.lens[i]) > KDG_MAP_BODY_MAX)
			break;
		memset(&it, 0, sizeof(it));
		it.len = res.lens[i];
		it.kind = 0;			/* DNS 名（wire） */
		it.ttl_ms = res.ttl_ms[i];
		memcpy(body + off, &it, sizeof(it));
		off += sizeof(it);
		memcpy(body + off, res.names[i], res.lens[i]);
		off += KDG_ALIGN4(res.lens[i]);
	}
	body_len = off;

	total = sizeof(hdr) + body_len;
	ctx->resp = kmalloc(total, GFP_KERNEL);
	if (!ctx->resp) {
		kfree(body);
		return -ENOMEM;
	}
	memset(&hdr, 0, sizeof(hdr));
	hdr.abi_version = KDG_ABI_VERSION;
	hdr.status = KDG_ST_OK;
	hdr.errno_hint = 0;
	hdr.request_cookie = req->request_cookie;
	hdr.actual_network = 0;
	hdr.generation = generation;
	hdr.response_len = (u32)body_len;
	memcpy(ctx->resp, &hdr, sizeof(hdr));
	memcpy(ctx->resp + sizeof(hdr), body, body_len);
	ctx->resp_len = total;
	ctx->resp_off = 0;
	ctx->have_resp = true;

	kfree(body);
	return (int)req->total_len;
}

/* ── write：提交查询 ─────────────────────────────────────────────────── */

static ssize_t kdg_chr_write(struct file *filp, const char __user *ubuf,
			     size_t count, loff_t *ppos)
{
	struct kdg_file_ctx *ctx = filp->private_data;
	struct kdg_req_v1 req;
	u8 *kbuf = NULL;
	size_t qlen;
	int ret;

	if (!ctx)
		return -EINVAL;
	if (!kdg_op_enter())
		return -ESHUTDOWN;
	/* 拒绝 seek：本设备是消息流，不是可定位的文件。
	 *
	 * ⚠️ 从此处起每一条失败路径都必须 kdg_op_exit()。漏一次就会把
	 * kdg_active_ops 留在 >0，kdg_chardev_exit() 永久等待，rmmod 卡死。
	 * 校验失败尤其常见（ABI / 长度 / opcode），所以不能只在成功路径配对。 */
	if (*ppos != 0) {
		ret = -ESPIPE;
		goto out_entered;
	}

	if (count < sizeof(req) || count > sizeof(req) + KDG_MAX_WIRE_MSG) {
		ret = -EMSGSIZE;
		goto out_entered;
	}

	kbuf = kmalloc(count, GFP_KERNEL);
	if (!kbuf) {
		ret = -ENOMEM;
		goto out_entered;
	}

	if (copy_from_user(kbuf, ubuf, count)) {
		ret = -EFAULT;
		goto out_entered;
	}

	memcpy(&req, kbuf, sizeof(req));

	/* ── 校验 ── */
	if (req.abi_version != KDG_ABI_VERSION) {
		/* 明确拒绝而不是尽力解析：ABI 不同意味着字段布局可能不同，
		 * 「尽力而为」会把错误解释成合法请求。 */
		ret = -EPROTO;
		goto out_entered;
	}
	if (req.opcode != KDG_OP_QUERY && req.opcode != KDG_OP_MAP_LOOKUP) {
		/* CANCEL / GET_HEALTH 在这条通道上未实现。明确返回「不支持」
		 * 而不是静默成功。 */
		ret = -EOPNOTSUPP;
		goto out_entered;
	}
	if (req.total_len != count) {
		ret = -EMSGSIZE;
		goto out_entered;
	}
	if (req.flags & ~KDG_REQ_FLAG_MASK) {
		ret = -EINVAL;
		goto out_entered;
	}
	/* 尚未实现的语义必须拒绝，不能默默改走默认网络。 */
	if (req.flags || req.requested_network_handle) {
		ret = -EOPNOTSUPP;
		goto out_entered;
	}
	if (req.reserved0 || req.deadline_ms > 60000) {
		ret = -EINVAL;
		goto out_entered;
	}
	qlen = req.query_len;
	if (sizeof(req) + qlen > count) {
		ret = -EMSGSIZE;
		goto out_entered;
	}
	if (req.opcode == KDG_OP_MAP_LOOKUP) {
		/* 反查的载荷是**裸地址**，长度即地址长度。 */
		if (qlen != 4 && qlen != 16) {
			ret = -EMSGSIZE;
			goto out_entered;
		}
	} else if (qlen == 0 || qlen > KDG_MAX_WIRE_MSG) {
		ret = -EMSGSIZE;
		goto out_entered;
	}
	if (req.expected_generation &&
	    req.expected_generation != READ_ONCE(kdg_cfg.generation)) {
		ret = -ESTALE;
		goto out_entered;
	}

	/* 方案 §14.2：「内核根据调用者凭据与系统授予的网络权限决定可用 network，
	 * 不相信请求中自报 UID」。P1 还没有网络上下文输入面（见 kdg_sock.c），
	 * 一律走 init_net；凭据裁决随 P3 的 SET_NETWORK 一起落地。 */

	ret = mutex_lock_interruptible(&ctx->lock);
	if (ret)
		goto out_entered;

	/* 未读取的结果属于原 cookie，不能被下一次提交覆盖。 */
	if (ctx->have_resp) {
		ret = -EAGAIN;
		mutex_unlock(&ctx->lock);
		goto out_entered;
	}

	ret = (req.opcode == KDG_OP_MAP_LOOKUP)
		? kdg_do_map_lookup(ctx, &req, kbuf + sizeof(req), qlen)
		: kdg_do_query(ctx, &req, kbuf + sizeof(req), qlen);
	mutex_unlock(&ctx->lock);

out_entered:
	kdg_op_exit();
	kfree(kbuf);
	return ret;
}

/* ── read：取回响应 ──────────────────────────────────────────────────── */

static ssize_t kdg_chr_read(struct file *filp, char __user *ubuf,
			    size_t count, loff_t *ppos)
{
	struct kdg_file_ctx *ctx = filp->private_data;
	size_t n;
	int ret;

	if (!ctx)
		return -EINVAL;
	if (!kdg_op_enter())
		return -ESHUTDOWN;
	if (*ppos != 0) {
		kdg_op_exit();
		return -ESPIPE;
	}

	ret = mutex_lock_interruptible(&ctx->lock);
	if (ret) {
		kdg_op_exit();
		return ret;
	}

	if (!ctx->have_resp || !ctx->resp) {
		ret = -EAGAIN;		/* 还没提交过查询，或已经读完 */
		goto out;
	}

	n = ctx->resp_len - ctx->resp_off;
	if (n > count)
		n = count;

	if (copy_to_user(ubuf, ctx->resp + ctx->resp_off, n)) {
		ret = -EFAULT;
		goto out;
	}

	ctx->resp_off += n;
	if (ctx->resp_off >= ctx->resp_len) {
		/* 整个响应已交付，清空以便下一次查询 */
		kfree(ctx->resp);
		ctx->resp = NULL;
		ctx->resp_len = 0;
		ctx->resp_off = 0;
		ctx->have_resp = false;
	}

	ret = (int)n;
out:
	kdg_op_exit();
	mutex_unlock(&ctx->lock);
	return ret;
}

/* ── poll / open / release ───────────────────────────────────────────── */

static __poll_t kdg_chr_poll(struct file *filp, poll_table *wait)
{
	struct kdg_file_ctx *ctx = filp->private_data;
	__poll_t mask = 0;

	if (!ctx)
		return EPOLLERR;

	/* 不做真正的等待队列：查询在 write() 里同步完成，返回时结果已就绪，
	 * 因此 poll 只需报告当前状态。方案 §9.3 要求「无请求时 worker 睡眠」，
	 * 本阶段没有常驻 worker，也就无从忙等。 */
	if (ctx->have_resp)
		mask |= EPOLLIN | EPOLLRDNORM;

	return mask;
}

static int kdg_chr_open(struct inode *inode, struct file *filp)
{
	struct kdg_file_ctx *ctx;

	/* 网络权限桥尚未落地，开发接口暂只服务受信控制方。 */
	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	mutex_init(&ctx->lock);
	kdg_doh_default_cfg(&ctx->cfg);
	filp->private_data = ctx;
	return 0;
}

static int kdg_chr_release(struct inode *inode, struct file *filp)
{
	struct kdg_file_ctx *ctx = filp->private_data;

	if (!ctx)
		return 0;

	kfree(ctx->resp);
	mutex_destroy(&ctx->lock);
	kfree(ctx);
	filp->private_data = NULL;
	return 0;
}

static const struct file_operations kdg_chr_fops = {
	.owner		= THIS_MODULE,
	.open		= kdg_chr_open,
	.release	= kdg_chr_release,
	.read		= kdg_chr_read,
	.write		= kdg_chr_write,
	.poll		= kdg_chr_poll,
	.llseek		= no_llseek,
};

/* ── 注册 ────────────────────────────────────────────────────────────── */

int kdg_chardev_init(void)
{
	int ret;

	ret = alloc_chrdev_region(&kdg_devno, 0, 1, KDG_DEVICE_NAME);
	if (ret) {
		pr_err("alloc_chrdev_region 失败: %d\n", ret);
		return ret;
	}

	cdev_init(&kdg_cdev, &kdg_chr_fops);
	kdg_cdev.owner = THIS_MODULE;

	ret = cdev_add(&kdg_cdev, kdg_devno, 1);
	if (ret) {
		pr_err("cdev_add 失败: %d\n", ret);
		goto err_region;
	}

	/* 只建字符设备，不建 sysfs class：class 会引出 /sys/class 条目与
	 * uevent，而 Android 的 ueventd 需要配套规则才能正确设权限。
	 * 本阶段用 devtmpfs 自动创建 /dev/kdnsguard（root:root 0600）。
	 * 非 root 访问所需的 ueventd 规则属于 P5 的平台集成。 */
	pr_info("/dev/%s 已注册（major %u，root:root 0600）\n",
		KDG_DEVICE_NAME, MAJOR(kdg_devno));
	return 0;

err_region:
	unregister_chrdev_region(kdg_devno, 1);
	return ret;
}

void kdg_chardev_exit(void)
{
	mutex_lock(&kdg_ops_lock);
	kdg_stopping = true;
	mutex_unlock(&kdg_ops_lock);
	wait_event(kdg_ops_wait, atomic_read(&kdg_active_ops) == 0);
	cdev_del(&kdg_cdev);
	unregister_chrdev_region(kdg_devno, 1);
}
