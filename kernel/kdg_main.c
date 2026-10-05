/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_main.c —— 模块生命周期、per-netns 状态、全局配置快照。
 *
 * 本项目以**可卸载模块**形态开发（方案 §15 的首选路径）。设备上的常规
 * 交付走 AnyKernel3，它只替换 boot 分区内核段、不安装模块（do.modules=0），
 * 所以将来若 kdnsguard 要常驻设备，必须改为内建集成 —— 那是 P3 的决策，
 * 骨架阶段用 LKM 换取快速迭代与故障隔离。
 */
#include <linux/ktime.h>

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

/*
 * 内建形态（CONFIG_KDNSGUARD=y）下参数默认会落到
 * /sys/module/kernel/parameters/，而且会与内核自带的同名参数撞车
 * （`debug`、`h3` 这类通用名尤其危险）。显式钉死前缀后，内建与模块两种
 * 形态的参数路径一致：/sys/module/kdnsguard/parameters/。
 * 内核里的标准做法见 drivers/misc/ddl_guard.c 的同一处。
 */
#ifdef MODULE_PARAM_PREFIX
#undef MODULE_PARAM_PREFIX
#endif
#define MODULE_PARAM_PREFIX "kdnsguard."

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <net/net_namespace.h>
/* net_generic() 的声明在 net/netns/generic.h，net_namespace.h 不转发它。 */
#include <net/netns/generic.h>

#include "kdg.h"
#include "kdg_tls.h"

/* ── 全局配置快照 ─────────────────────────────────────────────────────── */
/* 读写纪律：写路径只有两处 —— 模块 init（一次性）与 genl 的启停命令。
 * 读路径在 NAT hook 里，因此用 READ_ONCE/WRITE_ONCE 保证不撕裂，不引入
 * 锁（hook 上下文不可睡眠）。真正的事务化配置（PREPARE/COMMIT，方案 §14.1）
 * 在 P4 落地，届时这里会扩成 RCU 发布的不可变快照。 */
struct kdg_config_snapshot kdg_cfg = {
	.generation		= 1,
	.transaction_id		= 0,
	.ownership		= KDG_OWN_NONE,
	.net_id			= 0,
	.ifindex		= 0,
	.network_epoch		= 0,
	.private_dns_mode	= KDG_PDNS_UNKNOWN,
	.intercept_enabled	= false,
	.listen_port		= KDG_DEFAULT_LISTEN_PORT,
	.default_deadline_ms	= KDG_DEFAULT_DEADLINE_MS,
};

/* ── 模块参数（开发期配置面；正式配置面是 genl 事务接口） ─────────────── */
bool kdg_allow_intercept;
/*
 * 0444 → 0644：模块形态由 insmod allow_intercept=1 传入，而**内建形态没有
 * insmod**，只能由开机脚本写 /sys/module/kdnsguard/parameters/allow_intercept。
 * 放开写权限不改变安全边界：真正的开关是 genl 的所有权事务，而这个参数只是
 * 「本模块是否被允许进入接管业务」的前置闸门；能写它的进程已经需要 root。
 */
module_param_named(allow_intercept, kdg_allow_intercept, bool, 0644);
MODULE_PARM_DESC(allow_intercept,
	"允许通过 Generic Netlink 启用 53 端口接管。默认 0 —— 骨架阶段还没有本地 DNS 监听者，启用会把手机 DNS 打断。仅用于开发验证。");

bool kdg_debug;
bool kdg_allow_h3 = true;
module_param_named(h3, kdg_allow_h3, bool, 0644);
MODULE_PARM_DESC(h3, "上游优先走 HTTP/3（QUIC），失败回落 HTTP/2");
module_param_named(debug, kdg_debug, bool, 0644);
MODULE_PARM_DESC(debug,
	"为最早的若干次 NAT hook 调用打印 pf/协议/端口。默认 0。用于排查「hook 已挂但谓词不匹配」。");

static uint kdg_listen_port = KDG_DEFAULT_LISTEN_PORT;
module_param_named(listen_port, kdg_listen_port, uint, 0444);
MODULE_PARM_DESC(listen_port, "本地 DNS 监听端口（默认 1054）");

static uint kdg_deadline_ms = KDG_DEFAULT_DEADLINE_MS;
module_param_named(deadline_ms, kdg_deadline_ms, uint, 0444);
MODULE_PARM_DESC(deadline_ms, "单次查询默认 deadline（毫秒，默认 3000）");

/*
 * 客户端入口接口名（逗号分隔）。这些接口上的 53 **转发**流量（热点 / USB
 * 共享 / AP 的客户端）会被 PREROUTING 接管。方案 §5.2 要求「外部接口默认
 * 不允许主动访问这个 listener，除明确的热点客户端入口」—— 这张名单就是
 * 「明确」的落点：不在名单里的接口上的 53 一律 NF_ACCEPT，既不改写也不建
 * listener，因此手机在运营商网络上的地址不会变成开放解析器。
 *
 * 置空串可整体关闭该能力（只保留本地 LOCAL_OUT 接管）。
 */
static char *kdg_client_ifaces_spec = "rndis0,rndis1,usb0,wlan0,wlan1,wlan2,bt-pan";
module_param_named(client_ifaces, kdg_client_ifaces_spec, charp, 0444);
MODULE_PARM_DESC(client_ifaces,
	"客户端入口接口名，逗号分隔；这些接口的 53 转发流量交给内核。空串=关闭。");

/* ── per-netns 状态 ───────────────────────────────────────────────────── */
static unsigned int kdg_net_id;

int kdg_netns_id(void)
{
	return (int)kdg_net_id;
}

struct kdg_netns *kdg_netns_of(struct net *net)
{
	/* net_generic() 对本模块的 pernet init 尚未跑过的 netns 返回 NULL，
	 * 调用方必须容忍（NAT hook 里就是直接 NF_ACCEPT）。 */
	if (!net)
		return NULL;
	return net_generic(net, kdg_net_id);
}

static int kdg_net_init(struct net *net)
{
	struct kdg_netns *ns = net_generic(net, kdg_net_id);
	int ret;

	ret = kdg_nat_register(net);
	if (ret) {
		/*
		 * 有意**不**让 netns 创建失败。
		 *
		 * pernet_operations.init 返回非 0 会令整个网络命名空间建不起来
		 * ——那会把 VPN、容器、以及任何用 netns 的系统服务一起拖垮。
		 * 对一个 DNS 模块而言，这个代价远大于「这个 netns 没被接管」。
		 * 所以这里吞掉错误、如实记进 degraded，由 GET_HEALTH 暴露出去，
		 * 让运维能看见，而不是让系统挂掉。
		 */
		ns->degraded = true;
		pr_err("netns NAT 注册失败: %d（该 netns 不接管，其余功能不受影响）\n",
		       ret);
	}
	ret = kdg_edns_register(net);
	if (ret) {
		ns->degraded = true;
		pr_err("netns 加密 DNS 封锁注册失败: %d\n", ret);
	}
	return 0;
}

static void kdg_net_exit(struct net *net)
{
	kdg_edns_unregister(net);
	kdg_nat_unregister(net);
}

static struct pernet_operations kdg_net_ops = {
	.init	= kdg_net_init,
	.exit	= kdg_net_exit,
	.id	= &kdg_net_id,
	.size	= sizeof(struct kdg_netns),
};

/* ── 生命周期 ─────────────────────────────────────────────────────────── */

/* 自启的实现见文件末尾（它要用 genl 的 PREPARE/接管入口）。 */
int kdg_autostart_init(void);
void kdg_autostart_stop(void);

static int __init kdg_init(void)
{
	int ret;

	/* 名单须在 hook 注册（pernet init）之前就绪；默认串是编译期常量，
	 * 解析失败只可能是代码缺陷，按失败处理。 */
	ret = kdg_edns_init();
	if (ret) {
		pr_err("加密 DNS 默认名单解析失败: %d\n", ret);
		return ret;
	}

	ret = kdg_listener_init_state();
	if (ret)
		return ret;

	ret = kdg_listener_client_config(kdg_client_ifaces_spec);
	if (ret)
		return ret;

	/* 参数落到配置快照。越界值直接拒绝而不是静默截断。
	 * 上限 65535 是端口上限；下限 1024 避开特权端口 —— 本项目不该
	 * 去争 53（那正是它要接管的目标，自己占用会造成语义混乱）。 */
	if (kdg_listen_port < 1024 || kdg_listen_port > 65535) {
		pr_err("listen_port=%u 非法（允许 1024..65535）\n",
		       kdg_listen_port);
		return -EINVAL;
	}
	if (kdg_deadline_ms == 0 || kdg_deadline_ms > 60000) {
		pr_err("deadline_ms=%u 非法（允许 1..60000）\n", kdg_deadline_ms);
		return -EINVAL;
	}

	WRITE_ONCE(kdg_cfg.listen_port, (u16)kdg_listen_port);
	WRITE_ONCE(kdg_cfg.default_deadline_ms, (u32)kdg_deadline_ms);

	/*
	 * 平台层必须最先就绪：MBEDTLS_PLATFORM_NO_STD_FUNCTIONS 下
	 * mbedTLS 的 calloc/free/snprintf/time 函数指针初值为 NULL，
	 * 任何早于本调用的 mbedTLS 入口都是空指针解引用。
	 */
	ret = kdg_mbedtls_init();
	if (ret) {
		pr_err("mbedTLS 平台层初始化失败: %d\n", ret);
		return ret;
	}

	/* TLS 子系统（熵源/DRBG/信任锚容器）也必须早于任何会话。
	 * 信任锚本身由用户空间经事务接口注入，此处只建容器。 */
	ret = kdg_tls_global_init();
	if (ret) {
		pr_err("TLS 子系统初始化失败: %d\n", ret);
		return ret;
	}

	/* 再注册管理面，最后挂 NAT hook：这样任何时刻用户空间看到的都是一个
	 * 能被查询的状态，而不是「NAT 已经在拦包但没人能问它在干什么」。 */
	ret = kdg_genl_init();
	if (ret) {
		pr_err("Generic Netlink 族注册失败: %d\n", ret);
		kdg_tls_global_exit();
		return ret;
	}

	ret = kdg_cache_tab_init();
	if (ret) {
		pr_err("缓存初始化失败: %d\n", ret);
		kdg_genl_exit();
		kdg_tls_global_exit();
		return ret;
	}

	ret = kdg_map_init();
	if (ret) {
		pr_err("IP/域名映射表初始化失败: %d\n", ret);
		kdg_cache_tab_exit();
		kdg_genl_exit();
		kdg_tls_global_exit();
		return ret;
	}

	ret = kdg_quota_init();
	if (ret) {
		pr_err("配额表初始化失败: %d\n", ret);
		kdg_map_exit();
		kdg_cache_tab_exit();
		kdg_genl_exit();
		kdg_tls_global_exit();
		return ret;
	}

	ret = kdg_sflight_init();
	if (ret) {
		pr_err("同名合并表初始化失败: %d\n", ret);
		kdg_quota_exit();
		kdg_map_exit();
		kdg_cache_tab_exit();
		kdg_genl_exit();
		kdg_tls_global_exit();
		return ret;
	}

	/* 连接池只建槽位表，**不建线程** —— 驱动线程在第一次真正要查上游时
	 * 才懒启动（方案 §9.3「无请求时 worker 睡眠」）。放在 TLS 之后：
	 * 池的驱动线程要用 TLS 子系统，而它的第一条命令就是建连握手。 */
	ret = kdg_pool_init();
	if (ret) {
		pr_err("上游连接池初始化失败: %d\n", ret);
		kdg_sflight_exit();
		kdg_quota_exit();
		kdg_map_exit();
		kdg_cache_tab_exit();
		kdg_genl_exit();
		kdg_tls_global_exit();
		return ret;
	}

	ret = kdg_chardev_init();
	if (ret) {
		pr_err("字符设备注册失败: %d\n", ret);
		kdg_pool_shutdown();
		kdg_sflight_exit();
		kdg_quota_exit();
		kdg_map_exit();
		kdg_cache_tab_exit();
		kdg_genl_exit();
		kdg_tls_global_exit();
		return ret;
	}

	ret = register_pernet_subsys(&kdg_net_ops);
	if (ret) {
		pr_err("pernet 子系统注册失败: %d\n", ret);
		kdg_chardev_exit();
		kdg_pool_shutdown();
		kdg_sflight_exit();
		kdg_quota_exit();
		kdg_map_exit();
		kdg_cache_tab_exit();
		kdg_genl_exit();
		kdg_tls_global_exit();
		return ret;
	}

	kdg_autostart_init();

	pr_info("已加载：ABI v%d，监听端口 %u，接管 %s（capability=0x%08x）\n",
		KDG_ABI_VERSION, READ_ONCE(kdg_cfg.listen_port),
		READ_ONCE(kdg_cfg.intercept_enabled) ? "已启用" : "未启用",
		kdg_nat_capability_bits());
	return 0;
}

static void __exit kdg_exit(void)
{
	/* 先停自启工作，否则它可能在拆卸过程中重新排程/调用已停掉的东西。 */
	kdg_autostart_stop();

	/* 先撤销 ownership、停止 listener，再撤销管理面和其他资源。 */
	if (READ_ONCE(kdg_cfg.intercept_enabled)) {
		WRITE_ONCE(kdg_cfg.intercept_enabled, false);
		WRITE_ONCE(kdg_cfg.ownership, KDG_OWN_NONE);
		WRITE_ONCE(kdg_cfg.generation, READ_ONCE(kdg_cfg.generation) + 1);
	}
	kdg_listener_stop();
	/* 逆序拆除，且**先撤管理面**：否则会出现「用户空间刚把接管打开、
	 * NAT hook 却正在被拆掉」的窗口。撤掉 genl 后不再有新的配置变更，
	 * 再拆 NAT 就是纯粹的收敛过程。 */
	kdg_genl_exit();
	unregister_pernet_subsys(&kdg_net_ops);
	kdg_chardev_exit();
	/* 连接池放在这里而不是更早：它要拆掉驱动线程与上游连接，而这两者
	 * 只有在上面的 listener 与字符设备都停掉之后才确定没有调用方
	 * （kdg_chardev_exit 等过 active_ops、kdg_listener_stop 等过
	 * kthread_stop）。放在 kdg_tls_global_exit 之前是硬要求 ——
	 * 驱动线程的收尾要发 TLS close_notify。 */
	kdg_pool_shutdown();
	kdg_sflight_exit();
	kdg_quota_exit();
	kdg_map_exit();
	kdg_cache_tab_exit();
	kdg_tls_global_exit();

	pr_info("已卸载\n");
}


/* ── 内建形态的开机自启：不依赖任何用户空间脚本 ─────────────────────
 *
 * 目标：设备开机后，内核态 DNS 自己进入接管态 —— 不需要 insmod（已内建）、
 * 不需要脚本喂信任锚、不需要任何人做 PREPARE/COMMIT。
 *
 * 三件事都必须由内核自己做：
 *   ① 信任锚：编进镜像（kdg_root_ca.h，由 tools/gen-root-ca.py 生成）。
 *      它本来就是公开的根证书，且**钉死**正是目的：内核只认这一个上游身份。
 *   ② 时机：网络就绪之前 PREPARE 必然失败（它要探测上游）。所以用延迟工作
 *      反复重试，而不是在 initcall 里一次性尝试 —— 这也是原来那个开机脚本
 *      存在的全部理由。
 *   ③ 不抢所有权：ownership 不是 NONE 就说明已有人（mihomo 或管理脚本）持有，
 *      本工作只跳过这一次；对方释放后下一拍自然接管。因此它与既有的
 *      脚本/代理路径**可以共存**，不会互相打架。
 */
#ifdef CONFIG_KDNSGUARD_EMBED_CA
#include "kdg_root_ca.h"
#endif

/* 默认值随 Kconfig：内建时开机自启，树外模块形态默认关（开发时由 insmod
 * 的 allow_intercept 显式控制）。 */
#if defined(CONFIG_KDNSGUARD_AUTO_START)
static bool kdg_auto_start = true;
#else
static bool kdg_auto_start;
#endif
module_param_named(auto_start, kdg_auto_start, bool, 0644);
MODULE_PARM_DESC(auto_start, "开机后由内核自己完成 PREPARE/COMMIT（内建形态默认开）");

#define KDG_AUTOSTART_FIRST_MS	20000	/* 首次尝试：等网络起来的起步时间 */
#define KDG_AUTOSTART_FAST_MS	15000	/* 前几次的间隔 */
#define KDG_AUTOSTART_SLOW_MS	60000	/* 连续失败后的间隔（不再打扰） */
#define KDG_AUTOSTART_FAST_N	8	/* 快速重试次数 */

static struct delayed_work kdg_autostart_dw;
static unsigned int kdg_autostart_tries;
static bool kdg_autostart_done;

static void kdg_autostart_work(struct work_struct *work)
{
	unsigned int next_ms;
	int ret;

	if (!READ_ONCE(kdg_auto_start) || !READ_ONCE(kdg_allow_intercept))
		return;			/* 被显式关掉：不再重试，也不再自排 */

	if (READ_ONCE(kdg_cfg.ownership) != KDG_OWN_NONE) {
		/* 有主：不抢。对方释放之后下一拍我们自然接管。 */
		next_ms = KDG_AUTOSTART_SLOW_MS;
		goto again;
	}

	/* 走到这里 ownership 必为 NONE，故不必先 DISABLE。事务号用单调毫秒，
	 * 只要每次尝试都不同即可（COMMIT 必须回填同一个值）。 */
	ret = kdg_genl_prepare_tx(div_u64(ktime_get_ns(), 1000000ULL));
	if (!ret)
		ret = kdg_genl_set_intercept(true);
	if (ret) {
		/* 上游还没通（网络未就绪）是最常见的原因，不值得每次都刷日志。 */
		kdg_autostart_tries++;
		if (kdg_autostart_tries == 1 || kdg_autostart_tries % 10 == 0)
			pr_info("自启：第 %u 次尝试未成功（%d），继续重试\n",
				kdg_autostart_tries, ret);
		next_ms = kdg_autostart_tries < KDG_AUTOSTART_FAST_N ?
			  KDG_AUTOSTART_FAST_MS : KDG_AUTOSTART_SLOW_MS;
		goto again;
	}

	kdg_autostart_done = true;
	pr_info("自启：内核态 DNS 已接管 53（无用户空间参与，第 %u 次尝试）\n",
		kdg_autostart_tries + 1);
	return;

again:
	schedule_delayed_work(&kdg_autostart_dw, msecs_to_jiffies(next_ms));
}

int kdg_autostart_init(void)
{
	INIT_DELAYED_WORK(&kdg_autostart_dw, kdg_autostart_work);

#ifdef CONFIG_KDNSGUARD_EMBED_CA
	{
		int added = kdg_tls_add_ca(kdg_root_ca, KDG_ROOT_CA_LEN);

		if (added < 0)
			pr_err("内建信任锚加载失败: %d（将无法自启，仍可由用户空间喂入）\n",
			       added);
		else
			pr_info("内建信任锚已加载（%d 张）\n", added);
	}
#endif

	if (!READ_ONCE(kdg_auto_start))
		return 0;
	pr_info("自启已排程：%d ms 后首次尝试，网络就绪前会反复重试\n",
		KDG_AUTOSTART_FIRST_MS);
	schedule_delayed_work(&kdg_autostart_dw,
			      msecs_to_jiffies(KDG_AUTOSTART_FIRST_MS));
	return 0;
}

void kdg_autostart_stop(void)
{
	cancel_delayed_work_sync(&kdg_autostart_dw);
}

module_init(kdg_init);
module_exit(kdg_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Wcoom");
MODULE_DESCRIPTION(KDG_MOD_DESC);
MODULE_VERSION("0.1.0");
