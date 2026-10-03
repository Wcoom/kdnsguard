/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_main.c —— 模块生命周期、per-netns 状态、全局配置快照。
 *
 * 本项目以**可卸载模块**形态开发（方案 §15 的首选路径）。设备上的常规
 * 交付走 AnyKernel3，它只替换 boot 分区内核段、不安装模块（do.modules=0），
 * 所以将来若 kdnsguard 要常驻设备，必须改为内建集成 —— 那是 P3 的决策，
 * 骨架阶段用 LKM 换取快速迭代与故障隔离。
 */
#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <net/net_namespace.h>
/* net_generic() 的声明在 net/netns/generic.h，net_namespace.h 不转发它。 */
#include <net/netns/generic.h>

#include "kdg.h"

/* ── 全局配置快照 ─────────────────────────────────────────────────────── */
/* 读写纪律：写路径只有两处 —— 模块 init（一次性）与 genl 的启停命令。
 * 读路径在 NAT hook 里，因此用 READ_ONCE/WRITE_ONCE 保证不撕裂，不引入
 * 锁（hook 上下文不可睡眠）。真正的事务化配置（PREPARE/COMMIT，方案 §14.1）
 * 在 P4 落地，届时这里会扩成 RCU 发布的不可变快照。 */
struct kdg_config_snapshot kdg_cfg = {
	.generation		= 1,
	.intercept_enabled	= false,
	.listen_port		= KDG_DEFAULT_LISTEN_PORT,
	.default_deadline_ms	= KDG_DEFAULT_DEADLINE_MS,
};

/* ── 模块参数（开发期配置面；正式配置面是 genl 事务接口） ─────────────── */
bool kdg_allow_intercept;
module_param_named(allow_intercept, kdg_allow_intercept, bool, 0444);
MODULE_PARM_DESC(allow_intercept,
	"允许通过 Generic Netlink 启用 53 端口接管。默认 0 —— 骨架阶段还没有本地 DNS 监听者，启用会把手机 DNS 打断。仅用于开发验证。");

bool kdg_debug;
module_param_named(debug, kdg_debug, bool, 0644);
MODULE_PARM_DESC(debug,
	"为最早的若干次 NAT hook 调用打印 pf/协议/端口。默认 0。用于排查「hook 已挂但谓词不匹配」。");

static uint kdg_listen_port = KDG_DEFAULT_LISTEN_PORT;
module_param_named(listen_port, kdg_listen_port, uint, 0444);
MODULE_PARM_DESC(listen_port, "本地 DNS 监听端口（默认 1054）");

static uint kdg_deadline_ms = KDG_DEFAULT_DEADLINE_MS;
module_param_named(deadline_ms, kdg_deadline_ms, uint, 0444);
MODULE_PARM_DESC(deadline_ms, "单次查询默认 deadline（毫秒，默认 3000）");

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
	return 0;
}

static void kdg_net_exit(struct net *net)
{
	kdg_nat_unregister(net);
}

static struct pernet_operations kdg_net_ops = {
	.init	= kdg_net_init,
	.exit	= kdg_net_exit,
	.id	= &kdg_net_id,
	.size	= sizeof(struct kdg_netns),
};

/* ── 生命周期 ─────────────────────────────────────────────────────────── */

static int __init kdg_init(void)
{
	int ret;

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
		return ret;
	}

	ret = kdg_cache_tab_init();
	if (ret) {
		pr_err("缓存初始化失败: %d\n", ret);
		kdg_genl_exit();
		kdg_tls_global_exit();
		return ret;
	}

	ret = kdg_chardev_init();
	if (ret) {
		pr_err("字符设备注册失败: %d\n", ret);
		kdg_cache_tab_exit();
		kdg_genl_exit();
		kdg_tls_global_exit();
		return ret;
	}

	ret = register_pernet_subsys(&kdg_net_ops);
	if (ret) {
		pr_err("pernet 子系统注册失败: %d\n", ret);
		kdg_chardev_exit();
		kdg_cache_tab_exit();
		kdg_genl_exit();
		kdg_tls_global_exit();
		return ret;
	}

	pr_info("已加载：ABI v%d，监听端口 %u，接管 %s（capability=0x%08x）\n",
		KDG_ABI_VERSION, READ_ONCE(kdg_cfg.listen_port),
		READ_ONCE(kdg_cfg.intercept_enabled) ? "已启用" : "未启用",
		kdg_nat_capability_bits());
	return 0;
}

static void __exit kdg_exit(void)
{
	/* 逆序拆除，且**先撤管理面**：否则会出现「用户空间刚把接管打开、
	 * NAT hook 却正在被拆掉」的窗口。撤掉 genl 后不再有新的配置变更，
	 * 再拆 NAT 就是纯粹的收敛过程。 */
	kdg_genl_exit();
	unregister_pernet_subsys(&kdg_net_ops);
	kdg_chardev_exit();
	kdg_cache_tab_exit();
	kdg_tls_global_exit();

	pr_info("已卸载\n");
}

module_init(kdg_init);
module_exit(kdg_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Wcoom");
MODULE_DESCRIPTION(KDG_MOD_DESC);
MODULE_VERSION("0.1.0");
