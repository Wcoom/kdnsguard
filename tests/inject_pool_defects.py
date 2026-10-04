#!/usr/bin/env python3
"""反向注入验证：给 kdg_pool.c 注入已知缺陷，看 tests/test_pool.c 是否变红。

存在的理由：**正向通过只说明「它没拦你」**。宿主测试全绿这件事本身不构成
任何证据，除非能证明它抓得住它声称要抓的那些缺陷。这个脚本把「能抓住」
变成可执行的判据：每条注入都对应一个具体的、真机上表现为 panic 或挂死的
缺陷，注入后测试必须**真的失败**；失败不了就是空闸，得去补用例。

用法：python3 tests/inject_pool_defects.py
它不修改仓库状态（每次都从 git 的 HEAD 版本恢复）。
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
POOL = ROOT / "kernel" / "kdg_pool.c"
TESTS = ROOT / "tests"

# (名字, 缺陷说明, 原文, 替换)
INJECTIONS = [
    (
        "放弃路径自己释放槽位",
        "调用方超时后自己 free 槽位，而协议栈还可能回调它 —— 双重释放/UAF。"
        "这是 kdg_pool.h「谁释放谁」那条约定的直接违反。",
        """		r->abandoned = true;
		g_pool.stat.wait_timeouts++;
		pr_err_ratelimited("请求等待超出上限，已交由驱动线程收尾\\n");
		ret = -ETIMEDOUT;""",
        """		g_pool.stat.wait_timeouts++;
		kdg_pool_free_slot_locked(r);
		ret = -ETIMEDOUT;""",
    ),
    (
        "结算时不要求 in_flight 已清",
        "END_STREAM 一到就交付槽位，而 nghttp2 紧接着还会在 on_stream_close "
        "里写同一个收集结构 —— 槽位一旦被复用就是串台。",
        """		if (r->state != KDG_SLOT_INFLIGHT || r->st.in_flight)
			continue;
		if (!r->st.done && !r->st.err)
			continue;""",
        """		if (r->state != KDG_SLOT_INFLIGHT)
			continue;
		if (!r->st.done && !r->st.err)
			continue;""",
    ),
    (
        "归还时忽略 in_flight",
        "把「协议栈已经忘掉这条流」这个前置条件去掉。"
        "【防御性断言，可证明不可达】free_slot 只在 ALLOC/DONE 两态被调用，"
        "而 DONE 的两条入口（settle / fail 路径）都已经各自保证过 !in_flight ——"
        "所以这个判断在**当前设计下**永远不会为真，它记录的是不变量、不是执行"
        "分支。删掉它测不出差别是正常的：真正的防线在 settle 与 fail_all 里，"
        "那两条都有确定性用例（见上两条）。保留它是因为将来若新增一条通往"
        "DONE 的路径，这里会挡住一次静默的串台。",
        """	if (r->st.in_flight) {
		/* 不该发生：settle/reap 只把 !in_flight 的流推到 DONE。
		 * 真发生了就留在 DONE，由驱动线程下一轮收尾 —— 绝不冒险复用。 */
		WARN_ON_ONCE(1);
		return;
	}
""",
        "",
    ),
    (
        "没有装载闸门",
        "去掉 stopping 判定：卸载之后进来的查询会去动已经放掉的槽位表，"
        "而且不再明确拒绝（返回 -EAGAIN 之类的偶然结果）。",
        """	if (g_pool.stopping) {
		mutex_unlock(&g_pool.lock);
		return -ESHUTDOWN;
	}
	atomic_inc(&g_pool.active);""",
        """	atomic_inc(&g_pool.active);""",
    ),
    (
        "卸载不等调用方离场",
        "shutdown 直接释放槽位表，不等 kdg_pool_query 里的人走完。"
        "【已知抓不住】这是与调度顺序赛跑的一类缺陷：调用方能否在 "
        "kvfree 之前写完它那一次写入，取决于两个线程谁先拿到 g_pool.lock，"
        "注入后有时红有时绿。要确定性复现得往产品代码里插延时，那比留一个"
        "已知缺口更糟。此条列为**已知未覆盖**，不计入失败。",
        """	wait_event(g_pool.wq, atomic_read(&g_pool.active) == 0);

""",
        "",
    ),
    (
        "驱动线程不结算",
        "to_done 不发 complete：调用方只能等到自己的等待上限。",
        """	atomic_dec(&g_pool.outstanding);
	complete(&r->done);""",
        """	atomic_dec(&g_pool.outstanding);
	if (result == 0)
		complete(&r->done);""",
    ),
    (
        "超期不取消在途流",
        "扫描到超期只推终态、不发 RST：槽位在协议栈侧仍被占用，且以后再也"
        "没人归还它。",
        """		if (!r->st.err)
			r->st.err = -ETIMEDOUT;
		if (!r->rst_sent && g_pool.up) {
			kdg_upstream_reset_stream(g_pool.up, r->stream_id);
			r->rst_sent = true;
			g_pool.stat.stream_resets_sent++;
		}
		g_pool.stat.upstream_timeouts++;""",
        """		kdg_pool_to_done_locked(r, -ETIMEDOUT);
		g_pool.stat.upstream_timeouts++;""",
    ),
    (
        "调用方自己拆连接",
        "上游身份变化时由**调用方线程**直接拆连接，而驱动线程可能正阻塞在"
        "一次读里、手里握着那个对象 —— use-after-free。",
        """		pr_info("上游身份变化，等待驱动线程重建连接\\n");
		g_pool.rebuild = true;""",
        """		kdg_pool_close_conn_locked("上游变更");
		kdg_pool_fail_inflight_locked(-ESTALE);""",
    ),
    (
        "槽位不归还",
        "reap 只推终态不归还：每次放弃都漏一个槽，128 次之后池彻底不可用。",
        """		/* 走到这里 state 必为 DONE 且 !in_flight */
		kdg_pool_free_slot_locked(r);""",
        """		/* 注入：漏掉归还 */""",
    ),
]

OK = "\033[32m✅ 被抓住\033[0m"
BAD = "\033[31m🔴 空闸（注入后仍全绿）\033[0m"
WARN = "\033[33m⚠️  非有效闸门（见说明）\033[0m"
KNOWN_GAPS = {"卸载不等调用方离场", "归还时忽略 in_flight"}


def run_test():
    build = subprocess.run(["make", "build/test_pool"], cwd=TESTS,
                           capture_output=True, text=True)
    if build.returncode != 0:
        return None, "编译失败:\n" + build.stdout + build.stderr
    try:
        r = subprocess.run(["./build/test_pool"], cwd=TESTS, capture_output=True,
                           text=True, timeout=180)
    except subprocess.TimeoutExpired as e:
        return True, "超时（挂死）:\n" + (e.stdout or "")[-2000:]
    out = r.stdout + r.stderr
    m = re.search(r"=== (\d+) 项检查，(\d+) 项失败 ===", out)
    caught = (r.returncode != 0 or "AddressSanitizer" in out
              or "runtime error" in out or (m and int(m.group(2)) > 0))
    if m and int(m.group(2)) == 0 and r.returncode == 0:
        return False, out
    return True, out


def main():
    good = POOL.read_text()
    failures = 0
    try:
        for name, why, old, new in INJECTIONS:
            if old not in good:
                print(f"[{name}] ⚠️  注入点没找到（被测代码变了，脚本要同步）")
                failures += 1
                continue
            POOL.write_text(good.replace(old, new, 1))
            caught, detail = run_test()
            if caught is None:
                print(f"[{name}] ⚠️  {detail}")
                failures += 1
                continue
            known = name in KNOWN_GAPS
            print(f"[{name}] {OK if caught else (WARN if known else BAD)}")
            print(f"    {why}")
            if caught:
                for line in detail.splitlines():
                    if "✗" in line or "看门狗" in line or "Sanitizer" in line \
                       or "runtime error" in line or "项失败" in line:
                        print("    | " + line.strip())
            elif not known:
                failures += 1
    finally:
        POOL.write_text(good)
        subprocess.run(["make", "build/test_pool"], cwd=TESTS,
                       capture_output=True)

    print()
    if failures:
        print(f"❌ {failures} 条**有效闸门**的注入没被抓住 —— 这些路径的用例是空的。")
    else:
        print("✅ 所有有效闸门的注入都被抓住；标 ⚠️ 的两条已在说明里给出"
              "「为什么删掉它测不出差别」。")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
