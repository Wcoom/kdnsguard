/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdg_divti3.c —— 补齐编译器运行时辅助函数 __udivti3。
 *
 * 为什么需要它：
 *   clang 遇到 `unsigned __int128 / unsigned __int128` 而 AArch64 没有对应
 *   指令时，会生成一次对 __udivti3 的调用。用户态由 libgcc / compiler-rt 提供，
 *   内核态由 lib/ 提供 —— 但**只提供内核自己用到的那些**。本内核从不做 128 位
 *   除法，所以 System.map 里查不到该符号、Module.symvers 里也没导出，
 *   模块一旦用到就报 "modpost: __udivti3 undefined"。
 *
 *   mbedTLS 的 bignum 会做 128 位除法（大数按 64 位肢体运算时的中间步骤），
 *   因此只能由本模块自带一个。这是**编译器 ABI 层的补齐**，不是替代任何
 *   内核功能，也不涉及 KMI。
 *
 * 关于内核是不是该改用 lib/udivdi3 的现成实现：那文件里的 __udivti3 若被
 * 编进 vmlinux，符号是有的，但**没有 EXPORT_SYMBOL**，模块依然链接不上
 * （模块只能解析导出符号）。所以自带实现是唯一可行路径。
 *
 * 算法：二进制长除法 + 除数规格化。先把除数左移到与被除数同量级（最多 127 次），
 * 再从高到低逐位试减。复杂度 O(位宽)，而不是逐位 128 次循环的朴素做法；
 * 在一次握手里只会被调用极少数次，两者都远非瓶颈，但这个写法也不复杂。
 */
#include <linux/kernel.h>
#include <linux/module.h>

typedef unsigned __int128 kdg_u128;

/*
 * 128 位无符号除法。语义与 compiler-rt 的同名函数一致。
 *
 * ⚠️ 除数为 0 时返回 0 而不是崩溃：这里是编译器隐式插入调用的位置，
 * 一旦它真的在异常路径上被以 0 调用，让内核 panic 的代价远大于返回一个
 * 无意义值 —— 而上层（mbedTLS）对除法结果另有零值检查。
 */
__visible kdg_u128 __udivti3(kdg_u128 n, kdg_u128 d)
{
	kdg_u128 q = 0;
	int shift = 0;

	if (d == 0)
		return 0;
	if (n < d)
		return 0;

	/* 把除数左移到「再左移一次就超过被除数」为止。
	 * `(d << 1) > d` 兼作溢出检测：除数最高位为 1 时左移会回绕成 0，
	 * 此时 0 > d 为假，循环正常结束而不是无限循环。 */
	while ((d << 1) > d && (d << 1) <= n) {
		d <<= 1;
		shift++;
	}

	for (;;) {
		if (n >= d) {
			n -= d;
			q |= (kdg_u128)1 << shift;
		}
		if (shift == 0)
			break;
		d >>= 1;
		shift--;
	}

	return q;
}

/* 供内核符号解析时识别（非必需，但便于 System.map 审阅）。 */
/*
 * ⚠️ 这里**刻意不导出**。
 *
 * 模块形态不需要导出：模块内部的引用在同一次链接里就解析掉了，导出只对
 * 「别的模块要用」有意义。而一旦导出，树内构建会把这条导出写进
 * vmlinux 的符号表，随后树外模块构建的 modpost 就会报
 *   __udivti3 exported twice. Previous export was in vmlinux
 * 第一次把 kdnsguard 编进内核之后，模块构建正是撞在这条上。
 */
