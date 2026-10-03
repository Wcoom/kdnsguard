#!/bin/bash
# build.sh —— 构建 kdnsguard.ko
#
# 目标内核就是本工作区自建的 out/（设备当前跑的就是它），所以**不覆盖**
# utsrelease.h，vermagic 天然一致 —— 这一点与 fq_guard_ko 相反（后者是给
# 上游 prebuilt 内核用的，必须伪造 vermagic）。
#
# 三个已知坑（与 ddl_guard_ko 同源，已在那边验证过）：
#  1) CONFIG_MODULE_SIG_ALL=y 会拿本地密钥签名，而设备端 SIG_FORCE 未开，
#     未签名模块可直接加载、签名反而可能验签失败 ⇒ 命令行覆盖为不签名；
#  2) 本树的 check_version() 恒返回 1（来自可单独 revert 的 LXC 补丁
#     84708f314ec5c），CRC 不匹配也会放行 —— 但这**不是**可以乱写符号的理由，
#     本模块只用 Module.symvers 里有的导出符号，未定义符号一律视为错误；
#  3) 每次重刷内核后 vermagic/CRC 都会变，必须重新构建并替换设备上的 .ko。
set -e
# 让 `make ... | tee` 的失败被 set -e 捕获：默认管道的退出码是 tee 的（恒为 0），
# 于是构建失败会被静默吞掉、脚本继续往下走并打印「全部合规」。
# 这个坑实际发生过一次 —— 我据此误以为改动生效，实际跑的是上一次的 .ko。
set -o pipefail

KERNEL_ROOT="/home/wcoom/桌面/oplus13/android_kernel_common_oneplus_sm8750"
KO_DIR="$(cd "$(dirname "$0")/../kernel" && pwd)"
OUT="$KERNEL_ROOT/out"

export PATH="/home/wcoom/桌面/oplus13/clang-19/bin:$PATH"
export KBUILD_BUILD_TIMESTAMP="Mon May 12 09:09:59 UTC 2025"

[ -f "$OUT/.config" ] || { echo "缺少 $OUT/.config（先在 $KERNEL_ROOT 跑 内核构建.sh）"; exit 1; }
[ -f "$OUT/Module.symvers" ] || { echo "缺少 $OUT/Module.symvers（构建树不完整）"; exit 1; }

# ── 同步 mbedTLS 到生成目录 ────────────────────────────────────────────
# kbuild 树外模块的编译规则是 $(obj)/%.o: $(src)/%.c，源文件必须物理位于
# 模块目录内。用目录符号链接会把编译产物写进上游树、破坏「third_party 逐字节
# 等于上游」这条纪律，故改为显式同步。
#
# 用内容哈希做判据而不是时间戳：一是确定性强，二是上游换版本时能自动清理
# 掉已删除的文件（否则会留下幽灵 .c 参与编译）。
PROJ_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MBSRC="$PROJ_ROOT/third_party/mbedtls/library"
MBDST="$PROJ_ROOT/kernel/mbedtls"

VENDOR_HASH=$(find "$MBSRC" -maxdepth 1 \( -name '*.c' -o -name '*.h' \) -print0 \
	      | sort -z | xargs -0 sha256sum | sha256sum | cut -c1-16)
STAMP="$MBDST/.vendor-hash"

if [ ! -f "$STAMP" ] || [ "$(cat "$STAMP" 2>/dev/null)" != "$VENDOR_HASH" ]; then
	echo "同步 mbedTLS 源码到 $MBDST （vendor hash $VENDOR_HASH）"
	find "$MBDST" -maxdepth 1 \( -name '*.c' -o -name '*.h' -o -name '*.o' \) -delete
	cp -a "$MBSRC"/*.c "$MBSRC"/*.h "$MBDST"/
	echo "$VENDOR_HASH" > "$STAMP"
	echo "  已同步 $(ls "$MBDST"/*.c | wc -l) 个 .c 文件"
else
	echo "mbedTLS 源码已是最新（vendor hash $VENDOR_HASH）"
fi

LOG="$KO_DIR/.build.log"
cd "$KERNEL_ROOT"
# 必须带上与 内核构建.sh **完全相同**的 CUSTOM_FLAGS，尤其是 -Wno-error：
# 本树 include/linux/signal.h 的 _SIG_SET_BINOP 在 _NSIG_WORDS==1 下仍被
# clang 做死代码分析并报 -Warray-bounds（sig[2]/sig[3] 越界），主构建正是
# 靠 -Wno-error 压住的。树外模块若不带同一套旗标，编出来的就不是同一棵树
# 的语义。代价是本模块自身的告警也会被降级 —— 因此下面单独 grep 本目录
# 的告警，把严格性补回来。
make LLVM=1 \
     ARCH=arm64 \
     CROSS_COMPILE=aarch64-linux-gnu- \
     PAHOLE=/usr/bin/pahole \
     LD=ld.lld \
     HOSTLD=ld.lld \
     O=out \
     CONFIG_MODULE_SIG_ALL= \
     KCFLAGS+="-O2 -mcpu=oryon-1 -Wno-error -pipe" \
     M="$KO_DIR" \
     modules 2>&1 | tee "$LOG"

echo "--- 本模块自身的告警审计（-Wno-error 会掩盖它们）---"
OWN_WARN=$(grep -E "^(kernel/)?kdg_[a-z]+\.c:" "$LOG" | grep -E "warning:" || true)
if [ -n "$OWN_WARN" ]; then
	echo "$OWN_WARN"
	echo "（以上为本项目新增代码的告警，请逐条确认）"
else
	echo "无"
fi

echo "--- 未定义符号审计（本模块不允许任何未定义符号）---"
UNEXPECTED=$(grep -o '"[^"]*" \[.*\.ko\] undefined!' "$LOG" \
	     | sed 's/"\([^"]*\)".*/\1/' | sort -u || true)
if [ -n "$UNEXPECTED" ]; then
	echo "构建失败：出现未定义符号（应全部在 Module.symvers 中）："
	echo "$UNEXPECTED"
	exit 1
fi

echo "========================================"
ls -la "$KO_DIR"/kdnsguard.ko
echo "--- vermagic（必须与设备 uname -r 一致）---"
modinfo -F vermagic "$KO_DIR"/kdnsguard.ko 2>/dev/null | head -1
echo "--- out/ 的 UTS_RELEASE ---"
grep UTS_RELEASE "$OUT/include/generated/utsrelease.h"
echo "--- 签名检查（应无输出）---"
tail -c 512 "$KO_DIR"/kdnsguard.ko | strings | grep "Module signature" || echo "未签名 OK"
echo "--- 未解析符号（正常：模块的未定义符号由内核在 insmod 时按导出表解析）---"
nm "$KO_DIR"/kdnsguard.ko 2>/dev/null | grep " U " || echo "无"
echo "--- kCFI 间接调用门禁（对内核符号的间接调用 = 设备上必 panic）---"
LLVM_NM="$KERNEL_ROOT/../clang-19/bin/llvm-nm"
[ -x "$LLVM_NM" ] || LLVM_NM=llvm-nm
KCFI_BAD=$("$LLVM_NM" "$KO_DIR"/kdnsguard.ko 2>/dev/null | awk '
	$2 == "U" { u[$3] = 1 }
	$2 == "W" && $3 ~ /^__kcfi_typeid_/ { t[substr($3, 15)] = 1 }
	END { for (x in t) if (u[x]) print x }')
if [ -n "$KCFI_BAD" ]; then
	echo "构建失败：本模块对以下**内核符号**发起了间接调用。"
	echo "内核汇编实现（如 memset/__memset）没有 kCFI 类型哈希，运行时必"
	echo "触发 'CFI failure ... brk #0x8228' → panic_on_oops → 手机重启。"
	echo "$KCFI_BAD"
	exit 1
fi
echo "无（未对任何内核符号做间接调用）"

echo "--- 逐个核对上述符号都在 out/Module.symvers 中（modpost 已保证，此处留证）---"
MISSING=""
for s in $(nm "$KO_DIR"/kdnsguard.ko 2>/dev/null | awk '$1=="U"{print $2}'); do
	grep -qP "\t$s\t" "$OUT/Module.symvers" || MISSING="$MISSING $s"
done
if [ -n "$MISSING" ]; then
	echo "构建失败：以下符号不在本内核导出表中：$MISSING"
	exit 1
fi
echo "全部合规"
echo "========================================"
