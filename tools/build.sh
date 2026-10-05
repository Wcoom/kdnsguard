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

# ── 同步第三方源码到生成目录 ──────────────────────────────────────────
# kbuild 树外模块的编译规则是 $(obj)/%.o: $(src)/%.c，源文件必须物理位于
# 模块目录内。用目录符号链接会把编译产物写进上游树、破坏「third_party 逐字节
# 等于上游」这条纪律，故改为显式同步。
#
# 用内容哈希做判据而不是时间戳：一是确定性强，二是上游换版本时能自动清理
# 掉已删除的文件（否则会留下幽灵 .c 参与编译）。
PROJ_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

sync_vendor() {
	local name="$1" srcdir="$2" dstdir="$3"
	local hash stamp

	mkdir -p "$dstdir"
	hash=$(find "$srcdir" -maxdepth 1 \( -name '*.c' -o -name '*.h' \) -print0 \
	       | sort -z | xargs -0 sha256sum | sha256sum | cut -c1-16)
	stamp="$dstdir/.vendor-hash"

	if [ ! -f "$stamp" ] || [ "$(cat "$stamp" 2>/dev/null)" != "$hash" ]; then
		echo "同步 $name 源码到 $dstdir （vendor hash $hash）"
		find "$dstdir" -maxdepth 1 \( -name '*.c' -o -name '*.h' -o -name '*.o' \) -delete
		cp -a "$srcdir"/*.c "$srcdir"/*.h "$dstdir"/
		echo "$hash" > "$stamp"
		echo "  已同步 $(ls "$dstdir"/*.c | wc -l) 个 .c 文件"
	else
		echo "$name 源码已是最新（vendor hash $hash）"
	fi
}

sync_vendor mbedTLS "$PROJ_ROOT/third_party/mbedtls/library" "$PROJ_ROOT/kernel/mbedtls"
sync_vendor nghttp2  "$PROJ_ROOT/third_party/nghttp2/lib"     "$PROJ_ROOT/kernel/nghttp2"

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
     KCFLAGS+="-O2 -mcpu=oryon-1 -Wno-error -pipe -DKDG_EMBED_CA -DKDG_AUTO_START" \
     M="$KO_DIR" \
     modules 2>&1 | tee "$LOG"

echo "--- 本模块自身的告警审计（-Wno-error 会掩盖它们）---"
OWN_WARN=$(grep -E '(^|/)kdg_[a-z0-9_]+\.c:[0-9]+:[0-9]+: warning:' "$LOG" || true)
if [ -n "$OWN_WARN" ]; then
	echo "$OWN_WARN"
	echo "构建失败：本项目代码存在告警。"
	exit 1
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

# ── 分配/释放配对审计 ──────────────────────────────────────────────────
# 为什么必须机械检查这一条：`kvmalloc` 家族在**大尺寸时返回 vmalloc 地址**，
# 用 `kfree` 释放它 → `Unable to handle kernel paging request` + panic。
# 而宿主侧的 host_kernel.h 把 kfree/kvfree 都映射成 free，**宿主单测对这一类
# 错误完全免疫** —— 2026-10-05 就是这么把手机搞重启的（kdg_map_exit 用 kfree
# 释放 kvcalloc 来的 316 KiB slots，rmmod 时 panic，minidump 里
# `pc: kfree+0x54  lr: kdg_map_exit`）。
#
# 判据刻意保守：只认 `X->Y = kv*alloc(...)` / `X = v*alloc(...)` 这种本仓库
# 实际使用的写法，并要求同文件出现**逐字符相同**的 `kvfree(X->Y)`。
# 写法变了就得同步改这里 —— 这是有意为之：宁可漏报也不要误报，误报会让人
# 把这道闸关掉，那才是真的失去保护。
echo "--- 分配/释放配对审计（kv* → kvfree，v* → vfree）---"
# 判据两条，缺一不可 —— 第一条才是真正救命的那条：
#  1) 该指针**不得**出现在错误的释放函数里（kvmalloc 来的东西用 kfree → panic）；
#  2) 该指针必须出现在正确的释放函数里（防泄漏）。
# 只写第二条是不够的：同一个指针常常在**多条错误路径**上释放，改错其中一处，
# 文件里仍然存在另一处正确的 kvfree —— 门禁会放行。（第一版就是这样，我把
# kvfree(m->slots) 改回 kfree 之后它照样报「无」，靠反向注入测试才发现。）
PAIR_BAD=""
for f in "$PROJ_ROOT"/kernel/kdg_*.c; do
	# 先去掉所有空白再匹配，避免 `kvfree( m->buckets )` 这种写法误报。
	FLAT=$(tr -d ' \t' < "$f")
	SITES=$(grep -nE '^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*((->|\.)[A-Za-z_][A-Za-z0-9_]*)?[[:space:]]*=[[:space:]]*(kv(calloc|malloc|malloc_array|zalloc)|v(malloc|zalloc))' "$f" \
		| sed -E 's/^([0-9]+):[[:space:]]*([^[:space:]=]+)[[:space:]]*=[[:space:]]*([A-Za-z_][A-Za-z0-9_]*).*/\1 \2 \3/' || true)
	[ -n "$SITES" ] || continue
	while read -r ln lhs fn; do
		[ -n "$lhs" ] || continue
		case "$fn" in
		kv*)	want=kvfree ; bad="kfree" ;;
		v*)	want=vfree  ; bad="kfree kvfree" ;;
		*)	continue ;;
		esac
		# 第一条：不得用错误的释放函数
		for b in $bad; do
			case "$FLAT" in
			*"${b}(${lhs})"*) PAIR_BAD="$PAIR_BAD
  $(basename "$f"):$ln  ${lhs} = ${fn}(...)  却用 ${b}(${lhs}) 释放（会 panic 重启）" ;;
			esac
		done
		# 第二条：必须有正确的释放（防泄漏）
		case "$FLAT" in
		*"${want}(${lhs})"*) ;;
		*)	PAIR_BAD="$PAIR_BAD
  $(basename "$f"):$ln  ${lhs} = ${fn}(...)  找不到 ${want}(${lhs})（会泄漏）" ;;
		esac
	done <<< "$SITES"
done
if [ -n "$PAIR_BAD" ]; then
	echo "构建失败：分配/释放配对错误。"
	echo "kvmalloc 家族在尺寸较大时返回 vmalloc 地址，用 kfree 释放会 panic 重启。"
	echo "$PAIR_BAD"
	exit 1
fi
echo "无（每个 kv*/v* 分配都用正确的函数释放）"

# ── 剥掉调试信息 ────────────────────────────────────────────────────────
# mbedTLS 的调试节让 .ko 从 ~1.4 MB 膨胀到 ~5.8 MB。这不只是浪费：
# 实测 5.85 MB 的模块在真机上 insmod 直接报 "Out of memory"（模块加载走
# module_alloc → vmalloc，大块分配在内存碎片化的手机上会失败），
# 而同一个模块剥掉 .debug_* 后 1.46 MB，加载正常。
# 用 llvm-strip --strip-debug 而不是 --strip-all：后者会连 .BTF 一起动，
# 而 BTF 是内核侧诊断（bpftrace 等）要用的。
LLVM_STRIP="$KERNEL_ROOT/../clang-19/bin/llvm-strip"
if [ -x "$LLVM_STRIP" ]; then
	BEFORE=$(stat -c %s "$KO_DIR"/kdnsguard.ko)
	"$LLVM_STRIP" --strip-debug "$KO_DIR"/kdnsguard.ko
	AFTER=$(stat -c %s "$KO_DIR"/kdnsguard.ko)
	echo "已剥离调试信息：$((BEFORE/1024)) KiB -> $((AFTER/1024)) KiB"
else
	echo "（未找到 llvm-strip，模块将保持带调试信息的大小）"
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
