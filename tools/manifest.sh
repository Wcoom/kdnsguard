#!/bin/bash
# manifest.sh —— 生成 kernel_build_manifest（方案 §15）。
#
# 为什么必须生成它：本内核的版本串是**固定**的
# （6.6.118-android15-8-gf4dc45704e54-abogki20260727-4k，CONFIG_LOCALVERSION 写死、
# LOCALVERSION_AUTO 关闭），所以 `uname -r` **无法**区分两次不同的构建。
# 方案 §2.1 已经点明这一点。模块与内核的任何不一致（符号表、配置、
# UAPI 版本）都必须靠这份清单比对，不能靠版本串。
#
# 输出为 key=value 纯文本，便于 diff 与机器读取。
#
# 用法： bash tools/manifest.sh [输出文件]     默认 third_party/ 下不带时间戳的 stdout
set -e

KERNEL_ROOT="${KDG_KERNEL_ROOT:-/home/wcoom/桌面/oplus13/android_kernel_common_oneplus_sm8750}"
PROJ_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-}"

[ -f "$KERNEL_ROOT/out/.config" ] || { echo "缺少 $KERNEL_ROOT/out/.config" >&2; exit 1; }
[ -f "$KERNEL_ROOT/out/Module.symvers" ] || { echo "缺少 Module.symvers" >&2; exit 1; }

sha() { [ -f "$1" ] && sha256sum "$1" | cut -d' ' -f1 || echo "(absent)"; }
gro() { echo "$(grep "$1" "$KERNEL_ROOT/out/include/generated/utsrelease.h" 2>/dev/null | sed 's/.*"\(.*\)"/\1/')"; }

emit() {
	printf '%-34s %s\n' "$1" "$2"
}

{
	emit "manifest_version" "1"
	emit "generated_at" "$(date -Is)"

	echo ""
	echo "# ── 源码与补丁 ──────────────────────────────────────────────"
	emit "source_commit" "$(git -C "$KERNEL_ROOT" rev-parse HEAD)"
	emit "source_branch" "$(git -C "$KERNEL_ROOT" rev-parse --abbrev-ref HEAD)"
	emit "source_dirty" "$([ -n "$(git -C "$KERNEL_ROOT" status --porcelain)" ] && echo yes || echo no)"
	# 本地补丁清单 = 相对上游 ack 分支未合并的提交签名概要
	emit "local_patch_count" "$(git -C "$KERNEL_ROOT" rev-list --count ack/android15-6.6..HEAD 2>/dev/null || echo '(unavailable)')"
	echo "local_patch_head:"
	git -C "$KERNEL_ROOT" log --oneline -12 2>/dev/null | sed 's/^/    /'

	echo ""
	echo "# ── 有效配置 ────────────────────────────────────────────────"
	emit "effective_config_sha256" "$(sha "$KERNEL_ROOT/out/.config")"
	emit "uts_release" "$(gro UTS_RELEASE)"
	# 与 kdnsguard 直接相关的若干项，单独列出以免 diff 淹没
	for sym in CONFIG_NF_TABLES CONFIG_NF_NAT CONFIG_NF_NAT_REDIRECT CONFIG_NF_CONNTRACK \
		   CONFIG_MODULES CONFIG_MODVERSIONS CONFIG_KALLSYMS_ALL CONFIG_DEBUG_FS \
		   CONFIG_X509_CERTIFICATE_PARSER CONFIG_CRYPTO_ECDH CONFIG_TLS; do
		v=$(grep -E "^${sym}=" "$KERNEL_ROOT/out/.config" 2>/dev/null || echo "# ${sym} is not set")
		emit "cfg.${sym}" "${v#*=}"
	done

	echo ""
	echo "# ── 编译环境 ────────────────────────────────────────────────"
	CLANG="$KERNEL_ROOT/../clang-19/bin/clang"
	[ -x "$CLANG" ] || CLANG="$KERNEL_ROOT/../../../clang-19/bin/clang"
	if [ -x "$CLANG" ]; then
		emit "compiler_identity" "$("$CLANG" --version 2>/dev/null | head -1)"
		emit "compiler_sha256" "$(sha "$CLANG")"
	else
		emit "compiler_identity" "(clang-19 未在预期路径找到)"
	fi
	emit "pahole" "$(pahole --version 2>/dev/null || echo '(absent)')"

	echo ""
	echo "# ── 符号表与产物 ────────────────────────────────────────────"
	emit "module_symvers_sha256" "$(sha "$KERNEL_ROOT/out/Module.symvers")"
	emit "image_bytes" "$(stat -c %s "$KERNEL_ROOT/out/arch/arm64/boot/Image" 2>/dev/null || echo '(absent)')"
	emit "image_sha256" "$(sha "$KERNEL_ROOT/out/arch/arm64/boot/Image")"
	emit "vmlinux_sha256" "$(sha "$KERNEL_ROOT/out/vmlinux")"

	echo ""
	echo "# ── 本项目 ──────────────────────────────────────────────────"
	KO="$PROJ_ROOT/kernel/kdnsguard.ko"
	emit "uapi_version" "$(grep -m1 '^#define KDG_ABI_VERSION' "$PROJ_ROOT/include/uapi/kdnsguard.h" | awk '{print $3}')"
	emit "genl_name" "$(grep -m1 '^#define KDG_GENL_NAME' "$PROJ_ROOT/include/uapi/kdnsguard.h" | awk '{print $3}')"
	emit "module_bytes" "$(stat -c %s "$KO" 2>/dev/null || echo '(not built)')"
	emit "module_sha256" "$(sha "$KO")"
	emit "module_vermagic" "$(modinfo -F vermagic "$KO" 2>/dev/null || echo '(absent)')"
	emit "project_commit" "$(git -C "$PROJ_ROOT" rev-parse HEAD 2>/dev/null || echo '(no git)')"

	echo ""
	echo "# ── 依赖锁定 ────────────────────────────────────────────────"
	emit "third_party_lock_sha256" "$(sha "$PROJ_ROOT/third_party/third_party.lock")"
} | { [ -n "$OUT" ] && tee "$OUT" || cat; }
