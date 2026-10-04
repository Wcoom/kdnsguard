#!/bin/bash
# build-android.sh —— 把 Rust 客户端交叉编译到 aarch64-linux-android。
#
# 为什么单独一个脚本而不是写进 .cargo/config.toml：linker 是**绝对路径**，
# 写进 config.toml 就等于把某台机器的目录结构提交进仓库，换机器必挂
# （而且失败信息会是难懂的 ld 报错，不是「找不到工具链」）。
# 这里显式检测、给出人话错误。
#
# 工具链来源：本机 Rust 在 ~/.local/boxp-toolchain（rustup 1.98.1，已装
# aarch64-linux-android target），NDK r29 同目录。别的机器上按需覆盖：
#   RUSTUP_HOME / CARGO_HOME / ANDROID_NDK_ROOT 三个环境变量。
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

: "${RUSTUP_HOME:=$HOME/.local/boxp-toolchain/rustup}"
: "${CARGO_HOME:=$HOME/.local/boxp-toolchain/cargo}"
: "${ANDROID_NDK_ROOT:=$HOME/.local/boxp-toolchain/android-ndk-r29}"
export RUSTUP_HOME CARGO_HOME

CARGO="$CARGO_HOME/bin/cargo"
[ -x "$CARGO" ] || { echo "找不到 cargo：$CARGO（设 CARGO_HOME 或用 rustup 装一个）"; exit 1; }
[ -d "$ANDROID_NDK_ROOT" ] || { echo "找不到 NDK：$ANDROID_NDK_ROOT（设 ANDROID_NDK_ROOT）"; exit 1; }

CLANG="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang"
[ -x "$CLANG" ] || { echo "找不到 NDK clang：$CLANG"; exit 1; }
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$CLANG"

cd "$HERE"
# --offline：本 crate 零依赖，不该因为 crates.io 不可达而失败（本机网络受限）。
"$CARGO" build --offline --target aarch64-linux-android --release "$@"

echo
echo "产物：$HERE/target/aarch64-linux-android/release/examples/kdgctl"
echo "推送到设备："
echo "  adb push target/aarch64-linux-android/release/examples/kdgctl /data/local/tmp/kdgctl-rs"
echo "  adb shell su -c 'chmod +x /data/local/tmp/kdgctl-rs'"
