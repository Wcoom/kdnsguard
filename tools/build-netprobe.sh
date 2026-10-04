#!/bin/bash
# 使用本地 Android NDK 构建静态路径探针；不部署、不改变设备网络。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NDK="${ANDROID_NDK_HOME:-/home/wcoom/.local/boxp-toolchain/android-ndk-r29}"
CC="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang"
"$CC" -std=gnu11 -O2 -Wall -Wextra -Werror -static \
    -I"$ROOT/include" -I"$ROOT/kernel" \
    "$ROOT/tools/netprobe.c" "$ROOT/kernel/kdg_wire.c" \
    -o "$ROOT/tools/netprobe"
file "$ROOT/tools/netprobe"
