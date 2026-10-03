#!/bin/bash
# 构建 kdgctl：aarch64 freestanding 静态二进制。
# 不链接 libc —— 本机没有 aarch64 交叉 libc，设备是 bionic，两者都不好用。
# 只发裸系统调用反而是最稳的路径，产物零依赖、直接 push 即可运行。
set -e

TOOLS_DIR="$(cd "$(dirname "$0")" && pwd)"
CLANG="/home/wcoom/桌面/oplus13/clang-19/bin/clang"
OUT="$TOOLS_DIR/kdgctl"

"$CLANG" --target=aarch64-linux-gnu \
	-nostdlib -static -fno-stack-protector -fno-builtin \
	-fno-asynchronous-unwind-tables \
	-O2 -Wall -Wextra \
	-I"$TOOLS_DIR/include" \
	-I"$TOOLS_DIR/../include" \
	-Wl,-e,_start -Wl,--build-id=none \
	-o "$OUT" "$TOOLS_DIR/kdgctl.c"

echo "构建完成："
ls -la "$OUT"
file "$OUT" 2>/dev/null || true
