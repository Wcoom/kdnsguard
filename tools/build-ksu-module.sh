#!/usr/bin/env bash
# 打包 KernelSU/Magisk 模块 zip：kdnsguard.ko + 开机脚本 + 安装期检查。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VER=$(sed -n 's/^version=//p' "$ROOT/deploy/ksu-module/module.prop")
DIST="$ROOT/dist"
STAGE="$DIST/ksu-stage"

echo "== 1/3 构建模块"
bash "$ROOT/tools/build.sh" >"$DIST/build.log" 2>&1 || { tail -20 "$DIST/build.log"; exit 1; }

echo "== 2/3 组装"
rm -rf "$STAGE"; mkdir -p "$STAGE"
cp -r "$ROOT/deploy/ksu-module/." "$STAGE/"
cp "$ROOT/kernel/kdnsguard.ko" "$STAGE/kdnsguard.ko"
[ -x "$ROOT/tools/kdgctl" ] && cp "$ROOT/tools/kdgctl" "$STAGE/kdgctl"
chmod 755 "$STAGE"/*.sh
[ -f "$STAGE/kdgctl" ] && chmod 755 "$STAGE/kdgctl"

echo "== 3/3 打包"
OUT="$DIST/kdnsguard-ksu-$VER.zip"
rm -f "$OUT"
(cd "$STAGE" && zip -qr "$OUT" .)
echo "完成: $OUT（$(stat -c%s "$OUT") 字节）"
unzip -l "$OUT" | tail -12
