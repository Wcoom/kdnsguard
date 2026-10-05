#!/usr/bin/env bash
# H3 帧解析的离线负例（不联网）
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$ROOT/tests/build/h3f"
Q="$ROOT/tests/build/quic"
rm -rf "$DIR"
mkdir -p "$DIR"
"$ROOT/tests/run-quic-crypto.sh" >/dev/null
CF=(-std=gnu11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined
    -fno-omit-frame-pointer -fno-sanitize-recover=all
    -DMBEDTLS_CONFIG_FILE='"tls_host_config.h"' -I"$ROOT/tests" -I"$ROOT/include"
    -I"$ROOT/kernel" -I"$ROOT/third_party/mbedtls-kernel" -I"$ROOT/third_party/mbedtls/include")
for f in kdg_h3 kdg_qpack kdg_quic_conn kdg_quic_frame kdg_tls13; do
  gcc "${CF[@]}" -c "$ROOT/kernel/$f.c" -o "$DIR/$f.o"
done
gcc "${CF[@]}" -c "$ROOT/tests/test_h3_frames.c" -o "$DIR/test_h3_frames.o"
gcc -fsanitize=address,undefined "$DIR"/*.o "$Q/kdg_quic_crypto.o" "$Q/libmbed.a" \
    -o "$DIR/test_h3_frames"
"$DIR/test_h3_frames"
