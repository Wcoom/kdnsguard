#!/usr/bin/env bash
# 与真实 QUIC 服务器对打（默认上游 DoH 端点）
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$ROOT/tests/build/quicctor"
Q="$ROOT/tests/build/quic"
mkdir -p "$DIR"
"$ROOT/tests/run-quic-crypto.sh" >/dev/null
CF=(-std=gnu11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined
    -fno-omit-frame-pointer -fno-sanitize-recover=all
    -DMBEDTLS_CONFIG_FILE='"tls_host_config.h"' -I"$ROOT/tests" -I"$ROOT/include"
    -I"$ROOT/kernel" -I"$ROOT/third_party/mbedtls-kernel" -I"$ROOT/third_party/mbedtls/include")
for f in kdg_quic_conn kdg_quic_frame kdg_tls13; do
  gcc "${CF[@]}" -c "$ROOT/kernel/$f.c" -o "$DIR/$f.o"
done
gcc "${CF[@]}" -c "$ROOT/tests/test_quic_conn.c" -o "$DIR/test_quic_conn.o"
gcc -fsanitize=address,undefined "$DIR"/*.o "$Q/kdg_quic_crypto.o" "$Q/libmbed.a" \
    -o "$DIR/test_quic_conn"
exec "$DIR/test_quic_conn" "$@"
