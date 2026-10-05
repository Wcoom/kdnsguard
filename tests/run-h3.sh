#!/usr/bin/env bash
# 端到端 H3 DoH：向真实上游发查询
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$ROOT/tests/build/h3"
Q="$ROOT/tests/build/quic"
mkdir -p "$DIR"
"$ROOT/tests/run-quic-crypto.sh" >/dev/null
CF=(-DKDG_H3_TRACE -std=gnu11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined
    -fno-omit-frame-pointer -fno-sanitize-recover=all
    -DMBEDTLS_CONFIG_FILE='"tls_host_config.h"' -I"$ROOT/tests" -I"$ROOT/include"
    -I"$ROOT/kernel" -I"$ROOT/third_party/mbedtls-kernel" -I"$ROOT/third_party/mbedtls/include")
for f in kdg_h3 kdg_qpack kdg_quic_conn kdg_quic_frame kdg_tls13; do
  gcc "${CF[@]}" -c "$ROOT/kernel/$f.c" -o "$DIR/$f.o"
done
gcc "${CF[@]}" -c "$ROOT/tests/test_h3.c" -o "$DIR/test_h3.o"
gcc -fsanitize=address,undefined "$DIR"/*.o "$Q/kdg_quic_crypto.o" "$Q/libmbed.a" \
    -o "$DIR/test_h3"
exec "$DIR/test_h3" "$@"
