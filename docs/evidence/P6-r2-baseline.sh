#!/system/bin/sh
# P6 第二轮 · 基线补测。
#
# 为什么必须补：上一版脚本对 C 路径是「每一档都重载模块」，对 A 路径却只在
# 最前面重启了一次 mihomo —— 于是 c1 那一跑把它的 DNS 缓存全部预热了，
# c16/c64 拿到的根本不是冷启动，p50 掉到 0.5–3 ms（表面上看比内核快几百倍，
# 实际是拿它的**热**去比内核的**冷**）。
#
# 这一版对 A 也逐档重启，口径与 C 完全对齐：两边每一档都是冷的。

T=/data/local/tmp
BB=/data/adb/ksu/bin/busybox
B=/data/user/0/com.boxproxy.box/files/box

echo "### 监听自检（用 /proc/net 而不是 busybox ss：后者在部分机型上拿不到 -p）"
grep -c ":1495" /proc/net/udp 2>/dev/null | $BB sed 's/^/1053(0x1495) 条目数=/'

run_a() {
	label=$1; shift
	$T/kdgbench udp 127.0.0.1:1053 "$@" --label "$label"
}

for c in 1 16 64; do
	$B/bin/boxctl service restart >/dev/null 2>&1
	$BB sleep 5
	run_a A2-real-cold-c$c --trace $T/real.txt --concurrency $c
done

$B/bin/boxctl service restart >/dev/null 2>&1
$BB sleep 5
run_a A2-burst100 --trace $T/burst100.txt --concurrency 32

$B/bin/boxctl service restart >/dev/null 2>&1
$BB sleep 5
run_a A2-random1000 --trace $T/random1000.txt --concurrency 16

echo "### 基线连通性复核"
$T/kdgbench udp 127.0.0.1:1053 --trace $T/smoke.txt --concurrency 1 --label A2-smoke
