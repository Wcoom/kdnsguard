#!/system/bin/sh
# P6 第二轮 · CPU 对比（修正版）。
#
# 两处修正，都是被实测打出来的：
#
# 1) **只报 kdgbench 的 CPU 会同时骗过两边**。
#    C 路径的 DNS 活在 kdg_pool 内核线程里，A 路径的活在 **mihomo 进程**里
#    —— 而两者都不是 kdgbench 这个进程。不把干活的进程算进来，就会看到
#    「内核几乎不花 CPU」和「基线几乎不花 CPU」两个都不成立的结论。
#
# 2) **不能靠逐线程累加 /proc/*/task/*/schedstat**。
#    对 Go 写的 mihomo，线程会随调度生灭，累加值因此**不单调** ——
#    实测拿到过 -1200 ms 的「CPU 用量」。改用 /proc/<pid>/stat 的
#    utime+stime：它覆盖整个线程组且单调递增，代价是 10 ms 的刻度
#    （HZ=100），对几秒级的运行完全够用。

T=/data/local/tmp
BB=/data/adb/ksu/bin/busybox
B=/data/user/0/com.boxproxy.box/files/box
HZ=100

pid_of() {
	for p in /proc/[0-9]*; do
		[ "$(cat "$p/comm" 2>/dev/null)" = "$1" ] && { echo "${p#/proc/}"; return; }
	done
}
# 整个线程组的 CPU（jiffies）
cpu_j() { awk '{print $14 + $15}' "/proc/$1/stat" 2>/dev/null || echo 0; }

MIHOMO_PID=""

run_a() {
	label=$1; shift
	# ⚠️ **必须在这里重新解析 pid**：run_a 的前一步是 boxctl service restart，
	# 它会换掉整个 mihomo 进程。沿用脚本开头抓到的 pid 就会去读一个已经消失的
	# /proc 条目，awk 打不出东西、回落到 0，于是得到「基线完全不花 CPU」这种
	# 看起来漂亮、实际是测量失败的数字。实测踩过一次。
	MIHOMO_PID=$(pid_of mihomo)
	m0=$(cpu_j "$MIHOMO_PID")
	out=$($T/kdgbench udp 127.0.0.1:1053 "$@" --label "$label" 2>&1)
	m1=$(cpu_j "$MIHOMO_PID")
	echo "$out mihomo_pid=$MIHOMO_PID mihomo_cpu_ms=$(( (m1 - m0) * 1000 / HZ ))"
}

run_c() {
	label=$1; shift
	t=$(pid_of kdg_pool)
	c0=$([ -n "$t" ] && cpu_j "$t" || echo 0)
	out=$($T/kdgbench chardev "$@" --label "$label" 2>&1)
	t=$(pid_of kdg_pool)
	c1=$([ -n "$t" ] && cpu_j "$t" || echo 0)
	echo "$out driver_cpu_ms=$(( (c1 - c0) * 1000 / HZ ))"
}

cold_start() {
	$BB rmmod kdnsguard 2>/dev/null
	for i in 1 2 3 4 5 6 7 8 9 10; do
		[ -z "$(pid_of kdg_pool)" ] && break
		$BB sleep 0.2
	done
	insmod $T/kdnsguard.ko >/dev/null 2>&1
	[ -e /dev/kdnsguard ] || mknod /dev/kdnsguard c 440 0
	$T/kdgctl trust $T/kdg_root.pem >/dev/null 2>&1
}

block() { $B/bin/boxctl service restart >/dev/null 2>&1; $BB sleep 5; }

MIHOMO_PID=$(pid_of mihomo)
echo "mihomo pid=$MIHOMO_PID  HZ=$HZ"

echo
echo "########## 0. 基线噪声：mihomo 空闲 5 秒的 CPU ##########"
for i in 1 2 3; do
	m0=$(cpu_j "$MIHOMO_PID")
	$BB sleep 5
	m1=$(cpu_j "$MIHOMO_PID")
	echo "  空闲 5s: $(( (m1 - m0) * 1000 / HZ )) ms"
done

echo
echo "########## A：用户态基线 ##########"
for r in 1 2 3; do
	block
	run_a A4-real-cold-c16-r$r --trace $T/real.txt --concurrency 16
done
for r in 1 2 3; do
	block
	run_a A4-random1000-cold-c16-r$r --trace $T/random1000.txt --concurrency 16
done

echo
echo "########## C：内核路径 ##########"
for r in 1 2; do
	cold_start
	run_c C4-real-cold-c16-r$r --trace $T/real.txt --concurrency 16
done
for r in 1 2; do
	cold_start
	run_c C4-random1000-cold-c16-r$r --trace $T/random1000.txt --concurrency 16
	echo "  计数: $($T/kdgctl 2>&1 | $BB grep -E 'pool_connects|doh_queries|h2_requests' | $BB tr '\n' ' ')"
done

echo
$BB rmmod kdnsguard; echo "rmmod rc=$?"
echo "告警=$(dmesg | $BB grep -cE 'BUG:|WARNING:|Oops|CFI failure|Internal error')"
