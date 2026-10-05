#!/system/bin/sh
# P6 第二轮：连接池落地后重跑 §17.3 矩阵。
#
# 与第一轮的差别只有两处，都是刻意的：
#   1) 每一次 C 路径运行都**额外记驱动线程的 CPU**。连接池把握手/收包的 CPU
#      从调用方线程搬到了内核的 kdg_pool 线程，而 kdgbench 报的是**它自己进程**
#      的 CPU（CLOCK_PROCESS_CPUTIME_ID）——只看那一栏会得到一个「CPU 大幅下降」
#      的假象，其实只是工作换了地方做。两栏相加才是真实成本。
#   2) 目录口径完全沿用第一轮（同轨迹、同上游、同网络、同并发档），
#      这样两轮的表格可以直接并排比。
#
# 驱动线程的 CPU 取 /proc/<tid>/schedstat 第一列（纳秒）。不用 /proc/<pid>/stat
# 的 utime/stime：本机 HZ=100，那是 10 ms 的刻度，量几百毫秒的运行等于拿尺子量头发。

T=/data/local/tmp
BB=/data/adb/ksu/bin/busybox
B=/data/user/0/com.boxproxy.box/files/box

# ── 驱动线程 ──────────────────────────────────────────────────────────
drv_tid() {
	for p in /proc/[0-9]*; do
		[ "$(cat "$p/comm" 2>/dev/null)" = "kdg_pool" ] && { echo "${p#/proc/}"; return; }
	done
}
drv_n() {
	n=0
	for p in /proc/[0-9]*; do
		[ "$(cat "$p/comm" 2>/dev/null)" = "kdg_pool" ] && n=$((n + 1))
	done
	echo "$n"
}
drv_cpu_ns() {
	t=$(drv_tid)
	[ -n "$t" ] || { echo 0; return; }
	awk '{print $1}' "/proc/$t/schedstat" 2>/dev/null || echo 0
}

kstats() {
	$T/kdgctl 2>&1 | $BB grep -E "doh_queries|doh_ok|h2_sessions|h2_requests|resolve_cache|resolve_upstream|resolve_joined|pool_connects|pool_reused|pool_inflight|pool_queued|pool_stream_limit|pool_idle_closes|pool_conn_errors|pool_upstream_timeouts|pool_rejected|pool_h1_fallbacks|pool_slots_used|pool_connected" \
		| $BB sed 's/^ *//' | $BB tr '\n' '|'
	echo
}

cold_start() {
	$BB rmmod kdnsguard 2>/dev/null
	# 等驱动线程真的消失：它没退干净时读到的 CPU 会把上一轮算进来
	for i in 1 2 3 4 5 6 7 8 9 10; do
		[ "$(drv_n)" = "0" ] && break
		$BB sleep 0.2
	done
	insmod $T/kdnsguard.ko >/dev/null 2>&1
	[ -e /dev/kdnsguard ] || mknod /dev/kdnsguard c 440 0
	$T/kdgctl trust $T/kdg_root.pem >/dev/null 2>&1
}

# C 路径单次运行。$1=label，其余是 kdgbench 参数。
# 线程在第一次查询时才懒启动，所以冷启动那一轮取的是「线程自诞生以来的总 CPU」，
# 正好就是这一轮的驱动开销；热态那一轮取差值。
run_c() {
	label=$1; shift
	c0=$(drv_cpu_ns)
	out=$($T/kdgbench chardev "$@" --label "$label" 2>&1)
	c1=$(drv_cpu_ns)
	echo "$out driver_cpu_ms=$(( (c1 - c0) / 1000000 ))"
}

run_a() {
	label=$1; shift
	$T/kdgbench udp 127.0.0.1:1053 "$@" --label "$label"
}

echo "########## 0. 环境 ##########"
echo "内核=$(uname -r)  构建号=$(uname -v | $BB sed 's/.*#\([0-9]*\).*/#\1/')"
echo "uptime=$(cut -d' ' -f1 /proc/uptime)s"
echo "出口接口=$(ip route | $BB awk '/^default/{print $5; exit}')  地址=$(ip route | $BB awk '/^default/{print $7; exit}')"
echo "充电=$(cat /sys/class/power_supply/battery/status) current_now=$(cat /sys/class/power_supply/battery/current_now)"
echo "kdgbench=$(ls -l $T/kdgbench | $BB awk '{print $5}')  ko=$(ls -l $T/kdnsguard.ko | $BB awk '{print $5}')"
echo "real.txt=$(wc -l < $T/real.txt) 行  burst100=$(wc -l < $T/burst100.txt) 行  random1000=$(wc -l < $T/random1000.txt) 行"
echo

echo "########## 1. 基线 A：mihomo 用户态 DNS（127.0.0.1:1053）##########"
$BB ss -lnpu 2>/dev/null | grep -q 1053 && echo "1053 在监听" || echo "!! 1053 未监听"
$B/bin/boxctl service restart >/dev/null 2>&1
$BB sleep 8
for c in 1 16 64; do
	run_a A-real-cold-c$c --trace $T/real.txt --concurrency $c
done
run_a A-burst100 --trace $T/burst100.txt --concurrency 32
run_a A-random1000 --trace $T/random1000.txt --concurrency 16

echo
echo "########## 2. 内核路径 C：冷 / 热（每档重载模块以得真空缓存）##########"
for c in 1 16 64; do
	cold_start
	run_c C-real-cold-c$c --trace $T/real.txt --concurrency $c
	echo "  cold 计数: $(kstats)"
	run_c C-real-warm-c$c --trace $T/real.txt --concurrency $c
	echo "  warm 计数: $(kstats)"
	echo "  驱动线程数=$(drv_n)"
done

echo
echo "########## 3. 同名爆发（§17.3：100 并发同名只应发 1 次上游）##########"
cold_start
run_c C-burst100 --trace $T/burst100.txt --concurrency 32
echo "  计数: $(kstats)"
$BB rmmod kdnsguard; echo "rmmod rc=$?  驱动线程数=$(drv_n)"

echo
echo "########## 4. 随机域名 1000（缓存完全帮不上忙）##########"
cold_start
run_c C-random1000 --trace $T/random1000.txt --concurrency 16
echo "  计数: $(kstats)"
$BB rmmod kdnsguard; echo "rmmod rc=$?  驱动线程数=$(drv_n)"

echo
echo "########## 5. 池化证据：一条连接服务了多少次查询 ##########"
cold_start
run_c C-pool-evidence --trace $T/real.txt --concurrency 16
echo "  第一次: $(kstats)"
run_c C-pool-evidence2 --trace $T/real.txt --concurrency 16
echo "  第二次: $(kstats)"

echo
echo "########## 6. 空闲关闭（方案 §6.3：60–180 秒）##########"
echo "查询前: $(kstats)"
$BB sleep 95
echo "空闲 95s 后: $(kstats)"
run_c C-after-idle --trace $T/smoke.txt --concurrency 1
echo "再次查询后: $(kstats)"

echo
echo "########## 7. 收尾 ##########"
$BB rmmod kdnsguard; echo "rmmod rc=$?"
$BB sleep 1
echo "驱动线程数=$(drv_n)"
echo "模块数=$(lsmod | $BB grep -c .)"
echo "告警=$(dmesg | $BB grep -cE 'BUG:|WARNING:|Oops|CFI failure|Internal error|cut here')"
echo "kdnsguard 相关 dmesg:"
dmesg | $BB grep -iE "kdnsguard" | $BB tail -20
