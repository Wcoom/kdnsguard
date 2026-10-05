#!/system/bin/sh
# 只补 A 的 CPU：把「重启后立刻开跑」改成「等 mihomo 真的静下来」。
# 上一版的 r3 量到 2050 ms，而 r1/r2 是 980/890 —— 差别不在 DNS，
# 在**重启后的配置/规则集加载**落进了测量窗口（mihomo 稳态空闲只有 0–8 ms/s）。
T=/data/local/tmp; BB=/data/adb/ksu/bin/busybox; B=/data/user/0/com.boxproxy.box/files/box; HZ=100
pid_of() { for p in /proc/[0-9]*; do [ "$(cat "$p/comm" 2>/dev/null)" = "$1" ] && { echo "${p#/proc/}"; return; }; done; }
cpu_j() { awk '{print $14 + $15}' "/proc/$1/stat" 2>/dev/null || echo 0; }

# 等到 mihomo 的 CPU 在连续 3 秒里几乎不动为止（上限 60 秒）
settle() {
	last=0; stable=0; n=0
	while [ $n -lt 60 ]; do
		p=$(pid_of mihomo); c=$(cpu_j "$p")
		d=$(( (c - last) * 1000 / HZ ))
		[ "$n" -gt 0 ] && [ "$d" -le 20 ] && stable=$((stable + 1)) || stable=0
		[ "$stable" -ge 3 ] && { echo "  mihomo 静下来用了 ${n}s"; return; }
		last=$c; n=$((n + 1)); $BB sleep 1
	done
	echo "  !! 60s 内没静下来"
}

for r in 1 2 3 4; do
	$B/bin/boxctl service restart >/dev/null 2>&1
	$BB sleep 5
	settle
	p=$(pid_of mihomo); m0=$(cpu_j "$p")
	$T/kdgbench udp 127.0.0.1:1053 --trace $T/random1000.txt --concurrency 16 --label A5-random1000-r$r
	m1=$(cpu_j "$p")
	echo "  mihomo_cpu_ms=$(( (m1 - m0) * 1000 / HZ ))"
done
