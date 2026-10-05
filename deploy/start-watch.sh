#!/system/bin/sh
# 拉起配置监视（kdgwatchd double-fork，活过 KernelSU su -c）。
set +e
KDG=/data/adb/kdnsguard
STATE=/data/user/0/com.boxproxy.box/files/box/run/state
BB=/data/adb/ksu/bin/busybox
killall inotifyd 2>/dev/null
killall kdgwatchd 2>/dev/null
sleep 0.2
# 掩码必须是 busybox 认的字母：w=close-write c=modify M=moved。
# 曾经写成 wcyn，y/n 非法，inotifyd 立刻退出，表现为「监视拉不起来」。
"$KDG/kdgwatchd" "$BB" inotifyd "$KDG/watch.sh" "$STATE:wcM"
echo "watch started"
