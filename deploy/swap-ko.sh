#!/system/bin/sh
# 热换 kdnsguard.ko：停核心 → 交还所有权 → rmmod → 换文件 → apply.sh 重新接上。
# 用法：先把新模块推到 /data/local/tmp/kdnsguard.ko.new，再以 root 执行本脚本。
KDG=/data/adb/kdnsguard
CTL=/data/user/0/com.boxproxy.box/files/box/bin/boxctl
NEW=/data/local/tmp/kdnsguard.ko.new
log() { echo "$(date +%H:%M:%S) swap-ko: $*" >> "$KDG/log"; echo "$*"; }

[ -f "$NEW" ] || { log "没有 $NEW"; exit 1; }
cp -f "$KDG/kdnsguard.ko" "$KDG/kdnsguard.ko.prev"
"$CTL" service stop >/dev/null 2>&1
"$KDG/kdgctl" disable >/dev/null 2>&1
rmmod kdnsguard || { log "rmmod 失败，保持旧模块"; "$CTL" service start; exit 1; }
cp -f "$NEW" "$KDG/kdnsguard.ko"
chmod 0644 "$KDG/kdnsguard.ko"
sh "$KDG/apply.sh"
rc=$?
"$CTL" service start >/dev/null 2>&1
log "已换模块，apply rc=$rc"
exit $rc
