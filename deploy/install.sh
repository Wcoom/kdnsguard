#!/bin/bash
# 从开发机把常驻资产推到设备并立刻启用。
# 用法：
#   bash deploy/install.sh
#   bash deploy/install.sh --enable-only
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
S="${ANDROID_SERIAL:-5d6d4090}"
ADB="adb -s $S"
KDG=/data/adb/kdnsguard
B=/data/user/0/com.boxproxy.box/files/box
KO="${KDG_KO:-$ROOT/kernel/kdnsguard.ko}"
CORE="${KDG_CORE:-/tmp/mihomo-kdgp4final}"
PEM_HOST=/tmp/kdg_root.pem
ENABLE_ONLY=0
[ "${1:-}" = "--enable-only" ] && ENABLE_ONLY=1

$ADB get-state >/dev/null
echo "device=$S"

if [ "$ENABLE_ONLY" -eq 0 ]; then
	[ -f "$KO" ] || { echo "没有 $KO"; exit 1; }
	[ -f "$CORE" ] || { echo "没有 $CORE（先编 android-arm64-ebpf 核心）"; exit 1; }
	if [ ! -f "$PEM_HOST" ]; then
		$ADB pull /data/local/tmp/kdg_root.pem "$PEM_HOST" >/dev/null
	fi
	[ -f "$PEM_HOST" ] || { echo "没有 kdg_root.pem"; exit 1; }

	$ADB shell su -c "mkdir -p $KDG /data/adb/service.d"
	$ADB push "$KO" /data/local/tmp/kdnsguard.ko >/dev/null
	$ADB push "$CORE" /data/local/tmp/mihomo-kdgp4final >/dev/null
	$ADB push "$ROOT/tools/kdgctl" /data/local/tmp/kdgctl >/dev/null
	$ADB push "$PEM_HOST" /data/local/tmp/kdg_root.pem >/dev/null
	$ADB push "$ROOT/deploy/edns-rules.yaml" /data/local/tmp/edns-rules.yaml >/dev/null
	for f in apply.sh watch.sh boot.sh disable.sh enable-now.sh start-watch.sh loop.sh swap-ko.sh; do
		$ADB push "$ROOT/deploy/$f" /data/local/tmp/kdg-$f >/dev/null
	done
	$ADB shell su -c "cp /data/local/tmp/kdnsguard.ko $KDG/kdnsguard.ko; cp /data/local/tmp/mihomo-kdgp4final $KDG/mihomo-kdgp4final; cp /data/local/tmp/kdgctl $KDG/kdgctl; cp /data/local/tmp/kdg_root.pem $KDG/kdg_root.pem; cp /data/local/tmp/kdg-apply.sh $KDG/apply.sh; cp /data/local/tmp/kdg-watch.sh $KDG/watch.sh; cp /data/local/tmp/kdg-boot.sh $KDG/boot.sh; cp /data/local/tmp/kdg-disable.sh $KDG/disable.sh; cp /data/local/tmp/kdg-enable-now.sh $KDG/enable-now.sh; cp /data/local/tmp/kdg-start-watch.sh $KDG/start-watch.sh; cp /data/local/tmp/kdg-loop.sh $KDG/loop.sh; cp /data/local/tmp/kdg-swap-ko.sh $KDG/swap-ko.sh; cp /data/local/tmp/edns-rules.yaml $KDG/edns-rules.yaml; chmod 755 $KDG/*.sh $KDG/kdgctl $KDG/mihomo-kdgp4final; chmod 644 $KDG/kdnsguard.ko $KDG/kdg_root.pem; test -f $KDG/mihomo.stock || cp -a $B/bin/mihomo $KDG/mihomo.stock; test -f $KDG/startup-config.stock || cp -a $B/run/state/startup-config $KDG/startup-config.stock; cp $KDG/boot.sh /data/adb/service.d/99-kdnsguard.sh; chmod 755 /data/adb/service.d/99-kdnsguard.sh; touch $KDG/enabled"
	echo "资产已落 $KDG"
fi

echo "立刻启用（不重启手机）"
$ADB push "$ROOT/deploy/enable-now.sh" /data/local/tmp/kdg-enable-now.sh >/dev/null
$ADB shell su -c "cp /data/local/tmp/kdg-enable-now.sh $KDG/enable-now.sh; chmod 755 $KDG/enable-now.sh; sh $KDG/enable-now.sh"
echo "INSTALL_DONE"
