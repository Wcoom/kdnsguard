#!/bin/bash
# 笔记本侧编排：P4 移交真机窗口。
# 设备是本机上网出口。adb 走 USB，不断网也能控。窗口结束必须还原。
set -euo pipefail
S=5d6d4090
ADB="adb -s $S"
B=/data/user/0/com.boxproxy.box/files/box
T=/data/local/tmp
OUT=$T/kdg-final
HERE=/tmp/kdg-final
LOG=/tmp/kdg-final/host.log
exec > >(tee -a "$LOG") 2>&1

cleanup() {
	echo
	echo "======== cleanup / 还原 ========"
	$ADB shell su -c "sh $T/90-restore.sh" || true
	$ADB forward --remove tcp:19090 >/dev/null 2>&1 || true
}
trap cleanup EXIT

say() { echo; echo "======== $* ========"; }

push_exec() {
	local f=$1
	$ADB push "$HERE/$f" $T/$f >/dev/null
	$ADB shell su -c "chmod 755 $T/$f && sh $T/$f"
}

say "0. 推送产物"
$ADB push /home/wcoom/桌面/kdnsguard/kernel/kdnsguard.ko $T/kdnsguard.ko
$ADB push /home/wcoom/桌面/kdnsguard/tools/kdgctl $T/kdgctl
$ADB push /home/wcoom/桌面/kdnsguard/tools/chrneg $T/chrneg
$ADB push /tmp/mihomo-kdgp4final $T/mihomo-kdgp4final
$ADB push $HERE/startup-kernel.yaml $T/startup-kernel.yaml
$ADB push $HERE/startup-userspace.yaml $T/startup-userspace.yaml
$ADB shell su -c "chmod 755 $T/kdgctl $T/chrneg $T/mihomo-kdgp4final; mkdir -p $OUT"
# 脚本
for f in 00-preflight.sh 10-deploy.sh 20-matrix.sh 22-owner-arm.sh 23-owner-disarm.sh 30-inject.sh 40-kill.sh 50-chrneg.sh 90-restore.sh; do
	$ADB push "$HERE/$f" $T/$f >/dev/null
	$ADB shell su -c "chmod 755 $T/$f"
done

say "1. 预检"
$ADB shell su -c "sh $T/00-preflight.sh"

say "2. 部署（换核心+配置+模块）"
$ADB shell su -c "sh $T/10-deploy.sh"

say "3. 接管矩阵"
$ADB shell su -c "sh $T/20-matrix.sh"

say "4. 笔记本 → 手机 rndis DNS（热点 PREROUTING）"
PHONE_DNS=$(ip -o -4 addr show | awk '/enx|usb/ {print $4}' | head -1 | cut -d/ -f1)
# 手机 rndis 地址：从设备读
RNDIS=$($ADB shell su -c "ip -o -4 addr show rndis0 | awk '{print \$4}' | cut -d/ -f1" | tr -d '\r')
echo "rndis0=$RNDIS  laptop=$(hostname -I | awk '{print $1}')"
if [ -n "$RNDIS" ]; then
	dig +time=3 +tries=1 @"$RNDIS" example.com A | tee $HERE/hotspot-dig.txt | tail -20
else
	echo "无 rndis0，跳过热点"
fi

say "5. adb forward 控制器 + 延迟测试（节点解析走 KernelResolver）"
$ADB forward tcp:19090 tcp:9090
sleep 1
curl -sS --max-time 3 http://127.0.0.1:19090/version | tee $HERE/ctrl-version.json || echo 'controller 未就绪'
# 取几个有 server 的代理名
python3 - <<'PY'
import json, urllib.request, urllib.parse, subprocess, time, sys
base='http://127.0.0.1:19090'
try:
    with urllib.request.urlopen(base+'/proxies', timeout=5) as r:
        data=json.load(r)
except Exception as e:
    print('proxies 失败', e); sys.exit(0)
proxies=data.get('proxies') or {}
# 挑 type 为 vmess/trojan/ss/hysteria 等、有 history 或可 delay 的
names=[]
for n,p in proxies.items():
    t=p.get('type','')
    if t in ('VMess','Trojan','SS','SSR','Hysteria','Hysteria2','VLESS','WireGuard','TUIC'):
        names.append(n)
    if len(names)>=4: break
print('delay targets:', names)
open('/tmp/kdg-final/delay-targets.txt','w').write('\n'.join(names))
PY

say "5b. 武装 uid-0 REJECT 再打 delay"
$ADB shell su -c "sh $T/22-owner-arm.sh"
python3 - <<'PY'
import json, urllib.request, urllib.parse, time
base='http://127.0.0.1:19090'
try:
    names=open('/tmp/kdg-final/delay-targets.txt').read().splitlines()
except FileNotFoundError:
    names=[]
results=[]
for n in names[:4]:
    q=urllib.parse.quote(n)
    url=f'{base}/proxies/{q}/delay?timeout=5000&url=http://www.gstatic.com/generate_204'
    t0=time.time()
    try:
        with urllib.request.urlopen(url, timeout=8) as r:
            body=r.read().decode()
        print(f'DELAY_OK {n} {body} elapsed={time.time()-t0:.2f}s')
        results.append(('ok', n, body))
    except Exception as e:
        print(f'DELAY_FAIL {n} {e} elapsed={time.time()-t0:.2f}s')
        results.append(('fail', n, str(e)))
# REST DNS query（直调 DefaultResolver.ExchangeContext）
import struct
# 用 /dns/query?name=example.com&type=A
try:
    with urllib.request.urlopen(base+'/dns/query?name=example.com&type=A', timeout=5) as r:
        print('DNSQ', r.status, r.read()[:200])
except Exception as e:
    print('DNSQ_FAIL', e)
open('/tmp/kdg-final/delay-results.txt','w').write('\n'.join(map(str,results)))
PY
$ADB shell su -c "sh $T/23-owner-disarm.sh"

say "6. 热重载：同配置 PUT（应复用，不 EBUSY）"
python3 - <<'PY'
import json, urllib.request
cfg=open('/tmp/kdg-final/startup-kernel.yaml').read()
req=urllib.request.Request('http://127.0.0.1:19090/configs?force=true',
    data=json.dumps({'payload': cfg}).encode(),
    headers={'Content-Type':'application/json'}, method='PUT')
try:
    with urllib.request.urlopen(req, timeout=20) as r:
        print('RELOAD_KERNEL', r.status, r.read()[:200])
except Exception as e:
    print('RELOAD_KERNEL_FAIL', e)
PY
sleep 3
$ADB shell su -c "$T/kdgctl 2>&1 | grep -E 'ownership|listener_ready'"
$ADB shell su -c "grep -aE 'kernel DNS backend|falling back|panic' $B/run/mihomo.log | tail -8"

say "7. 热重载：切到无 kernel backend 的用户态（验证 PatchFrom 不 panic）"
python3 - <<'PY'
import json, urllib.request
cfg=open('/tmp/kdg-final/startup-userspace.yaml').read()
req=urllib.request.Request('http://127.0.0.1:19090/configs?force=true',
    data=json.dumps({'payload': cfg}).encode(),
    headers={'Content-Type':'application/json'}, method='PUT')
try:
    with urllib.request.urlopen(req, timeout=20) as r:
        print('RELOAD_USER', r.status, r.read()[:200])
except Exception as e:
    print('RELOAD_USER_FAIL', e)
PY
sleep 3
$ADB shell su -c "grep -aE 'kernel DNS backend|falling back|panic|PatchFrom' $B/run/mihomo.log | tail -10"
$ADB shell su -c "$T/kdgctl 2>&1 | grep ownership || true"

say "7b. 切回 kernel backend"
python3 - <<'PY'
import json, urllib.request
cfg=open('/tmp/kdg-final/startup-kernel.yaml').read()
req=urllib.request.Request('http://127.0.0.1:19090/configs?force=true',
    data=json.dumps({'payload': cfg}).encode(),
    headers={'Content-Type':'application/json'}, method='PUT')
try:
    with urllib.request.urlopen(req, timeout=20) as r:
        print('RELOAD_BACK', r.status, r.read()[:200])
except Exception as e:
    print('RELOAD_BACK_FAIL', e)
PY
sleep 5
$ADB shell su -c "$T/kdgctl 2>&1 | grep -E 'ownership|listener_ready|doh_ok'"
$ADB shell su -c "grep -aE 'kernel DNS backend active|falling back' $B/run/mihomo.log | tail -6"

say "8. 故障注入"
$ADB shell su -c "sh $T/30-inject.sh"

say "9. SIGKILL + EBUSY 回收"
$ADB shell su -c "sh $T/40-kill.sh"

say "10. 还原（chrneg + 原二进制/配置 + rmmod）"
# trap EXIT 也会再跑一次 restore，幂等。
$ADB shell su -c "sh $T/90-restore.sh"

say "11. 终态核对"
$ADB shell su -c "sh $T/00-preflight.sh" | tail -50
echo
echo "WINDOW_DONE  log=$LOG"
