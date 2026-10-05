# kdnsguard 常驻交付（LKM + 开机脚本）

把已经真机验证过的 Path A 接到每次开机：加载模块、建 `/dev/kdnsguard`、
把 mihomo 换成带内核后端的核心、把 `startup-config` 改成 `backend: kernel`
+ `dns-mode: off`。BoxProxy 从 DB 重生配置时，开机循环每 20 秒补回。

**这不是内建进内核。** 模块仍是树外 LKM，放 `/data/adb/kdnsguard/`。
刷机包 `do.modules=0` 不装模块 —— 换内核镜像后必须用匹配 vermagic 的
`.ko` 再装一次。

## 它做什么

| 时机 | 动作 |
|---|---|
| 开机（`service.d/99-kdnsguard.sh`） | 等 bootanim 停 → `insmod allow_intercept=1` → `mknod` → 等 BoxProxy 写出 `startup-config` → 换核心（若 md5 对不上）→ 补丁 YAML → `boxctl service restart` → 进入 `loop.sh` |
| 配置被重生 | `loop.sh` 每 20 秒跑 `apply.sh`；已是目标态什么都不做，被冲掉就补回并重启核心 |
| 模块没起来 | **不改配置**，DNS 保持原用户态路径 |

## 明确的产品变化

内核返回**真实 IP**。`enhanced-mode: fake-ip` 与内核后端互斥（适配器会回退
用户态）。常驻后配置被改成 `redir-host`。依赖 FakeIP 的规则会按真实地址
分流；嗅探 `override-destination: true` 仍可用。方案 §12.2 的立场就是
「首期返回真实 IP」。

## 方案里做不到的（不要当缺陷重提）

- **H3 / DoH3**：`lxin/quic` 许可证 NOASSERTION 且握手在用户态；mbedTLS
  无现成内核 QUIC API。H2 DoH 是主线。
- **任意 App 加密内置 DNS**：UDP/TCP 53 可以接管（本交付覆盖）；未知
  HTTPS 443 DoH、ECH、VPN 隧道内 DNS **无法**无损识别（方案 §1.1 / §11）。
- **私人 DNS strict（853）**：内核不能接管 853（证书语义）。私人 DNS 必须
  保持 `off`，脚本会写一次。

## 安装 / 卸载

从开发机：

```
bash deploy/install.sh          # 推资产、装脚本、立刻启用
bash deploy/install.sh --enable-only   # 资产已在设备上，只跑启用
```

设备上卸载：

```
sh /data/adb/kdnsguard/disable.sh
```

卸载会：停监视、把核心和配置还原成安装时的备份、`DISABLE`+`rmmod`、
`boxctl service restart`。`service.d` 里的开机脚本一并删掉。

## 目录

```
/data/adb/kdnsguard/
  enabled                  存在 = 开机启用
  kdnsguard.ko
  mihomo-kdgp4final        带内核后端的核心
  mihomo.stock             安装时备份的原核心
  startup-config.stock     安装时备份的原配置
  kdg_root.pem             上游信任锚
  kdgctl                   诊断客户端
  apply.sh / loop.sh / disable.sh / boot.sh / enable-now.sh
  log
```

⚠️ 不要用 `adb shell su -c` 拉常驻守护：KernelSU 会话结束会清掉整棵进程树。
`watch.sh` / `start-watch.sh` / `tools/kdgwatchd.c` 是这次踩坑留下的，开机路径不用它们。
