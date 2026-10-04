# P4 第一步：IP ↔ 域名 关联表（实现与故障复盘）

日期：2026-10-05。设备：OnePlus 13 / PJZ110，内核
`6.6.118-android15-8-gf4dc45704e54-abogki20260727-4k #16`。

本文件记录**实测到的事实、设计取舍，以及一次真实的内核 panic 复盘**，
不复述《便携设备全局 DNS 内核架构与实施方案》的正文。

---

## 1. 为什么需要这张表（方案 §12.2）

DNS 一旦从代理挪进内核，代理就失去了它原先**由 DNS 应答触发**的域名/IP 映射。
它随后只看到一个连接连到某个**真实 IP**，却不知道这个连接原本要访问哪个域名
—— 而它的分流规则大量按域名写。方案 §12.2 因此要求内核

> 以 `network + profile + IP + domain + expire + provenance` 存有界关联，
> 并提供查询接口；同 IP 的多个域名必须保留集合和歧义，不能简单「最后一个
> 域名覆盖所有连接」。

---

## 2. 设计

| 项 | 取值 | 理由 |
|---|---|---|
| 方向 | **只有反查（IP → 域名集合）** | 代理手上的输入是「新连接的目标 IP」；正查本期没有消费者，不做（有意裁剪，不是遗漏） |
| 键 | `net_id + profile_gen + 地址长度 + 地址` | `profile_gen` 入键 ⇒ 换上游后旧关联**自动不可命中**，与缓存失效口径一致 |
| 值 | 一组域名（≤ 4），各带自己的到期时间 | §12.2 的「保留集合和歧义」 |
| 容量 | 512 槽 / 条目 632 B ⇒ **316 KiB**，模块参数未开放调 | 有界，且上界写在注释里可核算 |
| TTL | 取应答里 A/AAAA 的 TTL，夹到 [1 s, 1 h]；TTL=0 **不记** | 与缓存同口径 |
| 清理 | 惰性（查询/记录时顺手做过期与淘汰），**零定时器** | 方案 §9.3「不按条目建立周期定时器」 |
| 淘汰 | 空闲槽 → 已过期 → CLOCK 二次机会 | 不做引用计数：结果在锁内拷进调用方缓冲，**没有引用逃逸出锁** |

**记的是什么名字**：**调用方问的那个名字**（qname 的规范形式），不是 RR 的
owner 名。递归解析器返回的是整条链：

```
www.example.com.  CNAME  cdn.example.net.
cdn.example.net.  A      1.2.3.4
```

按 owner 名记会得到 `1.2.3.4 → cdn.example.net`，而应用按 `www.example.com`
分流就落空。所以 `kdg_wire_collect_addrs()` 只收集**值**，名字由调用方统一挂上。

**只在走上游那条路径记账**：缓存命中与搭车路径的关联在它**成为**缓存/合并项的
那一次就记过了，TTL 与缓存项同源同寿命，不必重复记。

**接口**：`KDG_OP_MAP_LOOKUP`（字符设备），请求体就是裸地址（4 或 16 字节），
`struct kdg_req_v1` 一个字节都不用改。响应体是 `kdg_map_result_v1` + 变长 item。
「没有关联」**不是错误**：count=0 + `KDG_ST_OK`，否则调用方没法把「这个 IP 没记录」
与「查询功能坏了」分开，而这两者的处置完全不同。

---

## 3. 🔴 一次真实的内核 panic（复盘）

### 现象

真机验证脚本在跑完全部功能用例、执行最后一步 `rmmod` 时，手机**卡死重启**。
功能路径（insmod / 查询 / 反查 / 计数）全程正常。

### 取证

`console-ramoops-0` 一如既往不可用；按既定路径取 qcom minidump
（`/data/persist_log/DCS/de/minidump/SYSTEM_LAST_KMSG@*@2026_10_05_05_46_04.dat.gz`），
`strings -n 8` 提取到完整 panic：

```
Unable to handle kernel paging request at virtual address ffffffff0347f348
Internal error: Oops: 0000000096000005 [#1] PREEMPT SMP
pc : kfree+0x54/0x174
lr : kdg_map_exit+0x30/0x48 [kdnsguard]
Call trace:
 kfree+0x54/0x174
 kdg_map_exit+0x30/0x48 [kdnsguard ...]
 cleanup_module+0x60/0x690 [kdnsguard ...]
Kernel panic - not syncing: Oops: Fatal exception
Modules linked in: ... [last unloaded: kdnsguard(O)]
```

崩溃地址 `ffffffff0347f348` 是 **vmalloc 区**的形态，而 `pc` 在 `kfree`。

### 根因

`kdg_map.c` 里 `buckets`(8 KiB，恰好走 kmalloc) 与 `slots`(316 KiB，**必然**
走 vmalloc) 都是 `kvcalloc` 分配的，我却在错误路径与 `kdg_map_exit()` 里用
**`kfree`** 释放。`kfree` 会对 vmalloc 地址做 `virt_to_head_page()`，拿到野
`struct page` 后 panic。

**同一个仓库里 `kdg_cache_tab.c` 用的正是 `kvfree`。我抄了它的分配方式，却没抄
释放方式。**

### 修法

`kfree` → `kvfree`（初始化错误路径 + `exit` 两处）。`struct kdg_map` 本身确实是
`kzalloc` 来的，继续用 `kfree`。

### 为什么宿主单测没拦住

`tests/host_kernel.h` 里 `kfree` 与 `kvfree` **都映射成 libc 的 `free`** ——
而这类错误的本质是「kmalloc 区与 vmalloc 区是两套地址空间」，宿主上根本不存在
这个区分。**宿主 ASan/UBSan 对这一整类错误免疫。**

### 补的闸：构建期分配/释放配对审计

`tools/build.sh` 新增一道门禁：扫描本模块全部 `kdg_*.c`，找出每个
`X = kv*alloc(...)` / `X->Y = v*alloc(...)` 的赋值目标，然后

1. 该指针**不得**出现在错误的释放函数里（kv\* 不得被 `kfree`，v\* 不得被
   `kfree`/`kvfree`）；
2. 该指针**必须**出现在正确的释放函数里（防泄漏）。

**⚠️ 这道闸的第一版是空闸，值得单独记住。** 它最初只做第 2 条（「同文件里存在
正确的 kvfree 吗」）。我把 `kvfree(m->slots)` 故意改回 `kfree` 做反向注入测试，
它**照样报「无」**——因为同一个指针在初始化错误路径上还有**另一处**正确的
`kvfree`，第 2 条被满足了。是我做的反向注入测试抓住的，不是代码审查。

于是补上第 1 条（检查危险模式本身）并把两条都保留：**只检查「有没有正确的」是
不够的，必须同时检查「有没有错误的」**。改完后再做一次反向注入，门禁给出精确
报错：

```
  kdg_map.c:232  m->slots = kvcalloc(...)  却用 kfree(m->slots) 释放（会 panic 重启）
```

**教训（已写入工作区记忆）**：给门禁做**反向注入验证**，是判断它是不是空闸的
唯一可靠办法；正向通过只说明它没拦你，不说明它拦得住。

---

## 4. 验证（修复后，真机）

| 项 | 实测 |
|---|---|
| 模块加载 | `map: 就绪：512 槽（条目 632 B，合计约 316 KiB）/ 1024 桶` |
| 记录 | 解析 4 个域名 → `map_entries=7`，与答案区 A 记录总数**逐条对上** |
| 反查 | `104.20.23.154 → example.com`，`ttl_ms` 随秒数递减（299144 → 297130） |
| 未记录 IP | `count=0` + `KDG_ST_OK`，不是错误 |
| 坏输入 | `999.1.1.1` / `1.2.3` / `not-an-ip` 全部被拒，进程不崩 |
| 内存核算 | `map_mem_bytes = 331776 = 512×632 + 1024×8`，与算术**精确一致** |
| **卸载** | `rmmod rc=0`，设备未重启，`dmesg` 0 告警 |

宿主侧新增 `tests/test_map.c`，**62 条断言**在 ASan/UBSan 下全过，覆盖：
容量不足时整体拒绝、CNAME 不计入地址、rdlen 与类型不符时跳过、非 IN 类跳过、
歧义集合、重复记录只刷新 TTL、过期与 TTL 夹取、**cap 截断标志**、超长名拒绝、
越界偏移丢弃、IPv6、**512 槽写满 3 倍量不崩且最近写入的不被淘汰**、flush。

> 写测试时也被 ASan 抓到一次**测试自身**的越界读：拿 4 字节指针配 `addr_len=16`
> 去查询。这正是宿主侧带 ASan 的价值 —— 顺带把「`kdg_map_lookup` 按调用方声明
> 的长度读地址」这条接口契约写进了注释。

---

## 5. 明确的范围裁剪与未覆盖

1. **只做反查**。正查（域名 → IP）本期无消费者，不做。
2. **不暴露给非 root**：`/dev/kdnsguard` 仍是 0600，入口 `capable(CAP_NET_ADMIN)`。
   让普通进程能用需要 ueventd 规则，属 **P5 平台集成**。
3. **不带网络上下文**：`net_id` 恒 0，`actual_network` 恒 0。方案 §5.3 的
   netId/fwmark 多网络隔离仍未实现，那时这张表的键要真正用上 `net_id`。
4. **不做持久化**：重启即空，与缓存同口径。
5. **`profile_gen` 入键意味着「换上游即全表不可命中」**，但旧条目仍占槽位，
   要靠后续记录把它们淘汰掉。条目数上限保证了这不会无限增长。
