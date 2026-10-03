# P1 阻塞项：mbedTLS ECP 在 P-256 / X25519 上失败

记录日期：2026-10-03。状态：**未解决**，但已把范围收窄到可继续推进的程度。

---

## 1. 现象

在同一台设备、同一个模块里，**按曲线选择性地失败**：

```
ECP P-256 : group_load=0   gen_key=-19584   ← MBEDTLS_ERR_ECP_INVALID_KEY
ECP P-384 : group_load=0   gen_key=0
ECP X25519: group_load=0   gen_key=-19584
```

| 曲线 | 位数 | 结果 |
|---|---:|---|
| X25519 | 255 | ✗ |
| P-256 | 256 | ✗ |
| P-384 | 384 | ✓ |

**只有 P-384 可用。** 这不是「ECP 整体坏了」，也不是「某条曲线不支持」——`group_load` 三条都返回 0。

连带影响（同一根因）：
- PSA `psa_export_public_key()` 在 P-256/X25519 上返回 `PSA_ERROR_INVALID_ARGUMENT (-135)`；
  该错误经 `psa_crypto_ecp.c` 的 `mbedtls_ecp_read_key()` → `mbedtls_to_psa_error()` 从
  `MBEDTLS_ERR_ECP_INVALID_KEY` 翻译而来。
- TLS 1.3 握手在生成 ECDHE 密钥份额时失败：
  `ssl_tls13_generic.c:1641 psa_export_public_key() returned -0x7100`。
- TLS 1.2 握手走得更远，但在解析服务端证书链时失败：
  `mbedtls_x509_crt_parse_der() returned -0x4f80 (MBEDTLS_ERR_ECP_BAD_INPUT_DATA)`。
  该证书链的**叶子证书正是 P-256**（由 `openssl x509 -text` 确认；其余三张为 P-384）。

## 2. 已收窄到的位置

`mbedtls_ecp_gen_key()` 的内部是 `group_load` → `gen_privkey` → `ecp_mul`。
前两步返回 0，`ecp_mul` 返回 `ECP_INVALID_KEY`。

`mbedtls_ecp_mul_restartable()` 在运算前会调用：

```c
MBEDTLS_MPI_CHK(mbedtls_ecp_check_pubkey(grp, P));   /* P = grp->G，即生成元 */
```

而 `mbedtls_ecp_check_pubkey()` 对两条失败曲线分别落到：

- **P-256（`ecp_check_pubkey_sw`）**：验算 `Y² == X³ + AX + B (mod P)`，
  不等则 `return MBEDTLS_ERR_ECP_INVALID_KEY`。
- **X25519（`ecp_check_pubkey_mx`）**：检查 `X` 的字节数不超过 `(nbits+7)/8`，
  以及 `ecp_check_bad_points_mx()`。

**⇒ 结论：P-256 与 X25519 的群参数（P、A、B、G 或 N）在运行时是错的，
而 P-384 的是对的。** 这不是算法问题，是数据/加载问题。

## 3. 已排除的假设（都是有实验依据的，不要重复走）

| 假设 | 实验 | 结论 |
|---|---|---|
| PSA usage 策略导致导出失败 | 同曲线、只改 `PSA_KEY_USAGE_EXPORT` 的对照 | **排除**。结果每次运行都不同，与标志无关（`0x4000` 有时成功有时失败） |
| ECP 优化（NIST_OPTIM / FIXED_POINT_OPTIM）的预计算表有问题 | 关掉这两项后重测 | **排除**，结果完全不变；配置改动已撤销 |
| 内核 kCFI 间接调用 | 已定位并修复 memset 那处，并加了构建期门禁 | 无关（那个问题已在 `6a8acf8` 修复） |
| 栈深不足 | P-384（需要更多栈）反而成功 | **方向相反，排除** |
| 群参数加载失败 | `mbedtls_ecp_group_load()` 三条曲线都返回 0 | 加载本身不报错，是**加载出来的值**不对 |

## 3b. 已确证的关键事实（2026-10-03 追加）

用**公开 API** 喂入**已知正确的 P-256 生成元编码**（SEC1 未压缩，65 字节）：

```
sizeof(mbedtls_mpi_uint) = 8        ← limb 宽度正常（64 位）
MBEDTLS_ECP_MAX_BITS     = 521      ← 正常
已知生成元 P-256: group_load=0  read_binary=-20352  check_pubkey=-20352
已知生成元 P-384: group_load=0  read_binary=0       check_pubkey=-19584
```

`mbedtls_ecp_point_read_binary()` 会先做：

```c
if (ilen != 1 + 2 * mbedtls_mpi_size(&grp->P))
    return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
```

我们传 65 字节（= 1 + 2×32，对 P-256 完全正确）却被拒 ⇒
**`mbedtls_mpi_size(&grp->P)` 在 P-256 的群对象里不等于 32。**
若 P 未被加载（空），size = 0，`1 + 0 = 1 ≠ 65`，与现象吻合。

**而 `mbedtls_ecp_group_load()` 对同一条曲线仍返回 0** —— 即「加载失败但不报错」，
这是最反直觉、也最需要解释的一点。

已排除数据/宏层面的原因：
- `secp256r1_p[]` 有 4 个条目，与 64 位 limb 相符（256/64）✅
- `MBEDTLS_BYTES_TO_T_UINT_8` 走的是 64 位分支（`sizeof(mbedtls_mpi_uint)==8` 佐证）✅
- 该宏是小端打包、与主机字节序无关 ✅

⚠️ **P-384 那一行的 `check_pubkey=-19584` 不可用于结论**：P-384 的生成元编码是
手写的常量，未经核对，`read_binary=0` 只说明长度对，不说明值对。
下一步应先从 `openssl` 或标准文档核对这两个生成元常量，再重跑。

## 4. 尚未验证、优先级最高的假设

0. **`ecp_group_load()` 为何在 P 未加载时仍返回 0。**
   读 `ecp_curves.c` 的 `ecp_group_load()`（静态函数，经 `LOAD_GROUP(secp256r1)`
   宏调用）逐行确认它对每个 `mbedtls_mpi_read_binary_le()` 的返回码是否都做了检查。
   这是当前最重要的一个待读代码点。

1. **`ecp_curves.c` 的静态常量表被错误读取。**
   mbedTLS 3.x 用 `MBEDTLS_BYTES_TO_T_UINT_8()` 之类的宏把曲线常量打包成
   `mbedtls_mpi_uint` 数组，其正确性依赖 `MBEDTLS_HAVE_INT64` 与字节序宏。
   若这些宏在本移植里被错误推导，**受影响的是按 8 字节打包的短表**——
   与「32 字节曲线失败、48 字节曲线成功」这个观察**吻合**（值得注意）。

   **下一步实验（决定性）**：在探针里用已知的 P-256 生成元编码
   （`04 6b17d1f2...`）调 `mbedtls_ecp_point_read_binary()` + `check_pubkey()`，
   再把 `grp->P`/`grp->G` 的实际字节打印出来与标准值逐字节比对。
   若表的字节序错了，一眼可见。

2. **`_kdg_common.h` 里的极值宏重定义。**
   为让 `#if SIZE_MAX > ...` 之类能通过，我把 `SIZE_MAX`/`INT_MAX`/`UINT_MAX`
   等重定义为纯常量。虽然取值与内核一致，但**这是 mbedTLS 看到的唯一非上游来源**。
   下一步：把这些重定义临时全部去掉、改为只重定义 `SIZE_MAX` 一个，
   看行为是否变化。（`CHAR_MIN` 的 bug 已修——ARM64 上 char 无符号，应为 0。）

3. **`mbedtls_config.h` 的某个 `#undef` 破坏了 bignum 的编译期假设。**
   尤其 `MBEDTLS_KEY_EXCHANGE_RSA_ENABLED` / `..._DHE_RSA_ENABLED` 被关掉后，
   某些 ECP/bignum 的路径选择可能随之改变。

## 5. 当前可用状态

- 模块**加载干净、不再 panic**（kCFI 问题已修）。
- 信任锚加载、Generic Netlink、字符设备、DNS wire 校验、HTTP 解析**全部可用且有测试**。
- DoH 链路已通到 TLS 握手，**卡在 ECP**。
- `kernel/kdg_tls.c` 当前把版本**限制为 TLS 1.2**（`conf_min/max_tls_version`），
  并留有注释指向本文档。TLS 1.2 同样受 ECP 影响（证书链含 P-256），故当前仍不通。

## 6. 复现方式

```bash
bash tools/build.sh
adb push kernel/kdnsguard.ko /data/local/tmp/
adb shell su -c 'insmod /data/local/tmp/kdnsguard.ko debug=1'
adb shell su -c 'dmesg | grep 探针'
```

探针源码：`kernel/kdg_psa_probe.c`（**排障专用，问题解决后应整体删除**）。
