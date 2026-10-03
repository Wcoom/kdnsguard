# P1 关键缺陷复盘：`UINT_MAX` 写成 `(~0U)` 让整条 TLS 链路瘫痪

状态：**已修复**（2026-10-03）。修复位置：
`third_party/mbedtls-kernel/shim/_kdg_common.h` 与同目录 `shim/limits.h`。

---

## 1. 现象

同一台设备、同一个模块里，**按曲线选择性地失败**：

| 曲线 | 结果 |
|---|---|
| X25519 | ✗ |
| P-256 | ✗ |
| P-384 | ✓（唯一） |

连带 TLS 1.3 握手在生成 ECDHE 密钥份额时失败
（`psa_export_public_key() -> PSA_ERROR_INVALID_ARGUMENT`），
TLS 1.2 在解析服务端证书链时失败
（`mbedtls_x509_crt_parse_der() -> MBEDTLS_ERR_ECP_BAD_INPUT_DATA`）。
而该证书链的叶子证书正是 **P-256**。

一度看起来像「非确定性」：同一份二进制、同一组参数，重新加载模块后结果会变。
**那个非确定性是假象**——它来自当时探针自身的栈/打印开销扰动，掩盖了真正的确定性规律。

## 2. 定位过程（可复用的手法）

1. PSA 把底层 mbedTLS 错误码**翻译**后才上报，日志里只剩笼统的 `-0x7100`。
   ⇒ 写一个**绕过翻译层**的直探针（现 `kernel/kdg_psa_probe.c`，仅 `debug=1` 时运行）。
2. 逐步骤定位到 `mbedtls_ecp_gen_key()`：`group_load=0` 但 `gen_key=MBEDTLS_ERR_ECP_INVALID_KEY`。
3. 用**已知正确的生成元编码**喂 `mbedtls_ecp_point_read_binary()` —— 长度检查 `1+2*plen` 就挂了
   ⇒ 问题在 `mbedtls_mpi_size(&grp->P)`。
4. 把加载后的群参数**直接打出来**（探针文件内单独定义 `MBEDTLS_ALLOW_PRIVATE_ACCESS`，
   它只改成员宏的名字、不改布局，故是安全的）：

```
P-256: P.n=4 bitlen=225 size=29   limbs: ffffffffffffffff 00000000ffffffff 0000000000000000 ffffffff00000001
P-384: P.n=6 bitlen=384 size=48   limbs: ...（正确）
```

P-256 的四个 limb **逐位正确**，但 `bitlen` 报成 225 而不是 256。

`225 = 3*64 + (64 - 31)` ⇒ **`clz(0xffffffff00000001)` 返回了 31**——
而 `__builtin_clzll`/`__builtin_clzl` 都应返回 0。**只有 32 位的 `__builtin_clz` 会得到 31**
（参数被截断成 `0x00000001`）。

## 3. 根因

`library/bignum_core.c` 用**宏比较**决定 clz 用哪个内建：

```c
#if (MBEDTLS_MPI_UINT_MAX == UINT_MAX) && __has_builtin(__builtin_clz)
    #define core_clz __builtin_clz        /* 32 位 */
#elif (MBEDTLS_MPI_UINT_MAX == ULONG_MAX) && __has_builtin(__builtin_clzl)
    #define core_clz __builtin_clzl
#elif (MBEDTLS_MPI_UINT_MAX == ULLONG_MAX) && __has_builtin(__builtin_clzll)
    #define core_clz __builtin_clzll
#endif
```

我们在 shim 里为了让 `#if SIZE_MAX > ...` 之类能通过，把内核的极值宏重定义了一遍。
其中：

```c
#define UINT_MAX  (~0U)          /* ← 错在这里 */
```

**C 预处理器里的整数一律按 `intmax_t`/`uintmax_t` 运算 —— 本机是 64 位。**
于是 `(~0U)` 在 `#if` 中求值成 **`0xFFFFFFFFFFFFFFFF`**，而不是 32 位的 `0xFFFFFFFF`。

⇒ `MBEDTLS_MPI_UINT_MAX`（= `UINT64_MAX`）与 `UINT_MAX` **被判定相等**
⇒ 64 位肢体被当成 32 位
⇒ 选中 `__builtin_clz`，高位被静默截断
⇒ `mbedtls_mpi_bitlen()` 错误 → `mbedtls_mpi_size(P)` 错误 → 一切基于它的运算全错。

**P-384 之所以「正常」纯属侥幸**：它的最高 limb 是全 1，截断后 clz 仍为 0。
**它不是没坏，是这个输入掩盖了 bug。**

## 4. 修复

```c
#undef UINT_MAX
#define UINT_MAX  4294967295U    /* 字面常量，不是表达式 */
```

**通则：任何会被放进 `#if` 的宏，一律写成字面常量，绝不写 C 表达式。**
（本次一并复核了 `SIZE_MAX`/`LONG_MAX`/`ULONG_MAX`：它们写成 `(~0UL)` 在 LP64 的
`intmax_t` 语义下**恰好**等于正确值，故未暴露问题，但同样脆弱。）

同时修掉了另一处同源缺陷：曾把 `CHAR_MIN` 误写成 `-128`，
而 **ARM64 上 `char` 是无符号的**，正确值是 0。现已不再重定义内核本就正确的那些极值宏。

## 5. 验证

```
ECP P-256: group_load=0 gen_key=0          （修复前为 -0x4C80）
P-256: P.n=4 bitlen=256 size=32 pbits=256  （修复前为 225 / 29 / 225）
kdnsguard: TLS 握手完成（协议 TLSv1.3，密码套件 TLS1-3-CHACHA20-POLY1305-SHA256，ALPN http/1.1）
```

端到端 DoH 查询（真机，连续多轮稳定）：

| 域名 | 结果 |
|---|---|
| example.com | 104.20.23.154, 172.66.147.243 |
| www.baidu.com | 182.61.200.108, 182.61.200.110 |
| github.com | 140.82.121.4 |
| one.one.one.one | 1.1.1.1, 1.0.0.1 |

健康计数：`DOH_QUERIES=8, DOH_OK=8, LAST_STATUS=200, LAST_RTT=150ms`。

## 6. 留存的排障资产

`kernel/kdg_psa_probe.c` —— 仅在 `insmod ... debug=1` 时运行的 PSA/ECP 直探针。
**它不是死代码**：换选密码学库版本、或将来启用 X25519/新曲线时，
它是第一个该跑的东西。已在文件中注明用途。
