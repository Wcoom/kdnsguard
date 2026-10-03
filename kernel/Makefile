# SPDX-License-Identifier: GPL-2.0
#
# kdnsguard 内核模块的 kbuild 片段（树外模块）。
#
# 采用树外（M=）构建而不是把源码放进内核树 drivers/misc/：
#   - 骨架阶段要的是快速迭代与故障隔离，树外模块改一行不必重编整个 Image
#     再刷机；
#   - ddl_guard 那种「源码在内核树、符号链接进模块目录」的双份布局会带来
#     「改了哪一份」的隐患，这里直接以本目录为唯一真源。
# 将来若 kdnsguard 需要常驻设备（AnyKernel3 只换内核段、不装模块），
# 再改为内建集成 —— 那是 P3 的决策。

obj-m += kdnsguard.o

kdnsguard-y := kdg_main.o
kdnsguard-y += kdg_nat.o
kdnsguard-y += kdg_genl.o
kdnsguard-y += kdg_mbedtls.o
kdnsguard-y += kdg_divti3.o
kdnsguard-y += kdg_sock.o
kdnsguard-y += kdg_tls.o
kdnsguard-y += kdg_http.o
kdnsguard-y += kdg_doh.o
kdnsguard-y += kdg_chardev.o
kdnsguard-y += kdg_psa_probe.o
kdnsguard-y += kdg_wire.o
kdnsguard-y += kdg_cache.o
kdnsguard-y += kdg_cache_tab.o
kdnsguard-y += kdg_sflight.o
kdnsguard-y += kdg_resolve.o
# mbedTLS：**逐文件**列入复合对象，不能写 `kdnsguard-y += mbedtls/`。
# 子目录写法只对 obj-y / obj-m 生效；对复合对象（kdnsguard-y）会被当成一个
# 名为 "mbedtls/" 的目标文件，链接期报 "cannot open kernel/mbedtls/: Is a directory"。
# 目录里的 .c/.h 由 tools/build.sh 从 third_party/ 同步而来（生成目录，已 gitignore）；
# 不直接引用 third_party/ 是 kbuild 的硬限制：树外模块的编译规则是
# $(obj)/%.o: $(src)/%.c，源文件必须物理落在模块目录内，路径无法重定向。
KDG_MBEDTLS_OBJS := $(patsubst $(src)/mbedtls/%.c,mbedtls/%.o,\
			$(wildcard $(src)/mbedtls/*.c))
kdnsguard-y += $(KDG_MBEDTLS_OBJS)

# ── 包含路径 ────────────────────────────────────────────────────────────
# kdg.h 用 "uapi/kdnsguard.h" 引用 UAPI，故需要 include/ 在搜索路径上。
ccflags-y += -I$(src)
ccflags-y += -I$(src)/../include

# ── mbedTLS 适配（详见 third_party/mbedtls-kernel/ 下的说明）─────────────
KDG_THIRD := $(src)/../third_party
# shim 在前：它用 <string.h>/<stdlib.h>/<stdio.h> 等**同名**头遮蔽 libc。
# 内核态本就 -nostdinc、没有这些顶层头，故不存在与内核头冲突的问题。
ccflags-y += -I$(KDG_THIRD)/mbedtls-kernel/shim
ccflags-y += -I$(KDG_THIRD)/mbedtls-kernel
ccflags-y += -I$(KDG_THIRD)/mbedtls/include
ccflags-y += -DMBEDTLS_CONFIG_FILE='"kdnsguard_mbedtls_config.h"'

# 刻意**不加** -Wall -Wextra：内核头自身（如 include/linux/kcsan-checks.h 的
# static inline 空实现）在 -Wextra 下会大量报 unused-parameter，内核树本身
# 也从不开这个档；而 mbedTLS 作为第三方代码也不按内核的告警等级维护。
# 严格性由 tools/build.sh 的告警审计补回（只审计 kdg_*.c，不看 mbedtls/）。
