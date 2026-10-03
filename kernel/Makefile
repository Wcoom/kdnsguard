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

# kdg.h 用 "uapi/kdnsguard.h" 引用 UAPI，故需要 include/ 在搜索路径上。
ccflags-y += -I$(src)
ccflags-y += -I$(src)/../include

# 刻意**不加** -Wall -Wextra：内核头自身（如 include/linux/kcsan-checks.h 的
# static inline 空实现）在 -Wextra 下会大量报 unused-parameter，内核树本身
# 也从不开这个档。这里沿用内核既定的告警等级，不另行加码。
