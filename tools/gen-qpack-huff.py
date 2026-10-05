#!/usr/bin/env python3
"""从工程内 nghttp2 的 Huffman 表生成 QPACK 解码树（kernel/kdg_qpack_huff_table.h）。

QPACK（RFC 9204 §4.1.2）与 H2 共用同一张 Huffman 表（RFC 7541 附录 B），
而 nghttp2 已经作为 H2 依赖在树内，直接以它为唯一真源，避免再抄一份表。

生成物是编译期常量：内核里不需要运行时建树、不需要分配内存。
用法：python3 tools/gen-qpack-huff.py
"""
import re, sys, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "kernel/nghttp2/nghttp2_hd_huffman_data.c"
OUT = ROOT / "kernel/kdg_qpack_huff_table.h"

txt = SRC.read_text()
body = txt[txt.index("huff_sym_table[] = {"):]
syms = [(int(nb), int(cd, 16)) for nb, cd in
        re.findall(r"\{(\d+),\s*(0x[0-9A-Fa-f]+)U\}", body)]
if len(syms) not in (256, 257):
    sys.exit(f"符号数应为 256（不含 EOS）或 257（含 EOS），实为 {len(syms)}")
# 末尾若有第 257 项，是 EOS（RFC 7541 §5.2），不能出现在解码输出里
EOS = 256 if len(syms) == 257 else -1

# 按 (nbits, code) 建二叉树；code 在表里是左对齐 32 位
nodes = [[-1, -1, -1]]  # [sym, c0, c1]
for s, (nb, code) in enumerate(syms):
    cur = 0
    for i in range(nb):
        bit = (code >> (31 - i)) & 1
        nxt = nodes[cur][1 + bit]
        if nxt < 0:
            nxt = len(nodes)
            nodes.append([-1, -1, -1])
            nodes[cur][1 + bit] = nxt
        cur = nxt
    if nodes[cur][0] != -1:
        sys.exit(f"符号 {s} 落在一个已占用的叶子节点上（前缀码冲突）")
    nodes[cur][0] = s

# 校验：每个非叶节点都有两个子节点（前缀码的完整性）
for i, n in enumerate(nodes):
    if n[0] == -1 and (n[1] < 0 or n[2] < 0):
        sys.exit(f"节点 {i} 只有一个子节点：表不完整")

lines = [
    "/* SPDX-License-Identifier: GPL-2.0 */",
    "/* 由 tools/gen-qpack-huff.py 生成，勿手改。",
    f" * 源：kernel/nghttp2/nghttp2_hd_huffman_data.c（RFC 7541 附录 B 表）",
    f" * 节点数：{len(nodes)}，叶子：{len(syms)}（EOS {'在' if EOS == 256 else '不在'}表内） */",
    "",
    f"#define KDG_HUFF_EOS_SYM {EOS}",
    "#ifndef _KDG_QPACK_HUFF_TABLE_H",
    "#define _KDG_QPACK_HUFF_TABLE_H",
    "",
    f"#define KDG_HUFF_NODES {len(nodes)}",
    "",
    "static const struct kdg_huff_node {",
    "\ts16 sym;\t/* 叶子上的符号；内部节点为 -1 */",
    "\ts16 child[2];\t/* 0 位的子节点、1 位的子节点 */",
    "} kdg_huff_tree[KDG_HUFF_NODES] = {",
]
for n in nodes:
    lines.append(f"\t{{ {n[0]:4d}, {{ {n[1]:4d}, {n[2]:4d} }} }},")
lines += ["};", "",
    "/* 仅供宿主测试：用符号表另写一个编码器做交叉验证（内核不编译这段）。 */",
    "#ifndef __KERNEL__",
    "static const struct kdg_huff_sym {",
    "\tu16 nbits;\tu32 code;\t/* 左对齐 32 位 */",
    "} kdg_huff_sym[257] = {"]
for nb, code in syms:
    lines.append(f"\t{{ {nb:2d}, 0x{code:08X}U }},")
lines += ["};", "#endif", "", "#endif", ""]
OUT.write_text("\n".join(lines))
print(f"已写出 {OUT}（{len(nodes)} 节点）")
