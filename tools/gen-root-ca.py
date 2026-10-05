#!/usr/bin/env python3
"""把信任锚 PEM 变成 C 头文件，供内核内建形态直接用。

为什么需要：内建形态要「开机不依赖任何脚本」，而信任锚原本是用户空间喂进来的
（mihomo 的 kernel-trust-file 或部署脚本）。没有它，内核在开机时无法验证上游
证书，也就没法自己接管。把 PEM 编进内核镜像是最直接的做法 —— 它本来就是公开
的根证书，且是要**钉死**的那一张（钉死正是目的：内核只认这一个上游身份）。

用法：python3 tools/gen-root-ca.py <pem> <输出头文件>
"""
import sys, pathlib

src, dst = sys.argv[1], sys.argv[2]
data = pathlib.Path(src).read_bytes()
lines = [
    "/* SPDX-License-Identifier: GPL-2.0 */",
    "/* 由 tools/gen-root-ca.py 生成，勿手改。",
    f" * 源：{src}（{len(data)} 字节，PEM）",
    " * 这是上游 DoH 端点的信任锚：内核只认这一张，不做系统信任链回落。 */",
    "#ifndef _KDG_ROOT_CA_H",
    "#define _KDG_ROOT_CA_H",
    "",
    f"#define KDG_ROOT_CA_LEN {len(data)}",
    "",
    "static const unsigned char kdg_root_ca[KDG_ROOT_CA_LEN] = {",
]
for i in range(0, len(data), 12):
    chunk = ", ".join(f"0x{b:02x}" for b in data[i:i + 12])
    lines.append("\t" + chunk + ",")
lines += ["};", "", "#endif", ""]
pathlib.Path(dst).write_text("\n".join(lines))
print(f"已写出 {dst}（{len(data)} 字节）")
