#!/usr/bin/env python3
"""反向注入：逐条破坏 kdg_tls13.c 的安全闸门，确认 run-tls13.sh 必然变红。
正向全绿不构成证据；每条闸门都必须能被测试抓住。"""
import subprocess, sys, pathlib
ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "kernel/kdg_tls13.c"
DEFECTS = [
    ("Finished 校验", "if (!t13_ct_eq(want, msg + 4, 32))", "if (0 && !t13_ct_eq(want, msg + 4, 32))"),
    ("证书链校验", "if (ret || flags)\n\t\treturn t13_fail(t, -EKEYREJECTED, AL_BAD_CERTIFICATE);",
     "if (0)\n\t\treturn t13_fail(t, -EKEYREJECTED, AL_BAD_CERTIFICATE);"),
    ("HRR 识别", "if (!memcmp(rnd, t13_hrr_random, 32))", "if (0 && !memcmp(rnd, t13_hrr_random, 32))"),
    ("消息长度上限", "if (mlen > KDG_T13_RXBUF)", "if (0 && mlen > KDG_T13_RXBUF)"),
    ("签名校验结果", "if (ret)\n\t\treturn t13_fail(t, -EKEYREJECTED, AL_DECRYPT_ERROR);",
     "if (0)\n\t\treturn t13_fail(t, -EKEYREJECTED, AL_DECRYPT_ERROR);"),
    ("服务器 Finished 记入转录", "\tif (mbedtls_sha256_update(&t->transcript, msg, mlen))\n\t\treturn t13_fail(t, -EIO, AL_INTERNAL_ERROR);\n\n\t/* 应用流量密钥",
     "\n\t/* 应用流量密钥"),
]
orig = SRC.read_text()
caught = 0
try:
    for name, a, b in DEFECTS:
        assert orig.count(a) == 1, f"注入点不唯一或不存在：{name}"
        SRC.write_text(orig.replace(a, b))
        r = subprocess.run([str(ROOT / "tests/run-tls13.sh")], capture_output=True, text=True)
        red = r.returncode != 0
        caught += red
        print(f"{'抓住' if red else '漏掉'}  {name}")
finally:
    SRC.write_text(orig)
print(f"{caught}/{len(DEFECTS)} 条被测试抓住")
sys.exit(0 if caught == len(DEFECTS) else 1)
