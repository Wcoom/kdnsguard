#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""确定性生成 P6 用的查询轨迹（方案 §17.3 要求「可重放、经脱敏」）。

脱敏的含义在这里是**具体**的：轨迹里只有公开知名域名与保留 TLD 下的合成域名，
没有任何真实设备上抓下来的查询名。这样轨迹可以入库、可以给别人复现，
不会泄漏谁访问过什么。

三条轨迹对应方案 §17.3 的三种负载：
  real.txt      —— 冷/热缓存（173 个不同真实域名）
  burst100.txt  —— 同名爆发（同一域名 100 条，验收 single-flight）
  random1000.txt——缓存完全帮不上忙（1000 个各不相同的 .test 域名，必 NXDOMAIN）
"""
import hashlib
import os

REAL = """
example.com www.baidu.com github.com one.one.one.one cloudflare.com www.google.com
www.cloudflare.com dns.google www.apple.com www.microsoft.com www.amazon.com
www.wikipedia.org en.wikipedia.org zh.wikipedia.org www.zhihu.com www.bilibili.com
www.taobao.com www.tmall.com www.jd.com www.qq.com www.163.com www.sina.com.cn
www.sohu.com www.ifeng.com www.ctrip.com www.douban.com www.csdn.net
stackoverflow.com www.reddit.com news.ycombinator.com www.medium.com
www.linkedin.com www.instagram.com www.facebook.com twitter.com x.com
www.youtube.com www.netflix.com www.spotify.com www.twitch.tv www.discord.com
www.telegram.org www.whatsapp.com www.signal.org www.mozilla.org
www.debian.org www.ubuntu.com www.archlinux.org kernel.org www.kernel.org
git.kernel.org lkml.org www.gnu.org sourceware.org gitlab.com bitbucket.org
www.npmjs.com crates.io pypi.org hub.docker.com registry.npmjs.org
go.dev pkg.go.dev proxy.golang.org sum.golang.org www.rust-lang.org
doc.rust-lang.org www.python.org docs.python.org www.perl.org
www.ruby-lang.org nodejs.org deno.land bun.sh vitejs.dev
www.typescriptlang.org www.jetbrains.com code.visualstudio.com www.docker.com
kubernetes.io www.terraform.io ansible.com prometheus.io grafana.com
www.elastic.co redis.io www.postgresql.org www.mysql.com mariadb.org sqlite.org
www.mongodb.com www.nginx.com httpd.apache.org tomcat.apache.org
www.eclipse.org www.jenkins.io circleci.com www.atlassian.com slack.com zoom.us
www.dropbox.com drive.google.com mail.google.com calendar.google.com
maps.google.com translate.google.com photos.google.com play.google.com
store.google.com www.gstatic.com fonts.gstatic.com ajax.googleapis.com
apis.google.com accounts.google.com login.microsoftonline.com
outlook.office.com www.office.com teams.microsoft.com www.bing.com cn.bing.com
login.live.com www.icloud.com appleid.apple.com www.aliyun.com
cloud.tencent.com www.huaweicloud.com www.digitalocean.com www.vultr.com
www.linode.com www.hetzner.com www.oracle.com cloud.oracle.com aws.amazon.com
console.aws.amazon.com www.hao123.com www.360.cn www.sogou.com www.douyin.com
www.kuaishou.com www.xiaohongshu.com www.weibo.com tieba.baidu.com
zhuanlan.zhihu.com www.jianshu.com juejin.cn www.oschina.net www.cnblogs.com
segmentfault.com www.runoob.com www.w3schools.com developer.mozilla.org
developer.android.com source.android.com www.android.com developer.apple.com
learn.microsoft.com developer.chrome.com play.rust-lang.org godbolt.org
"""


def main() -> None:
    here = os.path.dirname(os.path.abspath(__file__))

    seen, uniq = set(), []
    for d in REAL.split():
        if d not in seen:
            seen.add(d)
            uniq.append(d)
    with open(os.path.join(here, "real.txt"), "w") as f:
        f.write("\n".join(uniq) + "\n")
    print(f"real.txt: {len(uniq)} 条不同真实域名")

    with open(os.path.join(here, "burst100.txt"), "w") as f:
        f.write("\n".join(["example.com"] * 100) + "\n")
    print("burst100.txt: 100 条同名")

    # .test 是 RFC 6761 保留 TLD，保证 NXDOMAIN 且不会有真实流量外泄
    lines = []
    for i in range(1000):
        h = hashlib.sha256(f"kdg-probe-{i}".encode()).hexdigest()[:12]
        lines.append(f"{h}.probe-kdg.test")
    with open(os.path.join(here, "random1000.txt"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print("random1000.txt: 1000 条各不同（保留 TLD，必 NXDOMAIN）")


if __name__ == "__main__":
    main()
