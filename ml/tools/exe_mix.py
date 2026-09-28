#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""核查纯 EXE 训练集两侧的构成，判断 EXE-only 方案是否站得住。

要回答三个问题：
  1) 白样本 EXE 里单一厂商占比多少 —— 太高模型会学成"某厂商签名就是干净"
  2) 恶意 EXE 的家族分布 —— 分组切分的组数够不够
  3) 两侧数量比 —— 决定 target-fpr 能测到多低（1000 个负样本才能分辨 0.1%）
"""
import collections
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, OSError):
    pass

VENDORS = [("microsoft", "Microsoft"), ("windows", "Microsoft"),
           ("google", "Google"), ("mozilla", "Mozilla"), ("intel", "Intel"),
           ("nvidia", "NVIDIA"), ("tencent", "Tencent"), ("adobe", "Adobe"),
           ("oracle", "Oracle"), ("apple", "Apple"), ("realtek", "Realtek"),
           ("qihoo", "Qihoo360"), ("360", "Qihoo360"), ("kingsoft", "Kingsoft"),
           ("huorong", "Huorong"), ("baidu", "Baidu"), ("igor pavlov", "7-Zip")]


def vendor(r):
    sub = (r.get("signer") or "").lower()
    if sub:
        for k, n in VENDORS:
            if k in sub:
                return n
        m = re.search(r"cn=(\"?)([^\",]+)", sub)
        return (m.group(2) if m else sub)[:44].strip()
    if r.get("pkg"):
        return "pkg:%s" % r["pkg"]
    return "src:%s" % (r.get("src") or "unknown")


def jl(path):
    if not os.path.isfile(path):
        return []
    out = []
    with open(path, encoding="utf-8-sig", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    pass
    return out


def main():
    ben_manifest, mal_vectors = sys.argv[1], sys.argv[2]

    ben = [r for r in jl(ben_manifest) if r.get("pe_type") == "exe"]
    print(f"白样本 EXE : {len(ben)}")
    v = collections.Counter(vendor(r) for r in ben)
    top = v.most_common(1)[0] if v else ("-", 0)
    print(f"  厂商数     : {len(v)}")
    print(f"  Top1       : {top[0]}  {top[1]}  ({top[1]*100.0/max(len(ben),1):.1f}%)")
    print("  Top 12:")
    for k, n in v.most_common(12):
        print(f"    {n:>6}  {n*100.0/len(ben):5.1f}%  {k}")
    src = collections.Counter(r.get("src") or "?" for r in ben)
    print("  来源:", "  ".join(f"{k}={n}" for k, n in src.most_common()))

    mal = [r for r in jl(mal_vectors) if r.get("pe_type") == "exe"]
    print(f"\n恶意 EXE   : {len(mal)}  (抓取仍在进行时这是当前进度)")
    if mal:
        fam = collections.Counter(r.get("family") or "(unknown)" for r in mal)
        cat = collections.Counter(r.get("category") or "(unknown)" for r in mal)
        print(f"  家族数     : {len(fam)}   <- 分组切分的组数")
        print("  家族 Top 10:")
        for k, n in fam.most_common(10):
            print(f"    {n:>6}  {k}")
        print("  类别:", "  ".join(f"{k}={n}" for k, n in cat.most_common(8)))
        sf = sum(1 for r in mal if r.get("silverfox"))
        print(f"  银狐标记   : {sf}")

    print("\n---- 判断 ----")
    if mal:
        ratio = len(ben) / max(len(mal), 1)
        print(f"正负比 1:{ratio:.2f}"
              f"（恶意 {len(mal)} / 良性 {len(ben)}）")
        if 0.5 <= ratio <= 4:
            print("  类型捷径已消除：两侧都是 EXE，模型不能靠 pe_type 走捷径。")
        # 5 折交叉验证时每折验证集的负样本数
        nva = len(ben) // 5
        print(f"5 折时每折验证集约 {nva} 个良性样本 -> 能分辨的最小 FPR 约"
              f" {1.0/max(nva,1)*100:.2f}%")
        if nva < 1000:
            print(f"  [!] 不足 1000，测不了 0.1% 的误报率。要么把 --target-fpr")
            print(f"      放宽到 {max(1.0/max(nva,1), 0.01):.2%} 附近，"
                  f"要么补白样本 EXE。")
    if v and top[1] * 100.0 / max(len(ben), 1) > 50:
        print(f"  [!] 单一厂商占白样本 EXE 的 {top[1]*100.0/len(ben):.0f}%，"
              f"仍需注意厂商捷径。")


if __name__ == "__main__":
    main()
