#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把确认可用的恶意 PE 从混杂样本堆里分离出来。

输入的 21,308 个本地样本是混的：Linux ELF、shell/JS/VBA 脚本、Android APK、压缩包，
以及没有标签的一万个。能进 Windows 静态 PE 模型的只是其中一部分。这个工具按
extract_local_vectors.py 已经算出的结论做物理分离，两边口径完全一致 —— 分出来的文件
就是进 X 矩阵的那些样本，不多不少。

分离判据（三个都要满足）
  1. 服务器 vt_reports 里有标签，且 malicious >= min_engines（默认 5）
  2. 本地字节头是 PE（MZ + PE\\0\\0），由 pefile 真实解析通过
  3. sha256 命名，即文件内容与文件名自洽

用硬链接不是复制
  同卷硬链接零额外占盘（这批 PE 约 10 GB），且原目录保持不动 —— 万一后面发现筛选口径
  要调整，重跑一遍就行，不用重新收集样本。原文件一个都不删。

目录结构
  <out>/exe/<sha256>      pe_type=exe
  <out>/dll/<sha256>      pe_type=dll
  <out>/_manifest.jsonl   每条含 sha256/pe_type/引擎数/威胁标签/家族/原路径
  <out>/_README.txt       写明这是活体恶意代码

【安全】分出来的目录里全是可执行的活体恶意代码。这里刻意【不】做任何解压、改名成
可双击的形态，也不碰扩展名 —— 文件名保持无扩展名的 sha256，双击不会执行。
"""
from __future__ import annotations

import argparse
import collections
import ctypes
import json
import os
import shutil
import sys

import numpy as np

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, OSError):
    pass


def hardlink(src: str, dst: str) -> str:
    """返回 'link' / 'copy' / 'exists'。同卷优先硬链接，跨卷退回复制。"""
    if os.path.exists(dst):
        return "exists"
    try:
        os.link(src, dst)
        return "link"
    except OSError:
        shutil.copy2(src, dst)
        return "copy"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--npz", required=True,
                    help="extract_local_vectors.py 的输出，决定分哪些")
    ap.add_argument("--roots", nargs="+", required=True, help="原样本根目录")
    ap.add_argument("--out", required=True, help="分离目标目录")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    z = np.load(args.npz, allow_pickle=False)
    sha = z["sha"].astype(str)
    pt = z["pe_type"].astype(str)
    fam = z["family"].astype(str)
    mal = z["mal"].astype(int) if "mal" in z else np.zeros(len(sha), dtype=int)
    print(f"npz 里的可用恶意 PE: {len(sha)}")
    print(f"  exe {int((pt == 'exe').sum())}   dll {int((pt == 'dll').sum())}")

    # 反查原路径。npz 只存了 sha，路径要重新扫一遍 —— 这样 npz 里不含任何路径信息，
    # 也就不可能有路径泄漏进训练数据。
    import re
    H = re.compile(r"^[0-9a-f]{64}$")
    loc: dict[str, str] = {}
    for root in args.roots:
        if not os.path.isdir(root):
            print(f"  [!] 目录不存在: {root}")
            continue
        for dp, _dn, fn in os.walk(root):
            for name in fn:
                if name.startswith("_"):
                    continue
                stem = os.path.splitext(name)[0].lower()
                if H.match(stem):
                    loc.setdefault(stem, os.path.join(dp, name))
    print(f"  原目录里可定位的文件: {len(loc)}")

    if args.dry_run:
        missing = sum(1 for s in sha if s not in loc)
        print(f"[dry-run] 会分离 {len(sha) - missing} 个，{missing} 个找不到原文件")
        return 0

    for sub in ("exe", "dll"):
        os.makedirs(os.path.join(args.out, sub), exist_ok=True)

    stat = collections.Counter()
    rows = []
    tot_bytes = 0
    for s, t, f, m in zip(sha, pt, fam, mal):
        src = loc.get(s)
        if not src:
            stat["missing"] += 1
            continue
        dst = os.path.join(args.out, t if t in ("exe", "dll") else "exe", s)
        try:
            how = hardlink(src, dst)
        except Exception as e:
            stat["error"] += 1
            if stat["error"] <= 5:
                print(f"  [err] {s[:12]} {e}")
            continue
        stat[how] += 1
        try:
            tot_bytes += os.path.getsize(dst)
        except OSError:
            pass
        rows.append({"sha256": s, "pe_type": t, "mal": int(m),
                     "family": f, "src": src})

    with open(os.path.join(args.out, "_manifest.jsonl"), "w",
              encoding="utf-8") as fh:
        for r in sorted(rows, key=lambda r: r["sha256"]):
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    with open(os.path.join(args.out, "_README.txt"), "w", encoding="utf-8") as fh:
        fh.write(
            "这个目录里是【活体恶意代码】，不是样本报告。\n\n"
            f"数量: {len(rows)}  (exe {stat['link'] + stat['copy']} 个已链接)\n"
            "来源: 本机样本库中「服务器 vt_reports 有标签且 >=5 引擎报毒」且\n"
            "      「本地字节头确认是 PE」的交集。\n\n"
            "文件名是各自内容的 sha256，刻意不带扩展名 —— 双击不会执行。\n"
            "请勿改名加 .exe/.dll，勿解压，勿放进会被自动扫描或自动执行的位置。\n"
            "这些文件是硬链接，原文件仍在原目录，删这里不会删掉原始语料。\n")

    print("\n================ 分离结果 ================")
    print(f"  硬链接 {stat['link']}   复制 {stat['copy']}   已存在 {stat['exists']}")
    print(f"  找不到原文件 {stat['missing']}   出错 {stat['error']}")
    print(f"  合计 {len(rows)} 个， {tot_bytes / 1e9:.2f} GB（硬链接不额外占盘）")
    print(f"  -> {args.out}")
    ptc = collections.Counter(r["pe_type"] for r in rows)
    print(f"  exe {ptc['exe']}   dll {ptc['dll']}")
    famc = collections.Counter(r["family"] for r in rows)
    print("  家族 Top10:", dict(famc.most_common(10)))
    engc = collections.Counter(
        ">=30" if r["mal"] >= 30 else
        ">=20" if r["mal"] >= 20 else
        ">=10" if r["mal"] >= 10 else "5-9" for r in rows)
    print("  引擎数分布:", dict(engc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
