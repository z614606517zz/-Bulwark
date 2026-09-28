#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把本地某天的 datalake 投递目录直接抽成特征向量，绕过网络重拉。

用途
----
datalake 的 daily 归档要 D+1 才发布，所以抓取器对最近一两天只能拿到 HTTP 404。
如果本地已经有那天的裸文件（按 sha256 命名），直接从磁盘抽特征更快也更完整。

同时做两件核对：
  1) 内容哈希必须等于文件名。名字是别人给的，不校验就等于无条件信任来源；
     一旦文件在传输或存放过程中被换过，就会把错误标签喂进训练集。
  2) 只收 PE。静态 PE 模型吃不了 ELF/JS/VBS/sh，这类占本目录一半以上。

标签从服务器导出的 malicious_targets.jsonl 里取（family / category / first_seen），
所以只处理那份清单里已有的哈希 —— 没有可信标签的样本不进训练集。
"""

import argparse
import collections
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "train"))
from pe_features import PEFeatureExtractor, FEATURE_DIM, SCHEMA_VERSION  # noqa: E402

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, OSError):
    pass

MAX_SAMPLE = 64 * 1024 * 1024


def load_jsonl(path):
    out = []
    if not os.path.isfile(path):
        return out
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
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True, help="本地投递目录（文件名即 sha256）")
    ap.add_argument("--targets", required=True, help="malicious_targets.jsonl")
    ap.add_argument("--out", required=True, help="追加写入的向量 JSONL")
    ap.add_argument("--report-only", action="store_true",
                    help="只统计，不抽特征不写文件")
    args = ap.parse_args()

    targets = {r["sha256"].lower(): r for r in load_jsonl(args.targets)
               if len(str(r.get("sha256", ""))) == 64}
    done = set()
    if os.path.exists(args.out):
        for r in load_jsonl(args.out):
            if r.get("sha256"):
                done.add(r["sha256"].lower())
    print(f"目标清单 {len(targets)} 条，已抽取 {len(done)} 条")

    files = []
    for fn in sorted(os.listdir(args.src)):
        p = os.path.join(args.src, fn)
        if not os.path.isfile(p):
            continue
        sha = fn.split(".")[0].lower()
        if len(sha) == 64 and all(c in "0123456789abcdef" for c in sha):
            files.append((sha, p, os.path.splitext(fn)[1].lower()))
    print(f"本地文件 {len(files)} 个")

    ext = collections.Counter(e for _s, _p, e in ext_iter) if False else \
        collections.Counter(e for _s, _p, e in files)
    print("扩展名:", "  ".join(f"{k or '(none)'}={v}" for k, v in ext.most_common()))

    in_t = [(s, p, e) for s, p, e in files if s in targets]
    print(f"\n在目标清单里（即服务器判定恶意 PE 且 >=5 引擎）: {len(in_t)}")
    not_in = [(s, p, e) for s, p, e in files if s not in targets]
    ne = collections.Counter(e for _s, _p, e in not_in)
    print(f"不在清单里: {len(not_in)}  ->",
          "  ".join(f"{k or '(none)'}={v}" for k, v in ne.most_common(10)))

    todo = [(s, p, e) for s, p, e in in_t if s not in done]
    print(f"其中尚未抽过特征的: {len(todo)}   <- 这就是本目录能带来的净增量")

    if args.report_only or not todo:
        return 0

    ex = PEFeatureExtractor()
    stats = collections.Counter()
    outf = open(args.out, "a", encoding="utf-8")
    for sha, path, _e in todo:
        try:
            size = os.path.getsize(path)
        except OSError:
            stats["stat_fail"] += 1
            continue
        if size > MAX_SAMPLE:
            stats["too_big"] += 1
            continue
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            stats["read_fail"] += 1
            continue

        # 名字是别人给的，必须校验内容
        if hashlib.sha256(data).hexdigest() != sha:
            stats["hash_mismatch"] += 1
            del data
            continue
        if not ex.is_pe(data):
            stats["not_pe"] += 1
            del data
            continue
        try:
            vec = ex.feature_vector(data)
        except Exception:
            stats["feat_fail"] += 1
            del data
            continue
        finally:
            del data

        r = targets[sha]
        outf.write(json.dumps({
            "sha256": sha, "label": "malicious",
            "pe_type": r.get("pe_type", ""),
            "family": r.get("family", ""),
            "category": r.get("category", ""),
            "silverfox": bool(r.get("silverfox")),
            "malicious": r.get("malicious", 0),
            "total_engines": r.get("total_engines", 0),
            "first_seen": r.get("first_seen", 0),
            "archive_day": "local:" + os.path.basename(args.src.rstrip("\\/")),
            "schema_ver": SCHEMA_VERSION,
            "vec": [round(float(x), 6) for x in vec],
        }, ensure_ascii=False) + "\n")
        stats["ok"] += 1
        if stats["ok"] % 25 == 0:
            outf.flush()
            print(f"  已抽 {stats['ok']}/{len(todo)}", flush=True)
    outf.close()

    print(f"\n新增特征 {stats['ok']} 条 -> {args.out}")
    other = {k: v for k, v in stats.items() if k != "ok"}
    if other:
        print("跳过明细:", other)
    if stats.get("hash_mismatch"):
        print("[!] 有文件内容与文件名不符，已全部丢弃 —— 不能让来源不明的字节"
              "带着别人的标签进训练集。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
