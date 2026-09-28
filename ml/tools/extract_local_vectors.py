#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从【本地已有字节】的恶意样本抽 2380 维特征，产出 build_features.py 能吃的 npz。

为什么需要这个工具（harvest_malicious.py 不够用）
------------------------------------------------
harvest_malicious.py 是为「服务器没有字节」设计的：从 datalake 流式取回、内存里抽完
就丢。但本机 D:\\新建文件夹 (9)/(10) 里已经躺着 21,308 个样本，每个都以自己的 sha256
命名。对这批样本，datalake 那条路是纯浪费：

  * 慢 —— 实测 20 个/分钟，11,000 个要 9 小时；本地读盘是几百个/分钟。
  * 拿不到 —— 07-31~08-04 那几天的归档在 datalake 已经 404。
  * 没必要 —— 字节就在手上。

标签同理不再问 VT：共享密钥池是【单个免费 key，500 次/天】。为 3,338 个哈希重新查一遍
要一周，且会榨干 datalake 采集器、bulwark-benign-verify，以及出货客户端 ReputationProxy
云查所依赖的同一份额度 —— 额度耗尽时客户端静默退回纯本地判定，是真实的产品降级。
标签因此全部取自服务器 vt_reports 存档（早已付过费的判定，边际成本为零）。

标签可信度
----------
vt_reports 按保留策略只存威胁，所以「在表里」本身不等于「判为恶意」—— 引擎数才是判据。
正样本要求 malicious >= --min-engines（默认 5）。

引擎数 1~4 的样本【两边都不进】：算良性会把真恶意掺进负类，算恶意等于在学 AV 行业的
噪声底。宁可丢掉。

是不是 PE 由【本地字节头】判定，不看 VT 的 type_tag
------------------------------------------------
重叠集里有 1,867 个样本的 report 没带 type_tag，若按 type_tag 过滤会白丢一批真 PE。
而 type_tag 对模型毫无意义 —— 决定样本能不能用的是 pefile 能不能解析它。所以这里的
判据是 PEFeatureExtractor.is_pe()（MZ + e_lfanew 处的 PE\\0\\0）加一次真实解析。
顺带把 ELF/脚本类样本自然排除：它们过不了字节头检查。

防标签泄漏
----------
写进向量的只有文件字节本身。路径、文件名、所在日期目录、签名者、签名有效性一律不进特征
—— 在这份语料里它们与标签完全相关（恶意在 (9)/(10)，白样本在别处），喂进去等于让模型
去学目录结构而不是文件格式。pe_type 和 family 只作为分层/分组的元数据随 npz 走，不进 X。
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import sys
import time
from multiprocessing import Pool, cpu_count

import numpy as np

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "train"))
from pe_features import PEFeatureExtractor, FEATURE_DIM, SCHEMA_VERSION  # noqa: E402

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, OSError):
    pass

SHA = re.compile(r"^[0-9a-f]{64}$")
_EX: PEFeatureExtractor | None = None

# 单个样本的读盘上限。恶意语料里偶有几百 MB 的自解压包，全读进来会把 worker 撑爆；
# 2380 维特征里字节直方图/熵图都是统计量，前 64 MiB 足够定形。
MAX_READ = 64 * 1024 * 1024


def _init() -> None:
    global _EX
    _EX = PEFeatureExtractor()


def _pe_type(data: bytes) -> str:
    """exe / dll，只看 COFF 头的 DLL 标志位，不看扩展名（扩展名可以撒谎）。"""
    try:
        import struct
        e = struct.unpack_from("<I", data, 0x3C)[0]
        chars = struct.unpack_from("<H", data, e + 4 + 18)[0]
        return "dll" if (chars & 0x2000) else "exe"
    except Exception:
        return "exe"


def _work(task):
    sha, path = task
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            data = f.read(MAX_READ)
    except Exception as e:
        return ("ioerr", sha, str(e)[:80], None, None, None)
    if not _EX.is_pe(data):
        return ("notpe", sha, "", None, None, None)
    try:
        vec = _EX.feature_vector(data).astype(np.float32)
    except Exception as e:
        return ("featerr", sha, str(e)[:80], None, None, None)
    return ("ok", sha, "", vec, _pe_type(data), size)


def load_labels(paths: list[str]) -> dict[str, dict]:
    """sha256 -> 标签记录。后面的文件覆盖前面的，让新查到的结果能顶掉旧存档行；
    但 404/报错行不允许覆盖已有的有效判定。"""
    out: dict[str, dict] = {}
    for p in paths:
        if not p or not os.path.exists(p):
            print(f"  [skip] 不存在: {p}")
            continue
        n = 0
        with open(p, encoding="utf-8-sig", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                sha = str(r.get("sha256") or "").lower()
                if not SHA.match(sha):
                    continue
                if r.get("error") and not r.get("mal"):
                    out.setdefault(sha, r)
                else:
                    out[sha] = r
                n += 1
        print(f"  标签 {os.path.basename(p):<26} {n:>7} 行")
    return out


def scan_roots(roots: list[str]) -> dict[str, str]:
    found: dict[str, str] = {}
    for root in roots:
        if not os.path.isdir(root):
            print(f"  [!] 目录不存在: {root}")
            continue
        n = 0
        for dp, _dn, fn in os.walk(root):
            for name in fn:
                if name.startswith("_"):
                    continue
                stem = os.path.splitext(name)[0].lower()
                if SHA.match(stem):
                    found.setdefault(stem, os.path.join(dp, name))
                    n += 1
        print(f"  本地文件 {root:<28} {n:>7} 个")
    return found


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--labels", nargs="+", required=True,
                    help="vt_labels.jsonl / lk_results.jsonl 等")
    ap.add_argument("--roots", nargs="+", required=True, help="本地样本根目录")
    ap.add_argument("--out", required=True, help="输出 .npz")
    ap.add_argument("--min-engines", type=int, default=5)
    ap.add_argument("--workers", type=int, default=max(1, min(8, cpu_count() - 1)))
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    print("== 标签 ==")
    labels = load_labels(args.labels)
    print(f"  带标签的唯一哈希: {len(labels)}")
    print("== 本地字节 ==")
    local = scan_roots(args.roots)
    print(f"  sha256 命名的唯一文件: {len(local)}")

    # 只按引擎数筛。是不是 PE 交给字节头判，不看 type_tag。
    tasks, weak, unlabelled = [], 0, 0
    for sha, path in sorted(local.items()):
        r = labels.get(sha)
        if r is None:
            unlabelled += 1
            continue
        if int(r.get("mal") or 0) < args.min_engines:
            weak += 1
            continue
        tasks.append((sha, path))
    if args.limit:
        tasks = tasks[:args.limit]

    print("\n== 候选 ==")
    print(f"  无标签，跳过           : {unlabelled}")
    print(f"  引擎数 <{args.min_engines}，两边都不进 : {weak}")
    print(f"  待抽特征               : {len(tasks)}   (workers={args.workers})")
    if not tasks:
        print("没有候选样本。")
        return 1

    X, sha_l, fam_l, pt_l, fs_l, mal_l = [], [], [], [], [], []
    stat = collections.Counter()
    errs: list[str] = []
    t0 = time.time()

    with Pool(processes=args.workers, initializer=_init) as pool:
        for i, res in enumerate(pool.imap_unordered(_work, tasks, chunksize=8), 1):
            kind, sha, msg, vec, pt, _size = res
            stat[kind] += 1
            if kind == "ok":
                r = labels[sha]
                X.append(vec)
                sha_l.append(sha)
                # 家族取 threat_label 的首段（trojan.emotet/x -> trojan），
                # 分组切分靠它防同族近似重复跨切分泄漏
                tl = str(r.get("label") or "")
                fam_l.append(tl.split(".")[0] or "(unknown)")
                pt_l.append(pt)
                fs_l.append(int(r.get("first_seen") or 0))
                mal_l.append(int(r.get("mal") or 0))
            elif len(errs) < 20 and msg:
                errs.append(f"{kind} {sha[:12]} {msg}")
            if i % 500 == 0 or i == len(tasks):
                el = time.time() - t0
                print(f"  {i:>6}/{len(tasks)}  ok={stat['ok']} notpe={stat['notpe']} "
                      f"ioerr={stat['ioerr']} featerr={stat['featerr']}  "
                      f"{i/max(el,.001)*60:.0f}/min", flush=True)

    if not X:
        print("一个都没抽出来。")
        return 1

    Xa = np.vstack(X).astype(np.float32)
    np.nan_to_num(Xa, copy=False, nan=0.0, posinf=0.0, neginf=0.0)
    np.savez_compressed(
        args.out, X=Xa,
        y=np.ones(Xa.shape[0], dtype=np.int8),
        sha=np.asarray(sha_l), family=np.asarray(fam_l),
        pe_type=np.asarray(pt_l),
        first_seen=np.asarray(fs_l, dtype=np.int64),
        mal=np.asarray(mal_l, dtype=np.int32),
        feature_dim=np.asarray([Xa.shape[1]]),
        schema_ver=np.asarray([SCHEMA_VERSION]))

    print("\n================ 恶意侧 ================")
    print(f"X {Xa.shape}  {Xa.dtype}   -> {args.out}")
    print(f"  抽取成功 {stat['ok']}   非 PE(ELF/脚本等) {stat['notpe']}   "
          f"读盘失败 {stat['ioerr']}   特征失败 {stat['featerr']}")
    pt_c = collections.Counter(pt_l)
    print(f"  pe_type: exe {pt_c['exe']}   dll {pt_c['dll']}")
    print(f"  家族分组数: {len(set(fam_l))}")
    print(f"  带 first_seen: {sum(1 for v in fs_l if v > 0)}/{len(fs_l)}")
    me = np.asarray(mal_l)
    print(f"  引擎数: 中位 {int(np.median(me))}  最小 {me.min()}  最大 {me.max()}")
    fam_c = collections.Counter(fam_l)
    print("  家族 Top10:", dict(fam_c.most_common(10)))
    const = int((Xa.max(axis=0) == Xa.min(axis=0)).sum())
    print(f"  常量列 {const}/{Xa.shape[1]}")
    if errs:
        print("\n  前若干条错误:")
        for e in errs:
            print("   ", e)
    return 0


if __name__ == "__main__":
    sys.exit(main())
