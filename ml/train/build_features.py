#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把两侧样本拼成 train.py 能吃的 features.npz。

为什么不用 extract_features.py
----------------------------
它假设两侧都有文件字节。但恶意侧【没有字节】—— harvest_malicious.py 是流式的：
从 datalake 取回来、在内存里抽完 2380 维特征就丢弃，磁盘上不留活体恶意代码。
所以恶意侧进来的是现成的特征向量(JSONL)，白样本侧才需要现场抽特征。

输出 npz 字段（比 extract_features.py 多带三个，都是为了防泄漏和分层）：
  X        float32 N x 2380
  y        int8    1=恶意 0=良性
  sha      str
  family   str      恶意侧是 VT 的 threat_label，良性侧是厂商/来源包 -> 分组切分用
  pe_type  str      exe / dll                                    -> 分层与偏斜核查用
  first_seen int64  恶意侧的首次出现时间(unix)                     -> 时间切分用

用法
----
  # 纯 EXE 模型（恶意 EXE vs 白样本 EXE，类型天然平衡）
  python build_features.py --petype exe \
      --malicious malicious_vectors.jsonl \
      --benign-manifest ".../data/manifests/benign_manifest.jsonl" \
      --benign-corpus  ".../data/benign" \
      --out features_exe.npz

  # 全量（EXE+DLL），会打印类型偏斜警告
  python build_features.py --malicious ... --benign-manifest ... --out features_all.npz
"""

import argparse
import collections
import json
import os
import sys
from multiprocessing import Pool, cpu_count

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_features import PEFeatureExtractor, FEATURE_DIM, SCHEMA_VERSION  # noqa: E402

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, OSError):
    pass

_EX = None


def _init():
    global _EX
    _EX = PEFeatureExtractor()


def _feat_benign(task):
    sha, path, family, pe_type = task
    try:
        with open(path, "rb") as f:
            data = f.read()
        if not _EX.is_pe(data):
            return None
        return sha, _EX.feature_vector(data).astype(np.float32), family, pe_type
    except Exception:
        return None


def vendor_key(r):
    """良性侧的分组轴。与 merge_benign.py 保持同一套口径：有签名用签名者，
    没签名退回来源包 —— 一个 wheel 里的几十个 .pyd 必须算同一组，否则分组切分
    会把同一个包的近似重复分到训练集和测试集两边，测出来的分数照样是泄漏。"""
    sub = (r.get("signer") or "").lower()
    if sub:
        import re
        for key, name in (("microsoft", "Microsoft"), ("windows", "Microsoft"),
                          ("google", "Google"), ("mozilla", "Mozilla"),
                          ("intel", "Intel"), ("nvidia", "NVIDIA"),
                          ("tencent", "Tencent"), ("adobe", "Adobe")):
            if key in sub:
                return name
        m = re.search(r"cn=(\"?)([^\",]+)", sub)
        return (m.group(2) if m else sub)[:48].strip()
    if r.get("pkg"):
        return "pkg:%s" % r["pkg"]
    return "src:%s" % (r.get("src") or "unknown")


def load_benign(manifest, corpus, petype, limit):
    tasks = []
    seen = set()
    with open(manifest, encoding="utf-8-sig", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue
            sha = str(r.get("sha256", "")).lower()
            if len(sha) != 64 or sha in seen:
                continue
            pt = r.get("pe_type") or ""
            if petype and pt != petype:
                continue
            p = os.path.join(corpus, sha[:2], sha)
            if not os.path.isfile(p):
                p = os.path.join(corpus, "benign", sha[:2], sha)
                if not os.path.isfile(p):
                    continue
            seen.add(sha)
            tasks.append((sha, p, vendor_key(r), pt))
            if limit and len(tasks) >= limit:
                break
    return tasks


def load_malicious(path, petype, limit):
    rows = []
    bad_dim = bad_schema = 0
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if petype and r.get("pe_type") != petype:
                continue
            v = r.get("vec")
            if not v or len(v) != FEATURE_DIM:
                bad_dim += 1
                continue
            if int(r.get("schema_ver", -1)) != SCHEMA_VERSION:
                bad_schema += 1
                continue
            rows.append(r)
            if limit and len(rows) >= limit:
                break
    if bad_dim:
        print(f"[warn] 恶意侧丢弃 {bad_dim} 条：向量维度不是 {FEATURE_DIM}")
    if bad_schema:
        print(f"[warn] 恶意侧丢弃 {bad_schema} 条：schema_ver 与当前"
              f"({SCHEMA_VERSION})不符，必须用同一版特征重抽")
    return rows


def load_malicious_npz(path, petype, limit):
    """extract_local_vectors.py 的输出。

    本地已有字节的那 2 万个样本走这条路而不是 JSONL：一行 2380 个浮点的 JSONL 单条约
    28 KB，1 万条就是 300 MB 文本，读写都在浪费时间，而 npz 压缩后只有几十 MB 且是
    float32 原样往返，没有十进制转换的精度损耗。"""
    z = np.load(path, allow_pickle=False)
    ver = int(z["schema_ver"][0]) if "schema_ver" in z else -1
    if ver != SCHEMA_VERSION:
        raise SystemExit(f"[fatal] {path} 的 schema_ver={ver}，当前特征版本是 "
                         f"{SCHEMA_VERSION}。两侧必须用同一版特征重抽，否则列错位。")
    X = z["X"]
    if X.shape[1] != FEATURE_DIM:
        raise SystemExit(f"[fatal] {path} 维度 {X.shape[1]} != {FEATURE_DIM}")
    pt = z["pe_type"].astype(str)
    keep = np.ones(X.shape[0], dtype=bool) if not petype else (pt == petype)
    idx = np.flatnonzero(keep)
    if limit:
        idx = idx[:limit]
    fam = z["family"].astype(str) if "family" in z else np.array(["(unknown)"] * len(idx))
    fs = z["first_seen"] if "first_seen" in z else np.zeros(X.shape[0], dtype=np.int64)
    return (X[idx], z["sha"].astype(str)[idx], fam[idx], pt[idx], fs[idx])


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--malicious", help="harvest_malicious.py 的 JSONL（流式、无字节）")
    g.add_argument("--malicious-npz", help="extract_local_vectors.py 的 npz（本地有字节）")
    ap.add_argument("--benign-manifest", required=True)
    ap.add_argument("--benign-corpus", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--petype", default="", choices=["", "exe", "dll"],
                    help="只取某一类；纯 EXE 模型用 exe")
    ap.add_argument("--max-benign", type=int, default=0)
    ap.add_argument("--max-malicious", type=int, default=0)
    ap.add_argument("--workers", type=int, default=max(1, cpu_count() - 1))
    args = ap.parse_args()

    mal_npz = None
    if args.malicious_npz:
        mal_npz = load_malicious_npz(args.malicious_npz, args.petype,
                                     args.max_malicious)
        n_mal = mal_npz[0].shape[0]
        mal = []
    else:
        mal = load_malicious(args.malicious, args.petype, args.max_malicious)
        n_mal = len(mal)
    print(f"恶意侧: {n_mal} 条（现成向量，无需再抽）")

    tasks = load_benign(args.benign_manifest, args.benign_corpus,
                        args.petype, args.max_benign)
    print(f"良性侧: {len(tasks)} 个待抽特征  (workers={args.workers})")
    if not n_mal or not tasks:
        print("有一侧为空，无法组装数据集。")
        return 1

    try:
        from tqdm import tqdm
    except ImportError:
        def tqdm(x, **k):
            return x

    X, y, sha, fam, pt, fs = [], [], [], [], [], []

    if mal_npz is not None:
        mX, msha, mfam, mpt, mfs = mal_npz
        for i in range(mX.shape[0]):
            X.append(mX[i])
            y.append(1)
            sha.append(str(msha[i]))
            fam.append(str(mfam[i]) or "(unknown)")
            pt.append(str(mpt[i]) or "?")
            fs.append(int(mfs[i]))
    for r in mal:
        X.append(np.asarray(r["vec"], dtype=np.float32))
        y.append(1)
        sha.append(r["sha256"])
        fam.append(r.get("family") or "(unknown)")
        pt.append(r.get("pe_type") or "?")
        fs.append(int(r.get("first_seen") or 0))

    ok = 0
    with Pool(processes=args.workers, initializer=_init) as pool:
        for res in tqdm(pool.imap_unordered(_feat_benign, tasks, chunksize=16),
                        total=len(tasks)):
            if res is None:
                continue
            s, v, f, p = res
            X.append(v)
            y.append(0)
            sha.append(s)
            fam.append(f)
            pt.append(p)
            fs.append(0)
            ok += 1
    print(f"良性侧抽取成功 {ok}/{len(tasks)}")

    X = np.vstack(X).astype(np.float32)
    y = np.asarray(y, dtype=np.int8)
    np.nan_to_num(X, copy=False, nan=0.0, posinf=0.0, neginf=0.0)
    np.savez_compressed(args.out, X=X, y=y,
                        sha=np.asarray(sha), family=np.asarray(fam),
                        pe_type=np.asarray(pt),
                        first_seen=np.asarray(fs, dtype=np.int64),
                        feature_dim=np.asarray([X.shape[1]]),
                        schema_ver=np.asarray([SCHEMA_VERSION]))

    n_pos = int((y == 1).sum())
    n_neg = int((y == 0).sum())
    print(f"\n================ 数据集 ================")
    print(f"X {X.shape}  {X.dtype}")
    print(f"恶意 {n_pos} / 良性 {n_neg}   正负比 1:{n_neg/max(n_pos,1):.2f}")
    print(f"输出 -> {args.out}")

    # ---- 偏斜核查：这几项不看，训出来的高分很可能是捷径 ----
    print("\n---- 偏斜核查 ----")
    tp = collections.Counter(zip(pt, y.tolist()))
    for t in sorted({p for p in pt}):
        a = tp.get((t, 1), 0)
        b = tp.get((t, 0), 0)
        print(f"  pe_type={t:<4} 恶意 {a:>6}  良性 {b:>6}")
    if not args.petype:
        me = tp.get(("exe", 1), 0) + tp.get(("dll", 1), 0)
        be = tp.get(("exe", 0), 0) + tp.get(("dll", 0), 0)
        if me and be:
            mshare = tp.get(("exe", 1), 0) * 100.0 / me
            bshare = tp.get(("exe", 0), 0) * 100.0 / be
            if abs(mshare - bshare) > 25:
                print(f"  [!] EXE 占比两侧差 {abs(mshare-bshare):.0f} 个百分点"
                      f"（恶意 {mshare:.0f}% vs 良性 {bshare:.0f}%）。")
                print("      模型可以只靠 '是 EXE 还是 DLL' 拿高分，恶意 DLL 会漏检。")
                print("      建议改用 --petype exe 先训纯 EXE 模型。")

    gm = len({f for f, yy in zip(fam, y.tolist()) if yy == 1})
    gb = len({f for f, yy in zip(fam, y.tolist()) if yy == 0})
    print(f"  分组数: 恶意家族 {gm}  良性厂商 {gb}"
          f"   <- 分组切分靠这个防同族近似重复泄漏")
    nfs = int((np.asarray(fs) > 0).sum())
    print(f"  带 first_seen 的恶意样本: {nfs}/{n_pos}   <- 时间切分靠这个")

    # 只有单一常量的列对树模型毫无用处，但大量常量列往往说明抽特征出了问题
    const = int((X.max(axis=0) == X.min(axis=0)).sum())
    print(f"  常量列: {const}/{X.shape[1]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
