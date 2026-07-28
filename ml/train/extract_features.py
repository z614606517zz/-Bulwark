"""
读 benign / malicious 两个 manifest，抽取静态 PE 特征，落成特征矩阵 (.npz)。

- 良性：从语料库裸文件读  ml/data/benign/<前2位>/<sha256>
- 恶意：从加密 zip 读      ml/data/malicious/zip/<前2位>/<sha256>.zip （密码 infected）
        标准 ZipCrypto 用内置 zipfile；若是 AES 加密则回退 pyzipper。
- 多进程并行；每条记录独立容错，坏样本跳过不影响整体。

输出 npz: X(float32 N×D), y(int8 0良性/1恶意), sha(str), family(str), feature_dim
用法:
  python extract_features.py                     # 全量
  python extract_features.py --limit 200         # 每类各取 200（冒烟）
  python extract_features.py --workers 8 --out features.npz
"""

import argparse
import json
import os
import sys
import zipfile
from multiprocessing import Pool, cpu_count

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pe_features import PEFeatureExtractor  # noqa: E402

_EX = None
_ZIP_PW = b"infected"


def _init_worker():
    global _EX
    _EX = PEFeatureExtractor()


def _read_zip_sample(zip_path):
    """返回加密 zip 里的样本字节；先试 ZipCrypto，失败回退 pyzipper(AES)。"""
    try:
        with zipfile.ZipFile(zip_path) as z:
            names = z.namelist()
            if not names:
                return None
            return z.read(names[0], pwd=_ZIP_PW)
    except (RuntimeError, NotImplementedError, zipfile.BadZipFile):
        try:
            import pyzipper
            with pyzipper.AESZipFile(zip_path) as z:
                z.setpassword(_ZIP_PW)
                names = z.namelist()
                if not names:
                    return None
                return z.read(names[0])
        except Exception:
            return None
    except Exception:
        return None


def _process(task):
    label, sha, family, path, is_zip = task
    try:
        if is_zip:
            data = _read_zip_sample(path)
        else:
            with open(path, "rb") as f:
                data = f.read()
        if not data:
            return None
        vec = _EX.feature_vector(data)
        return (sha, int(label), family or "", vec.astype(np.float32))
    except Exception:
        return None


def _load_manifest(path):
    rows = []
    if not os.path.isfile(path):
        return rows
    with open(path, "r", encoding="utf-8-sig", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                pass
    return rows


def build_tasks(ml_root, limit):
    man_dir = os.path.join(ml_root, "data", "manifests")
    benign = _load_manifest(os.path.join(man_dir, "benign_manifest.jsonl"))
    malicious = _load_manifest(os.path.join(man_dir, "malicious_manifest.jsonl"))
    tasks = []
    seen = set()

    # 良性：优先语料库裸文件，缺失回退原始 src_path
    b_dir = os.path.join(ml_root, "data", "benign")
    b_count = 0
    for r in benign:
        sha = str(r.get("sha256", "")).lower()
        if len(sha) != 64 or sha in seen:
            continue
        p = os.path.join(b_dir, sha[:2], sha)
        if not os.path.isfile(p):
            p = r.get("src_path", "")
        if not p or not os.path.isfile(p):
            continue
        seen.add(sha)
        tasks.append((0, sha, r.get("arch", ""), p, False))
        b_count += 1
        if limit and b_count >= limit:
            break

    # 恶意：优先裸文件(raw_path，来自 daily 批量导入 / 本地导入)，否则加密 zip(zip_path，来自 get_file API)
    m_count = 0
    for r in malicious:
        sha = str(r.get("sha256", "")).lower()
        if len(sha) != 64 or sha in seen:
            continue
        rawp = r.get("raw_path", "")
        zp = r.get("zip_path", "")
        if rawp and os.path.isfile(rawp):
            path, is_zip = rawp, False
        elif zp and os.path.isfile(zp):
            path, is_zip = zp, True
        else:
            continue
        seen.add(sha)
        tasks.append((1, sha, r.get("family", ""), path, is_zip))
        m_count += 1
        if limit and m_count >= limit:
            break

    return tasks, b_count, m_count


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    default_root = os.path.abspath(os.path.join(here, ".."))
    ap = argparse.ArgumentParser()
    ap.add_argument("--ml-root", default=default_root, help="ml/ 根目录")
    ap.add_argument("--out", default=os.path.join(here, "features.npz"))
    ap.add_argument("--limit", type=int, default=0, help="每类最多取多少（0=全量）")
    ap.add_argument("--workers", type=int, default=max(1, cpu_count() - 1))
    args = ap.parse_args()

    tasks, nb, nm = build_tasks(args.ml_root, args.limit)
    print(f"待抽取: 良性 {nb} + 恶意 {nm} = {len(tasks)}  (workers={args.workers})")
    if not tasks:
        print("没有可用样本，检查 manifest 与语料路径。")
        return

    try:
        from tqdm import tqdm
    except Exception:
        def tqdm(x, **k):
            return x

    shas, ys, fams, vecs = [], [], [], []
    ok = 0
    with Pool(processes=args.workers, initializer=_init_worker) as pool:
        for res in tqdm(pool.imap_unordered(_process, tasks, chunksize=16), total=len(tasks)):
            if res is None:
                continue
            sha, y, fam, vec = res
            shas.append(sha); ys.append(y); fams.append(fam); vecs.append(vec)
            ok += 1

    if not vecs:
        print("全部抽取失败。")
        return
    X = np.vstack(vecs).astype(np.float32)
    y = np.asarray(ys, dtype=np.int8)
    sha_arr = np.asarray(shas)
    fam_arr = np.asarray(fams)
    np.savez_compressed(args.out, X=X, y=y, sha=sha_arr, family=fam_arr,
                        feature_dim=np.asarray([X.shape[1]]))
    n_pos = int((y == 1).sum()); n_neg = int((y == 0).sum())
    print(f"成功 {ok}/{len(tasks)}  ->  {args.out}")
    print(f"矩阵: X{X.shape}  良性 {n_neg} / 恶意 {n_pos}  维度 {X.shape[1]}")


if __name__ == "__main__":
    main()
