#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
扫描一个恶意样本目录，生成 extract_features.py 需要的 malicious_manifest.jsonl。

支持三种存放形态（可混用，自动识别）：
  1) 裸文件      —— 任意目录结构，文件名随意，按内容算 sha256
  2) 加密 zip    —— 每个 zip 一个样本，密码 infected（MalwareBazaar 的标准形态）
  3) 已按哈希命名 —— <前2位>/<sha256>，仍会校验内容哈希是否相符

输出每行：
  {"sha256": ..., "label": "malicious", "size": N, "family": "...",
   "first_seen": "...", "raw_path": "..."}        # 裸文件
  {"sha256": ..., ..., "zip_path": "..."}          # 加密 zip

【绝不执行样本】。只读文件头判断是不是 PE，只算哈希，不解压到磁盘之外的地方，
加密 zip 只在内存里读头部用于确认 PE 与算哈希。

关于 first_seen（重要）
---------------------
train.py 必须【按时间切分】而不是随机切分：恶意样本同族近似重复极多，随机切会把
同一家族的变种分到训练集和测试集两边，测出来的高分全是泄漏，上线即崩。
所以这里尽力填 first_seen：
  --family-from-path 时用目录名当 family；
  时间优先取样本文件的 mtime（下载入库时间），并允许 --first-seen-map 从
  MalwareBazaar 导出的 CSV/JSONL 里补真实的 first_seen。
没有时间信息就留空，但会在结尾明确告警——那种情况下必须改用按家族分组切分。

用法:
  python build_malicious_manifest.py --src "D:\\samples" --out ml/data/manifests/malicious_manifest.jsonl
  python build_malicious_manifest.py --src "D:\\samples" --out ... --family-from-path
  python build_malicious_manifest.py --src "D:\\samples" --out ... --first-seen-map mb.jsonl
"""

import argparse
import collections
import csv
import datetime
import hashlib
import json
import os
import struct
import sys
import zipfile

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, OSError):
    pass

ZIP_PW = b"infected"
MIN_SIZE = 512
MAX_SIZE = 128 * 1024 * 1024


def is_pe_head(head):
    if len(head) < 0x40 or head[:2] != b"MZ":
        return False
    try:
        e = struct.unpack_from("<I", head, 0x3C)[0]
    except struct.error:
        return False
    if e + 4 > len(head):
        return True     # 头部读太少，无法否证；交给后续特征提取判断
    return head[e:e + 4] == b"PE\0\0"


def sha256_and_head(path):
    h = hashlib.sha256()
    head = b""
    try:
        with open(path, "rb") as f:
            first = True
            for b in iter(lambda: f.read(1 << 20), b""):
                if first:
                    head = b[:0x400]
                    first = False
                h.update(b)
    except OSError:
        return None, b""
    return h.hexdigest(), head


def read_zip_member(path):
    """从加密 zip 里读出唯一成员的字节。ZipCrypto 用标准库，AES 退回 pyzipper。"""
    try:
        with zipfile.ZipFile(path) as z:
            names = [n for n in z.namelist() if not n.endswith("/")]
            if not names:
                return None
            return z.read(names[0], pwd=ZIP_PW)
    except (RuntimeError, NotImplementedError, zipfile.BadZipFile):
        try:
            import pyzipper
            with pyzipper.AESZipFile(path) as z:
                z.setpassword(ZIP_PW)
                names = [n for n in z.namelist() if not n.endswith("/")]
                if not names:
                    return None
                return z.read(names[0])
        except Exception:
            return None
    except Exception:
        return None


def load_first_seen_map(path):
    """从 MalwareBazaar 导出的 CSV / JSONL 里取 sha256 -> (first_seen, family)。"""
    m = {}
    if not path or not os.path.isfile(path):
        return m
    with open(path, encoding="utf-8-sig", errors="ignore") as f:
        sample = f.read(4096)
        f.seek(0)
        if sample.lstrip().startswith("{"):
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    o = json.loads(line)
                except ValueError:
                    continue
                s = str(o.get("sha256") or o.get("sha256_hash") or "").lower()
                if len(s) == 64:
                    m[s] = (o.get("first_seen") or o.get("firstseen") or "",
                            o.get("signature") or o.get("family") or "")
        else:
            for row in csv.DictReader(l for l in f if not l.startswith("#")):
                keys = {k.strip().lower(): v for k, v in row.items() if k}
                s = str(keys.get("sha256_hash") or keys.get("sha256") or "").lower()
                if len(s) == 64:
                    m[s] = (keys.get("first_seen_utc") or keys.get("first_seen") or "",
                            keys.get("signature") or keys.get("family") or "")
    return m


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True, help="恶意样本根目录(递归扫描)")
    ap.add_argument("--out", required=True, help="输出 malicious_manifest.jsonl")
    ap.add_argument("--family-from-path", action="store_true",
                    help="用样本所在的子目录名当 family")
    ap.add_argument("--first-seen-map", default="",
                    help="MalwareBazaar 导出的 CSV/JSONL，用于补 first_seen 和 family")
    ap.add_argument("--require-pe", action="store_true", default=True,
                    help="只收真 PE（默认开；静态 PE 模型喂非 PE 只会加噪声）")
    ap.add_argument("--allow-non-pe", dest="require_pe", action="store_false")
    args = ap.parse_args()

    fsmap = load_first_seen_map(args.first_seen_map)
    if fsmap:
        print(f"[map] 载入 {len(fsmap)} 条 first_seen/family")

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    seen = set()
    stats = collections.Counter()
    fams = collections.Counter()
    rows = []

    for root, _dirs, files in os.walk(args.src):
        for fn in files:
            fp = os.path.join(root, fn)
            try:
                size = os.path.getsize(fp)
            except OSError:
                stats["stat_fail"] += 1
                continue
            if size < MIN_SIZE or size > MAX_SIZE:
                stats["size_skip"] += 1
                continue

            is_zip = fn.lower().endswith(".zip")
            if is_zip:
                data = read_zip_member(fp)
                if not data:
                    stats["zip_fail"] += 1
                    continue
                sha = hashlib.sha256(data).hexdigest()
                head = data[:0x400]
                real_size = len(data)
                del data                      # 样本字节不留在内存里过夜
            else:
                sha, head = sha256_and_head(fp)
                if not sha:
                    stats["read_fail"] += 1
                    continue
                real_size = size

            if args.require_pe and not is_pe_head(head):
                stats["not_pe"] += 1
                continue
            if sha in seen:
                stats["dup"] += 1
                continue
            seen.add(sha)

            family = ""
            if args.family_from_path:
                rel = os.path.relpath(root, args.src)
                part = rel.split(os.sep)[0]
                # <前2位> 这种哈希分桶目录名不是家族名
                if part not in (".", "") and not (len(part) == 2 and
                                                  all(c in "0123456789abcdef"
                                                      for c in part.lower())):
                    family = part
            first_seen = ""
            if sha in fsmap:
                fs, fam = fsmap[sha]
                first_seen = fs or ""
                family = family or (fam or "")
            if not first_seen:
                try:
                    first_seen = datetime.datetime.fromtimestamp(
                        os.path.getmtime(fp), datetime.timezone.utc
                    ).strftime("%Y-%m-%d %H:%M:%S")
                    stats["first_seen_from_mtime"] += 1
                except OSError:
                    pass

            rec = {"sha256": sha, "label": "malicious", "size": real_size,
                   "family": family, "first_seen": first_seen}
            rec["zip_path" if is_zip else "raw_path"] = os.path.abspath(fp)
            rows.append(rec)
            fams[family or "(unknown)"] += 1
            stats["ok"] += 1
            if stats["ok"] % 1000 == 0:
                print(f"  已收 {stats['ok']} ...", flush=True)

    with open(args.out, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print("\n================ 恶意清单生成完成 ================")
    print(f"收录       : {stats['ok']}")
    print(f"输出       : {args.out}")
    print("跳过明细   : " + "  ".join(
        f"{k}={v}" for k, v in stats.items() if k != "ok") or "无")
    print(f"\n不同家族   : {len(fams)}")
    for k, c in fams.most_common(15):
        print(f"  {c:>6}  {k}")

    n_fs = sum(1 for r in rows if r.get("first_seen"))
    n_real_fs = n_fs - stats.get("first_seen_from_mtime", 0)
    print(f"\nfirst_seen : {n_fs}/{len(rows)} 有值"
          f"（其中真实来源 {max(n_real_fs, 0)}，靠文件 mtime 兜底 "
          f"{stats.get('first_seen_from_mtime', 0)}）")
    if n_real_fs <= 0:
        print("\n[!] 没有任何【真实】first_seen，全靠 mtime 兜底。")
        print("    mtime 通常是你下载入库的时间，不是样本真实出现时间，"
              "按它做时间切分只能挡住一部分泄漏。")
        print("    建议改用按家族分组切分（StratifiedGroupKFold, groups=family），"
              "或从 MalwareBazaar 导出 CSV 后用 --first-seen-map 补齐。")
    if len(fams) <= 1:
        print("\n[!] 家族信息为空。同族近似重复是恶意语料最大的泄漏源，"
              "既没有 family 也没有真实 first_seen 时，测试集分数不可信。")
        print("    补救：加 --family-from-path（若目录按家族组织），"
              "或跑 ml/train/mb_enrich.py 从 MalwareBazaar 补 signature。")


if __name__ == "__main__":
    main()
