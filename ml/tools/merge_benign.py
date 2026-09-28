#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把多路白样本语料合并成 extract_features.py 直接能吃的单一布局，并做语料体检。

输入是若干 (语料目录, manifest) 对：
  - Collect-BenignPE.ps1 的产物：<dir>/<sha256前2位>/<sha256> + benign_manifest.jsonl
  - harvest_benign.py 的产物：  <dir>/benign/<前2位>/<sha256> + manifests/benign_manifest.jsonl

输出统一到：
  <ml-root>/data/benign/<前2位>/<sha256>
  <ml-root>/data/manifests/benign_manifest.jsonl

默认用【硬链接】而不是复制 —— 同一个卷上不额外占盘。跨卷自动退回复制。

体检部分才是重点。它回答的是"这批负样本能不能用"，而不只是"有多少个"：
  - 签名者集中度：如果 Top1 签名者占比过高(基本就是微软)，模型会学成
    "微软签名 ⇒ 干净"，一遇第三方软件就狂误报。这是白样本最常见的坑。
  - 无签名占比：语料里必须有"无签名但良性"的样本。否则模型会把"无签名"
    当恶意特征，而按本项目设计原则无签名只是软信号、不能单独定罪。
  - 架构/类型分布：x86 太少会导致 32 位样本上表现塌陷。

用法:
  python merge_benign.py --ml-root "C:\\...\\新建文件夹 (12)" \
      --add "C:\\...\\system" "C:\\...\\benign_manifest.jsonl" \
      --add "C:\\...\\data\\benign" "C:\\...\\data\\manifests\\benign_manifest.jsonl"
  python merge_benign.py --ml-root ... --report-only
"""

import argparse
import collections
import json
import os
import re
import shutil
import sys

# 中文控制台默认是 GBK，报告里有中文和箭头会直接 UnicodeEncodeError 崩掉。
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, OSError):
    pass

HEX64 = re.compile(r"^[0-9a-f]{64}$")

# 归一签名者名字用的厂商关键字。目的不是穷举，而是把"同一家但 Subject 写法不同"
# 的合并掉，否则集中度会被低估。
VENDOR_KEYS = [
    ("microsoft", "Microsoft"), ("windows", "Microsoft"),
    ("google", "Google"), ("mozilla", "Mozilla"), ("intel", "Intel"),
    ("nvidia", "NVIDIA"), ("advanced micro devices", "AMD"), ("amd ", "AMD"),
    ("adobe", "Adobe"), ("oracle", "Oracle"), ("apple", "Apple"),
    ("tencent", "Tencent"), ("腾讯", "Tencent"),
    ("alibaba", "Alibaba"), ("baidu", "Baidu"), ("bytedance", "ByteDance"),
    ("kingsoft", "Kingsoft"), ("qihoo", "Qihoo360"), ("360", "Qihoo360"),
    ("beijing huorong", "Huorong"), ("huorong", "Huorong"),
    ("realtek", "Realtek"), ("logitech", "Logitech"), ("dell", "Dell"),
    ("hewlett", "HP"), ("hp inc", "HP"), ("lenovo", "Lenovo"),
    ("asus", "ASUS"), ("qualcomm", "Qualcomm"), ("broadcom", "Broadcom"),
    ("synaptics", "Synaptics"), ("igor pavlov", "7-Zip"),
    ("the qt company", "Qt"), ("videolan", "VideoLAN"),
    ("python software foundation", "PSF"), ("valve", "Valve"),
    ("nullsoft", "Nullsoft"), ("jetbrains", "JetBrains"),
    ("docker", "Docker"), ("vmware", "VMware"), ("citrix", "Citrix"),
]


def norm_signer(subject):
    """Subject -> 厂商短名。空签名返回 None(区别于"签了但不认识的厂商")。"""
    if not subject:
        return None
    s = subject.lower()
    for key, name in VENDOR_KEYS:
        if key in s:
            return name
    m = re.search(r"cn=(\"?)([^\",]+)", s)
    cn = (m.group(2) if m else s)[:48].strip()
    return cn or None


def vendor_key(r):
    """样本的"厂商轴"。

    有有效签名就用归一后的签名者；没签名(PyPI 的 .pyd、NuGet 托管程序集大多无签名)
    就退回来源包名。这一步很关键：numpy 一个 wheel 里的 21 个 .pyd 必须算【1 家】，
    否则多样性统计会被单个包灌水，平衡采样也就失去意义。
    """
    v = norm_signer(r.get("signer") or "")
    if v:
        return v
    pkg = r.get("pkg")
    if pkg:
        return f"pkg:{pkg}"
    return f"src:{r.get('src') or 'unknown'}"


def balance(rows, n_target, seed=42, key="vendor"):
    """按厂商轴轮转取样，产出多样性最大化的训练子集。

    为什么不直接全量喂进去：本机系统语料里微软占了绝大多数，
    全量训练模型会走"微软 -> 干净"的捷径，第三方软件上必然误报。
    轮转取样让每家厂商的配额自然拉平 —— 小厂商全取，大厂商被截断。

    key="vendor+petype" 时再按 dll/exe 分一层桶。用途：这套采集方法(系统目录/
    wheel/nupkg)天然是 DLL 占九成，而 MalwareBazaar 的恶意侧以 EXE 为主，
    模型能靠 "DLL -> 良性" 走捷径、把恶意 DLL 全放过去。分层能把 EXE 比例顶上来，
    代价是可用总量被稀缺的那一类卡住(EXE 只有几千个)，得调小 n_target。
    """
    import random
    rnd = random.Random(seed)
    if key == "vendor+petype":
        def kf(r):
            return (vendor_key(r), r.get("pe_type") or "?")
    else:
        kf = vendor_key
    buckets = collections.defaultdict(list)
    for r in rows:
        buckets[kf(r)].append(r)
    for b in buckets.values():
        rnd.shuffle(b)

    # 桶按样本数【升序】轮转：样本少的先被取满，配额不会被大桶吃掉
    order = sorted(buckets.keys(), key=lambda k: (len(buckets[k]), str(k)))
    out = []
    idx = {k: 0 for k in order}
    while len(out) < n_target:
        progressed = False
        for k in order:
            if len(out) >= n_target:
                break
            i = idx[k]
            if i < len(buckets[k]):
                out.append(buckets[k][i])
                idx[k] = i + 1
                progressed = True
        if not progressed:
            break          # 所有厂商都取空了，语料总量不够 n_target
    return out


def load_manifest(path):
    rows = []
    if not os.path.isfile(path):
        return rows
    with open(path, encoding="utf-8-sig", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except ValueError:
                continue
    return rows


def find_blob(corpus_dir, sha):
    """两种落盘布局都试：<dir>/<前2位>/<sha> 和 <dir>/benign/<前2位>/<sha>。"""
    for p in (os.path.join(corpus_dir, sha[:2], sha),
              os.path.join(corpus_dir, "benign", sha[:2], sha)):
        if os.path.isfile(p):
            return p
    return None


def link_or_copy(src, dst, force_copy=False):
    if os.path.exists(dst):
        return "exists"
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    if not force_copy:
        try:
            os.link(src, dst)      # 同卷硬链接，不占额外空间
            return "link"
        except OSError:
            pass                   # 跨卷/文件系统不支持 -> 退回复制
    try:
        shutil.copyfile(src, dst)
        return "copy"
    except OSError:
        return "fail"


def src_label(src_root):
    """把采集根目录压成短标签，别把本机绝对路径留在 manifest 里。"""
    s = (src_root or "").lower()
    if "winsxs" in s:
        return "winsxs"
    if "syswow64" in s:
        return "syswow64"
    if "system32" in s:
        return "system32"
    if "program files (x86)" in s:
        return "programfiles_x86"
    if "program files" in s:
        return "programfiles"
    return "system" if s else "unknown"


def report(rows):
    n = len(rows)
    print("\n================ 语料体检 ================")
    print(f"唯一白样本总数 : {n}")
    if not n:
        return

    by_src = collections.Counter(r.get("src") or r.get("src_root") or "unknown"
                                 for r in rows)
    print("\n来源分布:")
    for k, c in by_src.most_common(12):
        k = str(k)
        print(f"  {c:>7}  {c*100.0/n:5.1f}%  {k[:70]}")

    # ---- 厂商集中度：白样本质量的第一指标 ----
    # 分母必须是【样本总数】，不能只算"已验签的那部分"。
    # 采集器抽出来的 PyPI/NuGet 样本没跑 Authenticode，若把它们排除在分母外，
    # 微软占比会被算成 94% 这种虚高数字，掩盖真实的 49%。厂商轴统一用
    # vendor_key（有签名用签名者、无签名退回来源包），和平衡采样用的是同一把尺。
    vendors = collections.Counter(vendor_key(r) for r in rows)
    signed = sum(1 for r in rows if norm_signer(r.get("signer") or ""))
    verified = sum(1 for r in rows if (r.get("sig_status") or "").strip())
    unsigned_verified = verified - signed

    print(f"\n签名情况:")
    print(f"  跑过验签   : {verified} ({verified*100.0/n:.1f}%)")
    print(f"    有效签名 : {signed}")
    print(f"    无/无效  : {unsigned_verified}")
    print(f"  未跑验签   : {n - verified} "
          f"({(n-verified)*100.0/n:.1f}%，PyPI/NuGet 侧多为无签名的合法二进制)")

    print(f"\n不同厂商/来源: {len(vendors)}")
    top_share = vendors.most_common(1)[0][1] * 100.0 / n if vendors else 0.0
    print(f"厂商 Top 15 (占样本总数；Top1 = {top_share:.1f}%):")
    for name, c in vendors.most_common(15):
        print(f"  {c:>7}  {c*100.0/n:5.1f}%  {name}")

    arch = collections.Counter(r.get("arch") or "?" for r in rows)
    ptype = collections.Counter(r.get("pe_type") or "?" for r in rows)
    print("\n架构分布:", "  ".join(f"{k}={v}" for k, v in arch.most_common(8)))
    print("类型分布:", "  ".join(f"{k}={v}" for k, v in ptype.most_common(4)))

    sizes = sorted(int(r.get("size") or 0) for r in rows)
    if sizes:
        def q(p):
            return sizes[min(int(len(sizes) * p), len(sizes) - 1)]
        print(f"大小分位(KB): p10={q(.1)//1024} p50={q(.5)//1024} "
              f"p90={q(.9)//1024} p99={q(.99)//1024}")

    # ---- 结论 ----
    print("\n---- 结论 ----")
    problems = []
    if vendors:
        if top_share > 50:
            problems.append(
                f"单一厂商占样本总数 {top_share:.0f}% ({vendors.most_common(1)[0][0]})。"
                "模型很可能学成 '该厂商 -> 干净'，第三方软件上会误报。"
                "继续补第三方来源，把 Top1 压到 50% 以下。")
        if len(vendors) < 300:
            problems.append(
                f"不同厂商/来源只有 {len(vendors)} 家，建议 >=300 家。")
    unsigned_total = n - signed
    if unsigned_total * 100.0 / n < 5:
        problems.append(
            f"无签名样本只占 {unsigned_total*100.0/n:.1f}%。语料里缺少"
            "'无签名但良性' 的反例，模型会把无签名当成恶意特征。")
    if arch.get("x86", 0) < n * 0.10:
        problems.append(
            f"x86 样本只有 {arch.get('x86', 0)} 个 (<10%)，32 位样本上会偏弱。")
    # DLL/EXE 偏斜是个隐蔽的泄漏源：MalwareBazaar 的恶意侧以 EXE 为主，
    # 若白样本几乎全是 DLL，模型可以靠 'DLL -> 良性 / EXE -> 恶意' 拿高分，
    # 线上遇到恶意 DLL(侧加载、注入载荷)就直接漏检。
    n_dll = ptype.get("dll", 0)
    n_exe = ptype.get("exe", 0)
    if n_dll + n_exe > 0:
        dll_share = n_dll * 100.0 / (n_dll + n_exe)
        if dll_share > 80:
            problems.append(
                f"DLL 占 {dll_share:.0f}% (dll={n_dll} exe={n_exe})。恶意侧以 EXE 为主，"
                "模型可能靠 'DLL -> 良性' 走捷径，恶意 DLL 会漏检。"
                "补 EXE 白样本，或训练时按 pe_type 分层采样。")
        elif dll_share < 20:
            problems.append(
                f"EXE 占 {100-dll_share:.0f}%，DLL 白样本偏少 (dll={n_dll})，"
                "对恶意 DLL 的判别会不稳。")
    if problems:
        for p in problems:
            print(f"  [!] {p}")
    else:
        print("  未发现明显偏斜。")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ml-root", default="", help="合并输出根目录(--analyze 时不需要)")
    ap.add_argument("--add", nargs=2, action="append", metavar=("CORPUS", "MANIFEST"),
                    default=[], help="可重复：语料目录 + manifest 路径")
    ap.add_argument("--report-only", action="store_true",
                    help="只体检合并后的 manifest，不再搬文件")
    ap.add_argument("--analyze", default="",
                    help="只体检指定的某个 manifest，不合并不搬文件")
    ap.add_argument("--copy", action="store_true", help="强制复制而不是硬链接")
    ap.add_argument("--balance-n", type=int, default=0,
                    help="额外产出一个按厂商轮转取样的训练子集(建议 = 恶意样本数 x 3)")
    ap.add_argument("--balance-out", default="",
                    help="平衡子集的 manifest 路径(默认 benign_manifest_balanced.jsonl)")
    ap.add_argument("--balance-key", default="vendor",
                    choices=["vendor", "vendor+petype"],
                    help="平衡维度：只按厂商，或再按 dll/exe 分层")
    args = ap.parse_args()

    if args.analyze:
        rows = load_manifest(args.analyze)
        print(f"体检: {args.analyze}  ({len(rows)} 条)")
        report(rows)
        if args.balance_n:
            sub = balance(rows, args.balance_n, key=args.balance_key)
            out = args.balance_out or (
                os.path.splitext(args.analyze)[0] + "_balanced.jsonl")
            with open(out, "w", encoding="utf-8") as f:
                for r in sub:
                    f.write(json.dumps(r, ensure_ascii=False) + "\n")
            print(f"\n\n######## 平衡子集 -> {out} ########")
            report(sub)
        return

    if not args.ml_root:
        ap.error("需要 --ml-root（除非用 --analyze）")

    out_b = os.path.join(args.ml_root, "data", "benign")
    out_m = os.path.join(args.ml_root, "data", "manifests")
    os.makedirs(out_b, exist_ok=True)
    os.makedirs(out_m, exist_ok=True)
    out_manifest = os.path.join(out_m, "benign_manifest.jsonl")

    if args.report_only:
        report(load_manifest(out_manifest))
        return

    seen = set()
    merged = []
    for r in load_manifest(out_manifest):
        s = str(r.get("sha256", "")).lower()
        if HEX64.match(s) and s not in seen:
            seen.add(s)
            merged.append(r)
    print(f"[base] 目标 manifest 已有 {len(merged)} 条")

    stats = collections.Counter()
    for corpus_dir, manifest in args.add:
        rows = load_manifest(manifest)
        print(f"\n[add] {manifest}  ({len(rows)} 条)  <- {corpus_dir}")
        added = 0
        for r in rows:
            sha = str(r.get("sha256", "")).lower()
            if not HEX64.match(sha) or sha in seen:
                stats["dup"] += 1
                continue
            blob = find_blob(corpus_dir, sha)
            if not blob:
                stats["missing_blob"] += 1
                continue
            dst = os.path.join(out_b, sha[:2], sha)
            res = link_or_copy(blob, dst, force_copy=args.copy)
            stats[res] += 1
            if res == "fail":
                continue
            seen.add(sha)
            # 先把来源压成一个短标签，再把本机绝对路径全部丢掉。
            # 路径绝不能进特征(负样本全来自固定目录，一进特征就靠路径分类)，
            # 留在 manifest 里也只是泄漏本机布局的噪音。
            if not r.get("src"):
                r["src"] = src_label(r.get("src_root", ""))
            r.pop("src_path", None)
            r.pop("src_root", None)
            merged.append(r)
            added += 1
        print(f"  新增 {added}")

    with open(out_manifest, "w", encoding="utf-8") as f:
        for r in merged:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    print(f"\n落盘方式统计: {dict(stats)}")
    print(f"合并后 manifest: {out_manifest}")
    print(f"语料目录       : {out_b}")
    report(merged)

    if args.balance_n:
        sub = balance(merged, args.balance_n, key=args.balance_key)
        out = args.balance_out or os.path.join(
            out_m, "benign_manifest_balanced.jsonl")
        with open(out, "w", encoding="utf-8") as f:
            for r in sub:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"\n\n######## 平衡子集 -> {out} ########")
        print("训练时把它改名成 benign_manifest.jsonl（或用 --ml-root 指到另一个目录），"
              "extract_features.py 就只会读这批。")
        report(sub)


if __name__ == "__main__":
    main()
