#!/usr/bin/env python3
"""
分析已收集的 VT 结果(vt_results.jsonl)，按【样本类型】拆开做人工核查报告：
  - 各类型(恶意PE/脚本/安装包/文档/良性)的收录率、检出分布
  - 每类里"该恶意却低检出/未收录"的清单(附各引擎判定，作核查证据)
  - 良性里被报毒的(标签污染)
  - 家族(threat_label)分布
只读分析，不改文件。
"""
import argparse
import collections
import json
import os

MAL_LABELS = ('malicious', 'script', 'installer', 'document', 'archive')


def load(path):
    rows = []
    if os.path.isfile(path):
        with open(path, encoding='utf-8-sig', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        rows.append(json.loads(line))
                    except Exception:
                        pass
    return rows


def engines_flagging(rec, limit=5):
    res = (rec.get('attributes', {}) or {}).get('last_analysis_results', {}) or {}
    hits = [f"{e}:{(r or {}).get('result') or (r or {}).get('category')}"
            for e, r in res.items() if (r or {}).get('category') in ('malicious', 'suspicious')]
    return hits[:limit]


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    default_root = os.path.abspath(os.path.join(here, '..'))
    ap = argparse.ArgumentParser()
    ap.add_argument('--ml-root', default=default_root)
    ap.add_argument('--low', type=int, default=5)
    args = ap.parse_args()

    rows = load(os.path.join(args.ml_root, 'data', 'vt', 'vt_results.jsonl'))
    if not rows:
        print('没有 VT 结果'); return
    by = collections.defaultdict(list)
    for r in rows:
        by[r.get('manifest_label', '?')].append(r)

    print(f'================ VT 分类型核查报告 (共 {len(rows)}) ================')
    hdr = f"{'类型':<10} {'总数':>5} {'收录':>5} {'404':>4} {'上传得':>5} {'中位检出':>7} {'低检出<%d':>8}"
    print(hdr % args.low)
    for lb in list(MAL_LABELS) + ['benign']:
        rs = by.get(lb, [])
        if not rs:
            continue
        found = [r for r in rs if r.get('found')]
        nf = sum(1 for r in rs if r.get('http') == 404)
        up = sum(1 for r in rs if r.get('uploaded') and r.get('found'))
        dets = sorted(int(r.get('vt_malicious', 0) or 0) for r in found)
        med = dets[len(dets) // 2] if dets else 0
        low = sum(1 for r in found if int(r.get('vt_malicious', 0) or 0) < args.low)
        print(f"{lb:<10} {len(rs):>5} {len(found):>5} {nf:>4} {up:>5} {med:>7} {low:>8}")

    # 各恶意类型的低检出/未收录清单
    for lb in MAL_LABELS:
        rs = by.get(lb, [])
        if not rs:
            continue
        susp = [r for r in rs if r.get('http') == 404 or (r.get('found') and int(r.get('vt_malicious', 0) or 0) < args.low)]
        if not susp:
            continue
        print(f'\n[{lb}] 需人工复核 {len(susp)} 个 (未收录 或 检出<{args.low}):')
        for r in susp[:12]:
            tag = '404未收录' if r.get('http') == 404 else f"{r.get('vt_malicious',0)}/{r.get('vt_total',0)}"
            print(f'  {r["sha256"][:16]}  {tag}  {r.get("threat_label","")}  {r.get("type_description","")}')
            eng = engines_flagging(r)
            if eng and r.get('found'):
                print('      引擎: ' + ', '.join(eng))

    # 良性污染
    bad_benign = [r for r in by.get('benign', []) if r.get('found') and int(r.get('vt_malicious', 0) or 0) >= 3]
    if bad_benign:
        print(f'\n[benign 标签污染] {len(bad_benign)} 个良性被 >=3 引擎报毒:')
        for r in bad_benign[:15]:
            print(f'  {r["sha256"][:16]}  {r.get("vt_malicious",0)}/{r.get("vt_total",0)}  {r.get("threat_label","")}')

    # 家族分布(全恶意侧)
    fam = collections.Counter()
    for lb in MAL_LABELS:
        for r in by.get(lb, []):
            if r.get('found') and int(r.get('vt_malicious', 0) or 0) >= 5:
                fam[r.get('threat_label', '') or '(无名)'] += 1
    if fam:
        print('\n[家族 Top15](恶意侧,检出>=5)')
        for name, n in fam.most_common(15):
            print(f'  {n:>4}  {name}')


if __name__ == '__main__':
    main()
