#!/usr/bin/env python3
"""
按 sha256 补查指定样本到 VT 结果(vt_results.jsonl)。复用 vt_enrich 的查询/记录逻辑,
产出记录与批量富集完全一致(可被 behavior_features.py / vt_to_reputation.py 直接消费)。

- 只按 hash 查 VT 报告(GET);无本地文件不能上传。
- 429/401/403 会换 Key + 等待重试(最多 --retries 次),【只持久化权威结果 200/404】,
  避免把限流失败写进数据集(那会污染语料且挡住以后重查)。
- 默认【刷新】:先从 vt_results.jsonl 删掉这些 hash 的旧记录,再写入新结果(可反复跑)。
- 标签:优先按 manifest 归属,查不到用 --label(默认 malicious)。

用法:  python vt_add.py <sha256> [<sha256> ...] [--label malicious] [--retries 5]
"""
import argparse
import json
import os
import re
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vt_enrich as ve

SHA_RE = re.compile(r'"sha256"\s*:\s*"([0-9a-fA-F]{64})"')


def query_with_retry(sha, keys, timeout, retries):
    """轮换 Key 查询;429/401/403 等待重试。返回 (code, body)。只在 200/404 时算权威。"""
    n = len(keys)
    for attempt in range(retries):
        key = keys[attempt % n]
        code, body = ve.curl_get(ve.VT_FILES + sha, key, timeout)
        if code in (200, 404):
            return code, body
        # 429 / 401 / 403 / 0(网络) -> 等待后换 Key 再试
        wait = 65 if code == 429 else 10
        print(f'  {sha[:12]} http={code} 第{attempt+1}/{retries}次,等{wait}s换Key重试...', flush=True)
        time.sleep(wait)
    return code, body


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ml_root = os.path.abspath(os.path.join(here, '..'))
    ap = argparse.ArgumentParser()
    ap.add_argument('hashes', nargs='+')
    ap.add_argument('--label', default='malicious')
    ap.add_argument('--out', default=os.path.join(ml_root, 'data', 'vt', 'vt_results.jsonl'))
    ap.add_argument('--timeout', type=int, default=60)
    ap.add_argument('--retries', type=int, default=6)
    args = ap.parse_args()

    keys = ve.load_keys()
    if not keys:
        print('[错误] BULWARK_VT_APIKEY 里没有有效 VT Key'); return

    targets = []
    for h in args.hashes:
        h = h.strip().lower()
        if ve.HEX64.match(h):
            targets.append(h)
        else:
            print('跳过(非 sha256):', h)
    if not targets:
        return
    tset = set(targets)

    man = os.path.join(ml_root, 'data', 'manifests')
    label_map = {}
    for name, lab in (('malicious_manifest.jsonl', 'malicious'),
                      ('script_manifest.jsonl', 'script'),
                      ('benign_manifest.jsonl', 'benign')):
        for sha, _ in ve.manifest_entries(os.path.join(man, name)):
            label_map.setdefault(sha, lab)

    # 1) 查询(带重试),只收权威结果
    new_recs = {}
    for h in targets:
        label = label_map.get(h, args.label)
        code, body = query_with_retry(h, keys, args.timeout, args.retries)
        if code in (200, 404):
            rec = ve.summarize(h, label, code, body, uploaded=False)
            new_recs[h] = rec
            if code == 200:
                print(f'{h}  http=200  label={label}  VT={rec.get("vt_malicious")}/{rec.get("vt_total")}  '
                      f'家族={rec.get("threat_label","")}  tags={rec.get("tags", [])[:6]}')
            else:
                print(f'{h}  http=404  VT 未收录(无本地文件不能上传)')
        else:
            print(f'{h}  最终 http={code}(限流/鉴权失败)—— 不写入,稍后可重跑')

    if not new_recs:
        print('\n没有拿到权威结果,vt_results.jsonl 未改动。'); return

    # 2) 重写 vt_results.jsonl:删掉这些 hash 的旧记录,追加新记录(原子替换)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    kept = 0
    fd, tmp = tempfile.mkstemp(prefix='vt_', suffix='.jsonl', dir=os.path.dirname(os.path.abspath(args.out)))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as w:
            if os.path.isfile(args.out):
                with open(args.out, encoding='utf-8-sig', errors='ignore') as f:
                    for line in f:
                        s = line.strip()
                        if not s:
                            continue
                        m = SHA_RE.search(s)
                        if m and m.group(1).lower() in tset:
                            continue  # 丢弃旧记录(含之前的 429)
                        w.write(line if line.endswith('\n') else line + '\n')
                        kept += 1
            for h, rec in new_recs.items():
                w.write(json.dumps(rec, ensure_ascii=False) + '\n')
        os.replace(tmp, args.out)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    print(f'\n完成:保留旧记录 {kept} 条 + 写入 {len(new_recs)} 条 -> {args.out}')


if __name__ == '__main__':
    main()
