#!/usr/bin/env python3
"""
用 MalwareBazaar(abuse.ch) 批量富集威胁语料 —— 不依赖 VT。

为什么用它:本语料本来就是从 MalwareBazaar 收的,所以 get_info 按 hash 查几乎 100% 命中,
免费(需 Auth-Key)、额度比 VT 宽松得多,能在几小时内把整个 3.3 万恶意语料"确认+打标"。
返回里含 signature(家族)、tags、file_type、以及 vendor_intel(Triage/CAPE 等沙箱情报:C2、
释放文件、ATT&CK 等)—— 既是标签也是行为特征来源,和 VT 的 sandbox_verdicts 互补。

对齐 C++ MalwareBazaarClient:POST query=get_info&hash=<sha>, 头 Auth-Key。query_status=ok => 恶意。

产物:ml/data/vt/mb_results.jsonl(每行一条,含完整 data[0] 于 "mb");可续跑、按 sha 去重。
只查,不上传、不执行样本。仅 stdlib(urllib)。
"""
import argparse
import datetime
import json
import os
import sys
import time
import urllib.request
import urllib.parse
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vt_enrich as ve  # 复用 manifest_entries / scan_dir / result_shas / take / *_EXTS

MB_URL = 'https://mb-api.abuse.ch/api/v1/'
UA = 'Bulwark-mb-enrich/1.0'


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def mb_query(sha, auth_key, timeout):
    """返回 (http_code, parsed_json_or_None)。"""
    data = urllib.parse.urlencode({'query': 'get_info', 'hash': sha}).encode()
    req = urllib.request.Request(MB_URL, data=data,
                                 headers={'Auth-Key': auth_key, 'User-Agent': UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode('utf-8', 'ignore')
            code = resp.status
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception:
        return 0, None
    try:
        return code, json.loads(raw)
    except Exception:
        return code, None


def to_record(sha, obj):
    """MB 响应 -> 落盘记录(小写字段;保留完整 data[0] 于 mb)。"""
    rec = {'sha256': sha, 'source': 'MalwareBazaar', 'queried_at': now_iso(),
           'http': 200, 'query_status': None, 'verdict': 'unknown',
           'signature': '', 'file_type': '', 'tags': [], 'vendor_count': 0}
    status = (obj or {}).get('query_status', '')
    rec['query_status'] = status
    if status == 'ok':
        data = obj.get('data') or []
        if data and isinstance(data[0], dict):
            d = data[0]
            rec['verdict'] = 'malicious'          # MB 命中即恶意(与 C++ 一致)
            rec['signature'] = d.get('signature') or ''
            rec['file_type'] = d.get('file_type') or ''
            rec['tags'] = d.get('tags') or []
            vi = d.get('vendor_intel') or {}
            rec['vendor_count'] = len(vi) if isinstance(vi, dict) else 0
            rec['mb'] = d                          # 完整明细(含 vendor_intel/沙箱情报)
    return rec


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ml_root = os.path.abspath(os.path.join(here, '..'))
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', default=os.path.join(ml_root, 'data', 'vt', 'mb_results.jsonl'))
    ap.add_argument('--sample-dir', default='')
    ap.add_argument('--n-malicious', type=int, default=100000)
    ap.add_argument('--n-script', type=int, default=100000)
    ap.add_argument('--n-installer', type=int, default=100000)
    ap.add_argument('--n-doc', type=int, default=100000)
    ap.add_argument('--n-archive', type=int, default=100000)
    ap.add_argument('--rpm', type=float, default=60.0, help='每分钟请求数(默认60=1/秒;429会自动退避)')
    ap.add_argument('--timeout', type=int, default=15)
    args = ap.parse_args()

    auth = os.environ.get('BULWARK_MB_AUTHKEY', '').strip()
    if not auth:
        print('[错误] 未设置 BULWARK_MB_AUTHKEY(MalwareBazaar Auth-Key)'); return

    if not args.sample_dir:
        sc = os.path.join(here, '_maldir.txt')
        if os.path.isfile(sc):
            args.sample_dir = open(sc, encoding='utf-8-sig').read().strip()

    man = os.path.join(ml_root, 'data', 'manifests')
    done = ve.result_shas(args.out)
    print(f'MB 富集 | 已有结果 {len(done)} 条,续查跳过 | Auth-Key len={len(auth)} | rpm={args.rpm}')

    # 组装待查(威胁向:恶意/脚本/安装包/文档/压缩包),按 sha 去重且跳过已查
    groups = [
        ('malicious', ve.manifest_entries(os.path.join(man, 'malicious_manifest.jsonl')), args.n_malicious),
        ('script',    ve.manifest_entries(os.path.join(man, 'script_manifest.jsonl')),    args.n_script),
    ]
    if args.sample_dir and os.path.isdir(args.sample_dir):
        groups += [
            ('installer', ve.scan_dir(args.sample_dir, ve.INSTALLER_EXTS), args.n_installer),
            ('document',  ve.scan_dir(args.sample_dir, ve.DOC_EXTS),       args.n_doc),
            ('archive',   ve.scan_dir(args.sample_dir, ve.ARCHIVE_EXTS),   args.n_archive),
        ]
    todo, seen = [], set(done)
    counts = {}
    for label, entries, cap in groups:
        picked = 0
        for sha, _path in entries:
            if picked >= cap:
                break
            sha = str(sha).lower()
            if len(sha) != 64 or sha in seen:
                continue
            seen.add(sha); todo.append((label, sha)); picked += 1
        counts[label] = picked
    print(f'待查 {len(todo)}: ' + ', '.join(f'{k}={v}' for k, v in counts.items()))
    if not todo:
        print('没有新样本要查(可能都查过了)。'); return

    interval = 60.0 / max(args.rpm, 1.0)
    ok = miss = err = 0
    out_f = open(args.out, 'a', encoding='utf-8')
    try:
        for i, (label, sha) in enumerate(todo, 1):
            t0 = time.time()
            code, obj = mb_query(sha, auth, args.timeout)
            if code == 429:
                out_f.flush(); time.sleep(60); code, obj = mb_query(sha, auth, args.timeout)
            if code == 200 and obj is not None:
                rec = to_record(sha, obj)
                rec['manifest_label'] = label
                out_f.write(json.dumps(rec, ensure_ascii=False) + '\n')
                if rec['query_status'] == 'ok':
                    ok += 1
                else:
                    miss += 1
            else:
                err += 1
            if i % 100 == 0:
                out_f.flush()
                print(f'  [{i}/{len(todo)}] 命中={ok} 未收录={miss} 错误/限流={err}', flush=True)
            dt = time.time() - t0
            if dt < interval:
                time.sleep(interval - dt)
    finally:
        out_f.flush(); out_f.close()

    print('\n================ MalwareBazaar 富集完成 ================')
    print(f'命中(恶意) {ok}  未收录 {miss}  错误 {err}  -> {args.out}')


if __name__ == '__main__':
    main()
