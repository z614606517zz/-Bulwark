#!/usr/bin/env python3
"""
抽检【混合样本】(恶意PE/良性PE/脚本/安装包/文档)走 VirusTotal 拿【完整报告】，
保存到 ml/data/vt/vt_results.jsonl。用途：清洗语料、补家族标签、核对良性、喂行为引擎。

Key 来源：环境变量 BULWARK_VT_APIKEY（可多 Key 逗号分隔，KEY 或 KEY:每日:每分钟）。只读、绝不打印。
网络：经系统 curl.exe 调 VT v3。限流：多 Key 轮询 ~4/min/Key；429 冷却 60s、401/403 冷却 6h、自动换 Key。
未收录(404)可选【上传文件扫描】：POST /files -> 轮询 /analyses/<id> 完成 -> 再拉完整报告。
  - 默认只上传"恶意侧"(恶意/脚本/安装包/文档/压缩包)，不上传良性(避免把你环境里的干净文件传到公网)。
  - 上传很耗配额(1 传 + 多次轮询)，用 --max-uploads 封顶；>32MB 跳过(免费档直传上限)。
可断点续跑(跳过已查 sha)。
"""
import argparse
import datetime
import json
import os
import random
import re
import subprocess
import time

HEX64 = re.compile(r'^[0-9a-fA-F]{64}$')
VT_FILES = 'https://www.virustotal.com/api/v3/files/'
VT_UPLOAD = 'https://www.virustotal.com/api/v3/files'
VT_ANALYSES = 'https://www.virustotal.com/api/v3/analyses/'

INSTALLER_EXTS = {'.msi', '.msix', '.appx', '.msixbundle', '.appxbundle', '.msp'}
DOC_EXTS = {'.doc', '.docx', '.docm', '.xls', '.xlsx', '.xlsm', '.ppt', '.pptx', '.pptm',
            '.pdf', '.rtf', '.one', '.pub', '.vsd'}
ARCHIVE_EXTS = {'.zip', '.rar', '.7z', '.iso', '.cab', '.gz', '.tar', '.img', '.lzh'}
UPLOAD_LABELS = {'malicious', 'script', 'installer', 'document', 'archive'}  # 默认可上传的(非良性)


def load_keys():
    raw = os.environ.get('BULWARK_VT_APIKEY', '').strip()
    keys, seen = [], set()
    for entry in raw.split(','):
        k = entry.split(':')[0].strip()
        if HEX64.match(k) and k not in seen:
            seen.add(k); keys.append(k)
    return keys


def iso(epoch):
    try:
        if epoch:
            return datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc).isoformat()
    except Exception:
        pass
    return ''


def manifest_entries(path):
    """返回 [(sha, local_path)]；local_path 取 raw_path/src_path(可上传)，没有则空串。"""
    out = []
    if not os.path.isfile(path):
        return out
    with open(path, encoding='utf-8-sig', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                m = re.search(r'"sha256"\s*:\s*"([0-9a-fA-F]{64})"', line)
                if m:
                    out.append((m.group(1).lower(), ''))
                continue
            sha = str(rec.get('sha256', '')).lower()
            if not HEX64.match(sha):
                continue
            p = rec.get('raw_path') or rec.get('src_path') or ''
            out.append((sha, p if (p and os.path.isfile(p)) else ''))
    return out


def scan_dir(root, exts):
    """扫目录取 <sha>.<ext> 文件，返回 [(sha, path)]。"""
    out = []
    try:
        with os.scandir(root) as it:
            for e in it:
                try:
                    if not e.is_file(follow_symlinks=False):
                        continue
                    stem, ext = os.path.splitext(e.name)
                    if ext.lower() in exts and HEX64.match(stem):
                        out.append((stem.lower(), e.path))
                except OSError:
                    continue
    except OSError:
        pass
    return out


def result_shas(path):
    s = set()
    if os.path.isfile(path):
        with open(path, encoding='utf-8-sig', errors='ignore') as f:
            for line in f:
                m = re.search(r'"sha256"\s*:\s*"([0-9a-fA-F]{64})"', line)
                if m:
                    s.add(m.group(1).lower())
    return s


def curl_get(url, key, timeout):
    try:
        p = subprocess.run(
            ['curl.exe', '-s', '-m', str(timeout), '-H', f'x-apikey: {key}', '-w', '\n%{http_code}', url],
            capture_output=True, text=True, encoding='utf-8', errors='ignore', timeout=timeout + 15)
        out = p.stdout or ''
        idx = out.rfind('\n')
        if idx < 0:
            return (0, out)
        try:
            code = int(out[idx + 1:].strip())
        except ValueError:
            code = 0
        return (code, out[:idx])
    except Exception:
        return (0, '')


def vt_upload(path, key, timeout):
    """上传文件，返回 analysis_id 或 None。"""
    try:
        p = subprocess.run(
            ['curl.exe', '-s', '-m', str(timeout), '-X', 'POST', '-H', f'x-apikey: {key}',
             '-F', f'file=@{path}', '-w', '\n%{http_code}', VT_UPLOAD],
            capture_output=True, text=True, encoding='utf-8', errors='ignore', timeout=timeout + 30)
        out = p.stdout or ''
        idx = out.rfind('\n')
        if idx < 0:
            return (0, None)
        try:
            code = int(out[idx + 1:].strip())
        except ValueError:
            code = 0
        if code != 200:
            return (code, None)
        aid = json.loads(out[:idx]).get('data', {}).get('id')
        return (code, aid)
    except Exception:
        return (0, None)


def vt_poll(analysis_id, key, timeout, next_key, sleep_fn, max_wait=180):
    """轮询分析完成(每 ~15s，最多 max_wait 秒)。返回 True/False。"""
    deadline = time.time() + max_wait
    while time.time() < deadline:
        sleep_fn(15)
        k = next_key() or key
        code, body = curl_get(VT_ANALYSES + analysis_id, k, timeout)
        if code == 200:
            try:
                st = json.loads(body).get('data', {}).get('attributes', {}).get('status', '')
            except Exception:
                st = ''
            if st == 'completed':
                return True
    return False


def summarize(sha, label, code, body, uploaded=False):
    rec = {'sha256': sha, 'manifest_label': label, 'http': code, 'found': (code == 200),
           'uploaded': uploaded, 'queried_at': datetime.datetime.now(datetime.timezone.utc).isoformat()}
    if code != 200:
        return rec
    try:
        attr = json.loads(body).get('data', {}).get('attributes', {})
    except Exception:
        rec['parse_error'] = True
        return rec
    stats = attr.get('last_analysis_stats', {}) or {}
    mal = int(stats.get('malicious', 0)); susp = int(stats.get('suspicious', 0))
    total = sum(int(v) for v in stats.values()) if stats else 0
    ptc = attr.get('popular_threat_classification', {}) or {}
    rec.update({
        'vt_malicious': mal, 'vt_suspicious': susp, 'vt_total': total,
        'vt_ratio': round(mal / total, 4) if total else 0.0,
        'threat_label': ptc.get('suggested_threat_label') or attr.get('suggested_threat_label', ''),
        'threat_categories': [c.get('value') for c in ptc.get('popular_threat_category', [])],
        'threat_names': [n.get('value') for n in ptc.get('popular_threat_name', [])],
        'first_submission': iso(attr.get('first_submission_date')),
        'last_analysis': iso(attr.get('last_analysis_date')),
        'times_submitted': attr.get('times_submitted'),
        'reputation': attr.get('reputation'),
        'type_description': attr.get('type_description', ''),
        'type_tags': attr.get('type_tags', []),
        'tags': attr.get('tags', []),
        'names': (attr.get('names') or [])[:10],
        'meaningful_name': attr.get('meaningful_name', ''),
        'size': attr.get('size'),
        'signed': bool(attr.get('signature_info')),
        'signature_info': attr.get('signature_info', {}),
        'attributes': attr,   # 完整数据(含每引擎结果 + 行为线索)
    })
    return rec


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    default_root = os.path.abspath(os.path.join(here, '..'))
    ap = argparse.ArgumentParser()
    ap.add_argument('--ml-root', default=default_root)
    ap.add_argument('--sample-dir', default='', help='安装包/文档 的散装目录(留空读 _maldir.txt)')
    ap.add_argument('--n-malicious', type=int, default=400)
    ap.add_argument('--n-benign', type=int, default=200)
    ap.add_argument('--n-script', type=int, default=150)
    ap.add_argument('--n-installer', type=int, default=150)
    ap.add_argument('--n-doc', type=int, default=100)
    ap.add_argument('--n-archive', type=int, default=0)
    ap.add_argument('--out', default='')
    ap.add_argument('--timeout', type=int, default=60)
    ap.add_argument('--seed', type=int, default=0)
    ap.add_argument('--rpm-per-key', type=float, default=3.6)
    ap.add_argument('--upload', action='store_true', default=True, help='404 时上传文件扫描(默认开)')
    ap.add_argument('--no-upload', dest='upload', action='store_false')
    ap.add_argument('--upload-benign', action='store_true', help='也上传良性 404(默认不传，避免公网泄露)')
    ap.add_argument('--max-uploads', type=int, default=25, help='最多上传多少个(耗配额，封顶)')
    ap.add_argument('--upload-max-mb', type=int, default=32)
    ap.add_argument('--upload-labels', default='malicious,script,installer,document,archive',
                    help='只对这些标签的未收录(404)样本上传(逗号分隔;默认全部非良性)。如 --upload-labels installer')
    args = ap.parse_args()
    upload_labels = {x.strip().lower() for x in args.upload_labels.split(',') if x.strip()}

    keys = load_keys()
    if not keys:
        print('[错误] BULWARK_VT_APIKEY 里没有有效 VT Key'); return
    interval = max(1.0, 60.0 / (args.rpm_per_key * len(keys)))
    print(f'VT Key 数: {len(keys)}  间隔 {interval:.2f}s/次  上传={args.upload}(封顶 {args.max_uploads}, 仅对 {sorted(upload_labels)})')

    if not args.sample_dir:
        sc = os.path.join(here, '_maldir.txt')
        if os.path.isfile(sc):
            with open(sc, encoding='utf-8-sig') as f:
                args.sample_dir = f.read().strip()

    man = os.path.join(args.ml_root, 'data', 'manifests')
    out = args.out or os.path.join(args.ml_root, 'data', 'vt', 'vt_results.jsonl')
    os.makedirs(os.path.dirname(out), exist_ok=True)
    done = result_shas(out)
    if done:
        print(f'已存在结果 {len(done)} 条，续查跳过')

    def take(entries, n):
        random.Random(args.seed or time.time_ns()).shuffle(entries)
        picked, seen = [], set()
        for sha, p in entries:
            if sha in done or sha in seen:
                continue
            seen.add(sha); picked.append((sha, p))
            if len(picked) >= n:
                break
        return picked

    groups = []
    groups += [(s, 'malicious', p) for s, p in take(manifest_entries(os.path.join(man, 'malicious_manifest.jsonl')), args.n_malicious)]
    groups += [(s, 'benign', p) for s, p in take(manifest_entries(os.path.join(man, 'benign_manifest.jsonl')), args.n_benign)]
    groups += [(s, 'script', p) for s, p in take(manifest_entries(os.path.join(man, 'script_manifest.jsonl')), args.n_script)]
    if args.sample_dir and os.path.isdir(args.sample_dir):
        groups += [(s, 'installer', p) for s, p in take(scan_dir(args.sample_dir, INSTALLER_EXTS), args.n_installer)]
        groups += [(s, 'document', p) for s, p in take(scan_dir(args.sample_dir, DOC_EXTS), args.n_doc)]
        if args.n_archive:
            groups += [(s, 'archive', p) for s, p in take(scan_dir(args.sample_dir, ARCHIVE_EXTS), args.n_archive)]
    random.Random((args.seed or 1) + 7).shuffle(groups)
    from collections import Counter
    cnt = Counter(l for _, l, _ in groups)
    print(f'本次混合抽样 {len(groups)}: ' + ', '.join(f'{k}={v}' for k, v in cnt.items()))
    if not groups:
        print('没有可查样本'); return

    cooldown = {}; ki = [0]
    ok = notfound = auth = rate = err = uploaded_ok = uploaded_fail = 0
    low_conf, mislabeled = [], []

    def next_key():
        now = time.time()
        for _ in range(len(keys)):
            k = keys[ki[0] % len(keys)]; ki[0] += 1
            if cooldown.get(k, 0) <= now:
                return k
        return None

    def note(code, key):
        if code == 429:
            cooldown[key] = time.time() + 60
        elif code in (401, 403):
            cooldown[key] = time.time() + 6 * 3600

    uploads_used = 0
    w = open(out, 'a', encoding='utf-8')
    try:
        for i, (sha, label, path) in enumerate(groups):
            key = next_key()
            if key is None:
                print('所有 Key 冷却中，等 60s...'); time.sleep(60); key = next_key()
                if key is None:
                    print('无可用 Key，停止(可续跑)'); break
            code, body = curl_get(VT_FILES + sha, key, args.timeout)
            note(code, key)
            if code in (429, 401, 403):
                k2 = next_key()
                if k2:
                    code, body = curl_get(VT_FILES + sha, k2, args.timeout); note(code, k2)
            was_uploaded = False

            # 未收录 -> 上传扫描
            if (code == 404 and args.upload and path and uploads_used < args.max_uploads
                    and label in upload_labels
                    and (label != 'benign' or args.upload_benign)):
                try:
                    sz_mb = os.path.getsize(path) / 1024 / 1024
                except OSError:
                    sz_mb = 1e9
                if sz_mb <= args.upload_max_mb:
                    ukey = next_key() or key
                    ucode, aid = vt_upload(path, ukey, args.timeout); note(ucode, ukey)
                    uploads_used += 1
                    if aid:
                        vt_poll(aid, ukey, args.timeout, next_key, time.sleep, max_wait=180)
                        rk = next_key() or key
                        code, body = curl_get(VT_FILES + sha, rk, args.timeout); note(code, rk)
                        was_uploaded = True
                        if code == 200:
                            uploaded_ok += 1
                        else:
                            uploaded_fail += 1
                    else:
                        uploaded_fail += 1

            rec = summarize(sha, label, code, body, uploaded=was_uploaded)
            w.write(json.dumps(rec, ensure_ascii=False) + '\n')
            if code == 200:
                ok += 1
                if label in ('malicious', 'script', 'installer', 'document') and rec.get('vt_total', 0) and rec['vt_malicious'] < 5:
                    low_conf.append((label, sha, rec['vt_malicious'], rec['vt_total']))
                if label == 'benign' and rec.get('vt_malicious', 0) >= 3:
                    mislabeled.append((sha, rec['vt_malicious'], rec['vt_total']))
            elif code == 404:
                notfound += 1
            elif code in (401, 403):
                auth += 1
            elif code == 429:
                rate += 1
            else:
                err += 1
            if (i + 1) % 20 == 0:
                w.flush()
                print(f'  [{i+1}/{len(groups)}] ok={ok} 未收录={notfound} 上传成功={uploaded_ok} 限流={rate} 其它={err}')
            time.sleep(interval)
    finally:
        w.flush(); w.close()

    print('\n================ VT 混合抽检完成 ================')
    print(f'成功 200        : {ok}')
    print(f'未收录 404      : {notfound}')
    print(f'  其中上传后拿到: {uploaded_ok}   上传失败/未完成: {uploaded_fail}')
    print(f'限流 429        : {rate}   鉴权失败 401/3: {auth}   其它: {err}')
    print(f'结果文件        : {out}')
    if low_conf:
        print(f'\n[清洗提示] {len(low_conf)} 个"恶意侧"样本 VT 检出 <5（疑似灰色/误标）:')
        for lb, sha, m, t in low_conf[:20]:
            print(f'  [{lb}] {sha[:16]}  {m}/{t}')
    if mislabeled:
        print(f'\n[警告] {len(mislabeled)} 个"良性"被 >=3 引擎报毒（疑似标签污染）:')
        for sha, m, t in mislabeled[:20]:
            print(f'  {sha[:16]}  {m}/{t}')


if __name__ == '__main__':
    main()
