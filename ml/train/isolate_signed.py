#!/usr/bin/env python3
"""
清洗恶意 PE 语料：把"被恶意安装包/压缩包捆绑进来的【合法依赖库】"隔离出去(容器解包副作用)，
否则模型会对正经软件误报。

【关键】银狐(Silver Fox/ValleyRAT)等大量借用【真实/被盗签名】和【被滥用的合法远控工具】
(ConnectWise/ScreenConnect/AnyDesk/向日葵/ToDesk/NetSupport…)，所以"有效签名"绝不等于良性。
因此只隔离【签名者属于纯运行时/系统/硬件厂商白名单】的；被滥用远控 + 不认识的签名者一律【保留】
(它们可能就是借合法签名的银狐)，并写入 review 供人工看。VT 已确认恶意的也一律保留。

两阶段：
  verify(默认): 扫带签名候选 -> Get-AuthenticodeSignature 拿 Status+签名者 ->
                白名单命中且非VT确认 -> _isolate_sha.txt；被滥用/不认识 -> _review_signed.txt。
  --apply     : 读 _isolate_sha.txt -> 从 malicious_manifest 移到 review(先备份)。
只读文件头/验证签名，绝不执行。
"""
import argparse
import collections
import datetime
import json
import os
import re
import shutil
import struct
import subprocess

HEX64 = re.compile(r'^[0-9a-fA-F]{64}$')

# 纯运行时/系统/硬件/库 厂商：其签名文件被捆进安装包 => 几乎必是合法依赖，可安全隔离。
RUNTIME_VENDORS = [
    'microsoft corporation', 'microsoft windows', '.net', 'python software foundation',
    'intel corporation', 'intel(r)', 'nvidia', 'advanced micro devices', 'adobe',
    'the qt company', 'qt company', 'videolan', 'google llc', 'mozilla corporation',
    'oracle america', 'oracle corporation', 'realtek', 'logitech', 'dell inc',
    'hewlett-packard', 'hewlett packard', 'hp inc', 'lenovo', 'igor pavlov', 'kitware',
    'apple inc', 'nullsoft', 'wireshark', 'khronos', 'gnu', 'the git development',
    'blender foundation', 'the document foundation', 'audacity', 'gimp', 'notepad++',
]
# 被银狐等滥用的远控/双用途工具：即便有效签名也可能是恶意 => 绝不自动隔离。
ABUSED_TOOLS = [
    'connectwise', 'screenconnect', 'anydesk', 'teamviewer', 'rustdesk', 'ammyy',
    'gotoassist', 'remote utilities', 'atera', 'splashtop', 'ultraviewer', 'todesk',
    'sunlogin', 'oray', 'netsupport', 'radmin', 'dwservice', 'gotohttp', 'aweray',
]


def signer_bucket(subject):
    s = (subject or '').lower()
    if not s:
        return 'review-unsigned-cn'
    if any(a in s for a in ABUSED_TOOLS):
        return 'review-abused'
    if any(v in s for v in RUNTIME_VENDORS):
        return 'isolate'
    return 'review-unknown'


def signer_cn(subject):
    m = re.search(r'CN=("?)([^",]+)', subject or '')
    return (m.group(2).strip() if m else (subject or '')[:40])


def is_signed(path):
    try:
        with open(path, 'rb') as f:
            head = f.read(4096)
    except Exception:
        return None
    if len(head) < 0x40 or head[:2] != b'MZ':
        return None
    try:
        e = struct.unpack_from('<I', head, 0x3C)[0]
        if e + 0x78 > len(head) or head[e:e + 4] != b'PE\x00\x00':
            return None
        magic = struct.unpack_from('<H', head, e + 24)[0]
        dd = e + 24 + (112 if magic == 0x20b else 96)
        so = dd + 32
        if so + 8 > len(head):
            return None
        return struct.unpack_from('<I', head, so + 4)[0] > 0
    except Exception:
        return None


def load_vt_conf(path, vt_min):
    conf = set()
    if os.path.isfile(path):
        with open(path, encoding='utf-8-sig', errors='ignore') as f:
            for line in f:
                try:
                    o = json.loads(line)
                except Exception:
                    continue
                sha = str(o.get('sha256', '')).lower()
                if HEX64.match(sha) and o.get('found') and int(o.get('vt_malicious', 0) or 0) >= vt_min:
                    conf.add(sha)
    return conf


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    default_root = os.path.abspath(os.path.join(here, '..'))
    ap = argparse.ArgumentParser()
    ap.add_argument('--ml-root', default=default_root)
    ap.add_argument('--vt-min', type=int, default=5)
    ap.add_argument('--apply', action='store_true')
    args = ap.parse_args()

    man_dir = os.path.join(args.ml_root, 'data', 'manifests')
    manifest = os.path.join(man_dir, 'malicious_manifest.jsonl')
    review = os.path.join(man_dir, 'malicious_signed_review.jsonl')
    isolate_list = os.path.join(here, '_isolate_sha.txt')
    review_list = os.path.join(here, '_review_signed.txt')

    # ---------------- APPLY ----------------
    if args.apply:
        if not os.path.isfile(isolate_list):
            print('缺少 _isolate_sha.txt，请先跑 verify'); return
        drop = {s.strip().lower() for s in open(isolate_list, encoding='utf-8') if HEX64.match(s.strip().lower())}
        if not drop:
            print('待隔离为空'); return
        keep, iso = [], []
        with open(manifest, encoding='utf-8-sig', errors='ignore') as f:
            for line in f:
                s = line.strip()
                if not s:
                    continue
                m = re.search(r'"sha256"\s*:\s*"([0-9a-fA-F]{64})"', s)
                (iso if (m and m.group(1).lower() in drop) else keep).append(s)
        ts = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
        shutil.copy2(manifest, f'{manifest}.bak.{ts}')
        with open(review, 'a', encoding='utf-8') as f:
            f.write('\n'.join(iso) + ('\n' if iso else ''))
        with open(manifest, 'w', encoding='utf-8') as f:
            f.write('\n'.join(keep) + ('\n' if keep else ''))
        print(f'已隔离 {len(iso)} -> {review}\n恶意 manifest: {len(keep)+len(iso)} -> {len(keep)} (备份 .bak.{ts})')
        return

    # ---------------- VERIFY ----------------
    vt_conf = load_vt_conf(os.path.join(args.ml_root, 'data', 'vt', 'vt_results.jsonl'), args.vt_min)
    print(f'VT 已确认恶意(保护): {len(vt_conf)}')

    cand = []
    n = 0
    with open(manifest, encoding='utf-8-sig', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            sha = str(rec.get('sha256', '')).lower()
            path = rec.get('raw_path', '')
            if not HEX64.match(sha) or not path:
                continue
            n += 1
            if n % 5000 == 0:
                print(f'  扫描 {n}... 带签名候选 {len(cand)}')
            if os.path.isfile(path) and is_signed(path):
                cand.append((sha, path))
    print(f'带签名候选: {len(cand)}，开始 Authenticode 验证 + 签名者判定...')
    if not cand:
        return

    listfile = os.path.join(here, '_sig_paths.txt')
    with open(listfile, 'w', encoding='utf-8') as f:
        for _s, p in cand:
            f.write(p + '\n')
    path2sha = {p: s for s, p in cand}

    ps = ("Get-Content -LiteralPath '" + listfile + "' -Encoding UTF8 | ForEach-Object { "
          "$s=Get-AuthenticodeSignature -LiteralPath $_; "
          "$subj= if($s.SignerCertificate){$s.SignerCertificate.Subject}else{''}; "
          "Write-Output (\"{0}`t{1}`t{2}\" -f $s.Status,$subj,$_) }")
    proc = subprocess.run(['powershell', '-NoProfile', '-Command', ps],
                          capture_output=True, text=True, encoding='utf-8', errors='ignore', timeout=5400)

    status_ctr = collections.Counter()
    bucket_ctr = collections.Counter()
    iso_shas = []
    protected = 0
    iso_signers = collections.Counter()
    abused_signers = collections.Counter()
    unknown_signers = collections.Counter()
    review_rows = []
    for line in (proc.stdout or '').splitlines():
        parts = line.split('\t')
        if len(parts) < 3:
            continue
        status = parts[0].strip()
        path = parts[-1].strip()
        subject = '\t'.join(parts[1:-1]).strip()
        status_ctr[status] += 1
        if status != 'Valid':
            continue
        sha = path2sha.get(path)
        if not sha:
            continue
        if sha in vt_conf:
            protected += 1
            continue
        b = signer_bucket(subject)
        bucket_ctr[b] += 1
        cn = signer_cn(subject)
        if b == 'isolate':
            iso_shas.append(sha); iso_signers[cn] += 1
        else:
            review_rows.append(f'{sha}\t{b}\t{cn}')
            (abused_signers if b == 'review-abused' else unknown_signers)[cn] += 1

    with open(isolate_list, 'w', encoding='utf-8') as f:
        f.write('\n'.join(iso_shas) + ('\n' if iso_shas else ''))
    with open(review_list, 'w', encoding='utf-8') as f:
        f.write('\n'.join(review_rows) + ('\n' if review_rows else ''))

    total = sum(status_ctr.values())
    print(f'\n================ 验证 + 签名者判定({total} 带签名) ================')
    for st, c in status_ctr.most_common():
        print(f'  签名状态 {st:<14} {c:>5}')
    print(f'\n有效签名中:')
    print(f'  [隔离] 纯运行时/系统厂商        : {bucket_ctr.get("isolate",0)}  -> _isolate_sha.txt')
    print(f'  [保留] 被滥用远控(疑银狐)        : {bucket_ctr.get("review-abused",0)}')
    print(f'  [保留] 不认识的签名者(疑盗证书)  : {bucket_ctr.get("review-unknown",0)}')
    print(f'  [保留] VT 已确认恶意             : {protected}')
    if iso_signers:
        print('\n可安全隔离的签名者 Top:')
        for cn, c in iso_signers.most_common(15):
            print(f'  {c:>4}  {cn}')
    if abused_signers:
        print('\n[!] 保留的"被滥用远控"签名者(高度疑似银狐, 人工重点看):')
        for cn, c in abused_signers.most_common(15):
            print(f'  {c:>4}  {cn}')
    if unknown_signers:
        print('\n[?] 保留的"不认识"签名者 Top(可能盗证书/也可能小厂合法):')
        for cn, c in unknown_signers.most_common(20):
            print(f'  {c:>4}  {cn}')
    print(f'\n待隔离 {len(iso_shas)}，保留待复核 {len(review_rows)} (-> _review_signed.txt)')
    print('下一步: 加 --apply 执行隔离。')


if __name__ == '__main__':
    main()
