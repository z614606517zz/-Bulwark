#!/usr/bin/env python3
"""
批量摄取 MalwareBazaar 每日全量包(daily/*.zip，密码 infected）。

对下载目录里的每个 zip：
  逐条流式读取 -> 只保留【真 PE】(MZ + PE 头) -> SHA-256 去重(跨已有 manifest)
  -> 裸样本写入 ml/data/malicious/raw/<前2位>/<sha256> + 追加 malicious_manifest.jsonl
  -> 处理完该 zip 后【删除压缩包】(默认，省磁盘；--keep-zip 可保留)

特点：
  - 不整体解压，只把 PE 落地；非 PE(脚本/文档/elf/apk 等)直接丢弃，省磁盘。
  - 与 Collect-MalwareBazaar / Import-LocalMalware 共用 manifest，统一去重、可反复续跑。
  - 只读取样本，绝不执行。
  - 下载不完整/损坏的 zip 会跳过且【不删除】，便于重下。

用法：
  .venv\\Scripts\\python ingest_daily_batches.py --zip-dir D:\\mb_daily
  .venv\\Scripts\\python ingest_daily_batches.py --zip-dir D:\\mb_daily --keep-zip
  .venv\\Scripts\\python ingest_daily_batches.py --zip-dir D:\\mb_daily --max-total 20000
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import zipfile

DATE_RE = re.compile(r'(\d{4}-\d{2}-\d{2})')
PW = b'infected'


def is_pe(data: bytes) -> bool:
    if len(data) < 0x40 or data[:2] != b'MZ':
        return False
    try:
        e = int.from_bytes(data[0x3C:0x40], 'little')
        return 0 < e and e + 4 <= len(data) and data[e:e + 4] == b'PE\x00\x00'
    except Exception:
        return False


def load_seen(manifest_path):
    seen = set()
    if os.path.isfile(manifest_path):
        with open(manifest_path, 'r', encoding='utf-8-sig', errors='ignore') as f:
            for line in f:
                m = re.search(r'"sha256"\s*:\s*"([0-9a-fA-F]{64})"', line)
                if m:
                    seen.add(m.group(1).lower())
    return seen


def open_batch(path):
    """返回 (zipobj, open_fn, read_all_fn, info_fn, names)；自动在 ZipCrypto / AES 之间选择。
      open_fn(n)     -> 可流式读取的文件对象(只读文件头即可判 PE，省掉整条解密)
      read_all_fn(n) -> 整条读取(流式失败时回退)
      info_fn(n)     -> 该条【解压后】字节数(取自中央目录，无需解密)
    """
    z = zipfile.ZipFile(path)
    names = [n for n in z.namelist() if not n.endswith('/')]
    if names:
        try:
            with z.open(names[0], pwd=PW) as t:
                t.read(16)
            return (z, (lambda n: z.open(n, pwd=PW)), (lambda n: z.read(n, pwd=PW)),
                    (lambda n: z.getinfo(n).file_size), names)
        except Exception:
            z.close()
            import pyzipper
            az = pyzipper.AESZipFile(path)
            az.setpassword(PW)
            names = [n for n in az.namelist() if not n.endswith('/')]
            return (az, (lambda n: az.open(n)), (lambda n: az.read(n)),
                    (lambda n: az.getinfo(n).file_size), names)
    return (z, (lambda n: z.open(n, pwd=PW)), (lambda n: z.read(n, pwd=PW)),
            (lambda n: z.getinfo(n).file_size), names)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    default_root = os.path.abspath(os.path.join(here, '..'))
    ap = argparse.ArgumentParser()
    ap.add_argument('--zip-dir', default='', help='存放已下载 YYYY-MM-DD.zip 的目录(留空则读脚本旁 _zipdir.txt)')
    ap.add_argument('--ml-root', default=default_root)
    ap.add_argument('--keep-zip', action='store_true', help='处理后不删除压缩包(默认删除)')
    ap.add_argument('--min-size', type=int, default=1024)
    ap.add_argument('--max-size', type=int, default=100 * 1024 * 1024)
    ap.add_argument('--max-total', type=int, default=0, help='恶意样本累计达到该数即停(0=不限)')
    ap.add_argument('--max-zips', type=int, default=0, help='最多处理多少个 zip(0=不限，用于快速试跑)')
    args = ap.parse_args()
    if not args.zip_dir:
        sidecar = os.path.join(here, '_zipdir.txt')
        if os.path.isfile(sidecar):
            with open(sidecar, 'r', encoding='utf-8-sig') as f:
                args.zip_dir = f.read().strip()
    if not args.zip_dir or not os.path.isdir(args.zip_dir):
        print(f'[错误] zip-dir 无效: {args.zip_dir!r}(用 --zip-dir 指定,或写入脚本旁 _zipdir.txt)')
        return

    man_dir = os.path.join(args.ml_root, 'data', 'manifests')
    os.makedirs(man_dir, exist_ok=True)
    manifest = os.path.join(man_dir, 'malicious_manifest.jsonl')
    raw_root = os.path.join(args.ml_root, 'data', 'malicious', 'raw')
    os.makedirs(raw_root, exist_ok=True)

    seen = load_seen(manifest)
    base = len(seen)
    print(f'去重基线(已有恶意样本): {base}')

    zips = sorted([f for f in os.listdir(args.zip_dir) if f.lower().endswith('.zip')], reverse=True)
    if not zips:
        print('目录里没有 .zip'); return
    print(f'发现 {len(zips)} 个 zip，开始处理(新到旧)...')

    tot_added = tot_dup = tot_nonpe = tot_err = 0
    zips_done = 0
    stop = False
    mf = open(manifest, 'a', encoding='utf-8')
    try:
        for zf in zips:
            if stop:
                break
            if args.max_zips and zips_done >= args.max_zips:
                print(f'达到 --max-zips {args.max_zips}，停止'); break
            zpath = os.path.join(args.zip_dir, zf)
            dm = DATE_RE.search(zf)
            batch_date = dm.group(1) if dm else ''
            first_seen = (batch_date + ' 00:00:00') if batch_date else ''
            added = dup = nonpe = err = 0
            try:
                z, open_fn, read_all_fn, info_fn, names = open_batch(zpath)
            except Exception as e:
                print(f'[跳过] {zf} 打不开(可能没下完，保留): {type(e).__name__}')
                continue
            try:
                for i, name in enumerate(names):
                    try:
                        # 1) 先用中央目录里的解压后大小过滤，超范围者免解密直接跳过
                        try:
                            fsize = info_fn(name)
                        except Exception:
                            fsize = None
                        if fsize is not None and (fsize < args.min_size or fsize > args.max_size):
                            continue
                        # 2) 只解密前 4KB 文件头；非 MZ 直接判非 PE，省掉整条解密
                        data = None
                        try:
                            with open_fn(name) as fp:
                                head = fp.read(0x1000)
                                if len(head) < 0x40 or head[:2] != b'MZ':
                                    nonpe += 1; continue
                                rest = fp.read(args.max_size + 1)
                            data = head + rest
                        except Exception:
                            data = read_all_fn(name)  # 流式失败则整条读取，保证不漏
                        # 3) 完整校验 + 尺寸兜底
                        if len(data) < args.min_size or len(data) > args.max_size:
                            continue
                        if not is_pe(data):
                            nonpe += 1; continue
                        h = hashlib.sha256(data).hexdigest()
                        if h in seen:
                            dup += 1; continue
                        seen.add(h)
                        sub = os.path.join(raw_root, h[:2])
                        os.makedirs(sub, exist_ok=True)
                        dst = os.path.join(sub, h)
                        if not os.path.exists(dst):
                            with open(dst, 'wb') as out:
                                out.write(data)
                        ext = (os.path.splitext(name)[1][1:] or '').lower()
                        rec = {
                            'sha256': h, 'label': 'malicious', 'size': len(data),
                            'file_type': ext, 'family': '', 'tags': '',
                            'first_seen': first_seen, 'imphash': '',
                            'query_src': 'mb-daily', 'src': 'mb-daily', 'batch': batch_date,
                            'zip_path': '', 'raw_path': dst, 'extracted': True,
                            'collected': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        }
                        mf.write(json.dumps(rec, ensure_ascii=False) + '\n')
                        added += 1
                        if args.max_total and len(seen) >= args.max_total:
                            stop = True; break
                    except Exception:
                        err += 1
                    if (i + 1) % 2000 == 0:
                        print(f'    {zf}: 处理 {i + 1}/{len(names)}  +PE {added}')
            finally:
                z.close()
            mf.flush()
            zips_done += 1
            tot_added += added; tot_dup += dup; tot_nonpe += nonpe; tot_err += err
            print(f'  {zf}: +PE {added}  去重跳过 {dup}  非PE {nonpe}  错 {err}  | 累计恶意 {len(seen)}')
            if not args.keep_zip:
                try:
                    os.remove(zpath)
                    print(f'    已删除压缩包 {zf}')
                except Exception as e:
                    print(f'    [注意] 删除失败 {zf}: {e}')
    finally:
        mf.close()

    print('\n================ 摄取完成 ================')
    print(f'本次新增 PE : {tot_added}')
    print(f'去重跳过    : {tot_dup}')
    print(f'非 PE 丢弃  : {tot_nonpe}')
    print(f'出错        : {tot_err}')
    print(f'恶意样本累计: {len(seen)}  (之前 {base})')
    print(f'manifest    : {manifest}')
    print(f'裸样本目录  : {raw_root}')


if __name__ == '__main__':
    main()
