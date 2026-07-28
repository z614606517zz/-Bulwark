#!/usr/bin/env python3
"""
把 VT 抽检结果(ml/data/vt/vt_results.jsonl)保存进【产品的云信誉缓存】
%ProgramData%\\Bulwark\\reputation.jsonl —— 让本机产品离线即可识别这些哈希的结论。

产物严格对齐当前 C++ 版 FileReputation::toJson / fromJson 的磁盘格式:
  - 【小写键】(sha256/verdict/malicious/totalEngines/threatLabel/source/fetchedUtc/
    lastAnalysisUtc/querySucceeded);紧凑 JSON;每行以 CRLF 结尾;UTF-8 无 BOM。
  - verdict 枚举:0=Unknown 1=Clean 2=Suspicious 3=Malicious。
  - 判级与 VirusTotalClient::parse 一致:
      total = malicious+suspicious+undetected+harmless+timeout+failure+type-unsupported
      malicious >= 阈值(VT 默认 5) -> Malicious;malicious+suspicious >= 1 -> Suspicious;否则 Clean。

合并策略:
  - 只吃 VT 权威命中(http==200)的行;404/限流/错误(无结论)跳过。
  - 与目标文件已有条目【合并去重】:同一 sha 取【更强结论】(Malicious>Suspicious>Clean>Unknown),
    平局取 fetchedUtc 更新的。读取旧文件时【大小写键都认】,顺带把早期 .NET 的
    PascalCase 老条目迁移成当前 C++ 能读的小写格式(否则当前服务读不到它们)。
  - 覆盖写前先把原文件备份成 reputation.jsonl.bak.<时间戳>;先写临时文件再原子替换。

注意:产品仅在【服务启动时】读入该缓存到内存,种入后需重启 Bulwark 服务才会生效。

用法:
  .venv\\Scripts\\python vt_to_reputation.py --dry-run          # 只预览,不写
  .venv\\Scripts\\python vt_to_reputation.py                    # 合并进 %ProgramData%\\Bulwark
  .venv\\Scripts\\python vt_to_reputation.py --malicious-only   # 只种恶意(永久档,最有用)
  .venv\\Scripts\\python vt_to_reputation.py --out D:\\rep.jsonl # 写到别处先检查
"""
import argparse
import datetime
import json
import os
import re
import shutil
import tempfile

HEX64 = re.compile(r'^[0-9a-fA-F]{64}$')

# verdict 枚举(与 cpp/shared/include/bulwark/models/Enums.h::ReputationVerdict 一致)
V_UNKNOWN, V_CLEAN, V_SUSPICIOUS, V_MALICIOUS = 0, 1, 2, 3
VERDICT_NAME = {0: 'unknown', 1: 'clean', 2: 'suspicious', 3: 'malicious'}
MIN_VERDICT = {'clean': V_CLEAN, 'suspicious': V_SUSPICIOUS, 'malicious': V_MALICIOUS}

# last_analysis_stats 里计入 totalEngines 的类别(与 VirusTotalClient::parse 完全一致:
# 注意【不含】confirmed-timeout)。
STAT_KEYS = ('malicious', 'suspicious', 'undetected', 'harmless', 'timeout', 'failure', 'type-unsupported')


def program_data_dir():
    """复刻 service 端 programDataDir():BULWARK_DATA_DIR 覆盖,否则 %ProgramData%\\Bulwark。"""
    d = (os.environ.get('BULWARK_DATA_DIR') or '').strip()
    if not d:
        base = os.environ.get('ProgramData') or r'C:\ProgramData'
        d = os.path.join(base, 'Bulwark')
    return d


def to_iso_ms_z(raw):
    """把任意 ISO 时间串归一化成 Qt dateTimeToIso 的样子:UTC、毫秒精度、'Z' 结尾。
    解析失败返回 None。"""
    if not raw:
        return None
    s = str(raw).strip()
    if not s:
        return None
    # 'Z' -> '+00:00';分数秒截到 6 位(Qt/py 都不喜欢 7 位)。
    if s.endswith('Z') or s.endswith('z'):
        s = s[:-1] + '+00:00'
    m = re.search(r'\.(\d+)', s)
    if m and len(m.group(1)) > 6:
        s = s[:m.start() + 1] + m.group(1)[:6] + s[m.start() + 1 + len(m.group(1)):]
    dt = None
    try:
        dt = datetime.datetime.fromisoformat(s)
    except Exception:
        # 退一步:去掉分数秒再试
        s2 = re.sub(r'\.\d+', '', s)
        try:
            dt = datetime.datetime.fromisoformat(s2)
        except Exception:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    dt = dt.astimezone(datetime.timezone.utc)
    return dt.strftime('%Y-%m-%dT%H:%M:%S.') + f'{dt.microsecond // 1000:03d}Z'


def iso_sort_key(iso_z):
    """把归一化后的 ...Z 串转成可比较的 datetime;无则取最小值。"""
    if not iso_z:
        return datetime.datetime.min.replace(tzinfo=datetime.timezone.utc)
    try:
        return datetime.datetime.fromisoformat(iso_z.replace('Z', '+00:00'))
    except Exception:
        return datetime.datetime.min.replace(tzinfo=datetime.timezone.utc)


def stats_from_vt(rec):
    """返回 (malicious, suspicious, total)。优先用完整 attributes.last_analysis_stats
    重算(与产品口径一致),缺失则回退顶层 vt_* 字段。"""
    attr = rec.get('attributes') or {}
    stats = attr.get('last_analysis_stats') or {}
    if stats:
        def gi(k):
            try:
                return int(stats.get(k, 0) or 0)
            except Exception:
                return 0
        mal = gi('malicious')
        susp = gi('suspicious')
        total = sum(gi(k) for k in STAT_KEYS)
        return mal, susp, total
    # 回退
    try:
        mal = int(rec.get('vt_malicious', 0) or 0)
    except Exception:
        mal = 0
    try:
        susp = int(rec.get('vt_suspicious', 0) or 0)
    except Exception:
        susp = 0
    try:
        total = int(rec.get('vt_total', 0) or 0)
    except Exception:
        total = 0
    return mal, susp, total


def threat_label_from_vt(rec):
    lbl = rec.get('threat_label')
    if isinstance(lbl, str) and lbl.strip():
        return lbl.strip()
    attr = rec.get('attributes') or {}
    v = attr.get('suggested_threat_label')
    if isinstance(v, str) and v.strip():
        return v.strip()
    ptc = attr.get('popular_threat_classification') or {}
    v = ptc.get('suggested_threat_label')
    if isinstance(v, str) and v.strip():
        return v.strip()
    return ''


def last_analysis_from_vt(rec):
    """优先顶层 last_analysis(ISO 串),否则 attributes.last_analysis_date(epoch 秒)。"""
    la = rec.get('last_analysis')
    z = to_iso_ms_z(la) if la else None
    if z:
        return z
    attr = rec.get('attributes') or {}
    epoch = attr.get('last_analysis_date')
    if isinstance(epoch, (int, float)) and epoch > 0:
        dt = datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc)
        return dt.strftime('%Y-%m-%dT%H:%M:%S.') + f'{dt.microsecond // 1000:03d}Z'
    return None


def rep_from_vt(rec, threshold):
    """把一条 VT 结果转成 FileReputation dict(小写键);无结论返回 None。"""
    sha = str(rec.get('sha256', '')).lower()
    if not HEX64.match(sha):
        return None
    if int(rec.get('http', 0) or 0) != 200:
        return None  # 只吃权威命中
    mal, susp, total = stats_from_vt(rec)
    if mal >= threshold:
        verdict = V_MALICIOUS
    elif mal + susp >= 1:
        verdict = V_SUSPICIOUS
    else:
        verdict = V_CLEAN
    fetched = to_iso_ms_z(rec.get('queried_at')) or to_iso_ms_z(
        datetime.datetime.now(datetime.timezone.utc).isoformat())
    return {
        'sha256': sha,
        'verdict': verdict,
        'malicious': mal,
        'totalEngines': total,
        'threatLabel': threat_label_from_vt(rec),
        'source': 'VirusTotal',
        'fetchedUtc': fetched,
        'lastAnalysisUtc': last_analysis_from_vt(rec),
        'querySucceeded': True,
    }


def rep_from_existing(obj):
    """把已有 reputation.jsonl 的一行(键大小写都认)读成 FileReputation dict(小写键)。
    用于合并 + 迁移早期 .NET 的 PascalCase 老条目。"""
    low = {str(k).lower(): v for k, v in obj.items()}
    sha = str(low.get('sha256', '') or '').lower()
    if not HEX64.match(sha):
        return None
    try:
        verdict = int(low.get('verdict', 0) or 0)
    except Exception:
        verdict = 0
    if verdict not in (0, 1, 2, 3):
        verdict = 0
    try:
        mal = int(low.get('malicious', 0) or 0)
    except Exception:
        mal = 0
    try:
        total = int(low.get('totalengines', 0) or 0)
    except Exception:
        total = 0
    lbl = low.get('threatlabel')
    lbl = lbl.strip() if isinstance(lbl, str) else ''
    src = low.get('source')
    src = src.strip() if isinstance(src, str) else ''
    return {
        'sha256': sha,
        'verdict': verdict,
        'malicious': mal,
        'totalEngines': total,
        'threatLabel': lbl,
        'source': src,
        'fetchedUtc': to_iso_ms_z(low.get('fetchedutc')) or to_iso_ms_z(
            datetime.datetime.now(datetime.timezone.utc).isoformat()),
        'lastAnalysisUtc': to_iso_ms_z(low.get('lastanalysisutc')),
        'querySucceeded': bool(low.get('querysucceeded', True)),
    }


def merge_in(pool, rep, stat_key, stats):
    """把 rep 并入 pool(sha->rep):取更强结论,平局取 fetchedUtc 更新的。"""
    sha = rep['sha256']
    old = pool.get(sha)
    if old is None:
        pool[sha] = rep
        stats[stat_key + '_new'] += 1
        return
    if (rep['verdict'] > old['verdict']
            or (rep['verdict'] == old['verdict']
                and iso_sort_key(rep['fetchedUtc']) > iso_sort_key(old['fetchedUtc']))):
        pool[sha] = rep
        stats[stat_key + '_upd'] += 1
    else:
        stats[stat_key + '_kept'] += 1


def dump_line(rep):
    """紧凑 JSON,键序对齐 FileReputation::toJson。"""
    o = {
        'sha256': rep['sha256'],
        'verdict': rep['verdict'],
        'malicious': rep['malicious'],
        'totalEngines': rep['totalEngines'],
        'threatLabel': rep['threatLabel'],
        'source': rep['source'],
        'fetchedUtc': rep['fetchedUtc'],
        'lastAnalysisUtc': rep['lastAnalysisUtc'],  # None -> JSON null
        'querySucceeded': rep['querySucceeded'],
    }
    return json.dumps(o, ensure_ascii=False, separators=(',', ':'))


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    default_root = os.path.abspath(os.path.join(here, '..'))
    ap = argparse.ArgumentParser(description='把 VT 抽检结果种入产品云信誉缓存 reputation.jsonl')
    ap.add_argument('--vt', default=os.path.join(default_root, 'data', 'vt', 'vt_results.jsonl'),
                    help='VT 结果 JSONL(默认 ml/data/vt/vt_results.jsonl)')
    ap.add_argument('--out', default='', help='目标 reputation.jsonl(默认 %%ProgramData%%\\Bulwark)')
    ap.add_argument('--malicious-threshold', type=int, default=5,
                    help='检出引擎数 >= 该值判恶意(VT 默认 5,须与 appsettings 一致)')
    ap.add_argument('--min-verdict', choices=['clean', 'suspicious', 'malicious'], default='clean',
                    help='只种 >= 该结论等级的条目(默认 clean,即全部权威结论)')
    ap.add_argument('--malicious-only', action='store_true', help='等价 --min-verdict malicious')
    ap.add_argument('--no-merge', action='store_true', help='不合并已有条目(仅用 VT 结果覆盖写)')
    ap.add_argument('--no-backup', action='store_true', help='覆盖写前不备份原文件')
    ap.add_argument('--dry-run', action='store_true', help='只预览统计,不落盘')
    args = ap.parse_args()

    out = args.out or os.path.join(program_data_dir(), 'reputation.jsonl')
    min_verdict = V_MALICIOUS if args.malicious_only else MIN_VERDICT[args.min_verdict]

    if not os.path.isfile(args.vt):
        print(f'[错误] VT 结果文件不存在: {args.vt}')
        return

    stats = {k: 0 for k in ('vt_new', 'vt_upd', 'vt_kept', 'old_new', 'old_upd', 'old_kept')}
    pool = {}  # sha -> FileReputation dict

    # 1) 先并入已有条目(可迁移老格式);--no-merge 则跳过。
    existing_lines = 0
    existing_parsed = 0
    if not args.no_merge and os.path.isfile(out):
        with open(out, 'r', encoding='utf-8-sig', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                existing_lines += 1
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                rep = rep_from_existing(obj)
                if rep:
                    existing_parsed += 1
                    merge_in(pool, rep, 'old', stats)

    # 2) 并入 VT 结果。
    vt_lines = vt_ok = vt_skip = 0
    with open(args.vt, 'r', encoding='utf-8-sig', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            vt_lines += 1
            try:
                rec = json.loads(line)
            except Exception:
                continue
            rep = rep_from_vt(rec, args.malicious_threshold)
            if rep is None:
                vt_skip += 1
                continue
            # min-verdict 只约束【从 VT 新种入】的条目;已有缓存条目一律保留不删。
            if rep['verdict'] < min_verdict:
                vt_skip += 1
                continue
            vt_ok += 1
            merge_in(pool, rep, 'vt', stats)

    # 3) 结论分布(已有条目一律保留,不因 min-verdict 而丢弃)。
    kept = list(pool.values())
    dist = {0: 0, 1: 0, 2: 0, 3: 0}
    for r in kept:
        dist[r['verdict']] += 1

    print('================ VT -> 云信誉 合并预览 ================')
    print(f'VT 结果文件      : {args.vt}')
    print(f'  总行 {vt_lines}  权威命中(200) {vt_ok + stats["vt_kept"]}  '
          f'跳过(未命中/无结论/低于 min-verdict) {vt_skip}')
    print(f'  min-verdict     : >= {VERDICT_NAME[min_verdict]}(仅约束从 VT 新种入的条目)')
    if not args.no_merge:
        print(f'已有 reputation  : {out}')
        print(f'  原始行 {existing_lines}  成功解析 {existing_parsed}  (含老 .NET PascalCase 迁移,一律保留)')
    print(f'合并后待写入条目 : {len(kept)}')
    print(f'  结论分布  malicious={dist[3]}  suspicious={dist[2]}  clean={dist[1]}  unknown={dist[0]}')
    print(f'  合并明细  VT[新增 {stats["vt_new"]} 升格 {stats["vt_upd"]} 平局保留旧 {stats["vt_kept"]}]  '
          f'旧库[载入 {stats["old_new"]} 被 VT 覆盖 {stats["old_upd"]}]')

    if args.dry_run:
        print('\n[dry-run] 未写入任何文件。去掉 --dry-run 即执行合并。')
        return

    if not kept:
        print('\n没有可写入的条目,结束。')
        return

    # 4) 备份 + 原子替换。稳定排序(malicious 优先、其次 sha)让 diff 友好。
    kept.sort(key=lambda r: (-r['verdict'], r['sha256']))
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    if os.path.isfile(out) and not args.no_backup:
        bak = out + '.bak.' + datetime.datetime.now().strftime('%Y%m%d%H%M%S')
        shutil.copy2(out, bak)
        print(f'\n已备份原文件 -> {bak}')

    fd, tmp = tempfile.mkstemp(prefix='rep_', suffix='.jsonl',
                               dir=os.path.dirname(os.path.abspath(out)))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='') as w:
            for r in kept:
                w.write(dump_line(r) + '\r\n')
        os.replace(tmp, out)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)

    print(f'已写入云信誉缓存 : {out}  ({len(kept)} 条)')
    print('提示:产品仅在服务启动时读入该缓存,请重启 Bulwark 服务使其生效。')


if __name__ == '__main__':
    main()
