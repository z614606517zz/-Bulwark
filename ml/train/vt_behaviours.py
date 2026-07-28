#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
拉 VT 样本的【完整行为明细】/files/{sha}/behaviour_summary:
  释放文件 files_dropped、进程 processes_created、注册表 registry_keys_set、
  网络 dns_lookups / ip_traffic / http_conversations、MITRE ATT&CK、命令行、互斥量…
这是"行为模型"真正要的动态特征(比文件报告里的 sandbox_verdicts 汇总更细)。

目标 sha:默认取 vt_results.jsonl 里【确诊威胁】(manifest_label 属威胁类 且 vt_malicious>=阈值)。
复用 vt_enrich 的 load_keys / curl_get / result_shas。多 Key 轮换、429/401 冷却、可断点续跑。
输出:ml/data/vt/vt_behaviours.jsonl(每行一个 sha 的完整行为 + 便捷计数)。
只读查询,不上传、不执行。
"""
import argparse
import datetime
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vt_enrich as ve

VT_BEH = 'https://www.virustotal.com/api/v3/files/{}/behaviour_summary'
THREAT_LABELS = {'malicious', 'script', 'installer', 'document', 'archive'}
BENIGN_LABELS = {'benign'}

# behaviour_summary 里我们关心、做计数的键
COUNT_KEYS = [
    ('n_files_dropped', 'files_dropped'), ('n_files_written', 'files_written'),
    ('n_files_deleted', 'files_deleted'), ('n_processes', 'processes_created'),
    ('n_reg_set', 'registry_keys_set'), ('n_reg_deleted', 'registry_keys_deleted'),
    ('n_mutexes', 'mutexes_created'), ('n_dns', 'dns_lookups'),
    ('n_ip', 'ip_traffic'), ('n_http', 'http_conversations'),
    ('n_mitre', 'mitre_attack_techniques'), ('n_cmd', 'command_executions'),
    ('n_services', 'services_started'), ('n_sigma', 'sigma_analysis_results'),
]


def load_targets(vt_results, mal_thr, want_benign):
    out, seen = [], set()
    if not os.path.isfile(vt_results):
        return out
    with open(vt_results, encoding='utf-8-sig', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            sha = str(rec.get('sha256', '')).lower()
            if not ve.HEX64.match(sha) or sha in seen:
                continue
            lb = str(rec.get('manifest_label', '')).lower()
            try:
                vm = int(rec.get('vt_malicious', 0) or 0)
            except Exception:
                vm = 0
            if want_benign:
                if lb in BENIGN_LABELS and vm == 0:
                    seen.add(sha); out.append(sha)
            else:
                if lb in THREAT_LABELS and vm >= mal_thr:
                    seen.add(sha); out.append(sha)
    return out


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.abspath(os.path.join(here, '..'))
    ap = argparse.ArgumentParser()
    ap.add_argument('--vt-results', default=os.path.join(root, 'data', 'vt', 'vt_results.jsonl'))
    ap.add_argument('--out', default=os.path.join(root, 'data', 'vt', 'vt_behaviours.jsonl'))
    ap.add_argument('--mal-threshold', type=int, default=5)
    ap.add_argument('--benign', action='store_true', help='抓良性侧(默认抓威胁侧)')
    ap.add_argument('--sha-list', default='', help='从文件读显式 SHA256 列表(每行一个),优先于 vt_results')
    ap.add_argument('--no-wait', action='store_true', help='额度不可用(全 Key 冷却)时立即退出,不退避等待')
    ap.add_argument('--timeout', type=int, default=60)
    ap.add_argument('--rpm-per-key', type=float, default=3.6)
    ap.add_argument('--limit', type=int, default=0)
    args = ap.parse_args()

    keys = ve.load_keys()
    if not keys:
        print('[错误] BULWARK_VT_APIKEY 里没有有效 VT Key'); return
    interval = max(1.0, 60.0 / (args.rpm_per_key * len(keys)))
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    done = ve.result_shas(args.out)
    if args.sha_list and os.path.isfile(args.sha_list):
        seen_l = set(); base = []
        with open(args.sha_list, encoding='utf-8-sig', errors='ignore') as f:
            for line in f:
                s = line.strip().lower()
                if ve.HEX64.match(s) and s not in seen_l:
                    seen_l.add(s); base.append(s)
        print(f'  (SHA 列表模式: {args.sha_list} 读到 {len(base)} 个)')
    else:
        base = load_targets(args.vt_results, args.mal_threshold, args.benign)
        # 威胁侧:合并"等额度补充队列"pending_shas.txt(用户临时追加的哈希)
        if not args.benign:
            pend = os.path.join(os.path.dirname(args.out), 'pending_shas.txt')
            if os.path.isfile(pend):
                bset = set(base); added = 0
                with open(pend, encoding='utf-8-sig', errors='ignore') as pf:
                    for line in pf:
                        s = line.strip().lower()
                        if ve.HEX64.match(s) and s not in bset:
                            base.append(s); bset.add(s); added += 1
                if added:
                    print(f'  (合并 pending_shas.txt 补充目标 {added} 个)')
    targets = [s for s in base if s not in done]
    if args.limit:
        targets = targets[:args.limit]
    side = '良性' if args.benign else '威胁'
    print(f'VT Key {len(keys)}  间隔 {interval:.2f}s/次  已抓 {len(done)}  待抓{side}行为明细 {len(targets)}')
    if not targets:
        print('没有要抓的(可能都抓过了)'); return

    cooldown = {}; ki = [0]

    def next_key():
        now = time.time()
        for _ in range(len(keys)):
            k = keys[ki[0] % len(keys)]; ki[0] += 1
            if cooldown.get(k, 0) <= now:
                return k
        return None

    def note(code, body, key):
        if code == 429:
            if body and 'QuotaExceeded' in body:
                cooldown[key] = time.time() + 30 * 60   # 日配额耗尽 -> 退避 30 分钟
            else:
                cooldown[key] = time.time() + 90         # 每分钟限速 -> 短冷却
        elif code in (401, 403):
            cooldown[key] = time.time() + 60 * 60        # 1 小时后再试(常随日配额一起恢复)

    give_up_at = time.time() + 16 * 3600   # 全局放弃时限(熬过日配额重置 + 抓取窗口)

    def get_key_blocking():
        """等到有可用 Key 才返回；超过全局时限仍全部耗尽则返回 None(可续跑)。"""
        while True:
            k = next_key()
            if k is not None:
                return k
            if args.no_wait:
                return None
            now = time.time()
            if now > give_up_at:
                return None
            nxt = min(cooldown.values()) if cooldown else now + 60
            wait = int(max(30, min(nxt - now + 5, 30 * 60)))
            print(f'  [{datetime.datetime.now():%H:%M:%S}] 全部 Key 冷却中，休眠 {wait}s 等配额恢复...', flush=True)
            time.sleep(wait)

    def fetch_definitive(sha):
        """反复换 Key 重试，直到拿到确定结果(200/404)。返回 (code, body)；
        'GIVEUP'=全局配额长期不可用要停机，'SKIP'=该样本反复失败先跳过(不写,下次可续)。"""
        for _ in range(80):
            key = get_key_blocking()
            if key is None:
                return ('GIVEUP', '')
            code, body = ve.curl_get(VT_BEH.format(sha), key, args.timeout)
            note(code, body, key)
            if code in (200, 404):
                return (code, body)
            if code == 0:      # 网络错误，稍等再试
                time.sleep(3)
            # 429/401/403 -> 已 note 冷却，循环换 Key(全冷却时 get_key_blocking 会等待)
        return ('SKIP', '')

    ok = empty = miss = err = 0
    w = open(args.out, 'a', encoding='utf-8')
    try:
        for i, sha in enumerate(targets):
            code, body = fetch_definitive(sha)
            if code == 'GIVEUP':
                print('长期无可用配额，停止(可续跑)', flush=True); break
            if code == 'SKIP':
                err += 1
                print(f'  跳过(反复失败) {sha[:16]}', flush=True)
                continue
            # 只持久化确定结果(200/404)，绝不写入瞬时失败(429/401)，保证续跑正确
            rec = {'sha256': sha, 'http': code,
                   'fetched': datetime.datetime.now(datetime.timezone.utc).isoformat()}
            if code == 200:
                try:
                    data = json.loads(body).get('data', {}) or {}
                    rec['behaviour'] = data
                    for outk, ink in COUNT_KEYS:
                        v = data.get(ink)
                        rec[outk] = len(v) if isinstance(v, list) else 0
                    if any(rec[outk] for outk, _ in COUNT_KEYS):
                        ok += 1
                    else:
                        empty += 1
                except Exception:
                    rec['parse_error'] = True; err += 1
            else:  # 404 无行为报告(没被任何沙箱引爆)
                miss += 1
            w.write(json.dumps(rec, ensure_ascii=False) + '\n')
            if (i + 1) % 20 == 0:
                w.flush()
                print(f'  [{i+1}/{len(targets)}] 有行为={ok} 空={empty} 无报告404={miss} 其它={err}', flush=True)
            time.sleep(interval)
    finally:
        w.flush(); w.close()

    print(f'\n================ 行为明细抓取完成({side}) ================')
    print(f'有行为 {ok}  空报告 {empty}  无报告404 {miss}  其它 {err}  -> {args.out}')


if __name__ == '__main__':
    main()
