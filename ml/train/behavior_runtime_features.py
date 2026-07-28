#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
行为模型(路线B) - 运行时可观测特征抽取(喂 train.py)。

与 behavior_gran_features.py 的区别:
  behavior_gran 用的是 VT 云沙箱 behaviour_summary 的【全部】字段(含 MITRE/MBC/CAPA/sigma/tags),
  那些本机驱动/ETW 根本观测不到 -> 训练出来的模型只能吃 VT 报告,双击本地样本时无数据可打分。

本脚本【只抽取本机驱动/ETW 能复现的行为】:
  * 文件写入/释放(+类型)、文件删除、子进程创建、远程线程注入、注册表写入(Run/服务持久化)、
    网络外联、DNS、命令行(shell 派生)。
  * 一律【不用】VT 专属富化(MITRE/MBC/CAPA/sigma/tags/mutex/service 对象/payload/内存 dump...)。

训练数据仍复用 VT 行为明细(有标签):
  - 威胁侧 vt_behaviours.jsonl(label=1)   良性侧 vt_behaviours_benign.jsonl(label=0)
抽取时只取"本机可复现"的那部分字段,使【训练特征语义】== 【C++ 侧 LocalBehaviorFeatureExtractor
从 ChainEventInfo 进程树算出的特征】。

域偏移缓解(VT 是完整引爆、本机只观测短窗口):
  * 计数做饱和 min(n, SATURATE) 再 log1p —— VT"释放50个"和本机"释放4个"都趋同为"释放行为=有";
  * 主力特征是【能力布尔】(注入/落PE/持久化/派生shell/删文件/联网/大量进程/狂改注册表),跨窗口稳健。

产物:
  behavior_runtime_features.npz
  behavior_runtime_feature_spec.json  (特征顺序 + 关键字表,C++ 推理端复现同一向量)
"""
import argparse
import json
import math
import os
import re

import numpy as np

HEX64 = re.compile(r'^[0-9a-fA-F]{64}$')

# 计数饱和上限(缩小 VT 完整引爆 与 本机短窗口 的量级差)。
SATURATE = 10

# 释放文件类型分桶:按扩展名(本机侧只有路径/扩展名,故两侧都用扩展名对齐)。
DROP_EXT = {
    'pe_exe':  ['.exe', '.scr', '.com', '.pif', '.cpl'],
    'pe_dll':  ['.dll', '.ocx', '.sys', '.drv'],
    'script':  ['.ps1', '.psm1', '.vbs', '.vbe', '.js', '.jse', '.bat', '.cmd', '.wsf', '.hta', '.py', '.jar', '.lnk'],
    'doc':     ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf', '.rtf', '.one'],
    'archive': ['.zip', '.rar', '.7z', '.cab', '.gz', '.tar', '.iso', '.img'],
}
DROP_BUCKETS = ['pe_exe', 'pe_dll', 'script', 'doc', 'archive', 'other']

# 持久化注册表键(小写子串/正则)——本机 RegistryWrite target 与 VT registry_keys_set[].key 同源语义。
PERSIST_PATTERNS = [
    r'\\run\b', r'\\runonce', r'\\winlogon', r'\\userinit',
    r'image file execution', r'\\shell\\open\\command',
    r'\\policies\\explorer\\run', r'\\currentversion\\run',
]
SERVICE_PATTERN = r'\\services\\'

# 派生 shell / LOLBin(命令行或子进程映像里出现即置位)。
SHELL_HINTS = ['cmd.exe', 'powershell', 'pwsh', 'wscript', 'cscript', 'mshta',
               'rundll32', 'regsvr32', 'msiexec', 'certutil', 'bitsadmin']

# 启动目录写入(持久化)。
STARTUP_HINTS = [r'\\start menu\\programs\\startup\\', r'\\startup\\']

# 良性侧安全过滤:沙盒 verdicts 出现恶意词 -> 剔除该"良性"样本。
MAL_VERDICT_TOKENS = {
    'MALWARE', 'TROJAN', 'RANSOMWARE', 'SPYWARE', 'STEALER', 'BACKDOOR',
    'ROOTKIT', 'WORM', 'VIRUS', 'ADWARE', 'DROPPER', 'BANKER', 'RAT',
    'KEYLOGGER', 'COINMINER', 'MINER', 'EXPLOIT', 'MALICIOUS', 'SPREADER',
    'EVADER', 'PUA', 'PUP', 'GREYWARE',
}

# 注:不含 n_commands —— VT command_executions 与本机 ProcessCreate 命令行是不同概念
# (训练侧计数与推理侧计数语义不一致,属误导特征),故两侧一并剔除。
FEATURE_NAMES = [
    # 计数(饱和 + log1p)
    'n_files_written', 'n_files_deleted', 'n_proc_created', 'n_proc_injected',
    'n_reg_set', 'n_net', 'n_dns',
    # 释放文件类型桶(饱和 + log1p)
    'drop_pe_exe', 'drop_pe_dll', 'drop_script', 'drop_doc', 'drop_archive', 'drop_other',
    # 能力布尔(跨观测窗口稳健,主力)
    'cap_injects_code', 'cap_drops_pe', 'cap_drops_script', 'cap_persistence_run',
    'cap_creates_service', 'cap_deletes_files', 'cap_network', 'cap_many_procs',
    'cap_modifies_many_reg', 'cap_spawns_shell', 'cap_writes_startup',
]


def _lst(v):
    return v if isinstance(v, list) else []


def _sat_log1p(n):
    return math.log1p(float(min(int(n), SATURATE)))


def _path_of(item):
    """VT 条目可能是 str(路径) 或 dict{path/target/...}。统一取路径文本。"""
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        for k in ('path', 'target', 'file', 'name'):
            v = item.get(k)
            if isinstance(v, str) and v:
                return v
    return ''


def _text_of(item, *keys):
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        parts = []
        for k in keys:
            v = item.get(k)
            if isinstance(v, str):
                parts.append(v)
        return ' '.join(parts)
    return ''


def _ext_bucket(path):
    p = str(path or '').lower()
    dot = p.rfind('.')
    ext = p[dot:] if dot >= 0 else ''
    for bucket, exts in DROP_EXT.items():
        if ext in exts:
            return bucket
    return 'other'


def has_behaviour(beh):
    for field in ('files_dropped', 'files_written', 'files_deleted', 'processes_created',
                  'processes_injected', 'registry_keys_set', 'command_executions',
                  'dns_lookups', 'ip_traffic', 'http_conversations'):
        if len(_lst(beh.get(field))) > 0:
            return True
    return False


def verdict_is_malicious(beh):
    for v in _lst(beh.get('verdicts')):
        if str(v).upper().strip() in MAL_VERDICT_TOKENS:
            return True
    return False


def features_from_behaviour(beh):
    """VT behaviour_summary -> 运行时特征向量(仅本机可复现字段)。顺序同 FEATURE_NAMES。"""
    dropped = _lst(beh.get('files_dropped'))
    written = _lst(beh.get('files_written'))
    deleted = _lst(beh.get('files_deleted'))
    proc_created = _lst(beh.get('processes_created'))
    proc_injected = _lst(beh.get('processes_injected'))
    reg_set = _lst(beh.get('registry_keys_set'))
    commands = _lst(beh.get('command_executions'))
    dns = _lst(beh.get('dns_lookups'))
    net = _lst(beh.get('ip_traffic')) + _lst(beh.get('http_conversations'))

    n_files_written = len(dropped) + len(written)
    n_files_deleted = len(deleted)
    n_proc_created = len(proc_created)
    n_proc_injected = len(proc_injected)
    n_reg_set = len(reg_set)
    n_net = len(net)
    n_dns = len(dns)

    # 释放文件按扩展名分桶(dropped 有 type/path;written 是路径)。
    drop_counts = {b: 0 for b in DROP_BUCKETS}
    for item in dropped + written:
        drop_counts[_ext_bucket(_path_of(item))] += 1

    # 文本聚合:注册表键(持久化/服务)、命令行(shell)、写入路径(启动目录)。
    reg_text = ' '.join(_text_of(r, 'key', 'value', 'path').lower() for r in reg_set)
    cmd_text = ' '.join((_text_of(c, 'command', 'cmd') if isinstance(c, dict) else str(c)).lower()
                        for c in commands)
    proc_text = ' '.join(_path_of(p).lower() for p in proc_created)
    shell_hay = cmd_text + ' ' + proc_text
    write_paths_text = ' '.join(_path_of(x).lower() for x in (dropped + written))

    persistence = 1.0 if any(re.search(p, reg_text) for p in PERSIST_PATTERNS) else 0.0
    creates_service = 1.0 if re.search(SERVICE_PATTERN, reg_text) else 0.0
    spawns_shell = 1.0 if any(h in shell_hay for h in SHELL_HINTS) else 0.0
    writes_startup = 1.0 if any(re.search(h, write_paths_text) for h in STARTUP_HINTS) else 0.0
    drops_pe = 1.0 if (drop_counts['pe_exe'] + drop_counts['pe_dll']) > 0 else 0.0
    drops_script = 1.0 if drop_counts['script'] > 0 else 0.0

    row = [
        _sat_log1p(n_files_written), _sat_log1p(n_files_deleted),
        _sat_log1p(n_proc_created), _sat_log1p(n_proc_injected),
        _sat_log1p(n_reg_set), _sat_log1p(n_net), _sat_log1p(n_dns),
        _sat_log1p(drop_counts['pe_exe']), _sat_log1p(drop_counts['pe_dll']),
        _sat_log1p(drop_counts['script']), _sat_log1p(drop_counts['doc']),
        _sat_log1p(drop_counts['archive']), _sat_log1p(drop_counts['other']),
        1.0 if n_proc_injected > 0 else 0.0,
        drops_pe,
        drops_script,
        persistence,
        creates_service,
        1.0 if n_files_deleted > 0 else 0.0,
        1.0 if (n_net + n_dns) > 0 else 0.0,
        1.0 if n_proc_created >= 10 else 0.0,
        1.0 if n_reg_set >= 20 else 0.0,
        spawns_shell,
        writes_startup,
    ]
    return row


def iter_beh(path):
    if not os.path.isfile(path):
        return
    with open(path, encoding='utf-8-sig', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            if int(rec.get('http', 0) or 0) != 200:
                continue
            sha = str(rec.get('sha256', '')).lower()
            beh = rec.get('behaviour') or {}
            if not HEX64.match(sha) or not isinstance(beh, dict):
                continue
            yield sha, beh


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.abspath(os.path.join(here, '..'))
    ap = argparse.ArgumentParser()
    ap.add_argument('--threat', default=os.path.join(root, 'data', 'vt', 'vt_behaviours.jsonl'))
    ap.add_argument('--benign', default=os.path.join(root, 'data', 'vt', 'vt_behaviours_benign.jsonl'))
    ap.add_argument('--out', default=os.path.join(here, 'behavior_runtime_features.npz'))
    ap.add_argument('--out-spec', default=os.path.join(here, 'behavior_runtime_feature_spec.json'))
    args = ap.parse_args()

    samples = []  # (sha, row, label, side)
    stat = {'threat_total': 0, 'threat_empty': 0, 'benign_total': 0, 'benign_empty': 0, 'benign_dirty': 0}

    def ingest(path, label, side):
        seen = set()
        for sha, beh in iter_beh(path):
            if sha in seen:
                continue
            seen.add(sha)
            stat['%s_total' % side] += 1
            if not has_behaviour(beh):
                stat['%s_empty' % side] += 1
                continue
            if label == 0 and verdict_is_malicious(beh):
                stat['benign_dirty'] += 1
                continue
            samples.append((sha, features_from_behaviour(beh), label, side))

    ingest(args.threat, 1, 'threat')
    ingest(args.benign, 0, 'benign')

    if not samples:
        print('没有可用样本,先跑 vt_behaviours.py 拉行为明细。')
        return

    X = np.asarray([r for _s, r, _l, _sd in samples], dtype=np.float32)
    y = np.asarray([l for _s, _r, l, _sd in samples], dtype=np.int32)
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
    sha_arr = np.array([s for s, _r, _l, _sd in samples], dtype=object)
    side_arr = np.array([sd for _s, _r, _l, sd in samples], dtype=object)

    n_pos = int((y == 1).sum())
    n_neg = int((y == 0).sum())
    np.savez_compressed(args.out, X=X, y=y, sha=sha_arr, side=side_arr,
                        feature_names=np.array(FEATURE_NAMES, dtype=object))
    spec = dict(
        kind='runtime-observable',
        feature_dim=len(FEATURE_NAMES),
        feature_names=FEATURE_NAMES,
        saturate=SATURATE,
        drop_ext=DROP_EXT,
        drop_buckets=DROP_BUCKETS,
        persist_patterns=PERSIST_PATTERNS,
        service_pattern=SERVICE_PATTERN,
        shell_hints=SHELL_HINTS,
        startup_hints=STARTUP_HINTS,
        n_samples=len(samples), n_threat=n_pos, n_benign=n_neg,
        note='仅本机驱动/ETW 可复现的行为特征;C++ LocalBehaviorFeatureExtractor 复现同一向量。',
    )
    with open(args.out_spec, 'w', encoding='utf-8') as f:
        json.dump(spec, f, ensure_ascii=False, indent=2)

    print('================ 运行时行为特征抽取完成 ================')
    print('威胁侧: total=%d empty=%d -> 用 %d' % (stat['threat_total'], stat['threat_empty'], n_pos))
    print('良性侧: total=%d empty=%d 脏样本剔除=%d -> 用 %d' % (
        stat['benign_total'], stat['benign_empty'], stat['benign_dirty'], n_neg))
    print('样本合计 %d  (威胁=%d 良性=%d)  特征维度 %d' % (len(samples), n_pos, n_neg, len(FEATURE_NAMES)))
    print('特征矩阵 -> %s' % args.out)
    print('特征规格 -> %s' % args.out_spec)


if __name__ == '__main__':
    main()
