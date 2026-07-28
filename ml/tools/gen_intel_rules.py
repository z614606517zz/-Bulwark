#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
从 VT 拉取的恶意行为数据(vt_behaviours.jsonl)【抽取有用的】IOC 生成 Bulwark 防护规则。

不做「一股脑」:
  * 只取【复现】的 C2 指标(出现在 >= N 个不同恶意样本里)—— 单个样本的一次性外联多为噪声/合法服务;
    复现的才是家族/campaign 的真实基础设施。
  * 过滤合法服务(域名白名单 + 公共 DNS 拒绝表 + 跨查白名单域名解析出的 IP,剔除 CDN/云 IP)—— 避免
    误拦 Google/微软/Cloudflare/Telegram/GitHub 等恶意样本也会碰的正常服务。
  * 释放物哈希单独导出为「哈希黑名单」(交由信誉缓存 + 引擎硬拦,而非塞成上千条规则)。

产出:
  intel_rules.json     —— DefenseRule 数组(NetworkConnect/DnsQuery Block),可并入 rules.json
  dropped_hashes.txt   —— 释放物 sha256 列表(交由信誉缓存注入,做哈希黑名单)
"""
import argparse
import collections
import datetime
import ipaddress
import json
import os
import uuid

# EventType 序号(与 C++ Enums.h 一致)
EV_PROCESS_CREATE = 0
EV_NETWORK_CONNECT = 7
EV_DNS_QUERY = 9
ACT_BLOCK = 1  # VerdictAction::Block

# 公共 DNS / 常见解析器:恶意样本常查,绝不能拦。
IP_DENY = {
    '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9', '149.112.112.112',
    '114.114.114.114', '114.114.115.115', '223.5.5.5', '223.6.6.6', '119.29.29.29',
    '180.76.76.76', '208.67.222.222', '208.67.220.220', '4.2.2.1', '4.2.2.2',
    '8.26.56.26', '64.6.64.6', '84.200.69.80', '77.88.8.8', '76.76.2.0',
}

# 合法服务域名(子串匹配):恶意样本也会碰这些(连通性探测/证书校验/CDN/被滥用的合法平台),一律不拦。
DOM_ALLOW = [
    'google', 'gstatic', 'googleapis', 'googleusercontent', 'googletagmanager', 'google-analytics',
    'youtube', 'ytimg', 'ggpht', 'doubleclick', 'gvt1', 'gvt2', 'gvt3',
    'microsoft', 'msft', 'msftncsi', 'msftconnecttest', 'windows', 'windowsupdate', 'live.com',
    'office', 'office365', 'sharepoint', 'onedrive', 'skype', 'xboxlive', 'bing', 'azureedge',
    'azure', 'msedge', 'msecnd', 'trafficmanager', 'msn.com', 'outlook', 'hotmail',
    'cloudflare', 'cloudflare-dns', 'cloudflareinsights', 'akamai', 'akamaiedge', 'akamaihd',
    'akadns', 'edgesuite', 'edgekey', 'fastly', 'fastlylb', 'amazonaws', 'aws', 'cloudfront',
    'apple', 'icloud', 'mzstatic', 'aaplimg', 'itunes', 'mozilla', 'firefox', 'mozaws',
    'digicert', 'verisign', 'sectigo', 'letsencrypt', 'ocsp', 'symcb', 'symcd', 'thawte',
    'entrust', 'globalsign', 'comodoca', 'godaddy', 'usertrust', 'pki.goog', 'gvt.com',
    'telegram', 'telegram.org', 'discord', 'discordapp', 'github', 'githubusercontent',
    'githubassets', 'pastebin', 'dropbox', 'box.com', 'facebook', 'fbcdn', 'instagram',
    'twitter', 'twimg', 't.co', 'whatsapp', 'spotify', 'netflix', 'reddit', 'wikipedia',
    'wechat', 'weixin', 'qq.com', 'tencent', 'qpic', 'gtimg', 'qlogo', 'tencent-cloud',
    'alicdn', 'alibaba', 'aliyun', 'taobao', 'tmall', 'alipay', 'baidu', 'bdstatic', 'baidustatic',
    '360.cn', '360.com', 'qhimg', 'qhres', 'qihoo', 'ntp.org', 'pool.ntp', 'time.windows',
    'time.apple', 'time.nist', 'nvidia', 'steam', 'steampowered', 'steamstatic', 'valve',
    'adobe', 'adobedtm', 'typekit', 'java.com', 'oracle', 'ubuntu', 'debian', 'python.org',
    'pypi', 'npmjs', 'jsdelivr', 'unpkg', 'cdnjs', 'jquery', 'bootstrapcdn', 'wp.com',
    'wordpress', 'gmail', 'yahoo', 'yandex', 'mail.ru', 'vk.com', 'sentry', 'crashlytics',
    'gandi', 'ionos', 'cloudns',
]


# 主流云/CDN 网段:恶意样本大量走 Cloudflare/Fastly/Google/AWS/Azure/Akamai 的共享 IP
# (DoH、连通性探测、被套 CDN 的 C2 等)。这些 IP 无法按 IP 区分善恶,一律不生成拦截规则,
# 避免误拦正常业务(如 162.159.x.x=Cloudflare 出现在 35% 的样本里)。宁可漏 C2,不可误杀。
CLOUD_CIDRS = [ipaddress.ip_network(c) for c in [
    # Cloudflare
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18',
    '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17',
    '162.158.0.0/15', '162.159.0.0/16', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
    # Fastly
    '151.101.0.0/16', '199.232.0.0/16',
    # Google
    '8.8.4.0/24', '8.8.8.0/24', '142.250.0.0/15', '172.217.0.0/16', '216.58.192.0/19',
    '34.64.0.0/10', '35.184.0.0/13', '74.125.0.0/16', '64.233.160.0/19',
    # Microsoft / Azure (partial big ranges)
    '13.64.0.0/11', '20.0.0.0/8', '40.64.0.0/10', '52.0.0.0/8', '204.79.195.0/24', '23.32.0.0/11',
    # Akamai (partial)
    '23.192.0.0/11', '104.64.0.0/10', '184.24.0.0/13', '2.16.0.0/13',
    # Amazon (partial big ranges)
    '3.0.0.0/8', '18.0.0.0/8', '54.0.0.0/8', '99.80.0.0/12', '13.32.0.0/12',
]]


def in_cloud(ip):
    try:
        a = ipaddress.ip_address(ip)
        return any(a in net for net in CLOUD_CIDRS)
    except Exception:
        return True  # 解析不了当作不可用,跳过


def routable(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_global and not a.is_multicast
    except Exception:
        return False


def dom_allowed(dom):
    d = dom.lower()
    return any(tok in d for tok in DOM_ALLOW)


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.000Z')


def rule_base(note):
    return {
        'id': str(uuid.uuid4()),
        'actorPath': '', 'actorPattern': '',
        'type': None, 'targetPattern': '', 'commandLinePattern': '', 'parentPattern': '',
        'requireUnsigned': False, 'exemptTrustedOsComponent': False, 'hardOverride': False,
        'actorHashes': [], 'action': ACT_BLOCK, 'note': note,
        'createdUtc': now_iso(), 'expiresUtc': None, 'sessionOnly': False, 'enabled': True,
    }


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.abspath(os.path.join(here, '..'))
    ap = argparse.ArgumentParser()
    ap.add_argument('--beh', default=os.path.join(root, 'data', 'vt', 'vt_behaviours.jsonl'))
    ap.add_argument('--out-rules', default=r'C:\Users\61460\gen\intel_rules.json')
    ap.add_argument('--out-dropped', default=r'C:\Users\61460\gen\dropped_hashes.txt')
    ap.add_argument('--ip-min', type=int, default=3)   # C2 IP 至少出现在这么多样本
    ap.add_argument('--dom-min', type=int, default=3)  # C2 域名至少出现在这么多样本
    ap.add_argument('--max-frac', type=float, default=0.12)  # 超过此比例样本共享的 IOC 视为合法基础设施,跳过
    args = ap.parse_args()

    ip_samples = collections.defaultdict(set)
    dom_samples = collections.defaultdict(set)
    dropped = set()
    allow_ips = set()  # 白名单域名解析出的 IP(CDN/云)——从 C2 IP 里剔除,避免误拦

    n = 0
    with open(args.beh, encoding='utf-8-sig', errors='ignore') as f:
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
            if not isinstance(beh, dict):
                continue
            n += 1
            for it in (beh.get('ip_traffic') or []):
                ip = str((it or {}).get('destination_ip', '')).strip()
                if ip and routable(ip):
                    ip_samples[ip].add(sha)
            for it in (beh.get('dns_lookups') or []):
                host = str((it or {}).get('hostname', '')).strip().lower()
                resolved = (it or {}).get('resolved_ips') or []
                if host and '.' in host:
                    dom_samples[host].add(sha)
                    if dom_allowed(host):
                        for rip in resolved:
                            allow_ips.add(str(rip).strip())
            for it in (beh.get('files_dropped') or []):
                hh = str((it or {}).get('sha256', '')).lower()
                if len(hh) == 64:
                    dropped.add(hh)

    max_common = max(int(n * args.max_frac), 3)  # 超过这么多样本共享 -> 视为合法共享基础设施
    rules = []
    kept_ip_list = []
    skip_ip = 0
    for ip, shas in ip_samples.items():
        c = len(shas)
        if c < args.ip_min:
            continue
        # 跳过:公共 DNS / 白名单域名解析出的 IP / 主流云 CDN 网段 / 过于普遍(合法共享基础设施)。
        if ip in IP_DENY or ip in allow_ips or in_cloud(ip) or c > max_common:
            skip_ip += 1
            continue
        r = rule_base('[\u60c5\u62a5] \u6076\u610f\u6837\u672c\u9ad8\u9891\u5916\u8054 C2 IP(\u89c1\u4e8e %d \u4e2a\u6837\u672c)\uff0c\u7981\u6b62\u5916\u8054' % c)
        r['type'] = EV_NETWORK_CONNECT
        r['targetPattern'] = ip + ':*'
        rules.append(r)
        kept_ip_list.append((ip, c))

    kept_dom_list = []
    skip_dom = 0
    for dom, shas in dom_samples.items():
        c = len(shas)
        if c < args.dom_min:
            continue
        if dom_allowed(dom) or len(dom) < 4 or c > max_common:
            skip_dom += 1
            continue
        r = rule_base('[\u60c5\u62a5] \u6076\u610f\u6837\u672c\u9ad8\u9891\u89e3\u6790 C2 \u57df\u540d(\u89c1\u4e8e %d \u4e2a\u6837\u672c)' % c)
        r['type'] = EV_DNS_QUERY
        r['targetPattern'] = dom
        rules.append(r)
        kept_dom_list.append((dom, c))

    kept_ip = len(kept_ip_list)
    kept_dom = len(kept_dom_list)

    os.makedirs(os.path.dirname(args.out_rules), exist_ok=True)
    with open(args.out_rules, 'w', encoding='utf-8') as f:
        json.dump(rules, f, ensure_ascii=False, indent=4)
    with open(args.out_dropped, 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted(dropped)))

    print('behaviours parsed: %d   max_common(sample cap)=%d' % (n, max_common))
    print('C2 IP rules kept: %d  (skipped legit/CDN/DNS/too-common: %d, allow_ips from whitelisted domains: %d)'
          % (kept_ip, skip_ip, len(allow_ips)))
    print('C2 domain rules kept: %d  (skipped legit/too-common: %d)' % (kept_dom, skip_dom))
    print('total intel rules: %d -> %s' % (len(rules), args.out_rules))
    print('dropped payload hashes: %d -> %s' % (len(dropped), args.out_dropped))
    print('---- kept C2 IPs (ip x #samples) ----')
    for ip, c in sorted(kept_ip_list, key=lambda t: -t[1]):
        print('  %-18s %d' % (ip, c))
    print('---- kept C2 domains (domain x #samples) ----')
    for dom, c in sorted(kept_dom_list, key=lambda t: -t[1]):
        print('  %-40s %d' % (dom, c))


if __name__ == '__main__':
    main()
