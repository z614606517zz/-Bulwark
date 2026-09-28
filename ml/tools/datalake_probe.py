#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""可行性探针：确认 vt_reports 里的恶意 PE 哈希，字节还能不能从 abuse.ch datalake 取回。

为什么必须先探这一步
------------------
服务器上只存了 VT 报告，样本字节早在采集时就被删了（bulwark-datalake.py 的设计如此）。
要训静态 PE 模型就必须把字节重新拉回来。而 datalake 的归档是有保留期的：
  hourly 只留约 8 天，daily 可回溯到 2020-02-24。
所以先用少量样本验证「按 first_seen 日期定位 daily 归档 -> 在中央目录里找到该哈希」
这条路走得通，再决定要不要为 3611 个样本写完整的抓取器。

手法沿用 bulwark-datalake.py 已验证过的思路：用 HTTP Range 只读 zip 的中央目录。
一天的归档可能有几百 MB 到 18 GB，但中央目录只有几十 KB —— 枚举一整天的哈希清单
只需要约 180 KiB 流量，而不是把整包拖下来。
"""

import argparse
import datetime
import json
import ssl
import struct
import sys
import urllib.error
import urllib.request

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, OSError):
    pass

BASE = "https://datalake.abuse.ch/malware-bazaar"
UA = "Mozilla/5.0 bulwark-datalake-probe"

# Windows 上的 CPython 不用系统证书库，venv 里默认没有 CA 根，直接 urlopen 会报
# CERTIFICATE_VERIFY_FAILED（同一台机器 curl 却正常，因为 curl 用系统库）。
# 用 certifi 的根证书。绝不关掉校验 —— 这是从公网拉恶意样本，中间人被换包
# 就等于把别人的载荷当成自己的训练标签。
def _ssl_ctx():
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


SSL_CTX = _ssl_ctx()
EOCD_SIG = b"PK\x05\x06"
EOCD64_LOC = b"PK\x06\x07"
EOCD64_SIG = b"PK\x06\x06"


def http(url, rng=None, timeout=40):
    h = {"User-Agent": UA}
    if rng:
        h["Range"] = "bytes=%d-%d" % rng
    req = urllib.request.Request(url, headers=h)
    return urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX)


def head_len(url):
    """拿归档总长度。有的镜像不答 HEAD，就用一个 0-0 的 Range 读 Content-Range。"""
    try:
        with http(url, rng=(0, 0)) as r:
            cr = r.headers.get("Content-Range", "")
            if "/" in cr:
                return int(cr.rsplit("/", 1)[1]), r.headers.get("Accept-Ranges", "")
    except urllib.error.HTTPError as e:
        raise
    return None, ""


def read_tail(url, total, n=131072):
    start = max(0, total - n)
    with http(url, rng=(start, total - 1)) as r:
        return start, r.read()


def zip_names_via_range(url):
    """只下载尾部切片 + 中央目录，解析出条目名列表。

    返回 (names, bytes_downloaded, total_size)。
    支持 zip64 —— 这些归档动辄几 GB，32 位 EOCD 装不下，必须走 zip64 定位器。
    """
    total, accept = head_len(url)
    if not total:
        raise RuntimeError("拿不到 Content-Length")
    downloaded = 1

    tail_start, tail = read_tail(url, total)
    downloaded += len(tail)

    i = tail.rfind(EOCD_SIG)
    if i < 0:
        raise RuntimeError("尾部切片里找不到 EOCD")
    cd_size, cd_off = struct.unpack_from("<II", tail, i + 12)
    n_ent = struct.unpack_from("<H", tail, i + 10)[0]

    # zip64：32 位字段被打满(0xFFFFFFFF / 0xFFFF)时真值在 zip64 EOCD 里
    j = tail.rfind(EOCD64_LOC)
    if j >= 0 and (cd_off == 0xFFFFFFFF or cd_size == 0xFFFFFFFF
                   or n_ent == 0xFFFF):
        z64_off = struct.unpack_from("<Q", tail, j + 8)[0]
        with http(url, rng=(z64_off, z64_off + 55)) as r:
            z = r.read()
        downloaded += len(z)
        if z[:4] == EOCD64_SIG:
            n_ent = struct.unpack_from("<Q", z, 32)[0]
            cd_size = struct.unpack_from("<Q", z, 40)[0]
            cd_off = struct.unpack_from("<Q", z, 48)[0]

    # 中央目录可能已经落在刚才那片尾部里，能省一次请求
    if cd_off >= tail_start and (cd_off + cd_size) <= total:
        cd = tail[cd_off - tail_start: cd_off - tail_start + cd_size]
    else:
        with http(url, rng=(cd_off, cd_off + cd_size - 1)) as r:
            cd = r.read()
        downloaded += len(cd)

    names = []
    p = 0
    while p + 46 <= len(cd) and cd[p:p + 4] == b"PK\x01\x02":
        nlen, elen, clen = struct.unpack_from("<HHH", cd, p + 28)
        names.append(cd[p + 46: p + 46 + nlen].decode("utf-8", "ignore"))
        p += 46 + nlen + elen + clen
    return names, downloaded, total, n_ent


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--targets", required=True, help="malicious_targets.jsonl")
    ap.add_argument("--probe-days", type=int, default=4,
                    help="抽查几个不同日期的归档")
    ap.add_argument("--mode", default="daily", choices=["daily", "hourly"])
    args = ap.parse_args()

    rows = []
    with open(args.targets, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    pass
    print(f"目标清单: {len(rows)} 条")

    # 按 first_seen 归到 UTC 日期；没有 first_seen 的退回 stored_at
    by_day = {}
    no_date = 0
    for r in rows:
        fs = r.get("first_seen") or 0
        if fs:
            d = datetime.datetime.fromtimestamp(
                int(fs), datetime.timezone.utc).strftime("%Y-%m-%d")
        elif r.get("stored_at"):
            d = r["stored_at"][:10]
        else:
            no_date += 1
            continue
        by_day.setdefault(d, []).append(r["sha256"])

    print(f"覆盖 {len(by_day)} 个不同日期，无日期 {no_date} 条")
    days = sorted(by_day, reverse=True)
    print(f"日期范围: {days[-1]} .. {days[0]}")
    print("\n样本最多的日期 Top 8:")
    for d in sorted(by_day, key=lambda k: -len(by_day[k]))[:8]:
        print(f"  {d}  {len(by_day[d])} 个")

    # 挑样本最多的几天来探
    probe = sorted(by_day, key=lambda k: -len(by_day[k]))[:args.probe_days]
    print(f"\n==== 探测 {len(probe)} 个归档 ({args.mode}) ====")
    ok_days = 0
    total_hit = total_want = 0
    for d in probe:
        url = f"{BASE}/{args.mode}/{d}.zip"
        want = set(by_day[d])
        try:
            names, dl, size, n_ent = zip_names_via_range(url)
        except urllib.error.HTTPError as e:
            print(f"  {d}  HTTP {e.code}  <- 归档不存在或已过保留期")
            continue
        except Exception as e:
            print(f"  {d}  失败 {type(e).__name__}: {e}")
            continue
        have = {n.split(".")[0].lower() for n in names}
        hit = len(want & have)
        ok_days += 1
        total_hit += hit
        total_want += len(want)
        print(f"  {d}  归档 {size/1e6:.0f} MB / {n_ent} 条  "
              f"只下载 {dl/1024:.0f} KiB  ->  命中 {hit}/{len(want)}")

    print("\n---- 结论 ----")
    if not ok_days:
        print("[!] 所有归档都取不到。datalake 这条路不通，只能改走 MalwareBazaar")
        print("    get_file API（需要 abuse.ch API key）。")
        return 1
    rate = total_hit * 100.0 / max(total_want, 1)
    print(f"可达归档 {ok_days}/{len(probe)}，抽查命中率 {rate:.1f}%")
    if rate >= 80:
        print("可行：按 first_seen 定位 daily 归档能把字节取回来。")
        print(f"预计全量成本：{len(by_day)} 次中央目录读取(每次约 50-200 KiB) "
              f"+ {len(rows)} 次单条 ranged GET。")
    elif rate >= 30:
        print("部分可行：命中率偏低。可能原因是 first_seen(VT 首次提交时间)与")
        print("MalwareBazaar 入库日期不是同一天。改法：对每个哈希探它前后 1-2 天。")
    else:
        print("[!] 命中率过低，说明日期对不上或归档内容与预期不符，需要换思路。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
