#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把情报服务器的 vt_reports 导出成 harvest_malicious.py 需要的目标清单
malicious_targets.jsonl，并按【真 PE】筛一遍。

为什么需要这一步
--------------
服务器只存结论不存字节（bulwark-datalake.py 把样本写临时文件、算完哈希上传就在
finally 里删掉）。所以训练静态模型时，服务器能给的是【标签】，字节要靠
harvest_malicious.py 再从 abuse.ch datalake 按哈希拉回来。而它要的目标清单里
必须有 pe_type 和 first_seen —— 这两个字段【不在 vt_reports 的列里】，只埋在
report 那一大坨 JSON 文本里：
    report.file.type_tag            peexe / pedll / elf / script ...
    report.file.type_description    "Win32 EXE" / "Win32 DLL" / ...
    report.file.first_submission_date   VT 首次收到的 unix 时间
    report.file.popular_threat_classification.suggested_threat_label   家族名
所以本脚本的实质工作是【把 report 里的这几个字段挖出来铺平】。

为什么必须筛 PE
--------------
实测这份档案里绝大多数不是 Windows PE：最近 300 条里 145 条明确是
.elf/.sh/.js/.vbs/.apk/.zip，另有 83 条没有扩展名但文件名是 mpsl / arm7 / m68k /
mips / ppc —— 全是 mirai 的 ELF。pe_features.py 只吃 MZ+PE，非 PE 全会在抽特征时
失败。与其让它们污染目标清单，不如在这里就分流出去：
non_pe_targets.jsonl 单独留一份，将来训 ELF/脚本模型时还能用，不丢数据。

两种数据源
---------
--from-server  走 HTTP。能拿到的上限是 /vt/reports 的 300 条（list_vt_reports
               写死 LIMIT 300）+ /vt/reports 里 silverfox 那 800 上限的全量清单
               （list_silverfox，实际 164 条，含比 300 条窗口更早的）。两边并集去重。
--from-db      直接读 cache.db，能拿到【全部 12898 条】。这是真正该用的模式，
               但要求你手上有服务器上那个 sqlite 文件。

用法
----
  # 从线上服务器导（受 300 条上限）
  python export_targets.py --from-server https://vt.bulwark.icu:8787 \
      --out "D:\\新建文件夹 (7)"

  # 从 cache.db 导全量（推荐）
  python export_targets.py --from-db /var/lib/bulwark-intel/cache.db \
      --out "D:\\新建文件夹 (7)"

  # 只要恶意判定、只要 EXE
  python export_targets.py --from-db ... --out ... --min-malicious 5 --only exe
"""

import argparse
import concurrent.futures as cf
import json
import os
import re
import sqlite3
import ssl
import sys
import urllib.error
import urllib.request

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, OSError):
    pass

HEX64 = re.compile(r"^[0-9a-f]{64}$")
UA = "bulwark-export-targets"

# VT 的 type_tag -> 我们的 pe_type。只认这两个是"能进 pe_features 的 PE"。
# peexe 覆盖 exe/sys/scr 等可执行体，pedll 覆盖 dll/ocx/cpl。
TAG_TO_PETYPE = {"peexe": "exe", "pedll": "dll"}


def log(msg):
    print(msg, flush=True)


def _ctx():
    """venv 里常常没有 CA 根，Windows 的 CPython 不用系统证书库。
    有 certifi 就用，没有退回默认 —— 但【绝不】关校验：这是在拉威胁情报，
    被换包等于把别人的结论当成自己的训练标签。"""
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def http_json(url, token=None, timeout=120):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    if token:
        req.add_header("Authorization", "Bearer " + token)
    with urllib.request.urlopen(req, timeout=timeout, context=_ctx()) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


# --------------------------------------------------------------- 字段挖掘
def dig(report, row):
    """从 report JSON 里挖出 pe_type / first_seen / family / size。

    report 可能是 dict，也可能是数据库里存的 JSON 字符串；两种都认。
    挖不到就返回空值，由调用方决定丢还是留 —— 这里不做静默兜底，
    因为"pe_type 猜错"会直接导致后面抽特征全失败，宁可显式为空。
    """
    if isinstance(report, str):
        try:
            report = json.loads(report)
        except (ValueError, TypeError):
            report = {}
    f = (report or {}).get("file") or {}

    tag = str(f.get("type_tag") or "").lower()
    pe_type = TAG_TO_PETYPE.get(tag, "")
    if not pe_type:
        # type_tag 偶尔缺失/是别的值，退到 type_tags 列表里找
        tags = [str(t).lower() for t in (f.get("type_tags") or [])]
        for t in ("peexe", "pedll"):
            if t in tags:
                pe_type = TAG_TO_PETYPE[t]
                break
    if not pe_type:
        # 最后看人类可读描述。DLL 判定必须放在 EXE 前面：
        # "Win32 DLL" 里也含 "Win32"，顺序反了会把所有 DLL 认成 EXE。
        desc = str(f.get("type_description") or "")
        magic = str(f.get("magic") or "")
        blob = (desc + " " + magic).upper()
        if "DLL" in blob:
            pe_type = "dll"
        elif "WIN32 EXE" in blob or "WIN64 EXE" in blob or "PE32" in blob:
            pe_type = "exe"

    fs = f.get("first_submission_date") or f.get("creation_date") or 0
    try:
        fs = int(fs)
    except (TypeError, ValueError):
        fs = 0

    ptc = f.get("popular_threat_classification") or {}
    fam = ""
    if isinstance(ptc, dict):
        fam = str(ptc.get("suggested_threat_label") or "")
    if not fam:
        fam = str(row.get("threat_label") or "")

    size = f.get("size") or 0
    try:
        size = int(size)
    except (TypeError, ValueError):
        size = 0

    return pe_type, fs, fam, size, tag


def make_target(row, report):
    pe_type, fs, fam, size, tag = dig(report, row)
    return {
        "sha256": row["sha256"],
        "md5": row.get("md5") or "",
        "sha1": row.get("sha1") or "",
        "name": row.get("name") or "",
        "verdict": row.get("verdict") or "",
        "malicious": int(row.get("malicious") or 0),
        "total_engines": int(row.get("total_engines") or 0),
        "threat_label": row.get("threat_label") or "",
        "silverfox": row.get("silverfox") or "",
        "stored_at": row.get("stored_at") or "",
        # ↓ 这四个是从 report 里挖出来的，harvest_malicious.py / build_features.py 要用
        "family": fam,
        "pe_type": pe_type,
        "first_seen": fs,
        "size": size,
        "vt_type_tag": tag,
    }


# --------------------------------------------------------------- 数据源
def rows_from_db(db_path, min_malicious):
    """全量模式。只读打开，绝不写服务器的库。"""
    uri = "file:%s?mode=ro" % db_path.replace("?", "%3f").replace("#", "%23")
    con = sqlite3.connect(uri, uri=True)
    con.row_factory = sqlite3.Row
    try:
        sql = ("SELECT sha256, md5, sha1, name, verdict, malicious, total_engines,"
               "       stored_at, threat_label, category, silverfox, report"
               "  FROM vt_reports")
        if min_malicious > 0:
            sql += " WHERE malicious >= %d" % int(min_malicious)
        for r in con.execute(sql):
            d = dict(r)
            yield d, d.pop("report", "")
    finally:
        con.close()


def rows_from_server(base, token, min_malicious, workers):
    """HTTP 模式。/vt/reports 的 reports 只有 300 条，silverfox 那份是全量(<=800)，
    两边并集能多捞一些更早的银狐样本。report 正文要逐个哈希再取。"""
    base = base.rstrip("/")
    data = http_json(base + "/vt/reports", token)
    stats = data.get("stats") or {}
    log("服务器档案: 总 %s / 恶意 %s / 可疑 %s / 银狐 %s"
        % (stats.get("total"), stats.get("malicious"),
           stats.get("suspicious"), stats.get("silverfox")))

    merged = {}
    for r in (data.get("reports") or []) + (data.get("silverfox") or []):
        sha = str(r.get("sha256") or "").lower()
        if not HEX64.match(sha):
            continue
        if min_malicious > 0 and int(r.get("malicious") or 0) < min_malicious:
            continue
        r["sha256"] = sha
        merged.setdefault(sha, r)

    log("HTTP 能见到 %d 条唯一哈希（/vt/reports 固定 LIMIT 300 + 银狐全量并集）。"
        % len(merged))
    log("要全部 %s 条必须用 --from-db 读 cache.db。" % stats.get("total"))

    def fetch(sha):
        try:
            d = http_json("%s/vt/report/%s" % (base, sha), token)
            return sha, d.get("report") or {}
        except urllib.error.HTTPError as e:
            return sha, ("__http_%d__" % e.code)
        except Exception as e:                      # 网络抖动不该中断整批
            return sha, ("__err_%s__" % type(e).__name__)

    got = 0
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for sha, rep in ex.map(fetch, list(merged)):
            got += 1
            if got % 25 == 0:
                log("  取 report %d/%d" % (got, len(merged)))
            if isinstance(rep, str):                # 取不到正文，仍然产出该行，
                rep = {}                            # 只是 pe_type/first_seen 会空
            yield merged[sha], rep


# --------------------------------------------------------------- 主流程
def main():
    ap = argparse.ArgumentParser()
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--from-server", metavar="URL",
                     help="情报服务器根地址，如 https://vt.bulwark.icu:8787")
    src.add_argument("--from-db", metavar="PATH", help="cache.db 路径（全量）")
    ap.add_argument("--out", required=True, help="输出目录")
    ap.add_argument("--token", default="", help="服务器 auth_token（配了才需要）")
    ap.add_argument("--min-malicious", type=int, default=0,
                    help="只导 VT 报毒数 >= N 的（默认 0 = 全导，含 suspicious）")
    ap.add_argument("--only", default="", choices=["", "exe", "dll"],
                    help="只导某一类 PE")
    ap.add_argument("--workers", type=int, default=6, help="HTTP 模式并发")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    pe_path = os.path.join(args.out, "malicious_targets.jsonl")
    non_path = os.path.join(args.out, "non_pe_targets.jsonl")
    sum_path = os.path.join(args.out, "export_summary.json")

    # 排他锁。这一步是被实测教出来的：同一个输出目录跑了两份本脚本，两边都用 "w"
    # 打开同一个 jsonl，各自从 0 开始 truncate 再按自己的偏移写，最后文件里是
    # 两份内容互相盖出来的碎片 —— 行数比摘要少一大截，而摘要本身却是完整的，
    # 非常难发现。所以宁可直接拒绝启动。
    lock_path = os.path.join(args.out, ".export_targets.lock")
    try:
        lock_fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        log("输出目录已有导出在跑（%s 存在）。" % lock_path)
        log("确认没有别的进程后删掉这个文件再重试。")
        return 3
    os.write(lock_fd, str(os.getpid()).encode())
    os.close(lock_fd)

    try:
        return run(args, pe_path, non_path, sum_path)
    finally:
        try:
            os.unlink(lock_path)
        except OSError:
            pass


def run(args, pe_path, non_path, sum_path):
    if args.from_db:
        if not os.path.isfile(args.from_db):
            log("找不到 %s" % args.from_db)
            return 2
        src_iter = rows_from_db(args.from_db, args.min_malicious)
        source = "db:" + args.from_db
    else:
        src_iter = rows_from_server(args.from_server, args.token or None,
                                    args.min_malicious, args.workers)
        source = "server:" + args.from_server

    n_pe = n_non = n_unknown = n_skip = 0
    by_type = {}
    by_family = {}
    with_fs = 0
    seen = set()

    # 一边流式读一边写，避免把 12898 份 report 全塞内存
    with open(pe_path, "w", encoding="utf-8", newline="\n") as fpe, \
         open(non_path, "w", encoding="utf-8", newline="\n") as fnon:
        for row, report in src_iter:
            sha = str(row.get("sha256") or "").lower()
            if not HEX64.match(sha) or sha in seen:
                n_skip += 1
                continue
            seen.add(sha)
            row["sha256"] = sha

            t = make_target(row, report)
            pt = t["pe_type"]

            if pt in ("exe", "dll"):
                if args.only and pt != args.only:
                    n_skip += 1
                    continue
                fpe.write(json.dumps(t, ensure_ascii=False) + "\n")
                n_pe += 1
                by_type[pt] = by_type.get(pt, 0) + 1
                if t["first_seen"]:
                    with_fs += 1
                fam = t["family"] or "(unknown)"
                by_family[fam] = by_family.get(fam, 0) + 1
            else:
                fnon.write(json.dumps(t, ensure_ascii=False) + "\n")
                n_non += 1
                tag = t["vt_type_tag"] or "(none)"
                if not t["vt_type_tag"]:
                    n_unknown += 1
                by_type[tag] = by_type.get(tag, 0) + 1

    top_fam = sorted(by_family.items(), key=lambda kv: -kv[1])[:25]
    summary = {
        "source": source,
        "min_malicious": args.min_malicious,
        "only": args.only or None,
        "pe_targets": n_pe,
        "non_pe": n_non,
        "no_type_info": n_unknown,
        "skipped": n_skip,
        "pe_type_mix": {k: v for k, v in by_type.items() if k in ("exe", "dll")},
        "type_tag_mix": by_type,
        "pe_with_first_seen": with_fs,
        "pe_families": len(by_family),
        "top_families": top_fam,
        "out_pe": pe_path,
        "out_non_pe": non_path,
    }
    with open(sum_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    log("")
    log("================ 导出结果 ================")
    log("PE 目标      : %d   -> %s" % (n_pe, pe_path))
    log("  exe %d / dll %d" % (by_type.get("exe", 0), by_type.get("dll", 0)))
    log("  带 first_seen : %d/%d   <- harvest 按这个定位归档日期" % (with_fs, n_pe))
    log("  家族数        : %d      <- train.py 分组切分靠这个防泄漏" % len(by_family))
    log("非 PE（另存）: %d   -> %s" % (n_non, non_path))
    log("  其中完全无类型信息: %d" % n_unknown)
    log("跳过         : %d" % n_skip)
    log("摘要         : %s" % sum_path)
    if top_fam:
        log("")
        log("PE 侧 Top 家族:")
        for fam, n in top_fam[:12]:
            log("  %-46s %d" % (fam[:46], n))
    if n_pe:
        log("")
        log("下一步：")
        log('  python ml\\tools\\harvest_malicious.py --targets "%s" \\' % pe_path)
        log('      --out "%s"' % os.path.join(args.out, "malicious_vectors.jsonl"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
