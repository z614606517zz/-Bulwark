#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把已建好的硬链接落实成真正的「移动」：校验目标完好，然后删掉源文件名。

为什么删源是安全的
----------------
目标目录里已经有指向同一份数据的硬链接。删掉源那个名字，删的是【名字】而不是
字节 —— 数据仍然可以从目标目录读到。全程不存在「只剩一份脆弱副本」的窗口，
这正是它优于「先复制再删除」的地方。

校验到什么程度，以及为什么不再多
----------------------------
安全条件只有一条：源名字消失后，目标仍然持有数据。硬链接满足，普通副本也满足。
唯一危险的情况是目标是个指回源的【符号链接】—— 而这里从头到尾只用过
New-Item -ItemType HardLink，没有创建过任何符号链接。所以「目标存在 + 长度一致」
就足够，而且很便宜。

之前用 PowerShell 写过两版都失败，原因记下来避免重犯：
  1) 第一版要求 FileInfo.LinkType 等于 'HardLink'。PS 5.1 对硬链接并不可靠地
     填充这个属性，结果会把每一条都误判成不安全、直接中止整个移动。
  2) 第二版去掉了 LinkType 但保留了抽样重算哈希，而报告只在最后一次性写出，
     跑起来像卡死。
  3) 第三版改成流式输出后仍然极慢 —— 10107 次 Get-Item 走了几分钟还没到第一个
     进度点。这台机器上有实时防护在逐个扫描这些恶意样本，每次文件访问都被拦一下。
     Python 的 os.stat 走的是最短路径，快得多。
"""

import argparse
import csv
import os
import sys
import time

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, OSError):
    pass


def log(report, msg):
    line = "[%s] %s" % (time.strftime("%H:%M:%S"), msg)
    print(line, flush=True)
    with open(report, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True, help="源目录树")
    ap.add_argument("--dst", required=True, help="目标目录树（已含硬链接）")
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--report", required=True)
    ap.add_argument("--execute", action="store_true",
                    help="不加这个参数只校验，不删任何东西")
    args = ap.parse_args()

    open(args.report, "w", encoding="utf-8").close()
    log(args.report, "manifest = %s" % args.manifest)
    log(args.report, "mode = %s" % ("VERIFY + DELETE SOURCE" if args.execute
                                    else "VERIFY ONLY"))

    rows = []
    with open(args.manifest, encoding="utf-8-sig", newline="") as f:
        for r in csv.DictReader(f):
            if r.get("sha256"):
                rows.append(r)
    log(args.report, "entries = %d" % len(rows))

    ready = []
    problems = []
    src_gone = 0
    t0 = time.time()

    for i, r in enumerate(rows, 1):
        name = r["sha256"] + (r.get("ext") or "")
        src = os.path.join(args.root, r["day"], name)
        dst = os.path.join(args.dst, r["day"], name)
        try:
            dsize = os.stat(dst).st_size
        except OSError:
            problems.append("DST-MISSING %s" % r["sha256"])
            continue
        try:
            want = int(r["bytes"])
        except (TypeError, ValueError):
            want = -1
        if want >= 0 and dsize != want:
            problems.append("DST-SIZE %s %d != %d" % (r["sha256"], dsize, want))
            continue
        if not os.path.exists(src):
            src_gone += 1
            continue
        ready.append((src, dsize))

        if i % 2000 == 0:
            el = time.time() - t0
            log(args.report, "  verified %d/%d  (%.0f/s)" % (i, len(rows), i / max(el, 0.001)))

    log(args.report, "ready to unlink = %d   source already gone = %d   problems = %d"
        % (len(ready), src_gone, len(problems)))

    if problems:
        log(args.report, "ABORTED: 目标目录不完整，源文件一个都没动。")
        for p in problems[:20]:
            log(args.report, "  " + p)
        return 2

    if not args.execute:
        log(args.report, "校验通过。加 --execute 才会删除源文件名。")
        return 0

    deleted = 0
    failed = 0
    freed = 0
    t1 = time.time()
    for src, size in ready:
        try:
            os.remove(src)
            deleted += 1
            freed += size
        except OSError as e:
            failed += 1
            if failed <= 10:
                problems.append("DEL-FAIL %s (%s)" % (src, e))
        if deleted % 2000 == 0 and deleted:
            log(args.report, "  unlinked %d/%d" % (deleted, len(ready)))

    log(args.report, "源文件名已删除 = %d   失败 = %d   耗时 %.0f 秒"
        % (deleted, failed, time.time() - t1))
    log(args.report, "解除链接的逻辑字节 = %.2f GB（数据仍可从目标目录读取）"
        % (freed / (1024.0 ** 3)))

    # 收尾核对：目标必须一个不少
    present = lost = 0
    for r in rows:
        p = os.path.join(args.dst, r["day"], r["sha256"] + (r.get("ext") or ""))
        if os.path.exists(p):
            present += 1
        else:
            lost += 1
    log(args.report, "目标仍在 = %d   丢失 = %d" % (present, lost))

    left = 0
    for sub in sorted(os.listdir(args.root)):
        p = os.path.join(args.root, sub)
        if os.path.isdir(p):
            left += sum(1 for x in os.listdir(p)
                        if os.path.isfile(os.path.join(p, x)))
    log(args.report, "源目录树剩余文件 = %d（应为已收录的 11201 个）" % left)
    for p in problems[:20]:
        log(args.report, "  " + p)
    log(args.report, "DONE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
