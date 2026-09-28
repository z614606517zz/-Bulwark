#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""按哈希从 abuse.ch datalake 取回恶意样本字节 -> 抽静态 PE 特征 -> 立刻丢弃字节。

为什么必须这么做
--------------
情报服务器只存 VT 报告，样本字节在采集时就删了（bulwark-datalake.py 的设计）。
要训静态 PE 模型就得把字节重新拉回来。而拉回来之后【绝不落盘】：

    活体恶意代码一个都不写到磁盘上。ranged GET 拿到的密文在内存里解密，
    抽完 2380 维特征立刻丢掉，全程没有临时文件。

这比服务端那套（写临时文件再删）更严格，因为这里跑在开发机上，磁盘上多一个
活体样本就多一份被误双击、被别的工具扫到、或被同步到云盘的机会。
本脚本从不执行样本，只读字节。

手法
----
1) 目标清单来自 vt_reports 导出（sha256 + first_seen + family + pe_type）。
2) 按 first_seen 的 UTC 日期分组，逐个 daily 归档处理。VT 的首次提交时间和
   MalwareBazaar 的入库日不一定是同一天（实测精确命中率约 80%），所以对没命中的
   哈希再探 ±1、±2 天。
3) 归档动辄 0.8~18 GB，绝不整包下载。用一个支持 seek 的 HTTP Range 文件对象喂给
   stdlib zipfile，它只会去读中央目录和你真正要的那一条 —— 实测枚举一个 1.5 GB
   归档的全部条目只花 257 KiB。
4) 条目是 ZipCrypto 加密（密码 infected），不是 AES，所以 stdlib 能直接解，
   不需要外部 7z。
5) 解出来的字节必须校验 sha256 == 条目名。这既防传输损坏，也防中间人换包 ——
   训练标签的可信度全压在这一步上。

用法
----
  python harvest_malicious.py --targets malicious_targets.jsonl \\
      --out malicious_vectors.jsonl
  python harvest_malicious.py --targets ... --out ... --only-exe
  python harvest_malicious.py --targets ... --out ... --day-window 2
"""

import argparse
import collections
import concurrent.futures as cf
import datetime
import hashlib
import json
import os
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "train"))
from pe_features import PEFeatureExtractor, FEATURE_DIM, SCHEMA_VERSION  # noqa: E402

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, OSError):
    pass

BASE = "https://datalake.abuse.ch/malware-bazaar"
UA = "Mozilla/5.0 bulwark-malicious-harvester"
ZIP_PW = b"infected"
MAX_SAMPLE = 64 * 1024 * 1024      # 与 pe_features 的上限一致；更大的样本直接跳过


def _ssl_ctx():
    """Windows 上的 CPython 不用系统证书库，venv 里没有 CA 根会直接
    CERTIFICATE_VERIFY_FAILED。用 certifi。绝不 verify_mode=CERT_NONE ——
    这是从公网拉恶意样本，被换包就等于把别人的载荷当成自己的训练标签。"""
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


SSL_CTX = _ssl_ctx()


# --------------------------------------------------------------- HTTP Range 文件
class HttpRangeFile:
    """把一个 HTTP 资源包装成可 seek 的只读文件对象，供 zipfile 使用。

    zipfile 会先跳到尾部找 EOCD、再读中央目录、最后跳到某条目的局部头。
    每次 seek 后的读取都变成一个 Range 请求，所以整包不会被下载。

    两个性能要点（第一版都踩了）：
      * 【连接复用】用一个常驻的 HTTPSConnection，而不是每次 urlopen。
        对 datalake 每发一个 Range 都重做一次 TLS 握手时，实测只有 2 个样本/分钟，
        绝大部分时间花在握手上而非传输。
      * 【足够大的预读】zipfile 解析头部时会发很多几字节的小读。预读太小就会被
        放大成一串独立请求；1 MiB 能让整个中央目录一次到位。
    """

    def __init__(self, url, readahead=1 << 20, timeout=60, retries=3):
        self.url = url
        self.readahead = readahead
        self.timeout = timeout
        self.retries = retries
        self.pos = 0
        self._buf = b""
        self._buf_start = -1
        self.bytes_fetched = 0
        self.requests = 0

        u = urllib.parse.urlsplit(url)
        self._host = u.netloc
        self._path = u.path + (("?" + u.query) if u.query else "")
        self._conn = None
        self.size = self._probe_size()

    # -- 底层：一个常驻连接，坏了就重建 --
    def _connect(self):
        import http.client
        self._conn = http.client.HTTPSConnection(
            self._host, timeout=self.timeout, context=SSL_CTX)

    def _fetch(self, first, last):
        last_err = None
        for attempt in range(self.retries):
            try:
                if self._conn is None:
                    self._connect()
                self._conn.request("GET", self._path, headers={
                    "User-Agent": UA,
                    "Range": "bytes=%d-%d" % (first, last),
                    "Accept-Encoding": "identity",
                    "Connection": "keep-alive",
                })
                resp = self._conn.getresponse()
                body = resp.read()          # 必须读完，否则连接不能复用
                self.requests += 1
                if resp.status in (200, 206):
                    self.bytes_fetched += len(body)
                    return resp, body
                if resp.status in (404, 410, 416):
                    raise urllib.error.HTTPError(
                        self.url, resp.status, resp.reason, resp.headers, None)
                last_err = RuntimeError("HTTP %d" % resp.status)
            except urllib.error.HTTPError:
                raise
            except Exception as e:
                last_err = e
                try:
                    if self._conn:
                        self._conn.close()
                except Exception:
                    pass
                self._conn = None           # 下一轮重连
                time.sleep(0.5 * (attempt + 1))
        raise last_err

    def _probe_size(self):
        resp, _ = self._fetch(0, 0)
        cr = resp.getheader("Content-Range", "")
        if "/" in cr:
            return int(cr.rsplit("/", 1)[1])
        raise RuntimeError("服务器没给 Content-Range，无法确定归档大小")

    # -- 文件对象协议 --
    def seekable(self):
        return True

    def tell(self):
        return self.pos

    def seek(self, off, whence=0):
        if whence == 0:
            self.pos = off
        elif whence == 1:
            self.pos += off
        else:
            self.pos = self.size + off
        self.pos = max(0, min(self.pos, self.size))
        return self.pos

    def read(self, n=-1):
        if n is None or n < 0:
            n = self.size - self.pos
        n = min(n, self.size - self.pos)
        if n <= 0:
            return b""

        out = bytearray()
        while n > 0:
            if self._buf_start <= self.pos < self._buf_start + len(self._buf):
                off = self.pos - self._buf_start
                take = min(n, len(self._buf) - off)
                out += self._buf[off:off + take]
                self.pos += take
                n -= take
                continue
            # 缓冲没覆盖到：大读直接取，小读多取一些备用
            want = max(n, self.readahead)
            first = self.pos
            last = min(self.size - 1, first + want - 1)
            _resp, chunk = self._fetch(first, last)
            if not chunk:
                break
            self._buf = chunk
            self._buf_start = first
        return bytes(out)

    def prefetch(self, offset, length):
        """把 [offset, offset+length) 一次性取进缓冲。

        为什么需要它：zipfile 读一个条目时是顺序小块读，靠 1 MiB 预读会把一个
        5 MB 的样本拆成 5 次独立 Range 请求。到 abuse.ch 的单程延迟不低，
        这些往返就是主要开销。既然从中央目录里已经知道该条目的确切位置和长度，
        就一次请求全部拿回来，往返数从 5~10 次压到 1 次。
        """
        if length <= 0:
            return
        first = max(0, offset)
        last = min(self.size - 1, first + length - 1)
        if last < first:
            return
        if (self._buf_start <= first
                and last < self._buf_start + len(self._buf)):
            return                       # 已经在缓冲里
        _resp, chunk = self._fetch(first, last)
        if chunk:
            self._buf = chunk
            self._buf_start = first

    def close(self):
        self._buf = b""
        try:
            if self._conn:
                self._conn.close()
        except Exception:
            pass
        self._conn = None


# --------------------------------------------------------------- 目标清单
def load_targets(path, only_exe):
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if len(str(r.get("sha256", ""))) != 64:
                continue
            if only_exe and r.get("pe_type") != "exe":
                continue
            rows.append(r)
    return rows


def target_day(r):
    fs = r.get("first_seen") or 0
    if fs:
        return datetime.datetime.fromtimestamp(
            int(fs), datetime.timezone.utc).strftime("%Y-%m-%d")
    s = r.get("stored_at") or ""
    return s[:10] if len(s) >= 10 else ""


def shift_day(d, delta):
    try:
        dt = datetime.datetime.strptime(d, "%Y-%m-%d")
    except ValueError:
        return ""
    return (dt + datetime.timedelta(days=delta)).strftime("%Y-%m-%d")


# --------------------------------------------------------------- 主流程
class Tee:
    """同时写终端和日志文件，UTF-8 落盘。

    刻意不靠 shell 重定向：PowerShell 的 `>` 会按 UTF-16 写文件、还会被控制台
    代码页干扰，之前那版日志读出来全是乱码，进程被终止时也看不到最后状态。
    """

    def __init__(self, path):
        self.f = open(path, "a", encoding="utf-8", buffering=1)

    def write(self, s):
        try:
            sys.__stdout__.write(s)
        except Exception:
            pass
        try:
            self.f.write(s)
        except Exception:
            pass

    def flush(self):
        try:
            sys.__stdout__.flush()
        except Exception:
            pass
        try:
            self.f.flush()
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--targets", required=True)
    ap.add_argument("--out", required=True, help="输出 JSONL：元数据 + 特征向量")
    ap.add_argument("--log", default="", help="日志文件(UTF-8，自己写，不靠 shell 重定向)")
    ap.add_argument("--progress", default="",
                    help="心跳文件：每完成一个归档就覆盖写一次当前进度")
    ap.add_argument("--mode", default="daily", choices=["daily", "hourly"])
    ap.add_argument("--day-window", type=int, default=2,
                    help="精确日期没命中时，向前后各探几天")
    ap.add_argument("--only-exe", action="store_true",
                    help="只取 peexe（先训纯 EXE 模型时用）")
    ap.add_argument("--limit", type=int, default=0, help="最多处理多少个目标(0=全部)")
    ap.add_argument("--workers", type=int, default=8,
                    help="并发归档数。瓶颈是网络往返而非带宽，8 条基本够；"
                         "调太高对 abuse.ch 不友好")
    args = ap.parse_args()

    if args.log:
        sys.stdout = Tee(args.log)
        print(f"\n\n===== 启动 {time.strftime('%Y-%m-%d %H:%M:%S')} =====")

    rows = load_targets(args.targets, args.only_exe)
    if args.limit:
        rows = rows[:args.limit]
    by_sha = {r["sha256"].lower(): r for r in rows}
    print(f"目标: {len(by_sha)} 个"
          f"{'（只 EXE）' if args.only_exe else ''}  特征维度 {FEATURE_DIM}")

    # 断点续跑：已经抽好的跳过
    done = set()
    if os.path.exists(args.out):
        with open(args.out, encoding="utf-8") as f:
            for line in f:
                try:
                    done.add(json.loads(line)["sha256"])
                except Exception:
                    pass
        print(f"已完成 {len(done)} 个，续跑剩余 {len(by_sha) - len(done)} 个")

    pending = {s: r for s, r in by_sha.items() if s not in done}
    outf = open(args.out, "a", encoding="utf-8")

    stats = collections.Counter()
    t0 = time.time()
    net = [0]
    lock = threading.Lock()

    # 每个线程一个 PEFeatureExtractor：里面的 FeatureHasher 是有状态对象，
    # 多线程共用一个不安全。
    tls = threading.local()

    def extractor():
        if not hasattr(tls, "ex"):
            tls.ex = PEFeatureExtractor()
        return tls.ex

    def do_archive(day, want, mode):
        """处理一个归档。并发单位取「归档」而不是「样本」：中央目录只读一次，
        同一天的几十上百个样本共用一条连接，摊掉了绝大部分往返开销。"""
        ex_t = extractor()
        url = f"{BASE}/{mode}/{day}.zip"
        try:
            rf = HttpRangeFile(url)
            zf = zipfile.ZipFile(rf)
            names = zf.namelist()
        except urllib.error.HTTPError as e:
            with lock:
                stats["archive_http_%d" % e.code] += 1
            return day, 0, len(want), f"HTTP {e.code}"
        except Exception as e:
            with lock:
                stats["archive_fail"] += 1
            return day, 0, len(want), f"{type(e).__name__}"

        name_of = {}
        for n in names:
            h = n.split("/")[-1].split(".")[0].lower()
            if len(h) == 64:
                name_of[h] = n

        hit = 0
        note = collections.Counter()
        for sha in want:
            n = name_of.get(sha)
            if not n:
                note["miss"] += 1
                continue
            try:
                info = zf.getinfo(n)
                if info.file_size > MAX_SAMPLE:
                    note["toobig"] += 1
                    with lock:
                        stats["too_big"] += 1
                        pending.pop(sha, None)
                    continue
                # 局部头 + 压缩数据一把取回，避免被拆成一串小 Range 请求。
                # +4096 覆盖局部头、文件名、extra 字段和 ZipCrypto 的 12 字节头。
                rf.prefetch(info.header_offset, info.compress_size + 4096)
                data = zf.read(n, pwd=ZIP_PW)   # 字节只在内存
            except Exception:
                with lock:
                    stats["read_fail"] += 1
                continue

            if hashlib.sha256(data).hexdigest() != sha:
                # 内容与条目名不符：可能传输损坏，也可能被换包。宁可丢掉，
                # 也不能让来源不明的载荷进训练集当正样本。
                note["badhash"] += 1
                with lock:
                    stats["hash_mismatch"] += 1
                del data
                continue
            if not ex_t.is_pe(data):
                note["notpe"] += 1
                with lock:
                    stats["not_pe"] += 1
                    pending.pop(sha, None)
                del data
                continue
            try:
                vec = ex_t.feature_vector(data)
            except Exception:
                with lock:
                    stats["feat_fail"] += 1
                del data
                continue
            finally:
                del data                        # 尽早释放活体字节

            r = by_sha[sha]
            line = json.dumps({
                "sha256": sha, "label": "malicious",
                "pe_type": r.get("pe_type", ""),
                "family": r.get("family", ""),
                "category": r.get("category", ""),
                "silverfox": bool(r.get("silverfox")),
                "malicious": r.get("malicious", 0),
                "total_engines": r.get("total_engines", 0),
                "first_seen": r.get("first_seen", 0),
                "archive_day": day, "schema_ver": SCHEMA_VERSION,
                "vec": [round(float(x), 6) for x in vec],
            }, ensure_ascii=False) + "\n"
            with lock:
                outf.write(line)
                pending.pop(sha, None)
                stats["ok"] += 1
                hit += 1
        with lock:
            outf.flush()
            net[0] += rf.bytes_fetched
        rf.close()
        tail = "  ".join(f"{k} {v}" for k, v in note.items() if v)
        return day, hit, len(want), tail

    # 逐轮扩大日期窗口：先全部按精确日期扫一遍，再拿没命中的探 ±1、±2 …
    for delta in [0] + [d for k in range(1, args.day_window + 1) for d in (-k, k)]:
        if not pending:
            break
        buckets = collections.defaultdict(list)
        for sha, r in list(pending.items()):
            d = shift_day(target_day(r), delta)
            if d:
                buckets[d].append(sha)
        if not buckets:
            continue
        print(f"\n==== 日期偏移 {delta:+d} 天：{len(buckets)} 个归档，"
              f"待取 {len(pending)} 个样本  (并发 {args.workers}) ====", flush=True)

        # 样本多的日期先做：早点拿到大头，也让慢的大归档尽早开始
        order = sorted(buckets, key=lambda k: -len(buckets[k]))
        with cf.ThreadPoolExecutor(max_workers=args.workers) as pool:
            futs = {}
            for day in order:
                want = [s for s in buckets[day] if s in pending]
                if want:
                    futs[pool.submit(do_archive, day, want, args.mode)] = day
            for fut in cf.as_completed(futs):
                try:
                    day, hit, n_want, tail = fut.result()
                except Exception as e:
                    print(f"  [{futs[fut]}] 线程异常 {type(e).__name__}: {e}",
                          flush=True)
                    continue
                el = time.time() - t0
                print(f"  {day}  命中 {hit}/{n_want}"
                      f"{'  ' + tail if tail else ''}"
                      f"  |  累计 {stats['ok']}/{len(by_sha)}"
                      f"  流量 {net[0]/1e6:.0f} MB"
                      f"  {stats['ok']/max(el,1)*60:.0f}/min", flush=True)
                if args.progress:
                    # 覆盖写一个小 JSON。进程被杀时最后一次心跳还在，
                    # 比翻日志尾部可靠（日志可能正卡在缓冲里）。
                    try:
                        tmp = args.progress + ".tmp"
                        with open(tmp, "w", encoding="utf-8") as pf:
                            json.dump({
                                "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                                "extracted": stats["ok"],
                                "targets": len(by_sha),
                                "pending": len(pending),
                                "delta_day": delta,
                                "last_archive": day,
                                "net_mb": round(net[0] / 1e6, 1),
                                "rate_per_min": round(stats["ok"] / max(el, 1) * 60, 1),
                                "elapsed_min": round(el / 60, 1),
                            }, pf, ensure_ascii=False)
                        os.replace(tmp, args.progress)
                    except OSError:
                        pass

    outf.close()
    net_bytes = net[0]
    el = time.time() - t0
    print("\n================ 抓取结束 ================")
    print(f"成功抽取特征 : {stats['ok']} / {len(by_sha)}")
    print(f"仍未取到     : {len(pending)}")
    print(f"网络流量     : {net_bytes/1e6:.0f} MB（样本字节从未落盘）")
    print(f"耗时         : {el/60:.1f} 分钟")
    print(f"输出         : {args.out}")
    other = {k: v for k, v in stats.items() if k != "ok"}
    if other:
        print(f"异常明细     : {other}")
    if pending:
        ex_list = list(pending)[:3]
        print(f"\n未取到的样本多半是 MalwareBazaar 归档里本就没有（VT 有报告不等于"
              f"MB 收录过），或已过保留期。例: {[s[:12] for s in ex_list]}")
        print("要继续补可以加大 --day-window，或改用 MalwareBazaar get_file API"
              "（需要 abuse.ch API key）。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
