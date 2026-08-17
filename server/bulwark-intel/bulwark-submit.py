#!/usr/bin/env python3
"""Work the manual-submission queue on a collector node.

The dashboard's upload page only does two things per file: stream the bytes into
`submit-spool/inbox` and write a record next to them. Everything after that happens
here, driven by bulwark-submit.timer (every 3 minutes) and bulwark-submit.path (the
moment a new record lands, so the first pass is not up to 3 minutes late).

Why the query is NOT done in the upload request:
  * VirusTotal is paced at a couple of calls a minute on this node. A folder of 500
    files answered inline would hold 500 browser connections open for hours.
  * A verdict often does not exist yet. When VT has never seen a sample, the sample
    is submitted and the analysis takes minutes -- there is nothing to return at
    upload time, so the request would have to block or lie.
  * Progress has to survive navigation. The dashboard's nav links are real hrefs, so
    switching pages is a full document load and any progress held in JS is gone. The
    queue on disk IS the progress, which is why the page can be closed and reopened.

Order of questions per file, cheapest and most authoritative first:
  1. the MASTER, cache-only  -- costs nothing upstream, and the master's archive is a
     superset of ours (we push to it, it never pushes back). If it already has the
     file, we are done without spending a VT call.
  2. this node's own /vt/lookup -- shared cache first, then VT if needed.
  3. only if VT genuinely has no record: submit the bytes, then poll the analysis on
     later passes.

Every VT-touching call goes through the local bulwark-intel service. Never straight
to VirusTotal: the key pool, the cooldowns and the daily quota ledger all live there,
and a second caller doing its own accounting would make both wrong.
"""
try:
    import fcntl
except ImportError:  # pragma: no cover - Windows 上没有,只影响本机演练
    # 这个守卫的唯一目的是让这份代码能在非 Linux 上被 import 和测试。锁只在 main()
    # 里用到(见那里的 None 分支),Linux 上行为完全不变。
    # 之所以值得加:解压别人给的压缩包是这份文件里风险最高的一段,而在这个守卫之前,
    # 整个模块在开发机上连 import 都做不到 —— 也就一行都测不了。
    fcntl = None
import hashlib
import json
import os
import shutil
import ssl
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from datetime import datetime, timedelta, timezone

CONFIG_PATH = os.environ.get("BULWARK_INTEL_CONFIG", "/etc/bulwark-intel/config.json")
STATE_DIR = os.environ.get("BULWARK_STATE_DIR", "/var/lib/bulwark-intel")
SPOOL = os.path.join(STATE_DIR, "submit-spool")
INBOX = os.path.join(SPOOL, "inbox")
ITEMS = os.path.join(SPOOL, "items")
# Scratch space for the external extractor. Deliberately inside the spool rather than
# /tmp: the unit has ReadWritePaths=/var/lib/bulwark-intel, and this is where the disk
# budget is measured. Emptied on every pass, so a killed worker leaves no debris.
EXPAND = os.path.join(SPOOL, "expand")
LOCK = os.path.join(SPOOL, ".worker.lock")
TS_FMT = "%Y-%m-%dT%H:%M:%SZ"

# Terminal states: an item in one of these is never looked at again (except by the
# retention sweep). Kept as one list so "is this finished?" has exactly one answer.
# `expanded` is terminal for the CONTAINER: an archive is not a sample, so it is never
# queried or submitted -- the files it produced carry on as items of their own.
FINAL = ("done", "failed", "skipped", "expanded")

# Which uploads count as archives. Both the name AND the magic have to agree, because
# each on its own gets it wrong in a way that matters:
#   * extension alone would expand a .docx / .jar / .apk / .xlsx -- those are all zips,
#     and they are the sample being submitted, not a bag of samples.
#   * magic alone would do the same, plus it would expand anything a user happened to
#     name .bin that is internally a zip.
# So a file is only expanded when its name says "archive" and its first bytes agree.
ARCHIVE_EXTS = (
    (".tar.gz", "tar"), (".tar.bz2", "tar"), (".tar.xz", "tar"), (".tgz", "tar"),
    (".tbz2", "tar"), (".txz", "tar"), (".tar", "tar"),
    (".zip", "zip"), (".7z", "7z"), (".rar", "rar"),
    (".gz", "gz"), (".bz2", "bz2"), (".xz", "xz"),
)
ARCHIVE_MAGIC = (
    (b"PK\x03\x04", "zip"), (b"PK\x05\x06", "zip"), (b"PK\x07\x08", "zip"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07\x00", "rar"), (b"Rar!\x1a\x07\x01", "rar"),
    (b"\x1f\x8b", "gz"), (b"BZh", "bz2"), (b"\xfd7zXZ\x00", "xz"),
)
# What this python can open by itself. Everything else needs the external tool.
NATIVE_KINDS = ("zip",)
# 可用环境变量覆盖,理由和 STATE_DIR 一样:一条只能在生产环境上跑到的代码路径,等于
# 一条没测过的代码路径。7z 那条分支处理的正是「解压别人给的加密压缩包」,它必须能在
# 开发机上被真的跑一遍。
SEVENZIP = os.environ.get("BULWARK_7Z", "/usr/bin/7z")
# Read in chunks. The unit is capped at MemoryMax=192M, so a member is never held in
# memory -- a 600 MB entry read with .read() would get the worker OOM-killed mid-pass.
CHUNK = 1024 * 1024

# How long to wait before looking at an item again. Deliberately SHORTER than the
# 3-minute timer interval: if it were also 3 minutes, the timer's AccuracySec jitter
# could land a pass at 2m50s, find nothing due, and push the real re-check out to 6
# minutes -- quietly halving the cadence that was asked for. The margin costs nothing
# because being "due" only means eligible, not guaranteed a VT call.
RETRY_MIN = 2
# A refused submission is different: something upstream said no, so back off further.
SUBMIT_RETRY_MIN = 5
# VirusTotal being down or rate-limited is not going to clear in two minutes, and every
# retry costs a VT call. Waiting longer here is what keeps an outage from burning the
# daily quota on "still unavailable"; the per-pass budget caps the damage either way.
DEGRADED_RETRY_MIN = 10


def log(*a):
    print("[submit %s]" % datetime.now(timezone.utc).strftime("%H:%M:%S"), *a, flush=True)


def now_utc():
    return datetime.now(timezone.utc)


def iso(dt=None):
    return (dt or now_utc()).strftime(TS_FMT)


def parse_iso(s):
    try:
        return datetime.strptime(str(s).strip(), TS_FMT).replace(tzinfo=timezone.utc)
    except Exception:
        return None


def load_json(path, default=None):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {} if default is None else default


def cfg():
    return load_json(CONFIG_PATH, {})


def ucfg(c):
    """Upload/queue settings. Same block the dashboard reads, so the page's stated
    limits and the worker's actual behaviour cannot drift apart."""
    d = ((c.get("dashboard") or {}).get("upload") or {})
    return {
        "enabled": bool(d.get("enabled", True)),
        "allow_submit": bool(d.get("allow_vt_submit", True)),
        # VT-touching operations per pass. The node paces VT at ~2 calls/min and a
        # pass happens every 3 minutes, so 6 is "keep up with the pacing, never
        # outrun it". Master cache-only checks are free and are NOT counted here.
        "max_vt_per_pass": int(d.get("max_vt_per_pass", 6) or 6),
        # Wall clock, not just a call count. A single sample may be up to VirusTotal's
        # 650 MB limit, and streaming six of those to VT in one pass can outlast the
        # unit's TimeoutStartSec -- systemd would then SIGTERM the worker in the middle
        # of an upload. Stopping between items instead means the next pass picks up
        # cleanly; nothing is lost either way, but this way nothing is interrupted.
        "max_pass_seconds": int(d.get("max_pass_seconds", 900) or 900),
        # Master cache-only checks cost no VT quota, but the master rate-limits per IP
        # and this node is not on its whitelist. 12 per pass against a 3-minute timer is
        # ~240/hour, which stays under the master's hourly allowance even if every pass
        # is full. Set higher only after whitelisting this node there.
        "max_master_per_pass": int(d.get("max_master_per_pass", 12) or 12),
        # After this many refusals, stop waiting on the master and let VT answer. Being
        # thrifty with quota must not turn into never producing a verdict.
        "master_max_tries": int(d.get("master_max_tries", 3) or 3),
        "master_url": str(d.get("master_url", "https://vt.bulwark.icu:8787")).rstrip("/"),
        "master_token": str(d.get("master_token", "") or ""),
        "ask_master_first": bool(d.get("ask_master_first", True)),
        # Sample bytes are deleted as soon as they are no longer needed; this is the
        # backstop for anything that never reached a terminal state.
        "bytes_max_hours": float(d.get("bytes_max_hours",
                                       c.get("upload_retention_hours", 24) or 24)),
        # The records outlive the bytes on purpose: they are the behaviour history the
        # page shows, and they are tiny.
        "keep_days": float(d.get("keep_days", 7) or 7),
        "max_attempts": int(d.get("max_attempts", 60) or 60),
        # ---- 压缩包自动解压 ------------------------------------------------- #
        # 同一个 max_upload_mb:包里解出来的文件和直接上传的文件走的是同一条送检
        # 路径,上限必须是同一个数,否则会解出一个几分钟后才在提交时被拒的文件。
        "max_mb": int(d.get("max_upload_mb", 650) or 650),
        "archive_expand": bool(d.get("archive_expand", True)),
        # 空字符串在最前面:大多数压缩包没有密码,先拿 infected 去试会让每一个成员都
        # 白走一次失败的解密。infected 是恶意样本分发的事实标准口令(MalwareBazaar、
        # 各家沙箱都用它)。
        "archive_passwords": [str(p) for p in
                              (d.get("archive_passwords") or ["", "infected"])],
        # 三道防线针对的是同一件事的三种形态:条目数挡「10 万个空文件」,单条大小挡
        # 「一个 100 GB 的成员」,总量挡「1 MB 解出 40 GB」的压缩炸弹。
        "archive_max_entries": int(d.get("archive_max_entries", 2000) or 2000),
        "archive_max_total_mb": int(d.get("archive_max_total_mb", 4096) or 4096),
        # 解压后总量 / 压缩包本身大小。正常的样本包在 2~20 倍,炸弹是几千到上百万倍。
        "archive_ratio_max": float(d.get("archive_ratio_max", 500) or 500),
        "archive_use_7z": bool(d.get("archive_use_7z", True)),
        "archive_timeout": int(d.get("archive_timeout", 600) or 600),
        # 解压是要落盘的,必须给磁盘留底 —— 和上传端同一个数。
        "disk_floor_mb": int(d.get("disk_floor_mb", 4096) or 4096),
    }


# The local service is on loopback with a self-signed certificate; there is no
# middle to be in. The master is a real hostname with a real certificate and IS
# verified -- see master_lookup().
_LOOPBACK = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
_LOOPBACK.check_hostname = False
_LOOPBACK.verify_mode = ssl.CERT_NONE

_SVC = {"base": None}


def svc_base(c):
    """Probe the local intel service instead of hard-coding the scheme.

    The master terminates TLS itself; node 245 serves plain HTTP on the same port.
    Guessing wrong yields connection errors that read exactly like "the service is
    down", which has already cost one wasted investigation elsewhere in this tree.
    """
    if _SVC["base"]:
        return _SVC["base"]
    explicit = (c.get("harvest", {}) or {}).get("service_url")
    port = int(c.get("listen_port", 8787) or 8787)
    cands = ([str(explicit).rstrip("/")] if explicit else []) + [
        "https://127.0.0.1:%d" % port, "http://127.0.0.1:%d" % port]
    for b in cands:
        try:
            req = urllib.request.Request(b + "/health")
            with urllib.request.urlopen(req, timeout=8, context=_LOOPBACK) as r:
                if r.status == 200:
                    _SVC["base"] = b
                    return b
        except Exception:
            continue
    return None


def _auth_headers(c):
    """The local service only demands a token when one is configured. Sending it
    when it exists means this keeps working if the node is ever locked down, and
    sending nothing when it does not keeps working today."""
    tok = str(c.get("auth_token", "") or "").strip()
    return {"Authorization": "Bearer " + tok} if tok else {}


def http_json(url, payload, headers, timeout, ctx=None, raw=None, ctype=None):
    data = raw if raw is not None else (
        json.dumps(payload).encode("utf-8") if payload is not None else None)
    h = dict(headers or {})
    h["Content-Type"] = ctype or "application/json"
    req = urllib.request.Request(url, data=data, headers=h,
                                 method="POST" if data is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read().decode("utf-8", "replace")
            try:
                return r.status, json.loads(body)
            except Exception:
                return r.status, {"error": "non-JSON response"}
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8", "replace"))
        except Exception:
            return e.code, {}
    except Exception as e:
        return 0, {"error": "%s: %s" % (type(e).__name__, str(e)[:160])}


# --------------------------------------------------------------------------- #
#  records                                                                    #
# --------------------------------------------------------------------------- #
def rec_path(item_id, where=ITEMS):
    return os.path.join(where, item_id + ".json")


def bin_path(item_id, where=ITEMS):
    return os.path.join(where, item_id + ".bin")


def save_rec(rec, where=ITEMS):
    """Atomic replace, mode 644: the worker runs as root and the dashboard runs as
    bulwarkintel, which has to be able to read these to draw the page."""
    p = rec_path(rec["id"], where)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(rec, f, ensure_ascii=False)
    os.replace(tmp, p)
    try:
        os.chmod(p, 0o644)
    except OSError:
        pass


def note(rec, to_state, why=""):
    """Advance state and keep the trail. The history is the "行为数据" the page shows;
    it is also the only way to answer "why is this file still pending" after the fact.
    Capped so a file that retries for days cannot grow its record without bound."""
    frm = rec.get("state", "")
    rec["state"] = to_state
    rec["last_at"] = iso()
    h = rec.setdefault("history", [])
    h.append({"at": rec["last_at"], "from": frm, "to": to_state, "note": why[:200]})
    if len(h) > 40:
        del h[:len(h) - 40]


def drop_bytes(rec, why):
    """Delete the sample bytes. Called the moment they stop being needed -- a verdict
    is in, or VT has accepted the upload."""
    if rec.get("bytes_gone"):
        return
    p = rec.get("bin") or bin_path(rec["id"])
    try:
        if os.path.isfile(p):
            n = os.path.getsize(p)
            os.remove(p)
            rec["bytes_gone"] = True
            rec["bytes_gone_why"] = why
            rec["bytes_freed"] = n
        else:
            rec["bytes_gone"] = True
            rec["bytes_gone_why"] = why + " (already absent)"
    except OSError as e:
        rec["bytes_error"] = str(e)[:120]


# --------------------------------------------------------------------------- #
#  the three questions                                                        #
# --------------------------------------------------------------------------- #
def master_lookup(u, sha):
    """Ask the master whether it already has this hash. Cache-only: no upstream spend.

    lookupOnly is the master's own documented contract for "answer from what you
    have, never call a paid provider". Sending cacheOnly and X-Cache-Only too is
    belt-and-braces against an older build on the far side.

    TLS is verified here (unlike the loopback call): this one crosses the internet.
    """
    if not u["master_url"]:
        return None, "no master url configured"
    headers = {"X-Cache-Only": "1"}
    if u["master_token"]:
        headers["Authorization"] = "Bearer " + u["master_token"]
    st, body = http_json(u["master_url"] + "/v1/reputation/hash",
                         {"sha256": sha, "lookupOnly": True, "cacheOnly": True},
                         headers, 25, ctx=None)
    # 429 / transport failure is NOT "the master has no record". Recording it as a miss
    # would fall straight through to VirusTotal and spend the quota this step exists to
    # save -- so it is reported as RETRY and the item asks again on a later pass.
    if st == 429 or st == 0 or st >= 500:
        return None, "RETRY master 暂时答不了 (HTTP %s)" % st
    if st != 200 or not isinstance(body, dict):
        return None, "master http %s %s" % (st, str(body.get("error", ""))[:80]
                                            if isinstance(body, dict) else "")
    # Accept both spellings: the master's summary uses totalEngines, other shapes in
    # this codebase use total_engines.
    tot = body.get("totalEngines")
    if tot is None:
        tot = body.get("total_engines")
    verdict = str(body.get("verdict") or "").lower()
    ok = bool(body.get("querySucceeded"))
    # A cache MISS also answers 200. Requiring a real signal is what keeps "the master
    # has never seen this" from being recorded as "the master says it is unknown/clean",
    # which would skip the VT step and leave the file permanently unjudged.
    has = ok and (int(tot or 0) > 0 or verdict in ("malicious", "suspicious", "clean"))
    if not has:
        return None, "master has no record"
    return {"verdict": verdict or "unknown",
            "malicious": int(body.get("malicious") or 0),
            "total_engines": int(tot or 0),
            "threat_label": body.get("threatLabel") or body.get("threat_label") or "",
            "source": body.get("source") or "master",
            "fetched_at": body.get("fetchedAt") or body.get("fetched_at") or ""}, ""


def verdict_of(report):
    """Read "n of m engines" and a conclusion out of a report.

    Both shapes have to be handled: a normal VT answer puts the numbers in
    file.last_analysis_stats, while a degraded answer (VT unreachable, secondary
    sources replied) only has the sources array. Reading just the first shape makes a
    degraded report render as a confident 0/0 clean -- that is reporting "we could not
    ask" as "there is nothing wrong".
    """
    f = (report or {}).get("file") or {}
    stats = f.get("last_analysis_stats") or {}
    if stats:
        mal = int(stats.get("malicious", 0) or 0)
        susp = int(stats.get("suspicious", 0) or 0)
        tot = sum(int(v or 0) for v in stats.values())
        ptc = f.get("popular_threat_classification") or {}
        label = ptc.get("suggested_threat_label", "") if isinstance(ptc, dict) else ""
        v = "malicious" if mal >= 5 else ("suspicious" if (mal or susp) else "clean")
        return (v, mal, tot, label, f.get("meaningful_name") or "",
                f.get("type_tag") or "")
    ok = [s for s in ((report or {}).get("sources") or []) if s.get("querySucceeded")]
    rated = [s for s in ok if int(s.get("total_engines") or 0) > 0]
    best = max(rated, key=lambda s: int(s.get("malicious") or 0)) if rated else {}
    vs = [s.get("verdict") for s in ok]
    v = ("malicious" if "malicious" in vs else
         "suspicious" if "suspicious" in vs else
         "clean" if "clean" in vs else "unknown")
    label = next((s.get("threat_label") for s in ok if s.get("threat_label")), "")
    return (v, int(best.get("malicious") or 0), int(best.get("total_engines") or 0),
            label or "", "", "")


def local_lookup(base, c, sha, refresh=False):
    return http_json(base + "/vt/lookup", {"hash": sha, "refresh": bool(refresh)},
                     _auth_headers(c), 180, ctx=_LOOPBACK)


def local_upload(base, c, path, sha):
    """Hand the spooled bytes to the local service, which streams them to VT.

    Deliberately not urlopen(data=open(...)) with no length: app.py reads exactly
    Content-Length bytes, so the length must be set explicitly.
    """
    size = os.path.getsize(path)
    h = _auth_headers(c)
    h["Content-Type"] = "application/octet-stream"
    h["Content-Length"] = str(size)
    url = base + "/vt/upload?name=" + urllib.parse.quote(sha + ".bin")
    with open(path, "rb") as body:
        req = urllib.request.Request(url, data=body, headers=h, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=900, context=_LOOPBACK) as r:
                raw = r.read().decode("utf-8", "replace")
                try:
                    return r.status, json.loads(raw)
                except Exception:
                    return r.status, {"error": "non-JSON response"}
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read().decode("utf-8", "replace"))
            except Exception:
                return e.code, {}
        except Exception as e:
            return 0, {"error": "%s: %s" % (type(e).__name__, str(e)[:160])}


def local_analysis(base, c, aid):
    return http_json(base + "/vt/analysis/" + urllib.parse.quote(aid), None,
                     _auth_headers(c), 60, ctx=_LOOPBACK)


def apply_report(rec, res, source):
    rep = res.get("report") or {}
    v, mal, tot, label, vname, ttag = verdict_of(rep)
    rec.update({"verdict": v, "malicious": mal, "total_engines": tot,
                "threat_label": label, "vt_name": vname, "type_tag": ttag,
                "source": source,
                # 入库时刻是回传能不能被核对的钥匙:bulwark-sync 按 stored_at 水位推送,
                # 所以有了它才能回答「这个文件到底传回去了没有」。
                "stored_at": res.get("stored_at") or "",
                "degraded": bool(res.get("degraded") or rep.get("degraded")),
                "degraded_reason": (res.get("degraded_reason")
                                    or rep.get("degraded_reason") or ""),
                "stored": bool(res.get("stored")),
                "cached": bool(res.get("cached"))})


# --------------------------------------------------------------------------- #
#  one pass                                                                   #
# --------------------------------------------------------------------------- #
STAGING = os.path.join(SPOOL, "staging")
# 一个孤儿留在 inbox 多久算「肯定不会再有人来认领」。上传写的是 staging 而不是 inbox,
# 所以 inbox 里的孤儿只可能来自崩溃/重启的旧版本 —— 但仍给足余量,不去和任何还在飞的
# 请求抢文件。
ORPHAN_MIN = 30


def drain_orphans():
    """把 inbox 里【不成对】的东西清走,让它能真正变空。

    这条是承重的,不是打扫卫生:bulwark-submit.path 用的是 DirectoryNotEmpty,只要 inbox
    里剩下任何东西,触发条件就永远成立,worker 会被无限重启。线上实测同一秒三次空跑,原因
    就是一个上传被打断留下的 .part 孤儿。
    (上传现在写 staging,所以新的 .part 压根不会进 inbox;这里处理的是旧版本留下的,以及
     任何写了字节却没写成记录的残骸。)
    """
    cleaned = []
    try:
        names = os.listdir(INBOX)
    except OSError:
        return cleaned
    now = time.time()
    for nm in names:
        p = os.path.join(INBOX, nm)
        keep = False
        if nm.endswith(".json"):
            keep = True                       # 记录归 intake 处理
        elif nm.endswith(".bin"):
            # 有配对记录的字节等 intake 一起搬;没有记录的是残骸。
            keep = os.path.exists(p[:-4] + ".json")
        if keep:
            continue
        try:
            age_min = (now - os.path.getmtime(p)) / 60.0
        except OSError:
            continue
        if age_min < ORPHAN_MIN:
            continue                          # 可能还有人在写,不碰
        try:
            if nm.endswith(".bad"):
                # 刻意保留证据:挪到 items(不被 .path 监视),而不是删掉。
                os.replace(p, os.path.join(ITEMS, nm))
                cleaned.append("moved " + nm)
            else:
                os.remove(p)
                cleaned.append("removed %s (%.0f 分钟前的残骸)" % (nm, age_min))
        except OSError as e:
            log("cannot clear orphan %s: %s" % (nm, e))
    # staging 里的半成品同理:它不被监视,但也不该无限积累。
    try:
        for nm in os.listdir(STAGING):
            p = os.path.join(STAGING, nm)
            try:
                age_min = (now - os.path.getmtime(p)) / 60.0
            except OSError:
                continue
            if age_min >= ORPHAN_MIN:
                try:
                    os.remove(p)
                    cleaned.append("removed staging/%s" % nm)
                except OSError:
                    pass
    except OSError:
        pass
    return cleaned


def intake(u):
    """Move new records out of the inbox so the .path unit stops firing.

    bulwark-submit.path watches DirectoryNotEmpty on the inbox. If anything stayed
    there, the unit would re-trigger forever; emptying it is what makes the trigger
    edge-like -- which is why drain_orphans() runs alongside this.
    """
    got = 0
    for d in (STAGING,):
        try:
            os.makedirs(d, exist_ok=True)
        except OSError:
            pass
    left = drain_orphans()
    if left:
        log("inbox 残骸清理: %s" % "; ".join(left[:6]))
    try:
        names = sorted(os.listdir(INBOX))
    except OSError:
        return 0
    for nm in names:
        if not nm.endswith(".json"):
            continue
        src = os.path.join(INBOX, nm)
        rec = load_json(src, None)
        if not rec or not rec.get("id"):
            # Not a record we understand. Move it aside rather than delete: silent
            # deletion of something unexplained is how evidence disappears.
            try:
                os.replace(src, src + ".bad")
            except OSError:
                pass
            continue
        item_id = rec["id"]
        sb = os.path.join(INBOX, item_id + ".bin")
        if os.path.isfile(sb):
            try:
                os.replace(sb, bin_path(item_id))
            except OSError as e:
                log("cannot move bytes for %s: %s" % (item_id, e))
                continue
        rec["bin"] = bin_path(item_id)
        # 压缩包判定只在入队这一刻做一次,并把结论写进记录。不每轮重判,是为了让行为
        # 可预测:改了配置或换了判定逻辑,不会把一个已经当普通样本查过的文件突然拆开。
        # 也因此,这次改动之前就已经排在队列里的记录没有 kind,一律按普通样本处理 ——
        # 不追溯展开别人几天前上传的东西。
        if "kind" not in rec:
            k, why = sniff_archive(rec, u)
            rec["kind"] = ("archive:" + k) if k else "file"
            if why:
                rec["kind_note"] = why
        if rec.get("state") in (None, "", "new"):
            note(rec, "queued",
                 "收到上传(压缩包,待解压)" if str(rec.get("kind") or "").startswith("archive:")
                 else "收到上传")
        save_rec(rec)
        try:
            os.remove(src)
        except OSError:
            pass
        got += 1
    return got


# --------------------------------------------------------------------------- #
#  压缩包自动解压                                                             #
#                                                                             #
#  为什么解压放在 worker 而不是上传请求里:一个 650 MB 的包可能解出几千个文件,  #
#  在 HTTP 请求里做完这件事等于让浏览器挂几分钟然后超时。上传只管把字节收下,   #
#  解压和入队由这里做,进度落在磁盘上,页面刷新也不丢。                        #
#                                                                             #
#  为什么不递归:压缩包里的压缩包按普通样本处理。zip quine(自己包含自己的包)  #
#  能让递归解压永不停止,而「深度限制」这种参数总有人调大。包里的包本身就是一个  #
#  值得让 VT 看一眼的样本,交给正常流程反而更对。                              #
# --------------------------------------------------------------------------- #
def _ext_kind(name):
    """按文件名判断声称的压缩格式。.tar.gz 这类双后缀必须先匹配,所以 ARCHIVE_EXTS
    是有序的元组而不是 dict。"""
    low = str(name or "").lower()
    for ext, kind in ARCHIVE_EXTS:
        if low.endswith(ext):
            return kind
    return ""


def _magic_kind(path):
    try:
        with open(path, "rb") as f:
            head = f.read(8)
    except OSError:
        return ""
    for sig, kind in ARCHIVE_MAGIC:
        if head.startswith(sig):
            return kind
    return ""


def sniff_archive(rec, u):
    """(kind, why)。kind 非空表示这个上传应当被展开。

    名字和内容必须【都】指向压缩包:名字说是、内容不是 -> 当普通样本(可能是伪装的
    恶意文件,正是该送检的东西);内容说是、名字不是 -> 也当普通样本(.docx/.jar/.apk
    在内部都是 zip,把它们拆开就毁掉了用户真正想查的那个文件)。
    """
    if not u["archive_expand"]:
        return "", "配置里关闭了自动解压"
    ek = _ext_kind(rec.get("name") or "")
    if not ek:
        return "", ""
    p = rec.get("bin") or bin_path(rec["id"])
    mk = _magic_kind(p)
    # tar 没有前 8 字节的魔数(它在偏移 257),而 .tar.gz 的外层是 gz —— 对 tar 只认
    # 名字,交给外部工具去判断真伪,它认不出来就照常报错。
    if ek == "tar" and mk in ("", "gz", "bz2", "xz"):
        return "tar", ""
    if not mk:
        return "", "名字像压缩包但内容不是,按普通样本处理"
    if mk != ek and not (ek in ("tar", "gz", "bz2", "xz") and mk in ("gz", "bz2", "xz")):
        return "", "名字说是 %s 而内容是 %s,按普通样本处理" % (ek, mk)
    return mk if mk != "gz" or ek != "tar" else "tar", ""


def _fresh_id():
    return uuid.uuid4().hex


def _disk_ok(u):
    try:
        free_mb = shutil.disk_usage(SPOOL).free // (1024 * 1024)
    except OSError:
        return True, 0
    return free_mb > u["disk_floor_mb"], free_mb


def _clean_name(s, limit=180):
    """条目名只用来【显示】,绝不用来拼路径。但显示也得干净:控制字符会把日志和页面
    搞乱,超长名字会把记录撑大。"""
    s = str(s or "").replace("\\", "/")
    s = "".join(ch for ch in s if ch.isprintable())
    return s[:limit] or "(无名)"


def child_rec(parent, entry_name, size, sha, digest_hint=""):
    """从压缩包里解出来的一个文件,变成一条和手工上传等价的队列记录。

    刻意继承 want_submit:用户上传这个包时选了「是否允许提交给 VT」,包里的文件就是
    他要送检的东西,不该换一个默认值。
    kind 明确写成 file:防止包里的包被再展开一层(见本节顶部的说明)。
    """
    now = iso()
    return {
        "id": _fresh_id(),
        "at": now,
        "last_at": now,
        "name": os.path.basename(_clean_name(entry_name)) or "sample.bin",
        # 展示用的来源路径:「包名!内部路径」,一眼能看出这个文件是从哪个包里出来的。
        "path": "%s!/%s" % (_clean_name(parent.get("name") or "archive"),
                            _clean_name(entry_name)),
        "size": int(size),
        "sha256": sha,
        "state": "queued",
        "kind": "file",
        "source": "archive",
        "from_archive": {"id": parent.get("id"), "name": parent.get("name") or "",
                         "entry": _clean_name(entry_name)},
        "want_submit": bool(parent.get("want_submit")),
        "attempts": 0,
        "history": [{"at": now, "from": "", "to": "queued",
                     "note": "从压缩包 %s 解出%s" % (_clean_name(parent.get("name")),
                                                    digest_hint)}],
    }


def _stream_to_item(fh, dest, u, budget):
    """把一个成员流式写到 dest,边写边算 sha256 和大小。

    返回 (sha, size, err)。三个上限都在【写的过程中】检查,不是事后:声明的大小可以
    撒谎,只有真正读出来的字节数才算数。这是压缩炸弹唯一靠得住的防线。
    """
    h = hashlib.sha256()
    size = 0
    cap = u["max_mb"] * 1024 * 1024
    try:
        with open(dest, "wb") as out:
            while True:
                chunk = fh.read(CHUNK)
                if not chunk:
                    break
                size += len(chunk)
                if size > cap:
                    return "", size, "超过单文件上限 %d MB" % u["max_mb"]
                if size > budget["left"]:
                    return "", size, "会超出本轮解压总量预算"
                h.update(chunk)
                out.write(chunk)
    except (OSError, zipfile.BadZipFile, RuntimeError, EOFError) as e:
        return "", size, "读取失败: %s" % str(e)[:80]
    return h.hexdigest(), size, ""


def _adopt(parent, entry_name, tmp_path, size, sha, u, budget, made, hint=""):
    """把一个已经落盘、已经校验过的文件正式变成队列条目。"""
    kid = child_rec(parent, entry_name, size, sha, hint)
    try:
        os.replace(tmp_path, bin_path(kid["id"]))
    except OSError as e:
        return "落盘失败: %s" % str(e)[:60]
    kid["bin"] = bin_path(kid["id"])
    save_rec(kid)
    budget["left"] -= size
    budget["entries"] -= 1
    made.append({"id": kid["id"], "name": kid["name"], "size": size,
                 "sha256": sha})
    return ""


def expand_zip(rec, u, budget, made, skipped):
    """用 python 自己解 zip。返回 (ok, err, needs_external)。

    条目名【从不】参与路径拼接:每个成员都写到 items/<新 uuid>.bin,原始路径只作为
    记录里的一个字符串。zip slip 因此不是「检查掉的」,而是结构上做不到 —— 没有任何
    一处代码把包里的名字交给 open()。
    """
    src = rec.get("bin") or bin_path(rec["id"])
    try:
        zf = zipfile.ZipFile(src)
    except Exception as e:
        return False, "打不开 zip: %s" % str(e)[:80], False
    with zf:
        try:
            infos = [i for i in zf.infolist() if not i.is_dir()]
        except Exception as e:
            return False, "读目录失败: %s" % str(e)[:80], False
        if not infos:
            return False, "压缩包里没有文件", False
        # 能不能自己解,必须在【解出第一个字节之前】就决定。
        # 否则一个混合了 AES 和 deflate 的包会走成:前几个成员被 python 解出来入队,
        # 撞到 AES 再整包交给 7z —— 7z 会把所有成员再解一遍,同一个文件进队两次。
        methods = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
        for nm in ("ZIP_BZIP2", "ZIP_LZMA"):
            if hasattr(zipfile, nm):
                methods.add(getattr(zipfile, nm))
        odd = sorted({int(i.compress_type) for i in infos} - methods)
        if odd:
            # 99 = WinZip AES。标准库没有实现,换口令没有意义,只能交给外部工具。
            return False, ("包内压缩方法 %s 标准库解不了%s"
                           % (",".join(str(x) for x in odd),
                              "(99 = AES 加密)" if 99 in odd else "")), True
        if len(infos) > budget["entries"]:
            return False, ("包里有 %d 个文件,超过本轮上限 %d"
                           % (len(infos), budget["entries"])), False
        declared = sum(max(0, int(i.file_size or 0)) for i in infos)
        # 声明的总量就已经超预算的话,连第一个字节都不用解。声明可以撒谎,所以
        # _stream_to_item 里还会按真实字节再挡一次 —— 两道都要有:这一道省的是时间,
        # 那一道保的是正确。
        if declared > budget["left"]:
            return False, ("声明解压后 %d MB,超过剩余预算 %d MB"
                           % (declared // 1048576, budget["left"] // 1048576)), False
        # 压缩比的分母用【磁盘上的真实大小】,不用记录里的 size:记录里的数字来自上传端,
        # 缺失或为 0 时会让比值算成无穷大,把一个正常的包判成炸弹。
        try:
            csize = max(1, os.path.getsize(src))
        except OSError:
            csize = max(1, int(rec.get("size") or 1))
        if declared / float(csize) > u["archive_ratio_max"]:
            return False, ("压缩比 %.0f:1 超过上限 %.0f:1(疑似压缩炸弹)"
                           % (declared / float(csize), u["archive_ratio_max"])), False

        pwd_used = None
        for i in infos:
            if budget["entries"] <= 0:
                skipped.append({"name": _clean_name(i.filename),
                                "why": "本轮解压条目数已用满"})
                continue
            if int(i.file_size or 0) <= 0:
                skipped.append({"name": _clean_name(i.filename), "why": "空文件(0 字节)"})
                continue
            if int(i.file_size or 0) > u["max_mb"] * 1024 * 1024:
                skipped.append({"name": _clean_name(i.filename),
                                "why": "超过单文件上限 %d MB" % u["max_mb"]})
                continue
            encrypted = bool(i.flag_bits & 0x1)
            # 已经试出来的口令先用,别每个成员都从头试一遍。
            cands = ([pwd_used] if pwd_used is not None else []) + \
                    [p for p in u["archive_passwords"] if p != pwd_used]
            tmp = bin_path(rec["id"]) + ".part-" + _fresh_id()[:8]
            last = ""
            done = False
            for pw in cands:
                try:
                    fh = zf.open(i, pwd=(pw.encode("utf-8") if pw else None))
                except NotImplementedError as e:
                    # 上面的预检本该已经把这种包整包交给 7z 了。走到这里说明预检漏了
                    # 一种情况:只跳过这个成员,【不】整包重来 —— 此刻可能已经有成员
                    # 入队了,重来就会产生重复条目。
                    last = "标准库不支持: %s" % str(e)[:60]
                    break
                except RuntimeError as e:
                    # 判断【必须】用完整的消息,截断只能用于显示。
                    # zipfile 抛的是 "File <ZipInfo filename='x' filemode=... external_attr=...>
                    # is encrypted, password required for extraction" —— ZipInfo 的
                    # repr 很长,"password" 落在第 80 个字符之后。先截断再判断的结果是:
                    # 无口令那次尝试失败后直接 break,infected 根本没被试过,整个功能
                    # 看起来像「口令不对」。这一条是线上实测出来的。
                    msg = str(e)
                    last = msg[:120]
                    low = msg.lower()
                    if "password" in low or "encrypted" in low:
                        continue
                    break
                except Exception as e:
                    last = str(e)[:80]
                    break
                with fh:
                    sha, size, err = _stream_to_item(fh, tmp, u, budget)
                if err:
                    try:
                        os.remove(tmp)
                    except OSError:
                        pass
                    # ZipCrypto 的口令校验只有 1 字节,约 1/256 的错口令能通过 open()
                    # 而在读到末尾时 CRC 才失败。所以「读失败」也要换下一个口令再试。
                    if encrypted and "读取失败" in err:
                        last = err
                        continue
                    skipped.append({"name": _clean_name(i.filename), "why": err})
                    done = True
                    break
                if pw:
                    pwd_used = pw
                e2 = _adopt(rec, i.filename, tmp, size, sha, u, budget, made,
                            "(口令 %s)" % ("infected" if pw == "infected"
                                           else ("已配置口令" if pw else "无")))
                if e2:
                    skipped.append({"name": _clean_name(i.filename), "why": e2})
                done = True
                break
            if not done:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
                skipped.append({"name": _clean_name(i.filename),
                                "why": ("口令不对或成员损坏" + (": " + last if last else ""))
                                if encrypted else ("解不开" + (": " + last if last else ""))})
    return True, "", False


def expand_with_7z(rec, u, budget, made, skipped):
    """用 7z 解 python 解不了的格式(AES 的 zip、7z、rar、tar.*)。

    这里必须让外部工具自己写文件,所以路径安全变成了「事后核对」而不是结构保证:
    解到一个空的临时目录里,然后只认【realpath 仍在这个目录内】且是普通文件的东西。
    符号链接、设备节点、跳出目录的路径一律不碰。
    """
    if not u["archive_use_7z"]:
        return False, "需要外部工具但配置里禁用了 7z"
    if not os.path.isfile(SEVENZIP):
        return False, "本机没有 %s" % SEVENZIP
    src = rec.get("bin") or bin_path(rec["id"])
    try:
        os.makedirs(EXPAND, exist_ok=True)
    except OSError as e:
        return False, "建临时目录失败: %s" % e
    tmp = os.path.join(EXPAND, _fresh_id())
    try:
        os.makedirs(tmp, exist_ok=False)
    except OSError as e:
        return False, "建临时目录失败: %s" % e
    try:
        rc, err = 1, ""
        for pw in u["archive_passwords"]:
            # -p 必须【总是】给:少了它,遇到加密包时 7z 会去读 stdin 等口令。
            # stdin 也接到 /dev/null,双保险。-bso0/-bse0 关掉它的进度输出。
            cmd = [SEVENZIP, "x", "-y", "-bd", "-bso0", "-bse0",
                   "-p" + pw, "-o" + tmp, "--", src]
            try:
                p = subprocess.run(cmd, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   timeout=u["archive_timeout"])
            except subprocess.TimeoutExpired:
                return False, "解压超时(%d 秒)" % u["archive_timeout"]
            rc = p.returncode
            err = (p.stdout or b"").decode("utf-8", "replace").strip()[-160:]
            if rc == 0:
                break
        if rc != 0:
            return False, "7z 退出码 %d%s" % (rc, (": " + err) if err else "")

        root = os.path.realpath(tmp)
        found = 0
        for dirpath, dirnames, filenames in os.walk(tmp):
            for fn in sorted(filenames):
                if budget["entries"] <= 0:
                    skipped.append({"name": _clean_name(fn),
                                    "why": "本轮解压条目数已用满"})
                    continue
                full = os.path.join(dirpath, fn)
                real = os.path.realpath(full)
                # 逃出临时目录的一律不碰(符号链接、被清理过的 ../)。
                if real != root and not real.startswith(root + os.sep):
                    skipped.append({"name": _clean_name(fn),
                                    "why": "路径逃出解压目录,已拒绝"})
                    continue
                try:
                    st = os.lstat(full)
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode):
                    skipped.append({"name": _clean_name(fn),
                                    "why": "不是普通文件(链接/设备),已跳过"})
                    continue
                rel = os.path.relpath(full, tmp)
                if st.st_size <= 0:
                    skipped.append({"name": _clean_name(rel), "why": "空文件(0 字节)"})
                    continue
                if st.st_size > u["max_mb"] * 1024 * 1024:
                    skipped.append({"name": _clean_name(rel),
                                    "why": "超过单文件上限 %d MB" % u["max_mb"]})
                    continue
                if st.st_size > budget["left"]:
                    skipped.append({"name": _clean_name(rel),
                                    "why": "会超出本轮解压总量预算"})
                    continue
                h = hashlib.sha256()
                try:
                    with open(full, "rb") as f:
                        while True:
                            b = f.read(CHUNK)
                            if not b:
                                break
                            h.update(b)
                except OSError as e:
                    skipped.append({"name": _clean_name(rel),
                                    "why": "读取失败: %s" % str(e)[:60]})
                    continue
                e2 = _adopt(rec, rel, full, st.st_size, h.hexdigest(), u, budget, made,
                            "(7z)")
                if e2:
                    skipped.append({"name": _clean_name(rel), "why": e2})
                else:
                    found += 1
        if not found and not skipped:
            return False, "7z 解开了但里面没有文件"
        return True, ""
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def expand_archive(rec, u, budget):
    """展开一个压缩包条目。返回 touched(记录是否被改过)。"""
    kind = str(rec.get("kind") or "")[len("archive:"):]
    ok_disk, free_mb = _disk_ok(u)
    if not ok_disk:
        note(rec, "queued", "磁盘剩余 %d MB 低于保留下限,等下一轮" % free_mb)
        rec["next_at"] = iso(now_utc() + timedelta(minutes=DEGRADED_RETRY_MIN))
        return True
    made, skipped = [], []
    note(rec, "expanding", "开始解压(%s)" % (kind or "未知格式"))
    save_rec(rec)

    external = False
    if kind in NATIVE_KINDS:
        ok, err, external = expand_zip(rec, u, budget, made, skipped)
    else:
        ok, err = False, ""
        external = True
    if external:
        ok, err2 = expand_with_7z(rec, u, budget, made, skipped)
        if not ok:
            err = "; ".join(x for x in (err, err2) if x)

    rec["archive_kind"] = kind
    rec["archive_made"] = made
    rec["archive_skipped"] = (rec.get("archive_skipped") or []) + skipped
    rec["archive_count"] = len(made)
    if made:
        note(rec, "expanded",
             "解出 %d 个文件%s" % (len(made),
                                  (",跳过 %d 个" % len(skipped)) if skipped else ""))
        # 包本身不是样本,不查也不提交;字节留着没有意义。
        drop_bytes(rec, "已解压,包本身不送检")
        rec["want_submit"] = False
    else:
        # 一个都没解出来:这不能算成功。保留字节,让人能下载下来自己看。
        note(rec, "failed", "解压没有产出文件: %s" % (err or "原因未知")[:120])
        rec["error"] = err or "archive produced nothing"
    return True


def expand_pass(u, deadline):
    """把本轮所有待展开的压缩包展开。

    刻意放在 VT 预算的循环【之前】:解出来的文件当轮就能进入 todo,而不是白等 3 分钟。
    解压不花 VT 额度,所以它有自己独立的预算(条目数 / 总字节 / 墙钟)。
    """
    if not u["archive_expand"]:
        return 0, 0
    try:
        names = sorted(os.listdir(ITEMS))
    except OSError:
        return 0, 0
    pend = []
    for nm in names:
        if not nm.endswith(".json"):
            continue
        r = load_json(os.path.join(ITEMS, nm), None)
        if not r or not str(r.get("kind") or "").startswith("archive:"):
            continue
        if r.get("state") in ("queued", "expanding"):
            pend.append(r)
    if not pend:
        return 0, 0
    pend.sort(key=lambda r: str(r.get("at") or ""))
    budget = {"left": u["archive_max_total_mb"] * 1024 * 1024,
              "entries": u["archive_max_entries"]}
    done = total_made = 0
    for rec in pend:
        if time.monotonic() > deadline:
            log("解压到墙钟预算,余下 %d 个包等下一轮" % (len(pend) - done))
            break
        if budget["entries"] <= 0 or budget["left"] <= 0:
            log("解压预算用满,余下 %d 个包等下一轮" % (len(pend) - done))
            break
        try:
            expand_archive(rec, u, budget)
        except Exception as e:
            note(rec, "failed", "解压异常: %s" % str(e)[:100])
            rec["error"] = "%s: %s" % (type(e).__name__, str(e)[:160])
            log("expand %s raised %s: %s" % (rec.get("id"), type(e).__name__, e))
        save_rec(rec)
        done += 1
        total_made += int(rec.get("archive_count") or 0)
    # 上一轮被 systemd 打断可能留下半个解压目录。
    if os.path.isdir(EXPAND):
        for nm in os.listdir(EXPAND):
            p = os.path.join(EXPAND, nm)
            if os.path.isdir(p):
                shutil.rmtree(p, ignore_errors=True)
    return done, total_made


def due(rec, now):
    if rec.get("state") in FINAL:
        return False
    nx = parse_iso(rec.get("next_at") or "")
    return nx is None or nx <= now


def work_item(rec, u, c, base, vt_left, master_left):
    """Advance one item as far as it can go this pass.

    Returns (vt_used, master_used, stored, touched). `touched` False means the record
    was not modified at all, so the caller must not rewrite it.

    The two budgets are separate because they are limited by different things: VT calls
    are limited by the daily quota this node shares with the collector, while the
    master's cache-only endpoint costs no quota at all and is limited only by its
    per-IP rate limit.
    """
    used = master_used = 0
    stored = False
    sha = rec.get("sha256") or ""
    if len(sha) != 64:
        note(rec, "failed", "记录里没有合法的 sha256")
        rec["error"] = "bad sha256"
        drop_bytes(rec, "记录不合法")
        return used, master_used, stored, True

    # What would this item need in order to make progress? Answered BEFORE anything is
    # written, because an item that cannot act this pass must be left completely alone.
    #
    # This is not a micro-optimisation. attempts used to be incremented at the top,
    # which meant a queue of 500 files bumped all 500 counters on every pass while only
    # 6 of them could actually do anything -- so files that had never once been queried
    # hit max_attempts and were marked failed. A retry counter must only count tries.
    waiting_analysis = rec.get("state") == "vt_wait" and bool(rec.get("analysis_id"))
    needs_master = (u["ask_master_first"] and not rec.get("master_checked")
                    and not waiting_analysis)
    if waiting_analysis:
        if vt_left <= 0:
            return 0, 0, False, False
    elif needs_master:
        if master_left <= 0:
            return 0, 0, False, False
    elif vt_left <= 0:
        return 0, 0, False, False

    rec["attempts"] = int(rec.get("attempts", 0) or 0) + 1
    if rec["attempts"] > u["max_attempts"]:
        note(rec, "failed", "重试次数用尽")
        rec["error"] = rec.get("error") or "retries exhausted"
        drop_bytes(rec, "重试用尽")
        return used, master_used, stored, True

    # ---- 1) already waiting on a VT analysis? finish that first ---------------- #
    if waiting_analysis:
        st, an = local_analysis(base, c, rec["analysis_id"])
        used += 1
        status = str((an or {}).get("status") or "").lower()
        if st == 200 and status == "completed":
            # The analysis result alone is not a report; re-lookup so the full report
            # is fetched AND archived by the service that owns the archive.
            if vt_left - used <= 0:
                note(rec, "vt_wait", "分析完成,下一轮取报告")
                rec["next_at"] = iso(now_utc() + timedelta(minutes=RETRY_MIN))
                return used, master_used, stored, True
            st2, res = local_lookup(base, c, sha, refresh=True)
            used += 1
            if st2 == 200 and res.get("ok"):
                apply_report(rec, res, "vt")
                stored = bool(res.get("stored"))
                note(rec, "done", "VT 分析完成并取回报告")
                drop_bytes(rec, "已出结论")
            else:
                note(rec, "vt_wait", "取报告失败: %s"
                     % str(res.get("error") or ("HTTP %s" % st2))[:80])
                rec["next_at"] = iso(now_utc() + timedelta(minutes=RETRY_MIN))
            return used, master_used, stored, True
        note(rec, "vt_wait", "VT 分析中(%s)" % (status or ("HTTP %s" % st)))
        rec["next_at"] = iso(now_utc() + timedelta(minutes=RETRY_MIN))
        return used, master_used, stored, True

    # ---- 2) the master, cache-only: free of VT quota, and its archive is a superset #
    if needs_master:
        hit, why = master_lookup(u, sha)
        master_used += 1
        rec["master_note"] = why or "master 已收录"
        if not hit and str(why).startswith("RETRY"):
            # Rate-limited or unreachable. Leave master_checked unset so the question
            # gets asked again, and do not touch VT this pass -- otherwise a burst of
            # uploads would quietly spend VT quota on files the master already has.
            rec["master_tries"] = int(rec.get("master_tries", 0) or 0) + 1
            if rec["master_tries"] < u["master_max_tries"]:
                note(rec, "queued", why[:80])
                rec["next_at"] = iso(now_utc() + timedelta(minutes=RETRY_MIN))
                return used, master_used, stored, True
            # Out of patience: stop asking and let the local path answer.
            rec["master_checked"] = True
            note(rec, "queued", "主服务器连续答不了,改问 VT")
        else:
            rec["master_checked"] = True
        if hit:
            rec.update({"verdict": hit["verdict"], "malicious": hit["malicious"],
                        "total_engines": hit["total_engines"],
                        "threat_label": hit["threat_label"], "source": "master",
                        "master_hit": True})
            note(rec, "done", "主服务器已收录,未动用 VT")
            drop_bytes(rec, "主服务器已有结论")
            return used, master_used, stored, True

    # ---- 3) this node: shared cache, then VT ---------------------------------- #
    # Reachable with no VT budget left when step 2 just ran on the master's allowance.
    # Leave it queued rather than annotate: the aggregate on the page already says how
    # many are waiting, and rewriting every waiting record each pass is pure churn.
    if vt_left - used <= 0:
        rec["next_at"] = iso(now_utc() + timedelta(minutes=RETRY_MIN))
        return used, master_used, stored, True
    note(rec, "checking", "查询本机 /vt/lookup")
    st, res = local_lookup(base, c, sha)
    used += 1
    rep = res.get("report") or {}
    unknown = bool(res.get("vt_unknown") or rep.get("vt_unknown"))

    # ok=false means two very different things on this endpoint and they must not be
    # collapsed: with vt_unknown it is an authoritative "VirusTotal has no record"
    # (that is harvest.py's load-bearing contract), without it the query simply
    # failed. Treating a failure as "not recorded" would upload samples for no reason;
    # treating "not recorded" as a failure would stop the submission path entirely.
    if st != 200 or (not res.get("ok") and not unknown):
        rec["error"] = str(res.get("error") or ("查询失败 HTTP %s" % st))[:200]
        note(rec, "queued", "查询失败,稍后重试: %s" % rec["error"][:80])
        rec["next_at"] = iso(now_utc() + timedelta(minutes=RETRY_MIN))
        return used, master_used, stored, True

    if not unknown:
        apply_report(rec, res, "cache" if res.get("cached") else "vt")
        # A degraded answer carrying no verdict at all is not an answer.
        #
        # app.py applies this exact guard before calling a lookup "found" (see
        # degraded_blank in vt_submit_path), and for the same reason: when VirusTotal is
        # unreachable or rate-limited, nobody has actually judged this file. Finalising
        # it as "unknown" and deleting the bytes would quietly turn "we could not ask"
        # into "nothing wrong with it", and the sample could then never be submitted
        # once VT came back -- the bytes would be gone.
        #
        # This is not hypothetical: the very first end-to-end probe hit it, because VT
        # was answering 429 at the time.
        if rec.get("degraded") and str(rec.get("verdict") or "unknown") == "unknown":
            note(rec, "queued", "上游降级、结论未定,保留样本稍后重试: %s"
                 % str(rec.get("degraded_reason") or "")[:60])
            rec["next_at"] = iso(now_utc() + timedelta(minutes=DEGRADED_RETRY_MIN))
            return used, master_used, stored, True
        stored = bool(res.get("stored"))
        note(rec, "done", "已有报告")
        drop_bytes(rec, "已出结论")
        return used, master_used, stored, True

    # VT genuinely has no record of this file.
    rec["vt_unknown"] = True
    apply_report(rec, res, "degraded")     # secondary sources may still have said something
    if not (u["allow_submit"] and rec.get("want_submit", True)):
        note(rec, "done", "VT 未收录;按设置不提交样本")
        drop_bytes(rec, "不提交")
        return used, master_used, stored, True
    p = rec.get("bin") or bin_path(rec["id"])
    if not os.path.isfile(p):
        note(rec, "done", "VT 未收录,但样本字节已不在本机,无法提交")
        return used, master_used, stored, True
    if vt_left - used <= 0:
        note(rec, "queued", "待提交 VT,本轮额度用完")
        rec["next_at"] = iso(now_utc() + timedelta(minutes=RETRY_MIN))
        return used, master_used, stored, True
    st, up = local_upload(base, c, p, sha)
    used += 1
    if st == 200 and up.get("ok") and up.get("analysis_id"):
        rec["analysis_id"] = up["analysis_id"]
        rec["submitted"] = True
        note(rec, "vt_wait", "样本已提交 VT,等待分析")
        rec["next_at"] = iso(now_utc() + timedelta(minutes=RETRY_MIN))
        drop_bytes(rec, "VT 已接收")
    elif st == 200 and up.get("ok") and up.get("found"):
        # The service found a report in the moment between our lookup and this call.
        apply_report(rec, up, "vt")
        stored = bool(up.get("stored"))
        note(rec, "done", "提交前发现已有报告")
        drop_bytes(rec, "已出结论")
    else:
        rec["error"] = str(up.get("error") or ("提交失败 HTTP %s" % st))[:200]
        note(rec, "queued", "提交失败,稍后重试: %s" % rec["error"][:80])
        rec["next_at"] = iso(now_utc() + timedelta(minutes=SUBMIT_RETRY_MIN))
    return used, master_used, stored, True


MARK = os.path.join(STATE_DIR, "sync_watermark.txt")
MASTER_LOG = os.path.join(STATE_DIR, "master_ingest.jsonl")


def update_sync_marks():
    """逐个文件核对「回传了没有」,并且尽量用【主服务器自己的凭据】来核对。

    页面上原来只有一句承诺(「出结论立刻回传主服务器」),看不出具体哪个文件真的回去了。
    这里给出两级证据,强度不同,不能混为一谈:

      sync_pushed  本端证据。bulwark-sync 按 stored_at 水位推送(stored_at >= mark),
                   水位只在主库回 OK 之后才前移。所以 stored_at <= 当前水位 ==> 这一行
                   一定被包含在某个已被主库受理的批次里。
      master_new   对端证据。主库的 ingest 账本会记下它【真正插入】的哈希清单,
                   bulwark-sync 每次推送后把这份账本拉回本地。哈希出现在里面,等于
                   主服务器亲口承认收到了这一条。

    没有 master_new 不代表没回传:主库如果早就有这个哈希,会记成 skipped 而不进 new 清单。
    那种情况 sync_pushed 仍然为真,页面上说「主库已有」。把两者分开正是为了不把
    「主库本来就有」说成「没传成功」。

    全程只读本地文件,不发一个网络请求。
    """
    try:
        wm = io_read(MARK)
    except Exception:
        wm = ""
    # 主库账本里被真正插入过的哈希集合
    acked = set()
    try:
        with open(MASTER_LOG, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except Exception:
                    continue
                if not d.get("ok"):
                    continue
                for s in (d.get("new") or []):
                    acked.add(str(s).lower())
    except OSError:
        pass

    changed = 0
    try:
        names = os.listdir(ITEMS)
    except OSError:
        return 0, wm
    for nm in names:
        if not nm.endswith(".json"):
            continue
        p = os.path.join(ITEMS, nm)
        rec = load_json(p, None)
        if not isinstance(rec, dict):
            continue
        sa = str(rec.get("stored_at") or "")
        if not sa:
            continue                       # 没入库就没有可回传的东西
        want_pushed = bool(wm) and sa <= wm
        want_ack = str(rec.get("sha256") or "").lower() in acked
        if (bool(rec.get("sync_pushed")) == want_pushed
                and bool(rec.get("master_new")) == want_ack):
            continue                       # 没变化就不重写,避免每轮把全部记录刷一遍
        if want_pushed and not rec.get("sync_pushed"):
            note(rec, rec.get("state") or "done", "已随回传批次推送到主服务器")
        if want_ack and not rec.get("master_new"):
            note(rec, rec.get("state") or "done", "主服务器账本已确认收到")
        rec["sync_pushed"] = want_pushed
        rec["master_new"] = want_ack
        rec["sync_checked_at"] = iso()
        save_rec(rec)
        changed += 1
    return changed, wm


def io_read(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()


def sweep(u):
    """Retention. Bytes go early and records go late, on purpose: the bytes are the
    liability, the records are the history the page shows."""
    now = time.time()
    freed = dropped = 0
    try:
        names = os.listdir(ITEMS)
    except OSError:
        return 0, 0
    for nm in names:
        if not nm.endswith(".json"):
            continue
        p = os.path.join(ITEMS, nm)
        rec = load_json(p, None)
        if not rec:
            continue
        changed = False
        b = rec.get("bin") or bin_path(rec.get("id", ""))
        if os.path.isfile(b):
            try:
                age_h = (now - os.path.getmtime(b)) / 3600.0
            except OSError:
                age_h = 0
            if rec.get("state") in FINAL or age_h > u["bytes_max_hours"]:
                drop_bytes(rec, "保留期到(%.1fh)" % age_h)
                freed += 1
                changed = True
        at = parse_iso(rec.get("at") or "") or parse_iso(rec.get("last_at") or "")
        if at and (now_utc() - at).total_seconds() > u["keep_days"] * 86400:
            try:
                if os.path.isfile(b):
                    os.remove(b)
                os.remove(p)
                dropped += 1
                continue
            except OSError:
                pass
        if changed:
            save_rec(rec)
    return freed, dropped


def trigger_sync():
    """Push straight away instead of waiting for the next collector run.

    Normally bulwark-sync is chained off the collector's OnSuccess=, which is up to
    30 minutes away. A hand-submitted file is being watched by someone, so the rows
    it produced go now. Safe to fire repeatedly: the watermark is inclusive and the
    master inserts with OR IGNORE.
    """
    try:
        subprocess.run(["systemctl", "start", "--no-block", "bulwark-sync.service"],
                       capture_output=True, timeout=30)
        log("triggered bulwark-sync (new rows to push)")
    except Exception as e:
        log("could not trigger sync: %s" % e)


def main():
    c = cfg()
    u = ucfg(c)
    for d in (SPOOL, INBOX, ITEMS, EXPAND):
        try:
            os.makedirs(d, exist_ok=True)
        except OSError as e:
            log("cannot create %s: %s" % (d, e))
            return 1
    # The timer and the path unit can fire at the same moment; two workers on the
    # same records would double-spend VT calls.
    lf = open(LOCK, "a+")
    if fcntl is None:
        # 只可能发生在非 Linux 的演练环境里。生产上 fcntl 一定在,所以这不是「悄悄
        # 放弃加锁」—— 但还是要说一声,免得有人在别的平台上真跑它。
        log("警告: 本平台没有 fcntl,未加互斥锁(仅限本机演练)")
    else:
        try:
            fcntl.flock(lf, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            log("another pass is already running -- nothing to do")
            return 0

    got = intake(u)
    if got:
        log("intake: %d 个新文件" % got)
    if not u["enabled"]:
        log("送检功能已在配置里关闭,只做保留期清理")
        freed, dropped = sweep(u)
        log("sweep: 删字节 %d, 删记录 %d" % (freed, dropped))
        return 0

    base = svc_base(c)
    if not base:
        log("本机 intel 服务不可达,本轮跳过查询(记录保持排队)")
        return 0

    started = time.monotonic()
    # 解压先做,而且是在 todo 之前扫的:这样这一轮解出来的文件当轮就会被排进去查,
    # 而不是白等下一个 3 分钟。给它整轮墙钟预算的一半,剩下的留给查询。
    if u["archive_expand"]:
        n_arc, n_made = expand_pass(u, started + max(60, u["max_pass_seconds"] // 2))
        if n_arc:
            log("解压: %d 个压缩包 -> %d 个文件" % (n_arc, n_made))

    now = now_utc()
    todo = []
    try:
        names = sorted(os.listdir(ITEMS))
    except OSError:
        names = []
    for nm in names:
        if not nm.endswith(".json"):
            continue
        rec = load_json(os.path.join(ITEMS, nm), None)
        if rec and due(rec, now):
            todo.append(rec)
    # Oldest first: a queue that answers the newest upload first would starve the
    # first folder someone dropped in.
    todo.sort(key=lambda r: str(r.get("at") or ""))

    vt_budget = max(1, u["max_vt_per_pass"])
    master_budget = max(1, u["max_master_per_pass"])
    vt_used = master_used_total = advanced = 0
    stored_any = False
    for rec in todo:
        # Both budgets spent -> nothing any remaining item could do. Stop instead of
        # walking the rest: an item that cannot act must not be rewritten at all.
        if vt_used >= vt_budget and master_used_total >= master_budget:
            break
        if time.monotonic() - started > u["max_pass_seconds"]:
            log("本轮已跑 %d 秒,到墙钟预算,余下的等下一轮(避免被 systemd 中途打断)"
                % int(time.monotonic() - started))
            break
        try:
            used, m_used, stored, touched = work_item(
                rec, u, c, base, vt_budget - vt_used, master_budget - master_used_total)
        except Exception as e:
            note(rec, "queued", "worker 异常: %s" % str(e)[:80])
            rec["error"] = "%s: %s" % (type(e).__name__, str(e)[:160])
            rec["next_at"] = iso(now_utc() + timedelta(minutes=SUBMIT_RETRY_MIN))
            used, m_used, stored, touched = 0, 0, False, True
            log("item %s raised %s: %s" % (rec.get("id"), type(e).__name__, e))
        vt_used += used
        master_used_total += m_used
        stored_any = stored_any or stored
        if touched:
            advanced += 1
            save_rec(rec)

    freed, dropped = sweep(u)
    # 回传核对放在最后,而且刻意不等 bulwark-sync 跑完:trigger_sync 是 --no-block,
    # 水位要过一会儿才前移,所以本轮存下的行会在下一轮(3 分钟后)被标成已推送。
    # 这比在这里阻塞等它更诚实 —— 也不会把一次回传的耗时算进这一轮的墙钟预算。
    marks, wm = update_sync_marks()
    log("pass: 待办 %d, 推进 %d, VT 调用 %d/%d, 主库查询 %d/%d, 删字节 %d, 删记录 %d, "
        "回传标记更新 %d (水位 %s)"
        % (len(todo), advanced, vt_used, vt_budget, master_used_total, master_budget,
           freed, dropped, marks, wm or "无"))
    if len(todo) > advanced:
        log("本轮额度用完,还有 %d 个等下一轮(每 %d 分钟一轮)"
            % (len(todo) - advanced, RETRY_MIN + 1))
    if stored_any:
        trigger_sync()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        log("FATAL", type(e).__name__, str(e)[:200])
        sys.exit(1)
