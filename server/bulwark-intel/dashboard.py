"""Bulwark harvester dashboard (node-local, stdlib only).

One page per concern instead of one wall of tables:

    /            总览    counters, quota bars, hourly chart -- statistics only
    /queries     查询    rate limit, VT quota detail, run history, stored hashes
    /queue       排队    the FIFO backlog waiting to be queried
    /downloads   下载    sample binaries fetched from abuse.ch
    /uploads     上传    binaries submitted to VirusTotal (the VT-unknown ones)
    /transfers   回传    pushes to the master node

Each route has its own /api/* endpoint so a page only pays for the data it
shows: the overview never touches the file ledger, the queue page never shells
out to journalctl. journalctl and systemctl results are TTL-cached because the
browser polls every few seconds.

Why a separate service instead of new routes in app.py: app.py is the shared
intel service and is byte-identical across nodes; forking it for a dashboard
would void that guarantee and put a reporting feature inside the process that
must never go down. This opens the same SQLite file read-only and reads the
harvester's append-only ledgers, so it cannot corrupt harvester state.

Auth: a bearer token is REQUIRED. No unauthenticated mode -- this box has a
public IP and the data includes malware hashes, file names and quota levels.
"""
import hashlib
import json
import os
import re
import shutil
import sqlite3
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONFIG_PATH = os.environ.get("BULWARK_INTEL_CONFIG", "/etc/bulwark-intel/config.json")
DASH_CONFIG = os.environ.get("BULWARK_DASH_CONFIG", "/etc/bulwark-intel/dashboard.json")
LISTEN_HOST = os.environ.get("BULWARK_DASH_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("BULWARK_DASH_PORT", "8788"))
# Overridable for the same reason bulwark-janitor.py makes it overridable: this
# process now WRITES here (the submit spool), and a write path that cannot be
# rehearsed against a throwaway directory is a write path nobody has actually tested.
# In production nothing sets it, so the value is unchanged.
STATE_DIR = os.environ.get("BULWARK_STATE_DIR", "/var/lib/bulwark-intel")
# Append-only ledger written by bulwark-sync.py after every push. Preferred over
# journal parsing: bulwark-sync runs as root (it needs root's SSH key), so a
# dashboard running as bulwarkintel only sees its own uid's journal entries and
# the transfer panel comes back empty. The ledger also outlives journal rotation.
SYNC_LOG = os.path.join(STATE_DIR, "sync_log.jsonl")
# Written by harvest.py: what is still waiting, and which binaries were fetched.
QUEUE_LOG = os.path.join(STATE_DIR, "harvest_queue.jsonl")
FILES_LOG = os.path.join(STATE_DIR, "harvest_files.jsonl")
# Must match keep_lines in each collector's append_file_log(). They differ on
# purpose: the datalake writes a line per sample looked at (~1200/day on node 245)
# and needed a bigger ledger to hold even one day, while harvest.py runs hourly and
# never came close. Used ONLY to explain a gap on the page ("the ledger rolled,
# nothing was lost"), never to decide how much of the file to read -- see
# file_records(). If a collector's cap changes, change it here too; being wrong here
# only mislabels a note, which is why it is not worth importing the collector.
LEDGER_KEEP_LINES = {"datalake": 4000, "harvest": 1000}
# Written by bulwark-datalake.py: real-time progress during a run
DATALAKE_PROGRESS = os.path.join(STATE_DIR, "datalake_progress.json")
# The master's own record of our pushes, pulled back by bulwark-sync.py after each
# one. Reconciling against it catches the case a local "success" is not matched by
# anything on the receiving side.
MASTER_LOG = os.path.join(STATE_DIR, "master_ingest.jsonl")
# Written by the white-sample quarantine pair (bulwark-benign-verify.py and
# bulwark-benign-push.py). Deliberately separate from SYNC_LOG: that one carries
# vt_reports (threats) and advances its own watermark, while these carry benign
# samples that had to survive a 24h hold before they were allowed to leave. Reading
# them here is what makes that pipeline visible at all -- without it the page showed
# threat pushes only and 200-plus white samples looked like they never happened.
BENIGN_VERIFY_LOG = os.path.join(STATE_DIR, "benign_verify_log.jsonl")
BENIGN_SYNC_LOG = os.path.join(STATE_DIR, "benign_sync_log.jsonl")


def now_utc():
    return datetime.now(timezone.utc)


def today():
    return now_utc().strftime("%Y-%m-%d")


def load_json(path, default=None):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default if default is not None else {}


def cfg():
    return load_json(CONFIG_PATH, {})


def dash_token():
    t = os.environ.get("BULWARK_DASH_TOKEN") or load_json(DASH_CONFIG, {}).get("token", "")
    return str(t or "").strip()


def db():
    """Read-only, short busy_timeout: a dashboard query must never block harvest."""
    p = cfg().get("db_path", os.path.join(STATE_DIR, "cache.db"))
    c = sqlite3.connect("file:%s?mode=ro" % p, uri=True, timeout=5)
    c.execute("PRAGMA busy_timeout=4000")
    c.row_factory = sqlite3.Row
    return c


_CACHE = {}


def cached(key, ttl, fn):
    """Tiny TTL cache for the expensive shell-outs. Six endpoints polled every few
    seconds would otherwise spawn a steady stream of journalctl processes. A racing
    duplicate computation is harmless, so no lock."""
    hit = _CACHE.get(key)
    now = time.monotonic()
    if hit and now - hit[0] < ttl:
        return hit[1]
    val = fn()
    _CACHE[key] = (now, val)
    return val


def journal(unit, lines=400):
    def run():
        try:
            r = subprocess.run(
                ["journalctl", "-u", unit, "-n", str(lines), "--no-pager", "-o", "short-iso"],
                capture_output=True, text=True, timeout=15)
            return r.stdout or ""
        except Exception:
            return ""
    return cached("journal:" + unit, 8.0, run)


def jsonl(path, limit=0, tail=True):
    """Read a JSONL ledger. tail=True returns the newest `limit` records, else the
    oldest. Bad lines are skipped rather than breaking the whole page."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception:
        return [], 0
    recs, total = [], 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        total += 1
        try:
            recs.append(json.loads(line))
        except Exception:
            continue
    if limit:
        recs = recs[-limit:] if tail else recs[:limit]
    return recs, total


# Two collectors, two closing-line shapes:
#   harvest.py           [harvest 17:11:06] done {json}
#   bulwark-datalake.py  [datalake] done stopped_by=<why> {json}
# The reason sits OUTSIDE the JSON in the second shape, so it needs its own group.
# Demanding '{' immediately after 'done ' matched zero datalake runs -- 118 of them
# on node 245 -- which left every per-run counter on every page reading 0 while the
# node was visibly working.
DONE_RE = re.compile(r"(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})\S*\s"
                     r".*done (?:stopped_by=(\S+)\s+)?(\{.*\})")

# A node runs one collector or the other. Reading both costs one extra cached
# journalctl call and means the dashboard never has to be told which is installed.
COLLECTOR_UNITS = ("bulwark-harvest", "bulwark-datalake")
SYNC_RE = re.compile(r"(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})\S*\s.*master says: OK "
                     r"received=(\d+) inserted=(\d+) skipped=(\d+)\D+total=(\d+)")
PAY_RE = re.compile(r"(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})\S*\s.*payload (\d+) rows, ([\d.]+) KB")


def collector_journal(unit, days=2):
    """Only the closing lines of collector runs, filtered inside journalctl.

    `-n 400` cannot work here: the datalake writes a rate-limiter progress line
    about once a second, so 400 lines is roughly the last ten minutes. Measured on
    node 245: 6 closing lines inside `-n 400` versus 86 inside a two-day window --
    so every run summary from earlier the same day was invisible and every per-run
    counter on every page read 0 while the node was busy.

    That same two-day window holds 24286 lines in total, which is why the filter
    goes into journalctl rather than into Python. --grep needs systemd >= 237
    (node 245 runs 255); older journalctl gets a large -n instead, still far
    above 400.
    """
    def run():
        base = ["journalctl", "-u", unit, "--since", "%d days ago" % days,
                "--no-pager", "-o", "short-iso"]
        try:
            r = subprocess.run(base + ["--grep", "done "],
                               capture_output=True, text=True, timeout=30)
            if r.returncode == 0 and r.stdout:
                return r.stdout
        except Exception:
            pass
        try:
            r = subprocess.run(base + ["-n", "20000"],
                               capture_output=True, text=True, timeout=45)
            return r.stdout or ""
        except Exception:
            return ""
    return cached("cj:%s:%d" % (unit, days), 20.0, run)


def _num(j, *names):
    """First name that is present wins.

    The two collectors count the same things under different names: harvest.py
    fetches a zip from MalwareBazaar and calls it `downloaded`, the datalake pulls
    the binary out of an hourly archive and calls it `extracted`. Mapping them here
    keeps every downstream panel collector-agnostic.
    """
    for nm in names:
        if j.get(nm) is not None:
            return int(j.get(nm) or 0)
    return 0


def harvest_runs(limit=0):
    """limit=0 = every run in the journal window.

    It defaulted to 30, which was fine for an hourly collector (24 runs a day) and
    silently wrong for one that runs every half hour: today's 34 runs on node 245
    got truncated to 30, so the per-day totals under-reported. Callers that display
    a table slice it themselves; callers that add up a day must not be handed a
    pre-truncated list.
    """
    out = []
    for unit in COLLECTOR_UNITS:
        for line in collector_journal(unit).splitlines():
            m = DONE_RE.search(line)
            if not m:
                continue
            try:
                j = json.loads(m.group(4))
            except Exception:
                continue
            out.append({
                "unit": unit,
                "day": m.group(1), "time": m.group(2),
                "looked": _num(j, "looked"),
                "stored": _num(j, "stored"),
                "unknown": _num(j, "unknown"),
                "downloaded": _num(j, "downloaded", "extracted"),
                "uploaded": _num(j, "uploaded"),
                "skipped": _num(j, "upload_skipped", "skipped_budget"),
                "stale": _num(j, "stale_skipped", "out_of_window"),
                "errors": _num(j, "errors"),
                "queued": _num(j, "queued"),
                # harvest.py puts the reason inside the JSON, the datalake puts it
                # in the line prefix. Accept either.
                "stopped_by": (m.group(3) or j.get("stopped_by") or ""),
                # VT spend per run. vt_calls counts lookups AND uploads, which is what
                # the per-minute limit actually meters; vt_left is what the shared daily
                # allowance had left when the run ended. The datalake's closing line
                # carries neither, so derive the spend from what a run demonstrably
                # spent: one call per lookup plus one per upload. Reporting 0 there
                # would understate the node's real VT usage, which is the one number
                # on this dashboard that must never read low.
                "vt_calls": (int(j.get("vt_calls") or 0)
                             if j.get("vt_calls") is not None
                             else _num(j, "looked") + _num(j, "uploaded")),
                "vt_left": (None if j.get("vt_left") is None
                            else int(j.get("vt_left") or 0)),
                "rate_per_min": _num(j, "rate_per_min"),
                "window_days": (None if j.get("max_age_days") is None
                                else int(j.get("max_age_days") or 0)),
            })
    # Newest first across BOTH units: a node that switched collectors mid-life
    # should read as one continuous history, not one unit's block then the other's.
    out.sort(key=lambda r: (r["day"], r["time"]), reverse=True)
    return out[:limit] if limit else out


def sync_ledger(limit=30):
    """Reads the append-only ledger bulwark-sync.py writes after each push."""
    recs, _ = jsonl(SYNC_LOG, limit * 4)
    out = []
    for j in recs:
        ts = str(j.get("ts", ""))
        day, _, tm = ts.partition("T")
        out.append({
            "day": day, "time": tm[:8],
            "rows": int(j.get("rows", 0) or 0),
            "kb": round(float(j.get("kb", 0) or 0), 1),
            "received": int(j.get("received", 0) or 0),
            "inserted": int(j.get("inserted", 0) or 0),
            "skipped": int(j.get("skipped", 0) or 0),
            "master_total": int(j.get("master_total", 0) or 0),
            "ok": bool(j.get("ok", False)),
            "error": j.get("error", ""),
        })
    out.sort(key=lambda r: (r["day"], r["time"]), reverse=True)
    return out[:limit]


def sync_runs(limit=30):
    """Ledger first; journal parsing is only a fallback for runs that predate it."""
    led = sync_ledger(limit)
    if led:
        return led
    text = journal("bulwark-sync")
    pay, out = [], []
    for line in text.splitlines():
        p = PAY_RE.search(line)
        if p:
            pay.append({"rows": int(p.group(3)), "kb": float(p.group(4))})
            continue
        m = SYNC_RE.search(line)
        if m:
            pl = pay.pop() if pay else {}
            out.append({"day": m.group(1), "time": m.group(2),
                        "rows": pl.get("rows", int(m.group(3))), "kb": pl.get("kb", 0.0),
                        "received": int(m.group(3)), "inserted": int(m.group(4)),
                        "skipped": int(m.group(5)), "master_total": int(m.group(6)),
                        "ok": True, "error": ""})
    for line in text.splitlines():
        if "push FAILED" in line:
            m = re.search(r"(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})", line)
            if m:
                out.append({"day": m.group(1), "time": m.group(2), "rows": 0, "kb": 0.0,
                            "received": 0, "inserted": 0, "skipped": 0,
                            "master_total": 0, "ok": False, "error": ""})
    out.sort(key=lambda r: (r["day"], r["time"]), reverse=True)
    return out[:limit]


def sysd(args, timeout=10):
    def run():
        try:
            r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
            return (r.stdout or "").strip()
        except Exception:
            return ""
    return cached("sysd:" + " ".join(args), 4.0, run)


def timer_next(unit):
    parts = sysd(["systemctl", "list-timers", unit, "--no-pager", "--no-legend"]).split()
    return " ".join(parts[:3]) if parts else ""


_TS = re.compile(r"(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})")


def sync_health():
    """回传 has no timer, by design -- so do not report it as one.

    bulwark-datalake.service and bulwark-harvest.service both carry
    OnSuccess=bulwark-sync.service: the push runs right after a collection run that
    actually finished cleanly, which is when there is something new to send. There is
    deliberately no bulwark-sync.timer.

    The header used to render `is-active bulwark-sync.timer`, which for a unit that
    does not exist answers "inactive" forever, and 下次回传 stayed "-". Both were
    read as "回传 is broken" while the service was in fact pushing every half hour
    and the master was accepting the rows. So report the last run of the *service*:
    its result, when it ended, and what triggers it.
    """
    out = sysd(["systemctl", "show", "bulwark-sync.service",
                "-p", "Result", "-p", "ExecMainExitTimestamp", "-p", "ActiveState"])
    kv = {}
    for ln in out.splitlines():
        if "=" in ln:
            k, v = ln.split("=", 1)
            kv[k.strip()] = v.strip()
    active = kv.get("ActiveState", "")
    result = kv.get("Result", "")
    stamp, ago = "", None
    m = _TS.search(kv.get("ExecMainExitTimestamp", ""))
    if m:
        stamp = m.group(2)
        try:
            # systemd prints these in UTC on these nodes (the header clock is UTC too),
            # so no timezone conversion is involved.
            when = datetime.strptime("%s %s" % (m.group(1), m.group(2)),
                                     "%Y-%m-%d %H:%M:%S")
            ago = max(0, int((now_utc().replace(tzinfo=None) - when).total_seconds() // 60))
        except Exception:
            ago = None
    if active in ("active", "activating", "reloading"):
        state = "running"
    elif not m:
        state = "never"
    elif result and result != "success":
        state = "fail"
    else:
        state = "ok"
    return {"state": state, "last": stamp, "ago": ago, "result": result or "-"}


def head_ctx():
    """Everything the shared header needs, on every view.

    The collector light used to watch bulwark-harvest.timer unconditionally, so on
    a datalake node it sat on "inactive" forever while collection was in fact
    running every half hour. Watch whichever collector timer this node has.
    """
    unit = ("bulwark-datalake" if collector_info()["name"] == "datalake"
            else "bulwark-harvest")
    sh = sync_health()
    return {
        "now": now_utc().strftime("%Y-%m-%d %H:%M:%S"),
        "node": os.uname().nodename,
        "u": {
            "intel": sysd(["systemctl", "is-active", "bulwark-intel"]),
            "collector": unit,
            "harvest": sysd(["systemctl", "is-active", unit + ".timer"]),
            "next_h": timer_next(unit + ".timer"),
            # 回传 is chained off the collector's success, not scheduled, so it gets
            # last-run health instead of an is-active light and a next-run time.
            "sync_state": sh["state"],
            "sync_last": sh["last"],
            "sync_ago": sh["ago"],
            "sync_result": sh["result"],
            "sync_trigger": "%s 每轮成功后自动触发" % collector_info()["label"],
        },
    }


VTKEY_SPOOL = os.path.join(STATE_DIR, "vtkey-spool")
VTKEY_LOG = os.path.join(STATE_DIR, "vtkey_log.jsonl")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def vtkey_fp(key):
    """Short, non-reversible label for a key. Never show the key itself: this
    page is reachable over plain HTTP, and a screenshot of it should not leak
    anything usable."""
    return hashlib.sha256(key.encode()).hexdigest()[:6]


VTKEY_STATUS = os.path.join(STATE_DIR, "vtkey_status.json")
# 这些状态说明密钥已经坏了、不会自己恢复,因此才允许删。
# quota / rate 是暂时的,刻意【不】列进来 —— 让一把还能用的密钥可删,等于把它交给一次手滑。
VTKEY_DEAD = ("banned", "invalid", "malformed")
# 「配额用完」既不是坏掉(UTC 0 点会自己回来),也不是「今天还能用」。这两件事都得说,
# 否则就会出现同一屏上 6 行全写着「配额用完」、而 KPI 写着「剩余 1796 次」的自相矛盾。
VTKEY_SPENT = ("quota",)
# 探测结果超过这个时长就不拿它下「今天到底还剩多少」的结论 —— 定时器 6 小时一轮,
# 留一倍余量。
VTKEY_FRESH_MIN = 12 * 60


def vtkey_age_minutes(checked_at):
    """探测结果的年龄(分钟)。拿不到就返回 None,由调用方决定怎么办 —— 不猜。"""
    if not checked_at:
        return None
    try:
        t = datetime.strptime(str(checked_at), "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None
    return max(0, int((now_utc() - t).total_seconds() // 60))


def utc_reset_minutes():
    """距离 UTC 0 点还有多少分钟。VirusTotal 的每日配额按 UTC 日切,所以「什么时候恢复」
    是个能算出来的具体数字,没必要让人自己猜。"""
    n = now_utc()
    return (23 - n.hour) * 60 + (60 - n.minute)


def vtkey_status():
    """root 侧探测出来的每把密钥的状态。页面【只读这个文件】。

    为什么不在这里直接问 VT:渲染一个页面不该发起对外网的调用。这一页每几秒轮询一次,
    每次渲染都探测会把当日配额全花在画界面上,而且上游一慢整页就挂住。
    所以由 bulwark-vtkey.py(root)按时探测并落这个文件,页面只管显示 —— 顺带也就不需要
    给仪表盘任何新权限。
    """
    d = load_json(VTKEY_STATUS, {})
    by_fp = {}
    for e in (d.get("keys") or []):
        if e.get("fp"):
            by_fp[str(e["fp"])] = e
    return d.get("checked_at", ""), by_fp


def vtkey_list():
    """The configured VT key pool, as fingerprints plus what the service makes of
    them. Reads the same config app.py reads, so what is shown is what is loaded
    (modulo a pending restart, which vtkey_pending() surfaces separately)."""
    vt = cfg().get("virustotal", {}) or {}
    raw = vt.get("api_keys") or ([vt.get("api_key")] if vt.get("api_key") else [])
    per_day = int(vt.get("requests_per_day", 0) or 0)
    checked_at, by_fp = vtkey_status()
    out, seen = [], set()
    for item in raw:
        k = str(item).split(":")[0].strip().lower()
        valid = bool(_HEX64.match(k))
        fp = vtkey_fp(k) if k else "??????"
        stat = by_fp.get(fp) or {}
        state = str(stat.get("state") or "")
        q = stat.get("quota") or {}
        out.append({
            "fp": fp,
            "len": len(k),
            "valid": valid,
            "duplicate": valid and k in seen,
            # app.py silently drops anything that is not 64 hex, so a malformed
            # entry contributes nothing to the pool -- say so rather than listing
            # it as if it were working.
            "counted": valid and k not in seen,
            # VT 自己的说法。没探测过就如实说没探测过,不猜。
            "state": state or ("malformed" if not valid else "unchecked"),
            "state_label": stat.get("label") or ("不是合法密钥" if not valid
                                                 else "尚未探测"),
            "http": stat.get("http"),
            "code": stat.get("code") or "",
            "q_used": q.get("used"), "q_allowed": q.get("allowed"),
            "removable": bool(stat.get("removable")) or not valid,
        })
        if valid:
            seen.add(k)
    live = len([x for x in out if x["counted"]])
    # 真正能用的把数:探测说坏掉的不算。这才是「今日还能查多少次」的正确分母 ——
    # 之前把 3 把封禁的也算进去,页面上写着 3000,实际只有 1500。
    usable = len([x for x in out if x["counted"] and x["state"] not in VTKEY_DEAD])
    age = vtkey_age_minutes(checked_at)
    counted = [x for x in out if x["counted"]]
    return {
        "keys": out,
        "live": live,
        "usable": usable,
        "dead": len([x for x in out if x["state"] in VTKEY_DEAD]),
        # 「此刻」的三种情形,分开数:探测说 ok 的、说配额用完的、说被限速的。
        # 合成一个「不可用」会把「明天回来」和「一分钟后回来」当成同一件事。
        "ok_now": len([x for x in counted if x["state"] == "ok"]),
        "exhausted": len([x for x in counted if x["state"] in VTKEY_SPENT]),
        "limited": len([x for x in counted if x["state"] == "rate"]),
        "probed": len([x for x in counted if x["state"] != "unchecked"]),
        "checked_at": checked_at,
        "age_minutes": age,
        "fresh": age is not None and age <= VTKEY_FRESH_MIN,
        "reset_minutes": utc_reset_minutes(),
        "per_day_each": per_day,
        "pool_per_day": per_day * max(1, live),
        "usable_per_day": per_day * usable,
    }


def vtkey_pending():
    """Requests dropped but not yet applied by the root-side helper."""
    try:
        return len([n for n in os.listdir(VTKEY_SPOOL) if n.endswith(".json")])
    except OSError:
        return 0


def vtkey_history(limit=20):
    recs, _ = jsonl(VTKEY_LOG, limit * 3)
    out = []
    for j in recs:
        out.append({
            "ts": j.get("ts", ""), "status": j.get("status", ""),
            "fp": j.get("fp", ""), "detail": j.get("detail", ""),
            "ok": bool(j.get("ok")), "restarted": bool(j.get("restarted")),
            "restart_error": j.get("restart_error", ""),
        })
    out.reverse()
    return out[:limit]


def vtkey_submit(raw):
    """Validate here too, not just in the root helper: rejecting an obvious typo
    with an immediate, specific message beats writing a spool file and making the
    user go read a log to find out it was malformed."""
    k = str(raw or "").split(":")[0].strip().lower()
    if not k:
        return False, "key is empty"
    if not _HEX64.match(k):
        return False, ("not a VirusTotal key: expected 64 hex characters, got %d "
                       "character(s)" % len(k))
    if any(x["fp"] == vtkey_fp(k) and x["counted"] for x in vtkey_list()["keys"]):
        return False, "this key is already configured"
    try:
        os.makedirs(VTKEY_SPOOL, exist_ok=True)
        os.chmod(VTKEY_SPOOL, 0o750)
        # Name by fingerprint, not by key, so the spool filename itself is not a
        # secret; timestamp keeps retries of the same key distinguishable.
        name = "%s-%s.json" % (int(time.time()), vtkey_fp(k))
        tmp = os.path.join(VTKEY_SPOOL, name + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"key": k, "requested_at": now_utc().strftime("%Y-%m-%dT%H:%M:%SZ")}, f)
        os.chmod(tmp, 0o640)
        os.replace(tmp, os.path.join(VTKEY_SPOOL, name))
    except OSError as e:
        return False, "could not queue the request: %s" % e
    return True, ("queued as %s; bulwark-intel restarts automatically to pick it up"
                  % vtkey_fp(k))


def _vtkey_queue(payload, tag):
    """把一条请求丢进 spool。仪表盘对 config.json 只有读权限,所有写动作都必须经由
    root 侧的 bulwark-vtkey.py —— 这条边界是刻意的,不为了一个按钮而放宽。"""
    try:
        os.makedirs(VTKEY_SPOOL, exist_ok=True)
        os.chmod(VTKEY_SPOOL, 0o750)
        name = "%s-%s.json" % (int(time.time()), tag)
        tmp = os.path.join(VTKEY_SPOOL, name + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(dict(payload,
                           requested_at=now_utc().strftime("%Y-%m-%dT%H:%M:%SZ")), f)
        os.chmod(tmp, 0o640)
        os.replace(tmp, os.path.join(VTKEY_SPOOL, name))
    except OSError as e:
        return False, "could not queue the request: %s" % e
    return True, name


def vtkey_remove(fp):
    """请求删除一把密钥。这里只做「能不能提出这个请求」的检查;真正的判据在 root 侧,
    它会在删除的那一刻重新探测一次,答案不是封禁/无效就拒绝。

    为什么不在这里就定死:页面上的状态最多可能是 6 小时前的快照,而删除是不可逆的。
    UI 的作用是把候选交上去,不是替 root 下结论。
    """
    fp = str(fp or "").strip().lower()
    if not re.match(r"^[0-9a-f]{6}$|^\?{6}$", fp):
        return False, "指纹格式不对(应为 6 位十六进制)"
    info = vtkey_list()
    hit = [k for k in info["keys"] if k["fp"] == fp]
    if not hit:
        return False, "配置里没有这个指纹"
    k = hit[0]
    if not k["removable"]:
        return False, ("这把密钥当前状态是「%s」,不是封禁或无效 —— 只有确定坏掉的才允许"
                       "删除。配额用完会自己恢复。" % k["state_label"])
    # 不能把池子删空:那等于悄悄把 VT 整个关掉,是另一回事。
    if info["usable"] <= 0 and len([x for x in info["keys"] if x["counted"]]) <= 1:
        return False, "这是最后一把密钥 —— 拒绝把 VirusTotal 清空"
    ok, detail = _vtkey_queue({"action": "remove", "fp": fp}, "rm" + fp)
    if not ok:
        return False, detail
    return True, ("已排队删除 %s;root 侧会重新探测确认后再删,并自动重启 bulwark-intel"
                  % fp)


def vtkey_capacity(info, used):
    """(今日剩余, 是不是每一把都把今天的配额用光了)。

    默认按【可用】把数算余量,不按配置里的把数 —— 后者会得到一个永远打不到的上限。

    但「按可用把数算」还不够:一把密钥可以既没被封、又拿不到任何结果。245 上现在就是
    6 把全部 429 QuotaExceededError —— 连 20 分钟前刚添加的新密钥也是,而本机今天只记了
    1210 次调用。实测把同一把密钥交给主服务器的 IP 调用会立刻返回 200,所以真正的原因
    不是账号额度,而是 VirusTotal 在拒绝这台机器的地址;本机的计数器不可能知道这件事。
    探测是问 VirusTotal 本人拿到的答案,所以当它说【每一把都被拒】时,今日剩余就是 0,
    不管本机的计数器写着多少。

    拆成独立函数是为了能在不搭起整页上下文的情况下测它:这一句决定页面上写 0 还是写
    1796,值得有测试守着。
    """
    left = max(0, info["usable_per_day"] - used)
    # 三个条件都必要:探测结果够新(否则拿半天前的快照下今天的结论)、确实探过、
    # 而且没有任何一把是 ok。少了 exhausted>0 这条,一池子全是 unknown/网络失败也会被
    # 说成「配额用完」—— 那是把「不知道」当成「知道」。
    spent_all = bool(info.get("fresh") and info.get("probed")
                     and not info.get("ok_now") and info.get("exhausted"))
    return (0 if spent_all else left), spent_all


def vtkey_probe_now():
    """让 root 侧立刻重新探测一次。给操作者一个不用等 6 小时的出口。"""
    ok, detail = _vtkey_queue({"action": "probe"}, "probe")
    if not ok:
        return False, detail
    return True, "已排队探测;几秒后刷新本页即可看到最新状态"


def v_vtkeys():
    d = head_ctx()
    info = vtkey_list()
    used = 0
    try:
        with db() as conn:
            row = conn.execute("SELECT count FROM quota WHERE source=? AND day=?",
                               ("VirusTotal", today())).fetchone()
            used = row["count"] if row else 0
    except Exception:
        pass
    left, spent_all = vtkey_capacity(info, used)
    d.update({
        "db_error": "",
        "k": {
            "keys": info["keys"],
            "live": info["live"],
            "usable": info["usable"],
            "dead": info["dead"],
            "ok_now": info["ok_now"],
            "exhausted": info["exhausted"],
            "limited": info["limited"],
            "probed": info["probed"],
            "checked_at": info["checked_at"],
            "age_minutes": info["age_minutes"],
            "fresh": info["fresh"],
            "reset_minutes": info["reset_minutes"],
            "spent_all": spent_all,
            "per_day_each": info["per_day_each"],
            "pool_per_day": info["pool_per_day"],
            "usable_per_day": info["usable_per_day"],
            "used_today": used,
            "left_today": left,
            "pending": vtkey_pending(),
            "history": vtkey_history(),
        },
    })
    return d


def _b_cap(h):
    """Daily VT upload ceiling. Negative means no local ceiling, in which case the
    shared VT quota metered by the intel service is the only limit. 0 still means
    uploads are switched off, so `x or 0` must not be used to normalise it."""
    v = h.get("vt_upload_budget_per_day")
    if v is None or v == "":
        return 20
    try:
        return int(v)
    except (TypeError, ValueError):
        return 20


def rate_cfg(h):
    """queries_per_minute is the knob; sleep_seconds is the legacy fallback, shown
    converted so a page always states an actual rate."""
    qpm = h.get("queries_per_minute")
    if qpm:
        rate = float(qpm)
    else:
        sl = float(h.get("sleep_seconds", 0) or 0)
        rate = round(60.0 / sl, 2) if sl else 0.0
    return rate, (round(60.0 / rate, 1) if rate else 0.0)


def file_records(limit=0):
    """harvest_files.jsonl, newest first. limit=0 = the whole ledger, on purpose.

    It used to default to 400 while both writers rotate the ledger at 1000 lines /
    512 KB. So on a node that logs a line per sample LOOKED AT (not just per sample
    downloaded), today's downloads scrolled out of the read window while still
    sitting in the file, and every download/upload panel showed 0 directly above
    "台账总条数 1016". Measured on node 245: 285 downloads / 22.6 MB, all inside
    lines 1..466 of 1016, none of them in the last 400.

    The rotation is what bounds the cost of reading this file, not this limit --
    which is exactly why the limit had no business being smaller than the rotation.
    """
    recs, total = jsonl(FILES_LOG, limit)
    out = []
    for x in reversed(recs):
        out.append({
            "ts": x.get("ts", ""), "sha256": str(x.get("sha256", "")),
            "name": x.get("name", ""), "type": x.get("type", ""),
            "size": int(x.get("size", 0) or 0), "sig": x.get("sig", ""),
            "zip_kb": float(x.get("zip_kb", 0) or 0),
            "day": x.get("day", ""),
            "vt_unknown": bool(x.get("vt_unknown")),
            "downloaded": bool(x.get("downloaded")),
            "uploaded": bool(x.get("uploaded")),
            "upload_ok": bool(x.get("upload_ok")),
            "skipped_budget": bool(x.get("skipped_budget")),
            "skipped_stale": bool(x.get("skipped_stale")),
            "zip_bad": bool(x.get("zip_bad")),
            "error": x.get("error", ""),
        })
    return out, total


def queue_count():
    try:
        with open(QUEUE_LOG, "r", encoding="utf-8") as f:
            return sum(1 for line in f if line.strip())
    except Exception:
        return 0


# --------------------------------------------------------------------------- #
#  手工送检:浏览器批量丢文件进来,本节点算哈希 -> 查 -> (可选)提交 VT           #
# --------------------------------------------------------------------------- #
# 样本字节【流式落到 submit-spool/inbox】,由 bulwark-submit.py(root)接手排队处理。
#
# 这里有过两版,都不够用:
#  · 第一版落 /var/lib/bulwark-intel/dash_uploads 再删,上线即报「Read-only file
#    system」—— bulwark-dash.service 带 ProtectSystem=strict。
#  · 第二版改成纯内存、一个字节不落盘,并把上限压到 32 MB、一批 50 个。它满足不了
#    现在的要求:数量不设上限、每 3 分钟复查、切页面不丢进度。三件事都要求记录活得
#    比一次请求久,而 VT 的分析本身就要好几分钟 —— 内存里的批次做不到。
#
# 所以回到磁盘,但口子开得和 vtkey-spool 一样窄:只有 submit-spool 一个子目录可写,
# cache.db、台账、config.json 仍然只读。字节的责任因此换成了「必须有人删」:
#   · 出结论/VT 已接收 -> worker 立刻删
#   · 没到终态的 -> 按 bytes_max_hours(默认 24h)删
#   · 兜底 -> bulwark-janitor.py --samples 每天按 2 倍保留期扫
# 再加一道总量闸门(spool_max_mb):数量不设上限的前提是磁盘有上限,否则「不限数量」
# 等于「谁拿到令牌都能把节点写满」,而这台机器上还躺着情报库。
SUBMIT_SPOOL = os.path.join(STATE_DIR, "submit-spool")
# 半成品【不能】写进 inbox。bulwark-submit.path 盯的是 inbox 的 DirectoryNotEmpty:
# 只要目录非空条件就成立,于是一个正在写的 .part(650 MB 能写好几分钟)会让 worker 被
# 无限重启;一个上传被打断留下的 .part 孤儿更会让它永远转下去。
# 线上实测就是这个形状:同一秒三次「待办 0」的空跑。
# 所以先写 staging,写完整了再 os.replace 进 inbox —— inbox 里因此只会出现成对的
# 完整文件,也就能真正被 worker 抽干、让触发表现成边沿。
SUBMIT_STAGING = os.path.join(SUBMIT_SPOOL, "staging")
SUBMIT_INBOX = os.path.join(SUBMIT_SPOOL, "inbox")
SUBMIT_ITEMS = os.path.join(SUBMIT_SPOOL, "items")


def upload_cfg():
    """上传相关的上限。

    单文件上限【跟着 VirusTotal 的上限走】,而且不写死:取 max_upload_mb —— 那正是本机
    intel 服务转发样本时会执行的上限(默认 650,就是 VT 公开 API 的上限)。写死一个数字
    的坏处很具体:两处一旦不一致,页面会先收下一个文件、排进队列、等到 worker 真去提交时
    才被 /vt/upload 以 400 拒掉,而那时用户已经等了几分钟。让页面宣称的上限【等于】
    转发端会执行的上限,这种失败就不存在。

    VT 侧还有一道分界:超过 32 MB 要先取专用上传地址,因此会多花一次 VT 请求。这条由
    app.py 的 submit_file_path 自动处理,这里不必区分,但页面上说清楚。
    """
    c = cfg()
    d = ((c.get("dashboard") or {}).get("upload") or {})
    svc_cap = int(c.get("max_upload_mb", 650) or 650)
    return {"enabled": bool(d.get("enabled", True)),
            # 显式配了就用配的,但绝不允许超过转发端的上限。
            "max_mb": min(int(d.get("max_mb", svc_cap) or svc_cap), svc_cap),
            "svc_cap_mb": svc_cap,
            "allow_submit": bool(d.get("allow_vt_submit", True)),
            # 0 = 不限数量。保留这个键只为让运维能临时收紧,默认放开。
            "max_batch": int(d.get("max_batch", 0) or 0),
            # 单文件能到 650 MB 之后,排队区得装得下几个这种文件才有意义。
            "spool_max_mb": int(d.get("spool_max_mb", 10240) or 10240),
            # 「数量不限」真正的护栏不是字节上限而是这条:无论上面配成多少,都必须给磁盘
            # 留出这么多空闲。情报库(cache.db)和采集都在同一块盘上,把盘写满的代价远大于
            # 拒收一个文件。
            "disk_floor_mb": int(d.get("disk_floor_mb", 4096) or 4096),
            "poll_minutes": int(d.get("poll_minutes", 3) or 3),
            "keep_days": float(d.get("keep_days", 7) or 7),
            # 这两个的默认值必须和 bulwark-submit.py 的 ucfg() 一字不差,否则页面写着
            # 「会自动解压、口令 infected」而 worker 用的是另一套 —— 页面上的承诺就成了
            # 假的。同一个配置块、同一个默认值,是唯一能保证两边一致的做法。
            "archive_expand": bool(d.get("archive_expand", True)),
            "archive_passwords": [str(p) or "(无密码)" for p in
                                  (d.get("archive_passwords") or ["", "infected"])]}


def disk_free_mb(path=STATE_DIR):
    """状态目录所在盘还剩多少 MB。-1 表示问不出来。

    用 shutil.disk_usage 而不是 os.statvfs:后者在 Windows 上不存在,于是这道闸门在开发
    机上永远返回 -1、永远被跳过 —— 也就永远测不到。一条只在生产环境才生效的拒收逻辑,
    等于一条没验证过的拒收逻辑。
    """
    try:
        return int(shutil.disk_usage(path).free / 1048576)
    except Exception:
        return -1          # 问不出来就不拿它当拒收依据


def spool_bytes():
    """当前 spool 里还压着多少字节。包含 inbox 与 items 两处。"""
    total, files = 0, 0
    # staging 也要算:正在传的字节同样占着磁盘,总量闸门必须看得见它们,否则同时传
    # 十几个大文件就能绕过上限。
    for d in (SUBMIT_INBOX, SUBMIT_ITEMS, SUBMIT_STAGING):
        try:
            names = os.listdir(d)
        except OSError:
            continue
        for nm in names:
            if not nm.endswith((".bin", ".bin.part")):
                continue
            try:
                total += os.path.getsize(os.path.join(d, nm))
                files += 1
            except OSError:
                pass
    return total, files


def submit_items(limit=400):
    """读队列。返回 (最近的 limit 条, 汇总计数)。

    汇总【必须扫全部记录】而不是只扫返回的那一页:页面上的「共 N 个/ 已完成 M」是
    进度条的分母和分子,用一页的数字当总数会让进度在记录变多时倒退。
    """
    recs = []
    agg = {"total": 0, "queued": 0, "checking": 0, "vt_wait": 0, "done": 0,
           "failed": 0, "skipped": 0, "malicious": 0, "suspicious": 0, "clean": 0,
           # 压缩包自己的两个状态。不并进 done:包没有被查过,并进去会让「已完成」
           # 这个数字变成一个查询量与容器数量的混合物。
           "expanding": 0, "expanded": 0, "archives": 0, "from_archive": 0,
           "unknown": 0, "master_hit": 0, "submitted": 0, "bytes": 0, "today": 0,
           # 回传三级:入库了 -> 随批次推送了 -> 主服务器账本确认收到了。
           "stored": 0, "pushed": 0, "acked": 0}
    t = today()
    for d in (SUBMIT_ITEMS, SUBMIT_INBOX):
        try:
            names = os.listdir(d)
        except OSError:
            continue
        for nm in names:
            if not nm.endswith(".json"):
                continue
            r = load_json(os.path.join(d, nm), None)
            if not isinstance(r, dict) or not r.get("id"):
                continue
            # inbox 里的还没被 worker 认领,状态显示成排队 —— 它确实在排队。
            st = str(r.get("state") or "queued")
            if d == SUBMIT_INBOX and st in ("", "new"):
                st = "queued"
            agg["total"] += 1
            if st in agg:
                agg[st] += 1
            if str(r.get("at") or "")[:10] == t:
                agg["today"] += 1
            if st == "done":
                v = str(r.get("verdict") or "unknown")
                agg[v if v in ("malicious", "suspicious", "clean") else "unknown"] += 1
            if str(r.get("kind") or "").startswith("archive:"):
                agg["archives"] += 1
            if r.get("from_archive"):
                agg["from_archive"] += 1
            if r.get("master_hit"):
                agg["master_hit"] += 1
            if r.get("submitted"):
                agg["submitted"] += 1
            if r.get("stored_at"):
                agg["stored"] += 1
            if r.get("sync_pushed"):
                agg["pushed"] += 1
            if r.get("master_new"):
                agg["acked"] += 1
            agg["bytes"] += int(r.get("size") or 0)
            r["state"] = st
            recs.append(r)
    recs.sort(key=lambda x: str(x.get("at") or ""), reverse=True)
    return recs[:limit], agg


_SVC = {"base": None, "at": 0.0}


def svc_base():
    """本机 intel 服务的地址,scheme 靠探测而不是写死。

    主服务器自己终止 TLS,节点 245 在同一个端口上是明文 HTTP。写死 scheme 的代价在
    _deploy-app.sh 里已经付过一次:探错协议时 curl 对每条路径都回 HTTP 000,读起来
    和服务挂了一模一样,白追过一次不存在的故障。所以这里也照 /health 探一次,并缓存。
    """
    now = time.time()
    if _SVC["base"] and now - _SVC["at"] < 60:
        return _SVC["base"]
    c = cfg()
    explicit = (c.get("harvest", {}) or {}).get("service_url")
    port = int(c.get("listen_port", 8787) or 8787)
    cands = ([explicit.rstrip("/")] if explicit else []) + [
        "https://127.0.0.1:%d" % port, "http://127.0.0.1:%d" % port]
    for b in cands:
        try:
            with urllib.request.urlopen(b + "/health", timeout=6,
                                        context=_NOVERIFY) as r:
                if r.status == 200:
                    _SVC["base"] = b
                    _SVC["at"] = now
                    return b
        except Exception:
            continue
    return None


# 回环上是自签证书,校验必然失败;对端是本机进程,没有中间人可插入。
_NOVERIFY = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
_NOVERIFY.check_hostname = False
_NOVERIFY.verify_mode = ssl.CERT_NONE


def svc_call(path, data, ctype, timeout=300):
    base = svc_base()
    if not base:
        return 0, {"error": "本机 intel 服务不可达(https/http 都探过)"}
    req = urllib.request.Request(base + path, data=data,
                                 headers={"Content-Type": ctype}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_NOVERIFY) as r:
            raw = r.read().decode("utf-8", "replace")
            try:
                return r.status, json.loads(raw)
            except Exception:
                return r.status, {"error": "服务端返回非 JSON"}
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8", "replace"))
        except Exception:
            return e.code, {}
    except Exception as e:
        return 0, {"error": repr(e)[:160]}


def verdict_of(report):
    """从一份报告里读出「几个引擎报毒 / 共几个」和结论。

    两种形状都要认:VT 正常作答时数据在 file.last_analysis_stats;VT 不可用而备用源
    答话时(degraded)只有 sources 数组。只认前者的话,降级报告会显示成 0/0 干净 ——
    那是把「没问到 VT」说成「没问题」。
    """
    f = (report or {}).get("file") or {}
    stats = f.get("last_analysis_stats") or {}
    if stats:
        mal = int(stats.get("malicious", 0) or 0)
        susp = int(stats.get("suspicious", 0) or 0)
        tot = sum(int(v or 0) for v in stats.values())
        ptc = f.get("popular_threat_classification") or {}
        label = (ptc.get("suggested_threat_label", "")
                 if isinstance(ptc, dict) else "")
        v = "malicious" if mal >= 5 else ("suspicious" if (mal or susp) else "clean")
        return v, mal, tot, label, f.get("meaningful_name") or "", f.get("type_tag") or ""
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


def v_upload():
    """送检页要的东西:上限、当日 VT 余量、本节点的采集器身份,以及【队列本身】。

    队列是从磁盘读的,不是从浏览器内存读的 —— 这就是切走再回来进度还在的原因:
    导航是真链接、整页重载,任何存在 JS 里的进度都必然丢。
    """
    u = upload_cfg()
    c = cfg()
    vt = c.get("virustotal", {}) or {}
    raw = vt.get("api_keys") or ([vt.get("api_key")] if vt.get("api_key") else [])
    keys = [k for k in (str(x).split(":")[0].strip() for x in raw) if len(k) == 64]
    cap = int(vt.get("requests_per_day", 500) or 500) * max(1, len(keys))
    used = 0
    db_err = ""
    try:
        with db() as conn:
            r = conn.execute("SELECT count FROM quota WHERE source=? AND day=?",
                             ("VirusTotal", today())).fetchone()
            used = r["count"] if r else 0
    except Exception as e:
        db_err = "%s: %s" % (type(e).__name__, str(e)[:140])
    h = c.get("harvest", {}) or {}
    budget = load_json(os.path.join(STATE_DIR, "harvest_upload_budget.json"), {})
    items, agg = submit_items()
    sp_bytes, sp_files = spool_bytes()
    # 最近几次真实的回传批次。用的是 bulwark-sync 自己写的台账,不是 journal ——
    # bulwark-sync 以 root 运行,而这个仪表盘是 bulwarkintel,看不到它的 journal。
    pushes = sync_ledger(6)
    # 用内建 open,不是 io.open —— 这个模块没有 import io,写成 io.open 会抛 NameError,
    # 而它会被下面这个 except 吞掉、水位静默变成空字符串。上线时就是这样:worker 明明
    # 读到了水位,页面上却是空的。宽 except 加上一个本可以在导入时就暴露的错误,等于
    # 把一个必然的 bug 变成一个看不见的 bug。
    try:
        with open(os.path.join(STATE_DIR, "sync_watermark.txt"),
                  encoding="utf-8") as f:
            wm = f.read().strip()
    except OSError:
        wm = ""
    d = head_ctx()
    d.update({
        "db_error": db_err,
        "up": {
            "enabled": u["enabled"], "max_mb": u["max_mb"],
            "allow_submit": u["allow_submit"], "max_batch": u["max_batch"],
            "svc": svc_base() or "",
            "vt_used": used, "vt_cap": cap, "vt_left": max(0, cap - used),
            "b_used": int(budget.get("used", 0) or 0),
            "b_cap": _b_cap(h), "b_unlimited": _b_cap(h) < 0,
            "collector": collector_info()["label"],
            "poll_minutes": u["poll_minutes"], "keep_days": u["keep_days"],
            "archive_expand": u["archive_expand"],
            "archive_passwords": u["archive_passwords"],
            "spool_mb": round(sp_bytes / 1048576.0, 1),
            "spool_max_mb": u["spool_max_mb"], "spool_files": sp_files,
            "svc_cap_mb": u["svc_cap_mb"], "disk_floor_mb": u["disk_floor_mb"],
            "disk_free_mb": disk_free_mb(),
            "worker": sysd(["systemctl", "is-active", "bulwark-submit.timer"]),
            "worker_next": timer_next("bulwark-submit.timer"),
        },
        "q2": agg,
        "items": items,
        "pushes": pushes,
        "wm": wm,
    })
    return d


def collector_info():
    """Which collector this node runs, and the download window IT actually used.

    The scope card read harvest.download_max_age_days unconditionally. On a datalake
    node that key means nothing -- the datalake walks hourly archives across
    `window_hours` -- so the card announced "当天 + 回溯 30 天" while the run had in
    fact used 192 hours. Wrong numbers presented confidently are worse than a dash.

    Preference order is deliberate: the last run's own recorded window first, config
    second. The state file says what happened; the config only says what was asked.
    """
    h0 = cfg().get("harvest", {}) or {}
    st = load_json(os.path.join(STATE_DIR, "datalake_state.json"), None)
    if isinstance(st, dict) and st.get("ts"):
        wh = st.get("window_hours")
        wh = None if wh is None else int(wh or 0)
        return {"name": "datalake", "label": "数据湖 · 小时归档",
                "mode": st.get("mode") or "-",
                "window_hours": wh,
                # Never hand the page a null here: it would render as "回溯 null 天".
                # An older state file with no window_hours falls back to the config
                # key, which is at least a number someone configured.
                "window_days": (round(wh / 24.0, 1) if wh is not None
                                else int(h0.get("download_max_age_days", 30) or 0)),
                "last_run": st.get("ts") or "",
                "stopped_by": st.get("stopped_by") or "",
                "vt_remaining": st.get("vt_remaining"),
                "uploads_today": st.get("uploads_today"),
                "newest_slot": st.get("newest_slot") or "",
                "newest_slot_age_hours": st.get("newest_slot_age_hours")}
    return {"name": "harvest", "label": "MalwareBazaar · 逐时采集",
            "mode": h0.get("download_mode") or "-",
            "window_hours": None,
            "window_days": int(h0.get("download_max_age_days", 30) or 0),
            "last_run": "", "stopped_by": "", "vt_remaining": None,
            "uploads_today": None, "newest_slot": "",
            "newest_slot_age_hours": None}


def residue_info():
    """Sample bytes that should not be on disk, separated from the work directory.

    harvest_work is only a leak when no run is in flight: harvest.py creates it at
    the start and rmtree's it at the end. Once the query rate limit stretched a run
    to max_run_seconds the directory became present for most of every hour, so
    flagging it unconditionally turned the residue indicator into a permanent false
    alarm. Loose .zip/.bin files and orphaned bwsync-* temp files are always real.

    Both collectors are covered: harvest.py stages under harvest_work, the datalake
    under datalake_work. Watching only the former meant a datalake node could leave
    a directory of sample bytes behind after a killed run and the indicator would
    still read "无样本字节留存" -- a leak reported as clean is worse than no
    indicator at all.
    """
    try:
        names = os.listdir(STATE_DIR)
    except OSError:
        return {"items": [], "work": False, "work_files": 0, "running": False}
    is_dl = collector_info()["name"] == "datalake"
    unit = "bulwark-datalake.service" if is_dl else "bulwark-harvest.service"
    wdir = "datalake_work" if is_dl else "harvest_work"
    # activating counts as running: the datalake spends most of a run inside the VT
    # rate limiter, and systemd reports Type=oneshot units as activating throughout.
    running = sysd(["systemctl", "is-active", unit]) in ("active", "activating")
    work = wdir in names
    work_files = 0
    if work:
        try:
            work_files = len(os.listdir(os.path.join(STATE_DIR, wdir)))
        except OSError:
            work_files = -1     # exists but unreadable, worth surfacing as unknown
    items = [n for n in names if n.endswith((".zip", ".bin")) or n.startswith("bwsync-")]
    if work and not running:
        items.append(wdir)
    return {"items": items, "work": work, "work_files": work_files, "running": running}


# ---------------------------------------------------------------- views

def _benign_brief():
    """Three numbers for the overview. Swallows every error: the white-sample tables
    are created by a job that may not have run yet on a given node, and a missing
    table must not take the whole overview down with it."""
    out = {"total": 0, "verified": 0, "rejected": 0, "pending": 0, "have": False}
    try:
        with db() as conn:
            out["total"] = conn.execute(
                "SELECT COUNT(*) FROM benign_reports").fetchone()[0]
            out["have"] = True
            for k, w in (("verified", "verified_at<>''"),
                         ("rejected", "rejected_at<>''"),
                         ("pending", "verified_at='' AND rejected_at=''")):
                out[k] = conn.execute(
                    "SELECT COUNT(*) FROM benign_quarantine WHERE " + w).fetchone()[0]
    except Exception:
        pass
    return out


def v_summary():
    """Overview: numbers only, no detail tables."""
    c = cfg()
    vt = c.get("virustotal", {}) or {}
    h = c.get("harvest", {}) or {}
    keys = [k for k in (str(x).split(":")[0].strip() for x in vt.get("api_keys", []))
            if len(k) == 64]
    vt_cap = int(vt.get("requests_per_day", 0) or 0) * max(1, len(keys))
    rate, gap = rate_cfg(h)
    t = today()

    quota, verdicts, per_hour = {}, {}, []
    total_rows = rows_today = 0
    db_err = ""
    try:
        with db() as conn:
            for r in conn.execute("SELECT source,count FROM quota WHERE day=?", (t,)):
                quota[r["source"]] = r["count"]
            total_rows = conn.execute("SELECT COUNT(*) FROM vt_reports").fetchone()[0]
            rows_today = conn.execute(
                "SELECT COUNT(*) FROM vt_reports WHERE substr(stored_at,1,10)=?",
                (t,)).fetchone()[0]
            for r in conn.execute(
                    "SELECT verdict, COUNT(*) n FROM vt_reports "
                    "WHERE substr(stored_at,1,10)=? GROUP BY verdict ORDER BY n DESC", (t,)):
                verdicts[r["verdict"] or "unknown"] = r["n"]
            for r in conn.execute(
                    # 12 是 ISO 时间戳里小时的起始位:2026-08-12T14:30:00Z -> "14"。
                    "SELECT substr(stored_at,12,2) hh, COUNT(*) n FROM vt_reports "
                    "WHERE substr(stored_at,1,10)=? GROUP BY hh ORDER BY hh", (t,)):
                per_hour.append({"h": r["hh"], "n": r["n"]})
    except Exception as e:
        db_err = "%s: %s" % (type(e).__name__, str(e)[:140])

    runs = harvest_runs()
    tr = [r for r in runs if r["day"] == t]
    syncs = sync_runs()
    ts = [s for s in syncs if s["day"] == t and s["ok"]]
    budget = load_json(os.path.join(STATE_DIR, "harvest_upload_budget.json"), {})
    files, files_total = file_records()
    f_today = [x for x in files if str(x["ts"])[:10] == t]
    qn = queue_count()

    d = head_ctx()
    d.update({
        "db_error": db_err,
        "q": {
            "looked": sum(r["looked"] for r in tr),
            "stored": sum(r["stored"] for r in tr),
            "unknown": sum(r["unknown"] for r in tr),
            "errors": sum(r["errors"] for r in tr),
            "runs": len(tr),
            "vt_used": quota.get("VirusTotal", 0), "vt_cap": vt_cap, "vt_keys": len(keys),
            "mb_used": quota.get("MalwareBazaar", 0),
            "rate": rate, "gap": gap,
            "rows_total": total_rows, "rows_today": rows_today,
            "verdicts": verdicts, "per_hour": per_hour,
        },
        "w": {"total": qn, "eta_min": round(qn / rate, 1) if rate else 0},
        # White-sample pipeline. On the overview as bare numbers only; the detail
        # lives on /benign. Without this the page reported threats exclusively and
        # gave no hint that a second corpus existed at all.
        "bn": _benign_brief(),
        "d": {
            "dl": sum(r["downloaded"] for r in tr),
            "up": sum(r["uploaded"] for r in tr),
            "sk": sum(r["skipped"] for r in tr),
            "b_used": int(budget.get("used", 0) or 0),
            "b_cap": _b_cap(h),
            "b_unlimited": _b_cap(h) < 0,
            "mode": collector_info()["mode"],
            "ledger": files_total,
            "dl_today": len([x for x in f_today if x["downloaded"]]),
            "up_today": len([x for x in f_today if x["uploaded"]]),
            "residue": len(residue_info()["items"]),
        },
        "t": {
            "pushes": len(ts),
            "rows": sum(s["rows"] for s in ts),
            "ins": sum(s["inserted"] for s in ts),
            "kb": round(sum(s["kb"] for s in ts), 1),
            "master": ts[0]["master_total"] if ts else 0,
            "fail": len([s for s in syncs if s["day"] == t and not s["ok"]]),
        },
    })
    return d


def v_queries():
    c = cfg()
    vt = c.get("virustotal", {}) or {}
    h = c.get("harvest", {}) or {}
    keys = [k for k in (str(x).split(":")[0].strip() for x in vt.get("api_keys", []))
            if len(k) == 64]
    vt_cap = int(vt.get("requests_per_day", 0) or 0) * max(1, len(keys))
    rate, gap = rate_cfg(h)
    t = today()

    quota, recent = {}, []
    total_rows = rows_today = 0
    db_err = ""
    try:
        with db() as conn:
            for r in conn.execute("SELECT source,count FROM quota WHERE day=?", (t,)):
                quota[r["source"]] = r["count"]
            total_rows = conn.execute("SELECT COUNT(*) FROM vt_reports").fetchone()[0]
            rows_today = conn.execute(
                "SELECT COUNT(*) FROM vt_reports WHERE substr(stored_at,1,10)=?",
                (t,)).fetchone()[0]
            for r in conn.execute(
                    "SELECT sha256,verdict,malicious,total_engines,threat_label,"
                    "stored_at,length(report) rlen FROM vt_reports "
                    "ORDER BY stored_at DESC LIMIT 100"):
                recent.append(dict(r))
    except Exception as e:
        db_err = "%s: %s" % (type(e).__name__, str(e)[:140])

    try:
        seen = sum(1 for _ in open(os.path.join(STATE_DIR, "harvest_seen.txt")))
    except Exception:
        seen = 0
    runs = harvest_runs()
    tr = [r for r in runs if r["day"] == t]

    d = head_ctx()
    d.update({
        "db_error": db_err,
        "cfgv": {
            "rate": rate, "gap": gap,
            "max_per_run": h.get("max_per_run") or 0,
            "max_run_seconds": int(h.get("max_run_seconds", 0) or 0),
            "selector": h.get("selector") or "time",
            "vt_keys": len(keys),
            # Same source as the downloads page, for the same reason: on a datalake
            # node the harvest config key does not describe the window in use.
            "window_days": collector_info()["window_days"],
        },
        "q": {
            "vt_used": quota.get("VirusTotal", 0), "vt_cap": vt_cap,
            "mb_used": quota.get("MalwareBazaar", 0),
            "looked": sum(r["looked"] for r in tr),
            "stored": sum(r["stored"] for r in tr),
            "unknown": sum(r["unknown"] for r in tr),
            "errors": sum(r["errors"] for r in tr),
            "runs": len(tr), "seen": seen,
            "rows_total": total_rows, "rows_today": rows_today,
        },
        "runs": runs[:30],
        "recent": recent,
    })
    return d


def v_queue():
    h = cfg().get("harvest", {}) or {}
    rate, gap = rate_cfg(h)
    head, total = jsonl(QUEUE_LOG, 300, tail=False)
    items = [{
        "sha256": str(x.get("sha256", "")),
        "name": x.get("name", ""), "type": x.get("type", ""),
        "size": int(x.get("size", 0) or 0), "sig": x.get("sig", ""),
        "first_seen": x.get("first_seen", ""),
        "queued_at": x.get("queued_at", ""),
    } for x in head]
    runs = harvest_runs(5)
    d = head_ctx()
    d.update({
        "db_error": "",
        "cfgv": {"rate": rate, "gap": gap,
                 "max_per_run": h.get("max_per_run") or 0,
                 "max_run_seconds": int(h.get("max_run_seconds", 0) or 0)},
        "w": {
            "total": total, "shown": len(items),
            "eta_min": round(total / rate, 1) if rate else 0,
            "carried": runs[0]["queued"] if runs else 0,
            "stopped_by": runs[0]["stopped_by"] if runs else "",
            "last_run": (runs[0]["day"] + " " + runs[0]["time"]) if runs else "",
            "vt_calls": runs[0]["vt_calls"] if runs else 0,
            "vt_left": runs[0]["vt_left"] if runs else None,
            "items": items,
        },
    })
    return d


def v_files(kind):
    """kind='download' -> everything we fetched; kind='upload' -> what went to VT."""
    h = cfg().get("harvest", {}) or {}
    t = today()
    files, total = file_records()
    budget = load_json(os.path.join(STATE_DIR, "harvest_upload_budget.json"), {})
    runs = harvest_runs()
    tr = [r for r in runs if r["day"] == t]

    if kind == "upload":
        rows = [x for x in files if x["uploaded"] or x["skipped_budget"]]
    else:
        # Stale skips belong on the downloads page: they are the reason a VT-unknown
        # sample has a report but no binary.
        rows = [x for x in files
                if x["downloaded"] or x["zip_bad"] or x["error"] or x["skipped_stale"]]
    r_today = [x for x in rows if str(x["ts"])[:10] == t]
    if kind == "upload":
        good = [x for x in r_today if x["upload_ok"]]
        bad = [x for x in r_today if x["uploaded"] and not x["upload_ok"]]
    else:
        good = [x for x in r_today if x["downloaded"]]
        bad = [x for x in r_today if x["zip_bad"] or x["error"]]

    res = residue_info()
    col = collector_info()
    d = head_ctx()
    d.update({
        "db_error": "",
        "kind": kind,
        "f": {
            "rows": rows[:200],
            "shown": min(len(rows), 200),
            "matched": len(rows),
            "ledger": total,
            "today": len(r_today),
            "ok_today": len(good),
            "bad_today": len(bad),
            "bytes": round(sum(x["size"] for x in r_today) / 1048576.0, 2),
            "zip_kb": round(sum(x["zip_kb"] for x in r_today), 1),
            "run_dl": sum(r["downloaded"] for r in tr),
            "run_up": sum(r["uploaded"] for r in tr),
            "run_sk": sum(r["skipped"] for r in tr),
            "run_stale": sum(r["stale"] for r in tr),
            "runs_today": len(tr),
            # The ledger is a rolling 1000 lines, so on a busy day it drops today's
            # earliest rows. Saying so beats letting two numbers disagree in silence
            # and letting the reader guess which one lost a download.
            "ledger_keep": LEDGER_KEEP_LINES.get(col["name"], 1000),
            "ledger_short": (sum(r["uploaded" if kind == "upload" else "downloaded"]
                                 for r in tr) > len(good)),
            # The download age gate. same_day_download was a boolean; it is now a
            # day window, because "today only" starved the daily VT allowance
            # whenever the last hour produced too few fresh samples. 0 = today only.
            # Sourced from whichever collector this node actually runs -- see
            # collector_info() for why the config key alone was misreporting it.
            "window_days": col["window_days"],
            "window_hours": col["window_hours"],
            "collector": col["name"],
            "collector_label": col["label"],
            "last_run": col["last_run"],
            "stopped_by": col["stopped_by"],
            "newest_slot": col["newest_slot"],
            "slot_age_h": col["newest_slot_age_hours"],
            "day": t,
            "stale_today": len([x for x in r_today if x["skipped_stale"]]),
            "b_used": int(budget.get("used", 0) or 0),
            "b_cap": _b_cap(h),
            "b_unlimited": _b_cap(h) < 0,
            "mode": col["mode"],
            "residue": res["items"],
            "work": res["work"], "work_files": res["work_files"],
            "running": res["running"],
        },
    })
    return d


# A run killed with SIGKILL (systemd timeout, OOM, reboot) never reaches its
# cleanup, so the file outlives the process. Treat an unrefreshed file as
# finished instead of advertising a run that is not happening. The collector
# rewrites the file at least once a second while rate-limited, and more often
# while transferring, so this threshold is generous.
STALE_PROGRESS_SEC = 90


def v_downloads_progress():
    """Real-time progress for the downloads page. Cheap on purpose: one small
    file plus a TTL-cached systemctl call, because this is polled every second."""
    try:
        age = time.time() - os.path.getmtime(DATALAKE_PROGRESS)
    except OSError:
        return {"running": False, "phase": "idle", "reason": "no_run"}
    prog = load_json(DATALAKE_PROGRESS, None)
    if not isinstance(prog, dict):
        return {"running": False, "phase": "idle", "reason": "no_run"}

    # The collector is a timer-driven Type=oneshot unit, so systemd reports it as
    # "activating" for the entire run and only ever reaches "active" momentarily,
    # if at all. Checking for "active" alone declared every real run dead.
    # An empty answer means the query itself failed (no dbus, no permission), and
    # that must not be read as "not running" -- the mtime check above is the
    # reliable signal, this is only a faster way to notice a crashed run.
    state = sysd(["systemctl", "is-active", "bulwark-datalake.service"])
    dead = state not in ("", "active", "activating", "reloading")
    if age > STALE_PROGRESS_SEC or dead:
        # Report why, so the page can say the last run ended abnormally instead
        # of looking idle while a leftover file sits on disk.
        return {"running": False, "phase": "stale",
                "reason": "stale" if age > STALE_PROGRESS_SEC else "not_active",
                "unit_state": state, "age_sec": round(age, 1),
                "slot": prog.get("slot", ""), "done": prog.get("done", 0)}

    prog["running"] = True
    prog["age_sec"] = round(age, 1)
    # Present speeds in MB/s for the UI; the collector reports raw bytes/sec.
    prog["speed_mbps"] = round(float(prog.get("speed_bps", 0) or 0) / 1048576.0, 2)
    prog["avg_mbps"] = round(float(prog.get("avg_bps", 0) or 0) / 1048576.0, 2)
    prog["mb"] = round(float(prog.get("bytes", 0) or 0) / 1048576.0, 2)
    return prog


def _ts_secs(ts):
    try:
        return datetime.strptime(str(ts), "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc).timestamp()
    except Exception:
        return None


def master_records(limit=60):
    """What the master says it received from us."""
    recs, total = jsonl(MASTER_LOG, limit)
    out = []
    for d in recs:
        out.append({
            "ts": d.get("ts", ""), "ok": bool(d.get("ok")),
            "received": int(d.get("received", 0) or 0),
            "inserted": int(d.get("inserted", 0) or 0),
            "skipped": int(d.get("skipped", 0) or 0),
            "malformed": int(d.get("malformed", 0) or 0),
            "total": int(d.get("total", 0) or 0),
            "kb": round(float(d.get("kb", 0) or 0), 1),
            "newest": d.get("newest", ""), "new_count": int(d.get("new_count", 0) or 0),
            "error": d.get("error", ""),
        })
    out.reverse()
    return out, total


def reconcile(local, master, window=180):
    """Pair each local push with the master's record of it. Matched on row count plus
    a time window, because the master's timestamp is a second or two earlier and
    nothing in the payload carries a batch id. Purely advisory: an unmatched local
    push most often just means the pull ran before the master's line was written."""
    used = set()
    mstamps = [(i, _ts_secs(m["ts"]), m) for i, m in enumerate(master)]
    matched = 0
    for s in local:
        st = _ts_secs("%sT%sZ" % (s["day"], s["time"])) if s.get("day") else None
        hit = None
        for i, mt, m in mstamps:
            if i in used or mt is None or st is None:
                continue
            if abs(mt - st) <= window and m["received"] == s["rows"]:
                hit = (i, m)
                break
        if hit:
            used.add(hit[0])
            s["m_ok"] = hit[1]["ok"]
            s["m_ts"] = hit[1]["ts"]
            s["m_inserted"] = hit[1]["inserted"]
            s["m_total"] = hit[1]["total"]
            s["m_agree"] = (hit[1]["inserted"] == s["inserted"]
                            and hit[1]["total"] == s["master_total"])
            matched += 1
        else:
            s["m_ok"] = None
            s["m_ts"] = ""
            s["m_inserted"] = None
            s["m_total"] = None
            s["m_agree"] = None
    return matched


def v_transfers():
    t = today()
    syncs = sync_runs(40)
    ok = [s for s in syncs if s["day"] == t and s["ok"]]
    mrows, mtotal = master_records()
    matched = reconcile(syncs, mrows)
    try:
        wm = open(os.path.join(STATE_DIR, "sync_watermark.txt")).read().strip()
    except Exception:
        wm = ""
    local_total = 0
    db_err = ""
    try:
        with db() as conn:
            local_total = conn.execute("SELECT COUNT(*) FROM vt_reports").fetchone()[0]
    except Exception as e:
        db_err = "%s: %s" % (type(e).__name__, str(e)[:140])
    d = head_ctx()
    d.update({
        "db_error": db_err,
        "t": {
            "pushes": len(ok),
            "rows": sum(s["rows"] for s in ok),
            "ins": sum(s["inserted"] for s in ok),
            "sk": sum(s["skipped"] for s in ok),
            "kb": round(sum(s["kb"] for s in ok), 1),
            "master": ok[0]["master_total"] if ok else 0,
            "last": ok[0]["time"] if ok else "",
            "fail": len([s for s in syncs if s["day"] == t and not s["ok"]]),
            "wm": wm,
            "local_total": local_total,
            "rows_all": sum(s["rows"] for s in syncs if s["ok"]),
        },
        "m": {
            "have": bool(mrows),
            "rows": mrows[:30],
            "count": mtotal,
            "matched": matched,
            "local_ok": len([s for s in syncs if s["ok"]]),
            "unmatched": len([s for s in syncs if s["ok"] and s.get("m_ok") is None]),
            "disagree": len([s for s in syncs if s.get("m_agree") is False]),
            "received_all": sum(x["received"] for x in mrows if x["ok"]),
            "inserted_all": sum(x["inserted"] for x in mrows if x["ok"]),
            "master_total": mrows[0]["total"] if mrows else 0,
            "last": mrows[0]["ts"] if mrows else "",
        },
        "syncs": syncs,
    })
    return d


def v_benign():
    """White samples: the 24h quarantine, what it threw out, and what left for the
    master.

    Counts come from benign_quarantine, not from the ledger, because the table is
    what the pipeline actually acts on. The ledger is still read for the reject
    detail (threat name, engine ratio) which the table does not carry, and to show
    the push history.

    rejected_at rows are tombstones: the benign row is deleted on rejection, so a
    tombstone is the only remaining record that a hash was once accepted and later
    turned out to be malware. They also bar it from ever being re-enrolled.
    """
    t = today()
    total = verified = rejected = pending = 0
    signed = win_pe = with_beh = 0
    oldest = newest = ""
    db_err = ""
    try:
        with db() as conn:
            def q1(sql, *a):
                r = conn.execute(sql, a).fetchone()
                return (r[0] or 0) if r else 0

            def qs(sql, *a):
                """Same, but for text columns -- q1 would turn NULL into 0 and then
                an empty table would render a date of '0'."""
                r = conn.execute(sql, a).fetchone()
                return str(r[0]) if (r and r[0]) else ""
            total = q1("SELECT COUNT(*) FROM benign_reports")
            signed = q1("SELECT COUNT(*) FROM benign_reports WHERE signed=1")
            win_pe = q1("SELECT COUNT(*) FROM benign_reports "
                        "WHERE type_tag IN ('pedll','peexe')")
            try:
                with_beh = q1("SELECT COUNT(*) FROM benign_reports WHERE has_behaviour=1")
            except Exception:
                # Older collector schema has no such column; every row there was
                # stored under the strict policy and did have sandbox behaviour.
                with_beh = total
            oldest = qs("SELECT MIN(stored_at) FROM benign_reports")
            newest = qs("SELECT MAX(stored_at) FROM benign_reports")
            try:
                verified = q1("SELECT COUNT(*) FROM benign_quarantine WHERE verified_at<>''")
                rejected = q1("SELECT COUNT(*) FROM benign_quarantine WHERE rejected_at<>''")
                pending = q1("SELECT COUNT(*) FROM benign_quarantine "
                             "WHERE verified_at='' AND rejected_at=''")
            except Exception:
                db_err = "benign_quarantine 尚未建立（复查作业还没跑过第一次）"
    except Exception as e:
        db_err = "%s: %s" % (type(e).__name__, str(e)[:140])

    # Reject detail + fast-track evidence live only in the ledger.
    rej_rows, ft_rows, runs = [], [], []
    reasons = {}
    ft_total = 0
    # jsonl() returns (records, total) -- iterating the call directly would walk the
    # tuple, not the records.
    vlog, _vtotal = jsonl(BENIGN_VERIFY_LOG)
    for r in vlog:
        ev = r.get("event")
        if ev == "reject":
            reasons[str(r.get("reason") or "?")] = \
                reasons.get(str(r.get("reason") or "?"), 0) + 1
            rej_rows.append({
                "ts": r.get("ts", ""), "sha256": r.get("sha256", ""),
                "name": r.get("name", ""), "reason": r.get("reason", ""),
                "verdict": r.get("verdict", ""),
                "malicious": r.get("malicious", 0),
                "total_engines": r.get("total_engines", 0),
                "threat_label": r.get("threat_label", ""),
            })
        elif ev == "verify":
            if "fast_track" in str(r.get("how") or ""):
                ft_total += 1
                ev2 = r.get("evidence") or {}
                ft_rows.append({
                    "ts": r.get("ts", ""), "sha256": r.get("sha256", ""),
                    "age_days": ev2.get("age_days"),
                    "last_scan_days_ago": ev2.get("last_scan_days_ago"),
                    "engines": ev2.get("engines"), "signed": ev2.get("signed"),
                })
        elif ev == "run":
            runs.append(r)

    pushes, _ptotal = jsonl(BENIGN_SYNC_LOG)
    p_ok = [p for p in pushes if p.get("ok")]
    p_today = [p for p in p_ok if str(p.get("ts", ""))[:10] == t]
    try:
        bwm = open(os.path.join(STATE_DIR, "benign_sync_watermark.txt")).read().strip()
    except Exception:
        bwm = ""

    rej_rows.reverse()
    ft_rows.reverse()

    d = head_ctx()
    d.update({
        "db_error": db_err,
        "b": {
            "total": total, "signed": signed, "win_pe": win_pe, "with_beh": with_beh,
            "verified": verified, "rejected": rejected, "pending": pending,
            "oldest": oldest[:19], "newest": newest[:19],
            "fast_tracked": ft_total,
            "reasons": reasons,
            # engine_build.BENIGN_MIN_CORPUS -- below this the attack-chain engine
            # refuses to use the corpus for grading at all.
            "min_corpus": 50,
            "usable_est": win_pe,
        },
        "p": {
            "pushes": len(p_ok), "today": len(p_today),
            "rows": sum(int(x.get("rows") or 0) for x in p_ok),
            "rows_today": sum(int(x.get("rows") or 0) for x in p_today),
            "inserted": sum(int(x.get("inserted") or 0) for x in p_ok),
            "refused": sum(int(x.get("threat_refused") or 0) for x in p_ok),
            "master_total": (p_ok[-1].get("master_benign_total") if p_ok else 0),
            "last": str(p_ok[-1].get("ts", ""))[11:19] if p_ok else "",
            "fail": len([p for p in pushes if not p.get("ok")]),
            "wm": bwm,
        },
        "rejects": rej_rows[:60],
        "fasts": ft_rows[:40],
        "runs": list(reversed(runs))[:20],
    })
    return d


PAGE = r"""<!DOCTYPE html>
<html lang="zh-CN"><head>
<meta charset="utf-8">
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Bulwark 采集节点</title>
<style>
/* Page is a soft grey, surfaces are white. An all-white page made the cards
   disappear into the background and glared on a big monitor; putting the tone
   difference between page and card is what gives the layout its structure, so
   borders can stay quiet instead of doing that job on their own. */
:root{
 --bg:#eceff4; --surface:#fff; --line:#dadfe6; --line2:#edf0f4;
 --soft:#f4f6f9; --chip:#e7ebf1; --track:#e5eaf0;
 --ink:#2c333d; --muted:#6a7480; --dim:#98a1ac;
 --blue:#2c6cd6; --green:#1f7a3d; --amber:#b57f07; --red:#c9313c;
 --shadow:0 1px 2px rgba(28,38,54,.05),0 2px 5px rgba(28,38,54,.04);
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--ink);font:15px/1.65 "Microsoft YaHei","PingFang SC",
 -apple-system,"Segoe UI",Roboto,sans-serif;padding:0 0 48px}
.top{background:var(--surface);border-bottom:1px solid var(--line);padding:12px 26px 0;
 position:sticky;top:0;z-index:9;box-shadow:0 1px 3px rgba(28,38,54,.06)}
.top .line1{display:flex;flex-wrap:wrap;gap:18px;align-items:center;margin-bottom:10px}
.top h1{font-size:17px;font-weight:700;letter-spacing:.2px}
.top .meta{font-size:13px;color:var(--muted)}
.top .meta b{color:var(--ink);font-variant-numeric:tabular-nums}
.nav{display:flex;gap:2px;flex-wrap:wrap}
.nav a{display:block;padding:8px 16px;font-size:14px;font-weight:600;color:var(--muted);
 text-decoration:none;border-bottom:2px solid transparent;border-radius:6px 6px 0 0}
.nav a:hover{color:var(--ink);background:var(--soft)}
.nav a.on{color:var(--ink);border-bottom-color:#e8834f}
.nav a .c{display:inline-block;margin-left:6px;padding:0 7px;border-radius:10px;
 background:var(--chip);color:var(--muted);font-size:12px;font-variant-numeric:tabular-nums}
.tag{display:inline-block;padding:2px 10px;border-radius:20px;font-size:12px;font-weight:600;
 border:1px solid transparent}
.tag.on{background:#e4f6e9;color:#146c30;border-color:#c2e5cb}
.tag.off{background:#fceced;color:#a5252f;border-color:#f4ccd0}
.tag.mid{background:#fdf4d6;color:#7a5300;border-color:#eddfaa}
.tag.gray{background:var(--soft);color:var(--muted);border-color:var(--line)}
.wrap{padding:22px 26px;max-width:1560px;margin:0 auto}
h2.pg{font-size:20px;font-weight:700;margin-bottom:4px}
p.lead{font-size:13px;color:var(--muted);margin-bottom:18px}
.kpi{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;margin-bottom:18px}
.k{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:16px 18px;
 border-top:3px solid var(--blue);box-shadow:var(--shadow)}
.k.g{border-top-color:var(--green)} .k.y{border-top-color:var(--amber)}
.k.r{border-top-color:var(--red)}
.k .lab{font-size:13px;color:var(--muted);margin-bottom:6px;font-weight:600}
.k .num{font-size:32px;font-weight:700;line-height:1.15;letter-spacing:-.5px;
 font-variant-numeric:tabular-nums}
.k .sub{font-size:13px;color:var(--muted);margin-top:6px}
.sec{font-size:16px;font-weight:700;margin:26px 0 12px;display:flex;align-items:center;gap:10px}
.sec:after{content:"";flex:1;height:1px;background:var(--line)}
.cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:14px}
.box{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:16px 18px;
 box-shadow:var(--shadow)}
.box h3{font-size:14px;color:var(--muted);margin-bottom:12px;font-weight:700}
.row{display:flex;justify-content:space-between;align-items:baseline;gap:12px;
 padding:7px 0;border-bottom:1px solid var(--line2);font-size:14px}
.row:last-child{border-bottom:none}
.row span{color:var(--muted)}
.row b{font-size:16px;font-weight:700;font-variant-numeric:tabular-nums}
.bar{height:8px;background:var(--track);border-radius:5px;overflow:hidden;margin:10px 0 5px}
.bar i{display:block;height:100%;background:var(--green);transition:width .5s}
.bar.y i{background:var(--amber)} .bar.r i{background:var(--red)}
.pct{font-size:12px;color:var(--muted);text-align:right;font-variant-numeric:tabular-nums}
.note{font-size:12px;color:var(--muted);margin-top:10px;line-height:1.5}
/* live download progress panel */
.lp{background:var(--surface);border:1px solid var(--line);border-radius:10px;
 padding:16px 18px;margin:0 0 18px;box-shadow:var(--shadow);border-left:3px solid var(--blue)}
.lphead{font-size:15px;font-weight:700;margin-bottom:12px;display:flex;
 align-items:center;gap:8px;flex-wrap:wrap}
.lpgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));
 gap:12px;margin-bottom:6px}
.lpgrid>div{min-width:0}
.lpgrid .z{font-size:12px}
.lpv{font-size:15px;margin-top:3px;font-variant-numeric:tabular-nums;
 overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.lpv b{font-size:19px;font-weight:700}
.lprow{font-size:12px;color:var(--muted);margin-top:12px;
 font-variant-numeric:tabular-nums}
.lpfile{margin-top:10px;font-size:12px;overflow:hidden;text-overflow:ellipsis;
 white-space:nowrap}
table{width:100%;border-collapse:collapse;font-size:13px}
th{background:var(--soft);color:var(--muted);font-size:12px;font-weight:700;
 padding:9px 11px;text-align:right;border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:8px 11px;text-align:right;border-bottom:1px solid var(--line2);
 font-variant-numeric:tabular-nums;white-space:nowrap}
th:first-child,td:first-child{text-align:left}
tbody tr:hover td{background:var(--soft)}
.mono{font-family:Consolas,"SF Mono",Menlo,monospace;font-size:12px;color:#215fbf}
.fn{font-family:Consolas,"SF Mono",Menlo,monospace;font-size:12px;
 max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:inline-block;
 vertical-align:bottom}
.z{color:var(--dim)}
.scroll{overflow-x:auto;background:var(--surface);border:1px solid var(--line);
 border-radius:10px;box-shadow:var(--shadow)}
.hrs{display:flex;align-items:flex-end;gap:3px;height:78px;margin:12px 0 4px}
.hrs i{flex:1;background:#7fb2ef;border-radius:2px 2px 0 0;min-height:2px}
.hrs i:hover{background:var(--blue)}
.err{background:#fceced;border:1px solid #f4ccd0;color:#a5252f;
 padding:12px 16px;border-radius:10px;margin-bottom:16px;font-size:14px}
/* 和 .err 分开:「今天的配额用完了」不是故障,明天自己就回来。用红色说这件事会让人
   去动配置,而正确的处置是等 UTC 日切。 */
.warn{background:#fdf7e6;border:1px solid #f0e2b6;color:#7a5a06;
 padding:12px 16px;border-radius:10px;margin-bottom:16px;font-size:14px;line-height:1.6}
.qn{color:var(--dim);font-size:12px}
.bad{color:var(--red);font-weight:700}

/* ---------- motion ----------
   Entrance animations are applied by adding .anim to #body, which the renderer
   only does on a fresh render (first paint or a page switch). The 5-second poll
   re-renders the same page, and replaying a fade-in every 5 seconds would be
   unreadable -- so a refresh gets no entrance animation at all, only the
   value-change flash below, which is the part that actually carries meaning. */
@keyframes rise{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
@keyframes fade{from{opacity:0}to{opacity:1}}
@keyframes growh{from{transform:scaleY(0)}to{transform:scaleY(1)}}
@keyframes flash{0%{background:#fff6d8}100%{background:transparent}}
@keyframes spin{to{transform:rotate(360deg)}}

.anim h2.pg,.anim p.lead{animation:fade .28s ease-out both}
.anim .k{animation:rise .34s ease-out both}
/* Stagger only the first row of cards. Beyond that the delay stacks up to a
   visible lag before the last card appears, which reads as slowness. */
.anim .k:nth-child(1){animation-delay:.02s}
.anim .k:nth-child(2){animation-delay:.06s}
.anim .k:nth-child(3){animation-delay:.10s}
.anim .k:nth-child(4){animation-delay:.14s}
.anim .k:nth-child(5){animation-delay:.18s}
.anim .k:nth-child(6){animation-delay:.22s}
.anim .sec{animation:fade .3s ease-out both;animation-delay:.16s}
.anim .box{animation:rise .34s ease-out both;animation-delay:.18s}
.anim .cols .box:nth-child(2){animation-delay:.22s}
.anim .cols .box:nth-child(3){animation-delay:.26s}
.anim .cols .box:nth-child(4){animation-delay:.30s}
.anim .scroll{animation:rise .34s ease-out both;animation-delay:.26s}
.anim .hrs i{animation:growh .45s ease-out both;transform-origin:bottom;animation-delay:.24s}

/* Refresh feedback: a number that changed since the last poll pulses once. This
   is the one animation that runs on every refresh, because it answers "what just
   moved?" without making the reader diff the page themselves. */
.chg{animation:flash 1.1s ease-out}

.bar i{transition:width .6s cubic-bezier(.4,0,.2,1)}
.k{transition:box-shadow .18s,transform .18s}
.k:hover{box-shadow:0 2px 6px rgba(28,38,54,.09),0 6px 16px rgba(28,38,54,.06);
 transform:translateY(-1px)}
.nav a{transition:background .15s,color .15s}
.tag{transition:background .2s}
tbody tr{transition:background .12s}
button{transition:background .15s,opacity .15s}
button:hover:not(:disabled){filter:brightness(1.08)}
button:disabled{opacity:.6;cursor:not-allowed}
.spin{display:inline-block;width:12px;height:12px;margin-right:7px;vertical-align:-1px;
 border:2px solid rgba(255,255,255,.45);border-top-color:#fff;border-radius:50%;
 animation:spin .7s linear infinite}
#tick{display:inline-block;min-width:1.6em;text-align:right;font-variant-numeric:tabular-nums}

/* Anyone who has asked the OS to reduce motion gets none of it. The dashboard
   still has to be fully usable, so this disables animation, never content. */
@media (prefers-reduced-motion:reduce){
  *,*::before,*::after{animation-duration:.001s!important;animation-delay:0s!important;
   transition-duration:.001s!important}
  .k:hover{transform:none}
}
</style></head><body>
<div class="top">
  <div class="line1">
    <h1>Bulwark 采集节点</h1>
    <span class="meta" id="node"></span>
    <span class="meta" id="now"></span>
    <span class="meta">刷新 <b id="tick">5</b>s</span>
    <span id="units"></span>
  </div>
  <div class="nav" id="nav"></div>
</div>
<div class="wrap">
  <div id="err"></div>
  <div id="body"></div>
</div>
<script>
var $=function(s){return document.querySelector(s)};
var VIEWS=[
  {p:'/',          k:'home',      t:'总览',  api:'/api/summary',   lead:'只看数字：各环节今日总量、配额占用、入库趋势。明细在各自页面。'},
  {p:'/queries',   k:'queries',   t:'查询',  api:'/api/queries',   lead:'限速配置、VT 配额、每轮执行记录、最近入库的哈希。'},
  {p:'/queue',     k:'queue',     t:'排队',  api:'/api/queue',     lead:'超出单轮能力的哈希在这里排队，先进先出，不会丢。'},
  {p:'/downloads', k:'downloads', t:'下载',  api:'/api/downloads', lead:'从 abuse.ch 取回的样本二进制。上传完成后本地立即删除。'},
  {p:'/uploads',   k:'uploads',   t:'上传',  api:'/api/uploads',   lead:'提交给 VirusTotal 的样本 —— 只提交 VT 未收录的那些。'},
  {p:'/transfers', k:'transfers', t:'回传',  api:'/api/transfers', lead:'把本节点新增的 vt_reports 推送到主服务器的每一批。'},
  {p:'/benign',    k:'benign',    t:'白样本',api:'/api/benign',    lead:'正常样本语料。一个干净判定只代表当下，所以每个样本先隔离 24 小时再复查一次，仍然干净才允许回传主服务器；已被 VT 追认为恶意的当场从语料里删除。VT 早已收录很久、近期复扫过且零检出的直接放行，不花配额。'},
  {p:'/vtkeys',    k:'vtkeys',    t:'密钥',  api:'/api/vtkeys',    lead:'VirusTotal API 密钥池与账号状态。状态是问 VT 本人拿到的：401 UserNotActiveError 才算封禁，429 只是配额用完会自己恢复。已封禁或无效的可以直接删除，删除前会重新探测确认。'},
  {p:'/submit',    k:'submit',    t:'送检',  api:'/api/submit',    lead:'手工上传文件或整个文件夹，数量不限。上传即入队，每 3 分钟复查一轮：先问主服务器是否已收录，再问 VT；出结论立刻回传主服务器，样本字节随即删除。进度记在服务端，切走再回来还在。'}
];
var PATH=location.pathname.replace(/\/index\.html$/,'/');
var CUR=VIEWS[0];
for(var vi=0;vi<VIEWS.length;vi++) if(VIEWS[vi].p===PATH) CUR=VIEWS[vi];

function n(v){return v==null?'-':Number(v).toLocaleString('en-US')}
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
function sz(v){
  v=Number(v||0);
  if(v<=0) return '<span class="z">-</span>';
  if(v<1024) return v+' B';
  if(v<1048576) return (v/1024).toFixed(1)+' KB';
  return (v/1048576).toFixed(2)+' MB';
}
function bar(u,c){
  // c < 0 means "no local ceiling" (vt_upload_budget_per_day=-1): the shared VT
  // quota is the only real limit, so a 0-100% fill against a negative number would
  // be meaningless. Show the raw count instead of a fabricated percentage.
  if(c==null || c<0){
    return '<div class="bar"><i style="width:100%;background:var(--dim)"></i></div>'+
           '<div class="pct">'+n(u)+' 次 · 不设上限（受当日 VT 共享配额约束）</div>';
  }
  var p = c ? Math.min(100, 100*u/c) : 0;
  var k = p>=95 ? 'bar r' : p>=75 ? 'bar y' : 'bar';
  return '<div class="'+k+'"><i style="width:'+p+'%"></i></div>'+
         '<div class="pct">'+n(u)+' / '+n(c)+'  ('+p.toFixed(1)+'%)</div>';
}
function kcard(cls,lab,num,sub){
  return '<div class="k '+cls+'"><div class="lab">'+lab+'</div>'+
         '<div class="num">'+num+'</div><div class="sub">'+sub+'</div></div>';
}
function row(l,v){return '<div class="row"><span>'+l+'</span><b>'+v+'</b></div>'}
function tag(v){return '<span class="tag '+(v==='active'?'on':'off')+'">'+esc(v||'?')+'</span>'}
function ago(m){
  if(m==null) return '';
  if(m<1) return '刚刚';
  if(m<60) return m+' 分钟前';
  var h=Math.floor(m/60);
  return h<24 ? h+' 小时前' : Math.floor(h/24)+' 天前';
}
/* 回传 is a oneshot chained off the collector's success, so "inactive" is its normal
   resting state and an active/inactive light says nothing. Show the last run. */
function syncTag(u){
  var s=u.sync_state, a=ago(u.sync_ago);
  if(s==='running') return '<span class="tag on">回传中</span>';
  if(s==='ok')  return '<span class="tag on">正常'+(a?' · '+esc(a):'')+'</span>';
  if(s==='fail') return '<span class="tag off">上次失败'+(a?' · '+esc(a):'')+'</span>';
  return '<span class="tag mid">尚未回传</span>';
}
function syncRows(u){
  return row('上次回传', u.sync_last
      ? esc(u.sync_last)+(u.sync_ago!=null?' <span class="z">('+esc(ago(u.sync_ago))+')</span>':'')
      : '<span class="z">尚未回传</span>')+
    row('回传触发', '<span class="z">'+esc(u.sync_trigger||'-')+'</span>');
}
function box(title,inner){return '<div class="box"><h3>'+title+'</h3>'+inner+'</div>'}
function table(head,rows,empty,cols){
  return '<div class="scroll"><table><thead><tr>'+head+'</tr></thead><tbody>'+
    (rows || '<tr><td colspan="'+(cols||9)+'" class="z">'+empty+'</td></tr>')+
    '</tbody></table></div>';
}
function hours(a){
  if(!a||!a.length) return '<div class="z">今日暂无入库</div>';
  var mx=1,i;
  for(i=0;i<a.length;i++) if(a[i].n>mx) mx=a[i].n;
  var h='<div class="hrs">';
  for(i=0;i<a.length;i++)
    h+='<i style="height:'+Math.max(2,78*a[i].n/mx)+'px" title="'+esc(a[i].h)+':00  '+a[i].n+' 条"></i>';
  return h+'</div><div class="pct">按小时入库量（UTC，峰值 '+mx+'）</div>';
}
function verd(v){
  if(v==='malicious') return '<span class="tag off">恶意</span>';
  if(v==='suspicious') return '<span class="tag mid">可疑</span>';
  if(v==='clean') return '<span class="tag on">干净</span>';
  return '<span class="z">未知</span>';
}
function stopTag(s){
  if(!s) return '<span class="tag on">全部处理完</span>';
  var m = s==='max_per_run' ? '达每轮上限' : s==='time_budget' ? '达时长上限' : s;
  return '<span class="tag mid">'+esc(m)+'</span>';
}
function nameCell(x){
  return '<td><span class="fn" title="'+esc(x.name)+'">'+
    (esc(x.name)||'<span class="z">无名</span>')+'</span></td>';
}
function shaCell(s,len){
  return '<td class="mono">'+esc(String(s||'').slice(0,len||24))+'…</td>';
}

function nav(counts){
  var h='';
  for(var i=0;i<VIEWS.length;i++){
    var v=VIEWS[i], c=counts&&counts[v.k];
    h+='<a href="'+v.p+'"'+(v.k===CUR.k?' class="on"':'')+'>'+v.t+
       (c!=null? '<span class="c">'+n(c)+'</span>':'')+'</a>';
  }
  $('#nav').innerHTML=h;
}
function head(d){
  $('#node').textContent=d.node||'';
  $('#now').textContent=(d.now||'')+' UTC';
  var u=d.u||{};
  $('#units').innerHTML='服务 '+tag(u.intel)+' 采集 '+tag(u.harvest)+' 回传 '+syncTag(u);
  $('#err').innerHTML = d.db_error ? '<div class="err">数据库读取异常：'+esc(d.db_error)+'</div>' : '';
}
function title(){
  return '<h2 class="pg">'+CUR.t+'</h2><p class="lead">'+CUR.lead+'</p>';
}

/* ---------- 总览：只有统计 ---------- */
function rHome(d){
  var q=d.q, w=d.w, dl=d.d, tr=d.t, u=d.u, bn=d.bn||{};
  nav({queue:w.total, downloads:dl.dl_today, uploads:dl.up_today, benign:bn.total});
  var pct=q.vt_cap?100*q.vt_used/q.vt_cap:0;
  var html=title()+'<div class="kpi">'+
    kcard('','今日查询哈希',n(q.looked),'入库 '+n(q.stored)+' 条 · '+n(q.runs)+' 轮')+
    kcard(w.total>200?'r':w.total>0?'y':'g','排队等待',n(w.total),
      q.rate?('限速 '+q.rate+' 条/分 · 约 '+n(w.eta_min)+' 分钟排空'):'未配置限速')+
    kcard('g','今日下载样本',n(dl.dl),'模式 '+esc(dl.mode))+
    kcard('g','今日上传 VT',n(dl.up),
      dl.b_unlimited?'预算不设上限（已用 '+n(dl.b_used)+' 次）':'预算 '+n(dl.b_used)+'/'+n(dl.b_cap))+
    kcard('y','今日回传主库',n(tr.rows),'新增 '+n(tr.ins)+' 条 · '+n(tr.pushes)+' 批')+
    kcard(pct>=95?'r':pct>=75?'y':'','VT 配额已用',n(q.vt_used),
      '上限 '+n(q.vt_cap)+'（'+q.vt_keys+' 把 key）')+
    '</div>';
  html+='<div class="sec">今日总量</div><div class="cols">'+
    box('查询',
      row('查询哈希',n(q.looked))+row('成功入库',n(q.stored))+
      row('VT 未收录',n(q.unknown))+
      row('错误',q.errors?'<span class="bad">'+n(q.errors)+'</span>':'0')+
      row('执行轮次',n(q.runs)))+
    box('下载与上传',
      row('下载样本',n(dl.dl)+' 个')+row('上传 VT',n(dl.up)+' 个')+
      row('预算不足跳过',n(dl.sk)+' 个')+
      row('逐文件台账',n(dl.ledger)+' 条')+
      row('磁盘样本残留',dl.residue?'<span class="tag off">'+n(dl.residue)+' 项</span>'
                                   :'<span class="tag on">无</span>'))+
    box('回传',
      row('推送',n(tr.rows)+' 行 / '+n(tr.pushes)+' 批')+
      row('主库新增',n(tr.ins)+' 条')+row('传输量',n(tr.kb)+' KB')+
      row('主库总行数',n(tr.master))+
      row('失败',tr.fail?'<span class="tag off">'+n(tr.fail)+'</span>'
                        :'<span class="tag on">0</span>'))+
    box('白样本语料',
      (bn.have
        ? row('语料样本',n(bn.total))+
          row('待复查',n(bn.pending))+row('已通过',n(bn.verified))+
          row('复查拒绝',bn.rejected?'<span class="tag off">'+n(bn.rejected)+'</span>':'0')+
          '<div class="note">威胁与白样本是两套库、两条回传通道。明细见 '+
          '<a href="/benign">白样本</a> 页。</div>'
        : '<div class="z">白样本管道尚未初始化</div>'))+
    '</div>';
  html+='<div class="sec">配额与库存</div><div class="cols">'+
    box('VT 配额',bar(q.vt_used,q.vt_cap)+
      row('MalwareBazaar 调用',n(q.mb_used))+
      row('查询速率',(q.rate||0)+' 条/分钟（间隔 '+(q.gap||0)+' 秒）'))+
    box('VT 上传预算',bar(dl.b_used,dl.b_cap)+
      row('下载模式',esc(dl.mode))+
      '<div class="note">只有 VT 未收录的样本会被下载并上传，上传后立即删除。</div>')+
    box('本节点库存',
      row('vt_reports 总数',n(q.rows_total))+row('今日新增','+'+n(q.rows_today))+
      hours(q.per_hour))+
    box('判定分布（今日）',
      (Object.keys(q.verdicts||{}).length
        ? Object.keys(q.verdicts).map(function(k){return row(esc(k),n(q.verdicts[k]))}).join('')
        : '<div class="z">今日暂无</div>')+
      row('下次采集',esc(u.next_h)||'-')+syncRows(u))+
    '</div>';
  $('#body').innerHTML=html;
}

/* ---------- 查询 ---------- */
function rQueries(d){
  var q=d.q, c=d.cfgv;
  nav(null);
  var pct=q.vt_cap?100*q.vt_used/q.vt_cap:0;
  var html=title()+'<div class="kpi">'+
    kcard('','今日查询',n(q.looked),'入库 '+n(q.stored)+' 条')+
    kcard('','查询速率',c.rate+' /分',(c.gap)+' 秒一条 · 每轮上限 '+n(c.max_per_run))+
    kcard(pct>=95?'r':pct>=75?'y':'g','VT 配额',n(q.vt_used)+' / '+n(q.vt_cap),
      c.vt_keys+' 把 key')+
    kcard('','库存',n(q.rows_total),'今日 +'+n(q.rows_today))+
    '</div>';
  html+='<div class="cols">'+
    box('限速与调度',
      row('查询速率',c.rate+' 条/分钟')+row('查询间隔',c.gap+' 秒')+
      row('每轮上限',n(c.max_per_run)+' 个')+
      row('单轮时长上限',c.max_run_seconds?Math.round(c.max_run_seconds/60)+' 分钟':'不限')+
      row('取样范围',esc(c.selector))+
      row('下载范围',c.window_days===0?'<span class="tag on">仅当天</span>'
                    :'<span class="tag gray">当天优先，回溯 '+n(c.window_days)+' 天</span>')+
      '<div class="note">间隔按“查询开始时刻”计算，慢查询不会额外拉长间隔。'+
      '「仅当天」只限制下载，查询仍覆盖队列里的全部哈希。</div>')+
    box('配额',bar(q.vt_used,q.vt_cap)+row('MalwareBazaar 调用',n(q.mb_used))+
      row('按当前速率日耗',n(Math.round((c.rate||0)*60*24))+' 次'))+
    box('今日明细',
      row('查询哈希',n(q.looked))+row('成功入库',n(q.stored))+
      row('VT 未收录',n(q.unknown))+
      row('错误',q.errors?'<span class="bad">'+n(q.errors)+'</span>':'0')+
      row('执行轮次',n(q.runs))+row('去重表条数',n(q.seen)))+
    '</div>';
  html+='<div class="sec">执行轮次</div>'+table(
    '<th>时间</th><th>查询</th><th>入库</th><th>未收录</th><th>下载</th><th>上传</th>'+
    '<th>预算跳过</th><th>非当天跳过</th><th>错误</th><th>结束时积压</th><th>停止原因</th>',
    (d.runs||[]).map(function(r){
      return '<tr><td>'+esc(r.day)+' '+esc(r.time)+'</td><td>'+n(r.looked)+'</td>'+
        '<td>'+n(r.stored)+'</td><td>'+n(r.unknown)+'</td><td>'+n(r.downloaded)+'</td>'+
        '<td>'+n(r.uploaded)+'</td><td>'+n(r.skipped)+'</td>'+
        '<td>'+(r.stale?'<span class="tag mid">'+n(r.stale)+'</span>':'0')+'</td>'+
        '<td>'+(r.errors?'<span class="bad">'+n(r.errors)+'</span>':'0')+'</td>'+
        '<td>'+n(r.queued)+'</td><td>'+stopTag(r.stopped_by)+'</td></tr>';
    }).join(''),'暂无记录',11);
  html+='<div class="sec">最近入库哈希</div>'+table(
    '<th>SHA-256</th><th>判定</th><th>检出</th><th>家族</th><th>报告</th><th>时间</th>',
    (d.recent||[]).map(function(r){
      return '<tr>'+shaCell(r.sha256,40)+'<td>'+verd(r.verdict)+'</td>'+
        '<td>'+n(r.malicious)+' / '+n(r.total_engines)+'</td>'+
        '<td>'+(esc(r.threat_label)||'<span class="z">-</span>')+'</td>'+
        '<td>'+n(Math.round((r.rlen||0)/1024))+' KB</td>'+
        '<td class="z">'+esc(r.stored_at)+'</td></tr>';
    }).join(''),'暂无记录',6);
  $('#body').innerHTML=html;
}

/* ---------- 排队 ---------- */
function rQueue(d){
  var w=d.w, c=d.cfgv;
  nav({queue:w.total});
  var html=title()+'<div class="kpi">'+
    kcard(w.total>200?'r':w.total>0?'y':'g','待查询',n(w.total),
      c.rate?('限速 '+c.rate+' 条/分'):'未配置限速')+
    kcard('','预计排空',(c.rate?n(w.eta_min):'-')+' 分',c.gap+' 秒一条')+
    kcard('','上轮结束时积压',n(w.carried),esc(w.last_run)||'-')+
    kcard('','单轮处理能力',n(c.max_per_run),
      c.max_run_seconds?('或 '+Math.round(c.max_run_seconds/60)+' 分钟封顶'):'不限时长')+
    '</div>';
  html+='<div class="cols">'+
    box('队列状态',
      row('待查询',n(w.total)+' 个')+
      row('预计排空',c.rate?n(w.eta_min)+' 分钟':'-')+
      row('上轮停止原因',stopTag(w.stopped_by))+
      row('上轮 VT 调用',n(w.vt_calls)+' 次'+(w.vt_left!=null?'（当日余 '+n(w.vt_left)+'）':''))+
      '<div class="note">队列文件 harvest_queue.jsonl，采集进程每处理一个就原子重写一次，'+
      '进程被杀也不会丢积压。旧版本会把超出上限的哈希直接丢弃，而 MalwareBazaar 只回看 '+
      '60 分钟，丢掉就找不回来了。</div>')+
    box('调度',
      row('下次采集',esc((d.u||{}).next_h)||'-')+
      syncRows(d.u||{})+
      row('本页显示',n(w.shown)+' / '+n(w.total)+' 个'))+
    '</div>';
  html+='<div class="sec">队首顺序（最新优先）</div>'+
    '<div class="note">按样本自己的日期倒序出队，不是先进先出：每日 VT 额度有限，'+
    '当天的新样本必须先拿到额度，历史回填只用来填没用完的余量。</div>'+table(
    '<th>#</th><th>文件名</th><th>类型</th><th>大小</th><th>家族</th>'+
    '<th>SHA-256</th><th>MB 首见</th><th>入队时间</th>',
    (w.items||[]).map(function(x,i){
      return '<tr><td class="qn">'+(i+1)+'</td>'+nameCell(x)+
        '<td>'+(esc(x.type)||'<span class="z">-</span>')+'</td>'+
        '<td>'+sz(x.size)+'</td>'+
        '<td>'+(esc(x.sig)||'<span class="z">-</span>')+'</td>'+
        shaCell(x.sha256)+
        '<td class="z">'+(esc(x.first_seen)||'-')+'</td>'+
        '<td class="z">'+esc(x.queued_at)+'</td></tr>';
    }).join(''),'队列为空，采集已跟上产量',8);
  $('#body').innerHTML=html;
}

/* ---------- 下载 ---------- */
function rDownloads(d){
  var f=d.f;
  /* 与卡片标题同源。原来用台账条数,台账一滚动导航上就写着「下载 0」,而卡片上是
     324 —— 同一页两个数字互相打脸,读者只会以为页面坏了。 */
  nav({downloads:f.run_dl});
  var html=title()+'<div class="kpi">'+
    /* 标题用运行汇总:它是采集器自己每轮报的计数,不会重复计。逐文件台账更详细,
       但它是滚动的(1000 行上限),忙的时候当天最早的记录会被自己挤掉 —— 实测 245
       上运行汇总 324、台账 285,差的 39 条就是被挤掉的。两个数并排摆着,不一致时
       自己就露出来,下面还会说明为什么。 */
    kcard('g','今日下载',n(f.run_dl),
      '运行汇总 · 逐文件台账 '+n(f.ok_today)+' 条'+(f.ledger_short?'（已滚动）':''))+
    /* 体积用样本原始字节。压缩包 KB 是 MalwareBazaar 那条路才有的东西,数据湖直接取
       裸文件、从不产生 zip —— 拿它当标题等于让一整台节点的下载量永远显示 0 KB。

       字节数只能从逐文件台账算,运行汇总不记字节。台账一滚动,这个数就只是下限,
       全滚掉就什么都算不出来 —— 实测 245 上今天下了 324 个 22.57 MB,五个小时后
       台账里一条不剩。这种时候写「0 MB」是在撒谎,所以标成 ≥ 或直接说不可统计。 */
    kcard('','今日下载量',
      f.ledger_short ? (f.bytes>0 ? '&ge; '+f.bytes+' MB' : '不可统计')
                     : (f.bytes+' MB'),
      f.ledger_short ? ('台账已滚动，只剩 '+n(f.ok_today)+' 条可计')
        : (f.zip_kb?('压缩包合计 '+f.zip_kb+' KB'):'样本原始字节合计'))+
    kcard('','下载范围',
      f.window_hours!=null ? ('回溯 '+n(f.window_hours)+' 小时')
        : (f.window_days===0?'仅当天':'当天 + 回溯 '+n(f.window_days)+' 天'),
      f.window_hours!=null
        ? (esc(f.collector_label)+(f.newest_slot?' · 最新档 '+esc(f.newest_slot):''))
        : (f.window_days===0?('当天 = '+esc(f.day)+' UTC')
                           :('当天 '+esc(f.day)+' 优先，不够才回填')))+
    kcard(f.residue.length?'r':'g','磁盘残留',n(f.residue.length),
      f.residue.length?'需要清理'
        :(f.work?'工作目录在用（采集运行中）':'无样本字节留存'))+
    '</div>'+
    '<div id="live_progress" class="lp"></div>';
  html+='<div class="cols">'+
    box('下载策略',
      row('采集器','<span class="tag on">'+esc(f.collector_label)+'</span>')+
      row('模式',esc(f.mode))+
      row('日期范围',f.window_hours!=null
            ?'<span class="tag on">回溯 '+n(f.window_hours)+' 小时</span> '+
             '<span class="tag gray">约 '+esc(f.window_days)+' 天</span>'
            :(f.window_days===0
                ?'<span class="tag on">仅当天 '+esc(f.day)+'</span>'
                :'<span class="tag on">当天 '+esc(f.day)+'</span> '+
                 '<span class="tag gray">回溯 '+n(f.window_days)+' 天补量</span>'))+
      (f.last_run?row('上一轮结束',esc(f.last_run)+
        (f.stopped_by?' · 收尾原因 '+esc(f.stopped_by):'')):'')+
      row('今日下载（运行汇总）',n(f.run_dl)+' 个 · 共 '+n(f.runs_today)+' 轮')+
      row('今日下载（逐文件台账）',n(f.ok_today)+' 个'+
        (f.ledger_short
          ? ' <span class="tag mid">台账少 '+n(f.run_dl-f.ok_today)+' 条</span>'
          : ''))+
      row('超出窗口跳过',(f.run_stale||f.stale_today)
            ? '<span class="tag mid">'+n(f.run_stale||f.stale_today)+'</span>'
            : '<span class="tag on">0</span>')+
      row('失败 / 非 zip',f.bad_today?'<span class="tag off">'+n(f.bad_today)+'</span>'
                                     :'<span class="tag on">0</span>')+
      '<div class="note">unknown 模式下只有 VT 未收录的样本才值得取回二进制（取回就是为了'+
      '上传）。预算用完后连下载也跳过，省 abuse.ch 带宽和本地磁盘。<br>'+
      '日期窗口只卡下载这一步，不卡查询 —— 哈希已经拿到了，顺手入库是免费情报；'+
      '真正花钱的是下载带宽和 VT 上传预算。队列会跨过零点，所以这个判断按样本自己的 '+
      'first_seen 日期算，不是按处理时间；元数据缺日期时按当天处理，宁可多下一个旧样本，'+
      '也不静默丢掉一个新样本。<br>'+
      '只收当天会在产量不足的时段浪费掉当日 VT 额度，所以当天优先、不够才回溯补量。</div>')+
    box('留存',
      row('台账总条数',n(f.ledger)+
        (f.ledger>=f.ledger_keep?' <span class="tag mid">已到滚动上限 '+
          n(f.ledger_keep)+' 行</span>':''))+
      row('本页显示',n(f.shown)+' / '+n(f.matched))+
      (f.ledger_short?'<div class="note">台账每到 '+n(f.ledger_keep)+
        ' 行就只保留最新的那些,所以忙的时候当天最早的下载记录会被挤掉 —— '+
        '上面「运行汇总」比「逐文件台账」多 '+n(f.run_dl-f.ok_today)+
        ' 条就是这个原因,不是漏下载。要逐条追溯更久以前的,看采集器日志。</div>':'')+
      row('磁盘残留',f.residue.length?'<span class="tag off">'+esc(f.residue.join(' '))+'</span>'
                                     :'<span class="tag on">无</span>')+
      row('工作目录',
        f.work
          ? (f.running
              ? '<span class="tag gray">采集运行中 · '+
                (f.work_files<0?'无法读取':n(f.work_files)+' 个临时项')+'</span>'
              : '<span class="tag off">采集已停却仍存在</span>')
          : '<span class="tag on">不存在</span>')+
      '<div class="note">样本解压、上传后立即 rmtree，工作目录本身在每轮结束时删除。'+
      '限速后单轮可跑数十分钟，所以采集运行期间工作目录存在是正常的 —— '+
      '只有「采集已停却仍存在」或出现 .zip / .bin 才算真残留。</div>')+
    '</div>';
  html+='<div class="sec">下载记录</div>'+table(
    '<th>时间</th><th>文件名</th><th>类型</th><th>原始大小</th><th>压缩包</th>'+
    '<th>家族</th><th>样本日期</th><th>VT 收录</th><th>结果</th><th>SHA-256</th>',
    (f.rows||[]).map(function(x){
      var res = x.error ? '<span class="tag off">出错</span>'
              : x.zip_bad ? '<span class="tag off">非 zip</span>'
              : x.skipped_stale ? '<span class="tag mid">非当天，未下载</span>'
              : x.downloaded ? '<span class="tag on">已下载</span>'
              : '<span class="tag gray">未下载</span>';
      var dayCell = x.day
        ? (x.day===f.day ? '<span class="tag on">'+esc(x.day)+'</span>'
                         : '<span class="tag mid">'+esc(x.day)+'</span>')
        : '<span class="z">未知</span>';
      return '<tr><td class="z">'+esc(x.ts)+'</td>'+nameCell(x)+
        '<td>'+(esc(x.type)||'<span class="z">-</span>')+'</td>'+
        '<td>'+sz(x.size)+'</td>'+
        '<td>'+(x.zip_kb?x.zip_kb+' KB':'<span class="z">-</span>')+'</td>'+
        '<td>'+(esc(x.sig)||'<span class="z">-</span>')+'</td>'+
        '<td>'+dayCell+'</td>'+
        '<td>'+(x.vt_unknown?'<span class="tag mid">未收录</span>'
                            :'<span class="tag on">已收录</span>')+'</td>'+
        '<td>'+res+'</td>'+shaCell(x.sha256)+'</tr>';
    }).join(''),
    /* 空表有两种完全不同的原因,给同一句话会把「记录被挤掉」说成「没下载」。 */
    f.ledger_short
      ? ('今天的逐文件记录已被台账滚动挤掉 —— 运行汇总仍记着 '+n(f.run_dl)+
         ' 个，不是没下载')
      : '暂无下载记录（当前批次没有 VT 未收录的样本，或上传预算已用完）',10);
  $('#body').innerHTML=html;
}

/* ---------- 上传 ---------- */
function rUploads(d){
  var f=d.f;
  nav({uploads:f.run_up});
  var unlimited = f.b_cap==null || f.b_cap<0;
  var pct = unlimited ? 0 : (f.b_cap?100*f.b_used/f.b_cap:0);
  var html=title()+'<div class="kpi">'+
    kcard('g','今日上传 VT',n(f.run_up),
      '运行汇总 · 逐文件台账 '+n(f.ok_today)+' 条'+(f.ledger_short?'（已滚动）':''))+
    kcard(unlimited?'g':pct>=95?'r':pct>=75?'y':'g','上传预算',
      unlimited?n(f.b_used)+' 次':n(f.b_used)+' / '+n(f.b_cap),
      unlimited?'不设上限':pct.toFixed(0)+'% 已用')+
    kcard(f.run_sk?'y':'g','预算不足跳过',n(f.run_sk),f.run_sk?'今日已转为只查询':'无跳过')+
    kcard('','上传字节',f.bytes+' MB','今日提交的样本原始大小合计')+
    '</div>';
  html+='<div class="cols">'+
    box('上传预算',bar(f.b_used,f.b_cap)+
      row('今日上传（运行汇总）',n(f.run_up)+' 个')+
      row('今日上传（逐文件台账）',n(f.today)+' 个')+
      row('上传异常',f.bad_today?'<span class="tag off">'+n(f.bad_today)+'</span>'
                                :'<span class="tag on">0</span>')+
      '<div class="note">预算按 UTC 日切自动归零。用完后当天剩余的未收录样本只做查询，'+
      '连下载都跳过。</div>')+
    box('上传条件',
      row('触发条件','VT 返回未收录（404）')+
      row('下载模式',esc(f.mode))+
      row('台账总条数',n(f.ledger))+
      row('本页显示',n(f.shown)+' / '+n(f.matched))+
      '<div class="note">提交走本机 /vt/upload，配额由 intel 服务集中管账，'+
      '所以这里永远不会超过共享预算。提交完成后样本立即删除。</div>')+
    '</div>';
  html+='<div class="sec">上传记录</div>'+table(
    '<th>时间</th><th>文件名</th><th>类型</th><th>大小</th><th>家族</th>'+
    '<th>上传结果</th><th>SHA-256</th>',
    (f.rows||[]).map(function(x){
      var res = x.skipped_budget ? '<span class="tag gray">预算跳过</span>'
              : x.uploaded ? (x.upload_ok ? '<span class="tag on">成功</span>'
                                          : '<span class="tag mid">服务返回异常</span>')
              : '<span class="tag gray">未上传</span>';
      return '<tr><td class="z">'+esc(x.ts)+'</td>'+nameCell(x)+
        '<td>'+(esc(x.type)||'<span class="z">-</span>')+'</td>'+
        '<td>'+sz(x.size)+'</td>'+
        '<td>'+(esc(x.sig)||'<span class="z">-</span>')+'</td>'+
        '<td>'+res+'</td>'+shaCell(x.sha256)+'</tr>';
    }).join(''),'暂无上传记录（没有 VT 未收录的样本，或上传预算为 0）',7);
  $('#body').innerHTML=html;
}

/* ---------- 回传 ---------- */
function rTransfers(d){
  var t=d.t, m=d.m||{};
  nav({transfers:t.pushes});
  var html=title()+'<div class="kpi">'+
    kcard('y','今日推送',n(t.rows),n(t.pushes)+' 批 · '+n(t.kb)+' KB')+
    kcard('g','主库新增',n(t.ins),'重复跳过 '+n(t.sk)+' 条')+
    kcard('','主库总行数',n(t.master),'本节点 '+n(t.local_total)+' 条')+
    kcard(t.fail?'r':'g','失败批次',n(t.fail),t.fail?'水位未推进，会自动重试':'全部成功')+
    '</div>';
  html+='<div class="cols">'+
    box('今日',
      row('推送',n(t.rows)+' 行 / '+n(t.pushes)+' 批')+
      row('主库新增',n(t.ins)+' 条')+row('重复跳过',n(t.sk)+' 条')+
      row('传输量',n(t.kb)+' KB')+row('最后成功',esc(t.last)||'-'))+
    box('水位',
      row('主库总行数',n(t.master))+row('本节点总行数',n(t.local_total))+
      row('累计推送行数',n(t.rows_all))+
      '<div class="note">水位含边界（stored_at >= mark）。同秒行不会被漏掉，'+
      '代价是每次重发 1 行，由主库 INSERT OR IGNORE 吞掉。</div>'+
      '<div class="mono">'+(esc(t.wm)||'-')+'</div>')+
    box('触发方式',
      syncRows(d.u||{})+
      row('上次结果',esc((d.u||{}).sync_result)||'-')+
      row('下次采集',esc((d.u||{}).next_h)||'-')+
      '<div class="note">回传没有自己的定时器：采集服务成功结束时由 OnSuccess 立刻触发一次，'+
      '所以每采一批就发一次，两次回传的间隔跟着采集节奏走。'+
      '失败或被单实例锁跳过的采集轮次不会触发，避免把没采完的批次发出去。</div>')+
    '</div>';
  html+='<div class="sec">推送批次（本节点记录 + 主服务器核对）</div>'+table(
    '<th>时间</th><th>发送行数</th><th>大小</th><th>主库收到</th><th>新增</th>'+
    '<th>重复</th><th>主库总数</th><th>本端结果</th><th>主服务器记录</th>',
    (d.syncs||[]).map(function(s){
      var mc;
      if(s.m_ok===null||s.m_ok===undefined)
        mc = m.have ? '<span class="tag gray" title="主服务器账本里没有匹配到这一批">未匹配</span>'
                    : '<span class="z">未拉取</span>';
      else if(!s.m_ok) mc='<span class="tag off">主服务器记为失败</span>';
      else if(s.m_agree) mc='<span class="tag on">一致 '+esc(String(s.m_ts).slice(11,19))+'</span>';
      else mc='<span class="tag mid" title="新增 '+n(s.m_inserted)+' / 总数 '+n(s.m_total)+
              '">数字不一致</span>';
      return '<tr><td>'+esc(s.day)+' '+esc(s.time)+'</td><td>'+n(s.rows)+'</td>'+
        '<td>'+n(s.kb)+' KB</td><td>'+n(s.received)+'</td><td>'+n(s.inserted)+'</td>'+
        '<td>'+n(s.skipped)+'</td><td>'+n(s.master_total)+'</td><td>'+
        (s.ok?'<span class="tag on">成功</span>'
             :'<span class="tag off" title="'+esc(s.error)+'">失败</span>')+'</td>'+
        '<td>'+mc+'</td></tr>';
    }).join(''),'暂无记录',9);

  html+='<div class="sec">白样本回传走的是另一条通道</div>'+
    '<div class="box"><div class="note">本页统计的是 vt_reports（威胁）。'+
    '正常样本经 24 小时隔离复查后由独立的通道回传，账本也是独立的 —— '+
    '见 <a href="/benign">白样本</a> 页。</div></div>';

  html+='<div class="sec">主服务器侧记录</div>';
  if(!m.have){
    html+='<div class="box"><div class="z">还没有拉到主服务器账本。'+
      'bulwark-sync.py 每次推送成功后会通过 export-ledger 拉一次；'+
      '如果一直为空，检查主服务器上的 /usr/local/sbin/bulwark-ledger-export.py 和'+
      ' authorized_keys 里的强制命令。</div></div>';
  } else {
    html+='<div class="cols" style="margin-bottom:12px">'+
      box('对账',
        row('本端成功批次',n(m.local_ok))+
        row('主服务器已确认',n(m.matched))+
        row('未匹配',m.unmatched?'<span class="tag mid">'+n(m.unmatched)+'</span>'
                                :'<span class="tag on">0</span>')+
        row('数字不一致',m.disagree?'<span class="tag off">'+n(m.disagree)+'</span>'
                                  :'<span class="tag on">0</span>')+
        '<div class="note">按「行数相同 + 时间相差 3 分钟内」匹配 —— 载荷里没有批次 ID，'+
        '主服务器的时间戳也比本端早 1~2 秒。刚推完还没拉到账本时会短暂显示未匹配，'+
        '属正常。</div>')+
      box('主服务器视角',
        row('账本记录数',n(m.count)+' 条')+
        row('累计接收行数',n(m.received_all))+
        row('其中真正入库',n(m.inserted_all))+
        row('主库总行数',n(m.master_total))+
        row('最后接收时间',esc(m.last)||'-')+
        '<div class="note">主服务器只导出来源 IP 等于本节点的那些记录，'+
        '看不到别的节点的数据。</div>')+
      '</div>';
    html+=table(
      '<th>主服务器时间 (UTC)</th><th>接收</th><th>真正入库</th><th>重复</th>'+
      '<th>畸形</th><th>大小</th><th>入库后主库总数</th><th>批次最新数据</th><th>结果</th>',
      (m.rows||[]).map(function(x){
        return '<tr><td>'+esc(String(x.ts).replace('T',' ').replace('Z',''))+'</td>'+
          '<td>'+n(x.received)+'</td><td><b>'+n(x.inserted)+'</b></td>'+
          '<td>'+n(x.skipped)+'</td>'+
          '<td>'+(x.malformed?'<span class="bad">'+n(x.malformed)+'</span>':'0')+'</td>'+
          '<td>'+n(x.kb)+' KB</td><td>'+n(x.total)+'</td>'+
          '<td class="z">'+esc(String(x.newest).slice(11,19))+'</td>'+
          '<td>'+(x.ok?'<span class="tag on">成功</span>'
                      :'<span class="tag off" title="'+esc(x.error)+'">失败</span>')+'</td></tr>';
      }).join(''),'暂无记录',9);
  }
  $('#body').innerHTML=html;
}

/* ---------- 密钥 ---------- */
function keyState(x){
  if(!x.valid) return '<span class="tag off">格式无效（已被忽略）</span>';
  if(x.duplicate) return '<span class="tag mid">重复（不计入额度）</span>';
  return '<span class="tag on">生效中</span>';
}
/* VirusTotal 自己对这把密钥的说法。分级刻意做细:
     banned/invalid  已经坏了,不会自己恢复 -> 才允许删
     quota/rate      暂时的,会自己恢复 -> 不给删除按钮
     unchecked       还没探测过 -> 如实说,不猜
   把 quota 和 banned 混成一个「不可用」,会让人把一把明天就恢复的密钥删掉。 */
function acctState(x){
  var s=x.state, t=esc(x.state_label||'');
  if(s==='ok'){
    var q=(x.q_used!=null&&x.q_allowed!=null)
      ? ' <span class="qn">'+n(x.q_used)+'/'+n(x.q_allowed)+'</span>' : '';
    return '<span class="tag on">正常</span>'+q;
  }
  if(s==='banned')   return '<span class="tag off" title="'+t+'">已封禁</span>';
  if(s==='invalid')  return '<span class="tag off" title="'+t+'">密钥无效</span>';
  if(s==='malformed')return '<span class="tag off" title="'+t+'">格式错误</span>';
  if(s==='quota')    return '<span class="tag mid" title="'+t+'">配额用完</span>';
  if(s==='rate')     return '<span class="tag mid" title="'+t+'">被限速</span>';
  if(s==='forbidden')return '<span class="tag mid" title="'+t+'">被拒 403</span>';
  if(s==='unchecked')return '<span class="z">尚未探测</span>';
  return '<span class="tag gray" title="'+t+'">'+esc(s||'?')+'</span>';
}
/* 「还有多久到 UTC 0 点」—— VT 的每日配额按 UTC 日切,所以恢复时间是个能算出来的
   具体数字,不该让人自己去换算时区。 */
function resetIn(m){
  m=Math.max(0,m||0);
  var h=Math.floor(m/60), r=m%60;
  return h?(h+' 小时'+(r?' '+r+' 分':'')):(r+' 分');
}
function rVtkeys(d){
  var k=d.k;
  nav(null);
  // 分母用【可用】把数,不用配置里的把数。用后者会得到一个永远打不到的上限:
  // 线上就出现过 3 把封禁的也被算进去,页面写着 3000/天而实际只有 1500。
  var capd=k.usable_per_day||0;
  var pct=capd?100*k.used_today/capd:0;
  // 「今天还剩多少」与「每天有多少」是两个数,刻意分开。全部 429 的时候前者是 0,而后者
  // 仍然是 capd —— 把它们混成一个数,就会出现下面 6 行全写着「配额用完」、上面 KPI 却
  // 宣布还剩 1796 次的自相矛盾。
  var spent=!!k.spent_all;
  var html=title()+
    (spent?'<div class="warn">配置的 '+n(k.live)+' 把密钥<b>此刻全部返回 429 '+
      '「配额已用完」</b>（探测于 '+
      esc(String(k.checked_at||'').replace('T',' ').replace('Z',''))+
      ' UTC），所以<b>今天的实际余量是 0</b>，'+resetIn(k.reset_minutes)+
      '后按 UTC 日切恢复。<br>'+
      '本机今日只记了 '+n(k.used_today)+' 次调用，远少于 '+n(capd)+
      '。<b>每一把都同时用完</b>（包括刚添加的新密钥）通常不是账号额度问题，而是'+
      'VirusTotal 在限制<b>本机这个 IP</b> —— 实测同一把密钥换到另一台机器上调用会'+
      '立刻返回 200。这种情况下<b>再加密钥没有用</b>，只能降低调用频率并等它解除。'+
      '</div>':'')+
    '<div class="kpi">'+
    kcard(k.dead?'y':(spent?'y':'g'),'可用密钥',n(k.usable)+' / '+n(k.live),
      k.dead?(n(k.dead)+' 把已坏，见下表')
            :(k.probed?(n(k.ok_now)+' 把此刻可查'+
                        (k.exhausted?'，'+n(k.exhausted)+' 把配额用完':''))
                      :'每把 '+n(k.per_day_each)+' 次/天'))+
    kcard('','每日额度上限',n(capd),
      n(k.usable)+' 把可用 × '+n(k.per_day_each)+
      (k.dead?'（已排除 '+n(k.dead)+' 把坏的）':''))+
    kcard(spent?'r':pct>=95?'r':pct>=75?'y':'g','今日已用',n(k.used_today),
      spent?'今日余量 0（全部配额用完）':'剩余 '+n(k.left_today)+' 次')+
    kcard(k.dead?'r':'g','已坏密钥',n(k.dead),
      k.dead?'占着容量却查不了，建议删除':'没有封禁或无效的密钥')+
    kcard(k.pending?'y':'g','待应用',n(k.pending),
      k.pending?'正在写入配置并重启服务':'没有排队的请求')+
    '</div>';

  html+='<div class="cols">'+
    box('添加密钥',
      '<div class="row"><span>VirusTotal API Key</span></div>'+
      '<input id="nk" type="text" placeholder="64 位十六进制字符" '+
        'autocomplete="off" spellcheck="false" '+
        'style="width:100%;padding:9px 11px;border:1px solid var(--line);border-radius:8px;'+
        'font-family:Consolas,monospace;font-size:13px;margin:4px 0 10px">'+
      '<button id="nkbtn" style="padding:9px 18px;border:0;border-radius:8px;'+
        'background:var(--blue);color:#fff;font-size:14px;font-weight:600;cursor:pointer">'+
        '添加并生效</button>'+
      '<div id="nkmsg" style="margin-top:10px;font-size:13px"></div>'+
      '<div class="note">密钥写入 /etc/bulwark-intel/config.json 后会自动重启 '+
      'bulwark-intel 服务（app.py 只在启动时读一次配置，不重启不生效）。'+
      '重启很轻：它是无状态的缓存代理，数据都在 SQLite 里，不会丢东西。<br>'+
      '页面只显示密钥的 sha256 前 6 位指纹，不回显明文。</div>')+
    box('账号状态',
      row('上次探测',k.checked_at
          ? '<span class="mono">'+esc(String(k.checked_at).replace('T',' ')
              .replace('Z',''))+'</span>'+
            (k.age_minutes!=null?' <span class="qn">'+resetIn(k.age_minutes)+
              '前</span>':'')+
            (k.fresh?'':' <span class="tag mid" title="超过 12 小时的探测结果不用来'+
              '判断今天还剩多少">已过期</span>')
          : '<span class="z">从未探测</span>')+
      row('可用 / 配置',n(k.usable)+' / '+n(k.live)+' 把')+
      // 「此刻可查」是这一页最实用的一个数:它既不是配置里的把数,也不是没被封的把数,
      // 而是现在真的能拿到结果的把数。
      row('此刻可查',k.probed
          ? (k.ok_now?'<span class="tag on">'+n(k.ok_now)+' 把</span>'
                     :'<span class="bad">0 把</span>')
          : '<span class="z">尚未探测</span>')+
      row('配额用完',k.exhausted?'<span class="tag mid">'+n(k.exhausted)+' 把</span>'+
            ' <span class="qn">'+resetIn(k.reset_minutes)+'后按 UTC 日切恢复</span>'
                                :'<span class="tag on">0</span>')+
      (k.limited?row('被限速','<span class="tag mid">'+n(k.limited)+' 把</span>'+
            ' <span class="qn">几分钟后自行恢复</span>'):'')+
      row('已封禁或无效',k.dead?'<span class="bad">'+n(k.dead)+' 把</span>'
                             :'<span class="tag on">0</span>')+
      '<div style="margin-top:10px;display:flex;gap:8px;align-items:center;'+
        'flex-wrap:wrap">'+
        '<button id="pbbtn" style="padding:9px 16px;border:1px solid var(--line);'+
        'border-radius:8px;background:var(--surface);color:var(--ink);'+
        'font-size:14px;cursor:pointer">重新探测状态</button>'+
        '<span id="pbmsg" style="font-size:13px"></span>'+
      '</div>'+
      '<div class="note">状态是<b>问 VirusTotal 本人</b>拿到的，不是本地推测：'+
      '401 <span class="mono">UserNotActiveError</span> 才算封禁，'+
      '429 只是配额用完或被限速、会自己恢复。<br>'+
      '探测由 root 侧每 6 小时跑一次，<b>不在渲染页面时进行</b> —— 这一页每几秒轮询一次，'+
      '每次渲染都去问 VT 会把当日配额全花在画界面上。要立刻刷新就点上面那个按钮。<br>'+
      '探测一把正常的密钥会花掉它 1 次额度；已封禁的密钥返回 401，不消耗配额。</div>')+
    box('额度说明',
      row('可用密钥数',n(k.usable)+' 把')+
      row('单把每日上限',n(k.per_day_each)+' 次')+
      row('可用叠加上限',n(capd)+' 次/天')+
      row('今日已用',n(k.used_today)+' 次 <span class="qn">（本机记账）</span>')+
      row('今日剩余',spent
          ? '<span class="bad">0 次</span> <span class="qn">探测说每一把都被拒，'+
            '本机记账在这种情况下不作数</span>'
          : n(k.left_today)+' 次')+
      bar(spent?capd:k.used_today,capd)+
      '<div class="note">配额是按 VirusTotal 这个来源整体计数的，不按单把 key 分别计。'+
      '加 key 的作用是把每日上限乘上去（<b>可用</b> key 数 × 单把上限）——'+
      '封禁的 key 不算进来，否则会显示一个永远打不到的上限。<br>'+
      '注意这个上限是本节点自己算的，VT 服务端按 key 记账——如果同一把 key 也被'+
      '别的机器用，真实消耗会比这里显示的快。</div>')+
    '</div>';

  html+='<div class="sec">密钥池</div>'+table(
    '<th>#</th><th>指纹</th><th>长度</th><th>配置状态</th><th>VT 账号状态</th>'+
    '<th>计入额度</th><th>操作</th>',
    (k.keys||[]).map(function(x,i){
      // 删除按钮只出现在确定坏掉的那几行。配额用完的不给按钮 —— 明天就恢复的密钥
      // 不该出现在一个不可逆操作的旁边。
      var act = x.removable
        ? '<button class="rmk" data-fp="'+esc(x.fp)+'" style="padding:5px 12px;'+
          'border:1px solid var(--red,#d92d20);border-radius:6px;background:var(--surface);'+
          'color:var(--red,#d92d20);font-size:12px;cursor:pointer">删除</button>'
        : '<span class="z">-</span>';
      return '<tr><td class="qn">'+(i+1)+'</td>'+
        '<td class="mono">'+esc(x.fp)+'</td>'+
        '<td>'+n(x.len)+'</td>'+
        '<td>'+keyState(x)+'</td>'+
        '<td>'+acctState(x)+'</td>'+
        '<td>'+(x.counted?'<span class="tag on">是</span>'
                         :'<span class="tag gray">否</span>')+'</td>'+
        '<td>'+act+'</td></tr>';
    }).join(''),'还没有配置任何 VT 密钥',7)+
    '<div id="rmmsg" style="margin-top:10px;font-size:13px"></div>';

  html+='<div class="sec">操作记录</div>'+table(
    '<th>时间</th><th>指纹</th><th>结果</th><th>服务重启</th><th>说明</th>',
    (k.history||[]).map(function(x){
      var st = x.status==='added' ? '<span class="tag on">已添加</span>'
             : x.status==='removed' ? '<span class="tag on">已删除</span>'
             : x.status==='probed' ? '<span class="tag gray">已探测</span>'
             : x.status==='refused' ? '<span class="tag mid">已拒绝</span>'
             : x.status==='notfound' ? '<span class="tag mid">未找到</span>'
             : x.status==='duplicate' ? '<span class="tag mid">重复</span>'
             : x.status==='invalid' ? '<span class="tag off">格式无效</span>'
             : x.status==='malformed' ? '<span class="tag off">请求损坏</span>'
             : '<span class="tag off">'+esc(x.status)+'</span>';
      var rs = (x.status!=='added'&&x.status!=='removed') ? '<span class="z">-</span>'
             : x.restarted ? '<span class="tag on">成功</span>'
             : '<span class="tag off" title="'+esc(x.restart_error)+'">失败</span>';
      return '<tr><td class="z">'+esc(String(x.ts).replace('T',' ').replace('Z',''))+'</td>'+
        '<td class="mono">'+(esc(x.fp)||'<span class="z">-</span>')+'</td>'+
        '<td>'+st+'</td><td>'+rs+'</td>'+
        '<td style="text-align:left">'+esc(x.detail)+'</td></tr>';
    }).join(''),'暂无记录',5);

  $('#body').innerHTML=html;

  var btn=$('#nkbtn'), inp=$('#nk'), msg=$('#nkmsg');
  function submit(){
    var v=(inp.value||'').trim();
    if(!v){ msg.innerHTML='<span class="bad">请先填入密钥</span>'; return; }
    var label=btn.innerHTML;
    btn.disabled=true;
    btn.innerHTML='<span class="spin"></span>提交中';
    msg.textContent='';
    fetch('/api/vtkeys/add',{
      method:'POST', cache:'no-store',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({key:v})
    }).then(function(r){return r.json()}).then(function(j){
      btn.disabled=false; btn.innerHTML=label;
      if(j.ok){
        inp.value='';
        msg.innerHTML='<span style="color:var(--green)">已受理：'+esc(j.message)+'</span>';
        // The root-side helper needs a moment to rewrite the config and restart
        // bulwark-intel; reload after that so the pool count reflects reality.
        setTimeout(load,4000);
      }else{
        msg.innerHTML='<span class="bad">'+esc(j.error||j.message||'提交失败')+'</span>';
      }
    }).catch(function(e){
      btn.disabled=false; btn.innerHTML=label;
      msg.innerHTML='<span class="bad">提交失败：'+esc(e.message)+'</span>';
    });
  }
  btn.addEventListener('click',submit);
  inp.addEventListener('keydown',function(e){ if(e.key==='Enter') submit(); });

  /* ---- 重新探测 ---- */
  var pb=$('#pbbtn'), pbm=$('#pbmsg');
  pb.addEventListener('click',function(){
    var lab=pb.innerHTML;
    pb.disabled=true; pb.innerHTML='<span class="spin"></span>探测中';
    fetch('/api/vtkeys/probe',{method:'POST',cache:'no-store',
      headers:{'Content-Type':'application/json'},body:'{}'})
      .then(function(r){return r.json()}).then(function(j){
        pbm.innerHTML = j.ok
          ? '<span style="color:var(--green)">'+esc(j.message)+'</span>'
          : '<span class="bad">'+esc(j.error||j.message||'失败')+'</span>';
        // root 侧要问一次 VT,给它几秒再刷新,否则看到的还是旧状态。
        setTimeout(function(){ pb.disabled=false; pb.innerHTML=lab; load(); },6000);
      }).catch(function(e){
        pb.disabled=false; pb.innerHTML=lab;
        pbm.innerHTML='<span class="bad">'+esc(e.message)+'</span>';
      });
  });

  /* ---- 删除坏掉的密钥 ---- */
  var rmm=$('#rmmsg');
  Array.prototype.forEach.call(document.querySelectorAll('.rmk'),function(b){
    b.addEventListener('click',function(){
      var fp=b.getAttribute('data-fp');
      // 删除不可逆,而且这一页是明文 HTTP 上的运维界面 —— 二次确认是最低成本的防手滑。
      if(!window.confirm('确定要从配置里删除指纹 '+fp+' 这把密钥吗？\n\n'+
        'root 侧会在删除前重新探测一次，如果它已经恢复正常就会拒绝删除。\n'+
        '删除后会自动备份原配置并重启 bulwark-intel。')) return;
      b.disabled=true; b.innerHTML='删除中';
      fetch('/api/vtkeys/remove',{method:'POST',cache:'no-store',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({fp:fp})})
        .then(function(r){return r.json()}).then(function(j){
          rmm.innerHTML = j.ok
            ? '<span style="color:var(--green)">'+esc(j.message)+'</span>'
            : '<span class="bad">'+esc(j.error||j.message||'删除失败')+'</span>';
          if(j.ok) setTimeout(load,6000);
          else { b.disabled=false; b.innerHTML='删除'; }
        }).catch(function(e){
          b.disabled=false; b.innerHTML='删除';
          rmm.innerHTML='<span class="bad">'+esc(e.message)+'</span>';
        });
    });
  });
}

/* ---------- 送检(批量手工上传) ----------
   分工:前端只负责【把字节送上去】,一个文件一个请求、限并发;查询与复查全在服务端的
   队列里。所以这一页的进度来自 /api/submit 读磁盘的结果,而不是浏览器内存 —— 导航是
   真链接、整页重载,存在 JS 里的进度必然丢,而那正是要修的问题。

   UP.up 只保留「本次浏览器会话还没传完的文件」;传完的文件在服务端有记录,由队列表
   格显示。两者刻意不共用一份状态:上传是本地的、可中断的,队列是服务端的、持久的。 */
/* skip 与 fails 是两件不同的事,刻意分开:
     skip  = 这个文件【不该传】(超过上限、空文件)。重试没有意义,但必须让人看见是哪些,
             否则拖一个 500 个文件的目录进来,少传了 3 个而屏幕上只有一个数字。
     fails = 传了但没成功。可以重试。
   两者都按文件累积,不会被后续的添加或「开始上传」冲掉 —— 上一版把它们塞进一个会被
   覆盖的 UP.msg 里,拖第二个文件夹就把第一个文件夹的跳过记录抹了。 */
/* submit 是勾选框的状态,存在这里而不是只存在 DOM 里。原因是页面在上传期间【也要】继续
   刷新,而刷新会整块换掉 #body:勾选状态若只活在 DOM 上,一次刷新就把「不要提交给 VT」
   悄悄翻回默认值 —— 那是拿用户的选择去换一次界面更新,不能接受。
   null = 还没初始化,首次渲染时按配置默认值填。 */
var UP={pend:[],skip:[],fails:[],done:0,bytes:0,sent:0,active:false,msg:'',
        submit:null};
function rSubmit(d){
  var u=d.up, agg=d.q2||{}, items=d.items||[];
  /* 解压中的包也算在「还没完」里:它没出结论,而且马上会变成一批新的排队文件。 */
  var wait=(agg.queued||0)+(agg.checking||0)+(agg.vt_wait||0)+(agg.expanding||0);
  var pct=agg.total?Math.round(100*(agg.done||0)/agg.total):0;
  var html=title()+'<div class="kpi">'+
    kcard('','已上传排队',n(agg.total),
      '今日 '+n(agg.today||0)+' 个 · 记录保留 '+n(u.keep_days)+' 天')+
    kcard(wait?'y':'g','待查询',n(wait),
      '排队 '+n(agg.queued||0)+' · 查询中 '+n(agg.checking||0)+
      ' · 等 VT 分析 '+n(agg.vt_wait||0))+
    kcard('g','已出结论',n(agg.done||0),
      '恶意 '+n(agg.malicious||0)+' · 可疑 '+n(agg.suspicious||0)+
      ' · 干净 '+n(agg.clean||0))+
    kcard((agg.failed||0)?'r':'','失败',n(agg.failed||0),
      (agg.failed||0)?'会自动重试，见下表原因':'没有失败的文件')+
    kcard('','主库直接命中',n(agg.master_hit||0),'这些一次 VT 都没花')+
    kcard((agg.stored||0)&&(agg.pushed||0)>=(agg.stored||0)?'g':(agg.pushed||0)?'y':'',
      '已回传主库',n(agg.pushed||0)+' / '+n(agg.stored||0),
      (agg.acked||0)?('主库账本确认 '+n(agg.acked)+' 条'):'等主库账本确认')+
    kcard(u.vt_left>50?'g':u.vt_left>0?'y':'r','当日 VT 余量',n(u.vt_left),
      '已用 '+n(u.vt_used)+' / '+n(u.vt_cap))+
    '</div>';

  html+='<div class="sec">进度</div><div class="cols">'+
    box('队列整体',
      bar(agg.done||0,agg.total||0)+
      row('已出结论',n(agg.done||0)+' / '+n(agg.total||0)+'（'+pct+'%）')+
      row('复查节奏','每 '+n(u.poll_minutes)+' 分钟一轮')+
      row('队列服务',u.worker==='active'?'<span class="tag on">已启用</span>'
                   :'<span class="tag off">'+esc(u.worker||'未安装')+'</span>')+
      row('下一轮',esc(u.worker_next)||'<span class="z">-</span>')+
      '<div class="note">上传完就可以离开这一页，甚至关掉浏览器：进度记在服务端，'+
      '回来还在。</div>')+
    box('本次上传',
      '<div id="upbar"></div>'+
      '<div id="uprow"></div>'+
      '<div class="note">上传只是把字节送到本节点，<b>不等查询结果</b>。'+
      '送到后立刻进队列，第一轮查询在几秒内开始。</div>')+
    box('体积与磁盘',
      bar(u.spool_mb,u.spool_max_mb)+
      row('排队区占用',n(u.spool_mb)+' MB / '+n(u.spool_max_mb)+' MB')+
      row('待处理样本',n(u.spool_files)+' 个文件')+
      row('单个文件上限','<b>'+n(u.max_mb)+' MB</b>'+
          (u.max_mb===u.svc_cap_mb
            ? ' <span class="tag on">与 VirusTotal 上限一致</span>'
            : ' <span class="tag mid">本机服务上限 '+n(u.svc_cap_mb)+' MB</span>'))+
      row('磁盘空闲',(u.disk_free_mb>=0
            ? n(u.disk_free_mb)+' MB（保留下限 '+n(u.disk_floor_mb)+' MB）'
            : '<span class="z">未知</span>'))+
      '<div class="note" id="szn">上限就是 VirusTotal 公开 API 的上限：单文件 <b>650 MB</b>。'+
      '超过 32 MB 的文件 VT 要求先取专用上传地址，因此会多花一次 VT 请求，这一步由'+
      '本机服务自动处理。<br>'+
      '出结论或 VT 收下之后，样本字节立刻删除；没走完的最多留 24 小时，另有每日清理'+
      '兜底。<b>数量不限</b>，但占用有上限、且始终给磁盘留出保留下限 —— 否则'+
      '「不限数量」等于允许把情报库所在的盘写满。</div>')+
    '</div>';

  /* ---- 回传主服务器:证据,不是承诺 ---- */
  var pu=d.pushes||[];
  html+='<div class="sec">回传主服务器</div><div class="cols">'+
    box('这一批的回传进度',
      bar(agg.pushed||0,agg.stored||0)+
      row('已入库（有结论且是威胁）',n(agg.stored||0)+' 条')+
      row('已随批次推送',n(agg.pushed||0)+' 条'+
        ((agg.stored||0)&&(agg.pushed||0)>=(agg.stored||0)
          ? ' <span class="tag on">全部推完</span>'
          : (agg.stored||0)?' <span class="tag mid">还在推</span>':''))+
      row('主库账本确认新增',(agg.acked||0)?('<span class="tag on">'+n(agg.acked)+
        ' 条</span>'):'<span class="z">0</span>')+
      row('当前回传水位','<span class="mono">'+(esc(d.wm)||'-')+'</span>')+
      '<div class="note">只有<b>威胁</b>才进归档、才需要回传；干净和「VT 未收录」不入库，'+
      '所以不会出现在这里。<br>'+
      '「已推送」是本端证据：回传按入库时刻的水位推，而水位只在主库回 OK 之后才前移，'+
      '所以入库时刻早于水位就一定在某个被受理的批次里。<br>'+
      '「主库账本确认」是<b>对端证据</b>：主服务器自己记下它真正插入的哈希，回传时把那份'+
      '账本拉回来比对。主库如果本来就有这个哈希，会记成重复跳过、不进新增清单 —— '+
      '那也算传到了，只是没新增。</div>')+
    box('最近的回传批次',
      (pu.length
        ? pu.slice(0,6).map(function(s){
            return row(esc(String(s.day||'').slice(5))+' '+esc(s.time||''),
              (s.ok?'<span class="tag on">OK</span>':'<span class="tag off">失败</span>')+
              ' 发 '+n(s.rows)+' 行 · 主库新增 '+n(s.inserted)+
              ' · 重复 '+n(s.skipped)+' · 主库共 '+n(s.master_total));
          }).join('')
        : '<div class="z">还没有回传记录</div>')+
      '<div class="note">出结论就立刻触发一次回传，不等采集器那半小时一次的链。'+
      '完整的批次账本与主服务器核对在「回传」页。</div>')+
    '</div>';

  html+='<div class="sec">添加文件</div><div class="cols">'+
    box('选择',
      '<div id="drop" style="border:2px dashed var(--line);border-radius:10px;'+
        'padding:26px 16px;text-align:center;color:var(--muted);cursor:pointer;'+
        'transition:.15s">'+
        '把文件<b>、整个文件夹或压缩包</b>拖到这里<br>'+
        '<span class="qn">数量不限；文件夹会递归展开，保留相对路径。'+
        '目录里超过 '+n(u.max_mb)+' MB 的文件会<b>单独跳过</b>，不影响其余文件<br>'+
        (u.archive_expand
          ? 'zip / 7z / rar / tar.* <b>自动在服务端解压</b>，'+
            '带密码的会依次试 '+esc((u.archive_passwords||[]).join(' / ')||'infected')+
            '；解出来的每个文件按单独样本排队送检'
          : '压缩包<b>不会</b>自动解压（配置里已关闭）')+'</span></div>'+
      '<input id="fs" type="file" multiple style="display:none">'+
      '<input id="fd" type="file" multiple webkitdirectory directory '+
        'style="display:none">'+
      '<div style="margin-top:12px;display:flex;gap:8px;align-items:center;'+
        'flex-wrap:wrap">'+
        '<button id="pickf" style="padding:9px 16px;border:1px solid var(--line);'+
        'border-radius:8px;background:var(--surface);color:var(--ink);'+
        'font-size:14px;cursor:pointer">选择文件</button>'+
        '<button id="pickd" style="padding:9px 16px;border:1px solid var(--line);'+
        'border-radius:8px;background:var(--surface);color:var(--ink);'+
        'font-size:14px;cursor:pointer">选择文件夹</button>'+
        '<button id="gobtn" style="padding:9px 18px;border:0;border-radius:8px;'+
        'background:var(--blue);color:#fff;font-size:14px;font-weight:600;'+
        'cursor:pointer">开始上传</button>'+
        '<button id="clrbtn" style="padding:9px 14px;border:1px solid var(--line);'+
        'border-radius:8px;background:var(--surface);color:var(--muted);'+
        'font-size:14px;cursor:pointer">清空列表</button>'+
        '<span id="submsg" style="font-size:13px"></span>'+
      '</div>'+
      '<div style="margin-top:12px">'+
        '<label style="font-size:13px;color:var(--ink);cursor:pointer">'+
        '<input id="dosub" type="checkbox"'+
        (UP.submit?' checked':'')+(u.allow_submit?'':' disabled')+
        (UP.active?' disabled':'')+
        ' style="vertical-align:-2px;margin-right:6px">'+
        'VT 未收录时，把样本提交给 VirusTotal</label>'+
        (u.allow_submit?'':'<div class="qn">配置里已禁止提交</div>')+
      '</div>'+
      '<div class="note">提交是<b>不可撤回的公开共享</b>，而且花当日预算，所以只在'+
      'VT 确实没收录时才发；已有报告的文件只查不传。</div>')+
    box('每个文件会被怎么处理',
      row('第 1 步','问主服务器是否已收录 <span class="tag on">不花 VT</span>')+
      row('第 2 步','问本节点缓存，再问 VT')+
      row('第 3 步','VT 确实没收录才提交样本，然后等分析')+
      row('出结论后','立刻回传主服务器，样本字节立刻删除')+
      row('哈希在哪算','<span class="tag on">本节点</span>')+
      '<div class="note">先问主服务器是因为它的归档是本节点的超集（回传是单向的），'+
      '命中就等于白省一次 VT 配额。<br>'+
      '哈希不在浏览器里算，是因为这个仪表盘走明文 HTTP —— crypto.subtle 只在安全'+
      '上下文里存在。所以：<b>只在你信任这条链路时使用</b>。</div>')+
    '</div>';

  html+='<div class="sec">队列 <span class="qn" id="subcnt"></span></div>'+
    '<div id="subtbl"></div>';
  $('#body').innerHTML=html;

  var drop=$('#drop'), fs=$('#fs'), fd=$('#fd'), go=$('#gobtn'), clr=$('#clrbtn'),
      msg=$('#submsg');
  if(UP.submit===null) UP.submit=!!u.allow_submit;
  $('#dosub').addEventListener('change',function(e){ UP.submit=!!e.target.checked; });
  // 刷新发生在上传中途时,把按钮的禁用态与提示语按 UP 重建 —— 否则新按钮看起来可点,
  // 而真正在跑的那一轮 pump() 抓着的是上一份已经脱离文档的按钮。
  if(UP.active){
    go.disabled=true;
    msg.innerHTML='<span class="qn"><span class="spin"></span>正在上传，'+
      '下面的队列数据仍在实时刷新</span>';
  }

  /* ---- 服务端队列表 ---- */
  var SST={queued:'<span class="tag gray">排队</span>',
           checking:'<span class="tag mid"><span class="spin"></span>查询中</span>',
           vt_wait:'<span class="tag mid"><span class="spin"></span>等 VT 分析</span>',
           done:'<span class="tag on">已完成</span>',
           failed:'<span class="tag off">失败</span>',
           skipped:'<span class="tag gray">跳过</span>',
           expanding:'<span class="tag mid"><span class="spin"></span>解压中</span>',
           /* 压缩包本身不是样本,所以它没有「判定」也不会被提交 —— 它的终态就是
              「已解压」。用「已完成」表示会让人以为这个包被 VT 查过了。 */
           expanded:'<span class="tag on">已解压</span>'};
  var SRC={master:'主服务器',cache:'本地缓存',vt:'VirusTotal',
           degraded:'备用情报源'};
  /* 逐文件的回传状态。四种情况必须分开说,合并任何两种都会误导:
       主库确认  对端账本点名收到了 —— 最强的证据
       已推送    本端证据:入库时刻早于回传水位
       待回传    入库了但还没轮到(回传是异步触发的,最多等一轮)
       不需回传  没入库,所以没有东西要传(干净 / VT 未收录 / 还没出结论)
     把「不需回传」显示成「未回传」是最容易让人误判的一种 —— 那会让 36 个还在排队的
     文件看起来像 36 个回传失败。 */
  function back(it){
    if(it.master_new) return '<span class="tag on">主库确认</span>';
    if(it.sync_pushed) return '<span class="tag on">已推送</span>';
    if(it.stored_at) return '<span class="tag mid">待回传</span>';
    return '<span class="z">不需回传</span>';
  }
  var rows=items.map(function(it){
    var last=(it.history&&it.history.length)?it.history[it.history.length-1]:null;
    var vd = it.state!=='done' ? '<span class="z">-</span>'
      : it.verdict==='malicious' ? '<span class="tag off">恶意</span>'
      : it.verdict==='suspicious' ? '<span class="tag mid">可疑</span>'
      : it.verdict==='clean' ? '<span class="tag on">干净</span>'
      : '<span class="tag gray">未知</span>';
    var hit=(it.state==='done'&&it.total_engines)
      ? n(it.malicious)+' / '+n(it.total_engines) : '<span class="z">-</span>';
    var arc=String(it.kind||'').indexOf('archive:')===0;
    // 压缩包和「从压缩包里解出来的文件」是两种行,都要一眼能认出来:前者解释了后面
    // 那一批文件是从哪来的,后者解释了这个文件为什么没人手工上传过。
    var tag=arc
      ? ' <span class="tag mid" title="压缩包，已在服务端解压">压缩包 '+
        esc(String(it.kind).slice(8))+'</span>'+
        (it.archive_count?' <span class="qn">解出 '+n(it.archive_count)+' 个</span>':'')
      : (it.from_archive?' <span class="tag gray" title="来自压缩包 '+
         esc(it.from_archive.name||'')+'">来自压缩包</span>':'');
    return '<tr><td style="text-align:left">'+
        '<span class="fn" title="'+esc(it.path||it.name)+'">'+esc(it.name)+'</span>'+tag+
        (it.path?'<div class="qn mono">'+esc(it.path)+'</div>':'')+
        (it.degraded?' <span class="tag mid" title="'+esc(it.degraded_reason||'')+
          '">降级</span>':'')+'</td>'+
      '<td>'+sz(it.size)+'</td>'+
      '<td class="mono">'+(it.sha256?esc(String(it.sha256).slice(0,16)):'<span class="z">-</span>')+'</td>'+
      '<td>'+(SST[it.state]||esc(it.state))+'</td>'+
      '<td>'+vd+'</td><td>'+hit+'</td>'+
      '<td>'+(it.master_hit?'<span class="tag on">主库</span>'
              :esc(SRC[it.source]||it.source||'')||'<span class="z">-</span>')+'</td>'+
      '<td>'+(it.submitted?'<span class="tag on">已提交</span>'
              :it.vt_unknown?'<span class="tag mid">未收录</span>':'<span class="z">-</span>')+'</td>'+
      '<td>'+back(it)+'</td>'+
      '<td style="text-align:left">'+
        (esc(it.error)||esc(last?last.note:'')||'<span class="z">-</span>')+'</td>'+
      '<td class="mono qn">'+esc(String(it.at||'').slice(11,19))+'</td></tr>';
  }).join('');
  $('#subtbl').innerHTML=table(
    '<th>文件</th><th>大小</th><th>SHA-256</th><th>状态</th><th>结论</th>'+
    '<th>命中/引擎</th><th>结论来自</th><th>VT</th><th>回传主库</th>'+
    '<th>最近一步</th><th>上传</th>',
    rows,'还没有上传过文件',11);
  $('#subcnt').textContent=agg.total?
    ('共 '+agg.total+' 个 · 已完成 '+(agg.done||0)+' · 待查询 '+wait+
     ((agg.failed||0)?(' · 失败 '+agg.failed):'')):'';

  /* ---- 本次上传的进度(只画 UP,不碰服务端队列) ---- */
  function skiplist(title,arr,cls){
    if(!arr.length) return '';
    var show=arr.slice(0,40).map(function(x){
      return '<div class="qn mono" style="white-space:nowrap;overflow:hidden;'+
        'text-overflow:ellipsis" title="'+esc(x.path||x.name)+'">'+
        esc(x.path||x.name)+' <span class="'+cls+'">— '+esc(x.why)+'</span></div>';
    }).join('');
    return '<div style="margin-top:8px"><b class="qn">'+title+'</b>'+show+
      (arr.length>40?('<div class="qn">…还有 '+n(arr.length-40)+' 个</div>'):'')+
      '</div>';
  }
  function upaint(){
    var tot=UP.pend.length+UP.done+UP.fails.length;
    if(!tot&&!UP.skip.length){
      $('#upbar').innerHTML='<div class="z">还没有待上传的文件</div>';
      $('#uprow').innerHTML='';
      return;
    }
    var fin=UP.done+UP.fails.length;
    $('#upbar').innerHTML=tot?bar(fin,tot):'';
    $('#uprow').innerHTML=
      row('待上传',n(UP.pend.length)+' 个')+
      row('已送达',n(UP.done)+' 个'+(UP.sent?'（'+sz(UP.sent)+'）':''))+
      row('已跳过',UP.skip.length?'<span class="tag mid">'+n(UP.skip.length)+
          '</span>':'0')+
      row('上传失败',UP.fails.length?'<span class="bad">'+n(UP.fails.length)+
          '</span>':'0')+
      row('并发',n(LIM)+' 个连接')+
      (UP.msg?('<div class="note">'+UP.msg+'</div>'):'')+
      // 跳过的是哪几个必须逐个列出来。目录里混进一个超大文件或一个 0 字节文件是常事,
      // 只报数字等于让人自己去猜少传了什么。
      skiplist('跳过的文件（不会上传）',UP.skip,'tag mid')+
      skiplist('失败的文件（可重新添加再传）',UP.fails,'bad');
  }

  /* 文件夹拖放:DataTransferItem.webkitGetAsEntry 递归。input[webkitdirectory] 只
     解决「点击选择」，拖一个文件夹进来走的是另一条 API，两条都要接。 */
  function walkEntry(entry,base,out){
    return new Promise(function(res){
      if(!entry){ res(); return; }
      if(entry.isFile){
        entry.file(function(f){
          out.push({file:f,path:(base?base+'/':'')+f.name});
          res();
        },function(){ res(); });
        return;
      }
      if(entry.isDirectory){
        var rd=entry.createReader(), all=[];
        var step=function(){
          rd.readEntries(function(ents){
            if(!ents.length){
              Promise.all(all.map(function(e){
                return walkEntry(e,(base?base+'/':'')+entry.name,out);
              })).then(function(){ res(); });
              return;
            }
            all=all.concat(Array.prototype.slice.call(ents));
            step();                       // readEntries 一次不保证给全，要读到空
          },function(){ res(); });
        };
        step();
        return;
      }
      res();
    });
  }

  /* 目录里有不能传的文件时,【只跳过那一个】,整个目录照常继续 —— 一个 700 MB 的文件
     不该让旁边 499 个正常文件一起传不上去。跳过的原因逐个记下来给人看。 */
  function addPairs(pairs){
    var added=0, cap=u.max_mb*1048576;
    pairs.forEach(function(p){
      var rel=p.path||p.file.name;
      if(p.file.size>cap){
        UP.skip.push({name:p.file.name,path:rel,size:p.file.size,
          why:sz(p.file.size).replace(/<[^>]*>/g,'')+' 超过上限 '+n(u.max_mb)+' MB'});
        return;
      }
      // 0 字节的项要么是空文件、要么是某些浏览器给出的目录占位项。上一版直接静默丢掉,
      // 于是它们从目录里凭空消失、连一行说明都没有。
      if(p.file.size<=0){
        UP.skip.push({name:p.file.name,path:rel,size:0,why:'空文件（0 字节）'});
        return;
      }
      UP.pend.push({file:p.file,name:p.file.name,path:rel,size:p.file.size});
      added++;
    });
    var parts=[];
    if(added) parts.push('已加入 '+n(added)+' 个');
    if(UP.skip.length) parts.push('累计跳过 '+n(UP.skip.length)+' 个（见下）');
    UP.msg = parts.length ? '<span class="qn">'+parts.join(' · ')+'</span>' : '';
    upaint();
  }

  function addFiles(files){
    var arr=Array.prototype.slice.call(files||[]);
    addPairs(arr.map(function(f){
      // input[webkitdirectory] 把相对路径放在 webkitRelativePath
      return {file:f,path:f.webkitRelativePath||f.name};
    }));
  }

  var LIM=3;
  function sendOne(it){
    var url='/api/submit/file?name='+encodeURIComponent(it.name)+
            '&path='+encodeURIComponent(it.path||'')+
            '&submit='+(UP.submit?'1':'0');
    var code=0;
    return fetch(url,{method:'POST',cache:'no-store',body:it.file})
      .then(function(r){
        code=r.status;
        return r.json().catch(function(){
          return {ok:false,error:'服务端返回非 JSON (HTTP '+r.status+')'};});
      })
      .then(function(j){
        if(j.ok){ UP.done++; UP.sent+=it.size; return; }
        // 413 是服务端说「这个文件太大」。前端已经按 max_mb 筛过一遍,但服务端才是权威
        // (比如页面开着时上限被改小了),所以这里也归到【跳过】而不是失败 —— 重传它
        // 永远不会成功,混进失败里只会让人白试。
        if(code===413){
          UP.skip.push({name:it.name,path:it.path,size:it.size,
                        why:esc(j.error||'超过服务端上限')});
          return;
        }
        UP.fails.push({name:it.name,path:it.path,size:it.size,
          why:(code===507?'排队区/磁盘暂时放不下，稍后重试':'')||
              String(j.error||('上传失败 HTTP '+code))});
      })
      .catch(function(e){
        UP.fails.push({name:it.name,path:it.path,size:it.size,
                       why:String(e.message||'连接失败')});
      })
      .then(upaint);
  }

  function run(){
    if(UP.active) return;
    if(!UP.pend.length){
      msg.innerHTML='<span class="qn">没有待上传的文件</span>'; return;
    }
    UP.active=true; go.disabled=true; msg.textContent='';
    // 上传中锁住勾选框:一批文件必须整批用同一个决定,中途改会让同一批里一半提交、
    // 一半不提交,而提交是不可撤回的公开共享。
    var ck0=$('#dosub'); if(ck0) ck0.disabled=true;
    var active=0;
    // 每次都重新按 id 取,不用 run() 那一刻捕获的引用:页面在上传期间照常 5 秒一刷,
    // 捕获的节点早就被换掉了,往它上面写状态等于写进一个已经不在文档里的元素。
    function btn(){ return $('#gobtn'); }
    function tip(){ return $('#submsg'); }
    function pump(){
      if(!UP.pend.length&&active===0){
        UP.active=false;
        var b=btn(); if(b) b.disabled=false;
        var ck=$('#dosub'); if(ck&&u.allow_submit) ck.disabled=false;
        msg=tip()||msg;
        // 收尾话术要把跳过说清楚,否则「上传完毕」会让人以为整个目录都传上去了。
        var tail='';
        if(UP.skip.length) tail+='，跳过 '+n(UP.skip.length)+' 个';
        if(UP.fails.length) tail+='，失败 '+n(UP.fails.length)+' 个';
        msg.innerHTML='<span style="color:var(--green)">已送达 '+n(UP.done)+' 个'+
          esc(tail)+'</span><span class="qn">　查询在队列里进行，可以离开这一页</span>';
        upaint();
        load();                            // 立刻拉一次，让队列表把新文件显示出来
        return;
      }
      while(active<LIM&&UP.pend.length){
        active++;
        sendOne(UP.pend.shift()).then(function(){ active--; pump(); });
      }
    }
    pump();
  }

  drop.addEventListener('click',function(){ fs.click(); });
  $('#pickf').addEventListener('click',function(){ fs.click(); });
  $('#pickd').addEventListener('click',function(){ fd.click(); });
  fs.addEventListener('change',function(e){ addFiles(e.target.files); fs.value=''; });
  fd.addEventListener('change',function(e){ addFiles(e.target.files); fd.value=''; });
  ['dragenter','dragover'].forEach(function(ev){
    drop.addEventListener(ev,function(e){ e.preventDefault();
      drop.style.borderColor='var(--blue)'; drop.style.color='var(--ink)'; });
  });
  ['dragleave','drop'].forEach(function(ev){
    drop.addEventListener(ev,function(e){ e.preventDefault();
      drop.style.borderColor='var(--line)'; drop.style.color='var(--muted)'; });
  });
  drop.addEventListener('drop',function(e){
    var dt=e.dataTransfer; if(!dt) return;
    var its=dt.items, out=[], jobs=[];
    if(its&&its.length&&its[0].webkitGetAsEntry){
      for(var i=0;i<its.length;i++){
        var en=its[i].webkitGetAsEntry&&its[i].webkitGetAsEntry();
        if(en) jobs.push(walkEntry(en,'',out));
      }
      Promise.all(jobs).then(function(){
        if(out.length) addPairs(out);
        else if(dt.files&&dt.files.length) addFiles(dt.files);
      });
      return;
    }
    if(dt.files&&dt.files.length) addFiles(dt.files);
  });
  go.addEventListener('click',run);
  clr.addEventListener('click',function(){
    if(UP.active) return;
    // 连跳过/失败清单一起清:按钮写的是「清空」,只清一半会让人以为清失败了。
    // 服务端队列不受影响 —— 那是已经收下的文件,不归这个按钮管。
    UP.pend=[]; UP.skip=[]; UP.fails=[]; UP.msg=''; msg.textContent=''; upaint(); });
  upaint();
}

/* ---------- 白样本 ---------- */
function rBenign(d){
  var b=d.b||{}, p=d.p||{};
  nav({benign:b.total});
  var short = (b.usable_est||0) < (b.min_corpus||50);
  var html=title()+'<div class="kpi">'+
    kcard('g','语料样本',n(b.total),'已签名 '+n(b.signed)+' · 带沙箱行为 '+n(b.with_beh))+
    kcard(short?'y':'g','可用语料',n(b.usable_est),
          'Windows PE，门槛 '+n(b.min_corpus)+(short?'（未达标，区分度不参与定级）':'（已达标）'))+
    kcard(b.rejected?'r':'','复查拒绝',n(b.rejected),'已被 VT 追认为恶意并从语料删除')+
    kcard('','零配额放行',n(b.fast_tracked),'VT 早已收录且复扫过，跳过等待')+
    '</div>';

  html+='<div class="cols">'+
    box('隔离状态',
      row('待复查',n(b.pending))+
      row('已通过',n(b.verified))+
      row('已拒绝',b.rejected?'<span class="tag off">'+n(b.rejected)+'</span>':'0')+
      row('最早入库',esc(b.oldest)||'-')+row('最新入库',esc(b.newest)||'-')+
      '<div class="note">一个干净判定只代表当下。样本先隔离 24 小时再复查一次，'+
      '仍然干净才允许回传；期间被 VT 追认为恶意的当场从语料删除，并留下墓碑记录，'+
      '之后永不重新入册。</div>')+
    box('回传主服务器',
      row('今日推送',n(p.rows_today)+' 行 / '+n(p.today)+' 批')+
      row('累计推送',n(p.rows)+' 行 / '+n(p.pushes)+' 批')+
      row('主库已收',n(p.inserted)+' 条')+
      row('主库拒收',p.refused?'<span class="tag mid">'+n(p.refused)+'</span>':'0')+
      row('主库白样本总数',n(p.master_total))+
      row('最后成功',esc(p.last)||'-')+
      (p.fail?row('失败批次','<span class="tag off">'+n(p.fail)+'</span>'):'')+
      '<div class="mono">'+(esc(p.wm)||'-')+'</div>'+
      '<div class="note">主服务器侧还有独立的第二道防线：若它自己的威胁库已判该哈希为恶意，'+
      '直接拒收（上面的「主库拒收」）。两端看到的情报源不同，主库常常先知道。</div>')+
    box('拒绝原因分布',
      (function(){
        var r=b.reasons||{}, ks=Object.keys(r), s='';
        if(!ks.length) return '<div class="z">暂无拒绝记录</div>';
        for(var i=0;i<ks.length;i++) s+=row(esc(ks[i]),n(r[ks[i]]));
        return s;
      })()+
      '<div class="note">vt_flipped = 复查时 VT 已改判恶意/可疑；'+
      'local_threat_archive = 本地威胁库已有该哈希,不必再花配额。</div>')+
    '</div>';

  html+='<div class="sec">复查拒绝的样本（最近 60 条）</div>'+table(
    '<th>时间</th><th>名称</th><th>哈希</th><th>判定</th><th>检出</th><th>威胁名</th><th>原因</th>',
    (d.rejects||[]).map(function(r){
      return '<tr><td>'+esc(String(r.ts).slice(5,19))+'</td>'+
        '<td>'+esc(r.name||'-')+'</td>'+
        '<td class="mono">'+esc(String(r.sha256).slice(0,16))+'</td>'+
        '<td><span class="tag off">'+esc(r.verdict||'-')+'</span></td>'+
        '<td>'+n(r.malicious)+' / '+n(r.total_engines)+'</td>'+
        '<td>'+esc(r.threat_label||'-')+'</td>'+
        '<td>'+esc(r.reason||'-')+'</td></tr>';
    }).join(''),'暂无拒绝记录 —— 说明进入语料的样本至今都还是干净的',7);

  html+='<div class="sec">零配额放行的样本（最近 40 条）</div>'+table(
    '<th>时间</th><th>哈希</th><th>VT 收录</th><th>最近复扫</th><th>应答引擎</th><th>签名</th>',
    (d.fasts||[]).map(function(r){
      return '<tr><td>'+esc(String(r.ts).slice(5,19))+'</td>'+
        '<td class="mono">'+esc(String(r.sha256).slice(0,16))+'</td>'+
        '<td>'+n(r.age_days)+' 天</td>'+
        '<td>'+n(r.last_scan_days_ago)+' 天前</td>'+
        '<td>'+n(r.engines)+'</td>'+
        '<td>'+(r.signed?'<span class="tag on">已签名</span>':'<span class="z">无</span>')+
        '</td></tr>';
    }).join(''),'暂无零配额放行记录',6);

  html+='<div class="sec">复查作业执行记录</div>'+table(
    '<th>时间</th><th>零配额放行</th><th>复查通过</th><th>拒绝</th><th>其中免费</th>'+
    '<th>推迟</th><th>可回传总数</th><th>VT 已用</th>',
    (d.runs||[]).map(function(r){
      return '<tr><td>'+esc(String(r.ts).slice(5,19))+'</td>'+
        '<td>'+n(r.fast_tracked)+'</td><td>'+n(r.verified)+'</td>'+
        '<td>'+n(r.rejected)+'</td><td>'+n(r.free_rejects)+'</td>'+
        '<td>'+n(r.deferred)+'</td><td>'+n(r.exportable_total)+'</td>'+
        '<td>'+n(r.vt_used)+'</td></tr>';
    }).join(''),'暂无执行记录',8);

  $('#body').innerHTML=html;
}

var RENDER={home:rHome,queries:rQueries,queue:rQueue,
            downloads:rDownloads,uploads:rUploads,transfers:rTransfers,
            benign:rBenign,vtkeys:rVtkeys,submit:rSubmit};

/* ---------- motion plumbing ----------
   Nav links are real hrefs, so switching pages is a full document load. "Fresh"
   therefore just means the first load() of this document; everything after is the
   5-second poll. Entrance animation runs only on fresh, change-flash only on
   poll -- see the CSS comment for why replaying entrances would be unusable. */
var FIRST=true;
var PREV={};
var REDUCED = window.matchMedia &&
              window.matchMedia('(prefers-reduced-motion: reduce)').matches;

function countUp(el,target){
  if(REDUCED){ el.textContent=target.toLocaleString('en-US'); return; }
  var dur=520, t0=0;
  function step(ts){
    if(!t0) t0=ts;
    var p=Math.min(1,(ts-t0)/dur);
    var e=1-Math.pow(1-p,3);                       // ease-out cubic
    el.textContent=Math.round(target*e).toLocaleString('en-US');
    if(p<1) requestAnimationFrame(step);
    else el.textContent=target.toLocaleString('en-US');
  }
  requestAnimationFrame(step);
}

function afterRender(fresh){
  var body=$('#body');
  if(fresh && !REDUCED){
    // Re-adding the class is not enough on its own to restart CSS animations;
    // forcing a reflow between remove and add is what makes them replay.
    body.classList.remove('anim');
    void body.offsetWidth;
    body.classList.add('anim');
  }else{
    body.classList.remove('anim');
  }

  var nums=body.querySelectorAll('.k .num, .row b');
  for(var i=0;i<nums.length;i++){
    var el=nums[i], txt=el.textContent.trim(), key=CUR.k+':'+i, prev=PREV[key];
    if(fresh){
      // Count up only a bare formatted integer, and only when the cell holds no
      // markup: several cells render a <span class="tag">0</span> whose textContent
      // also looks like a number, and overwriting textContent would delete the tag.
      var m=txt.match(/^([\d,]+)$/);
      if(m && el.children.length===0){
        var v=parseInt(m[1].replace(/,/g,''),10);
        if(v>0 && v<1e9){ el.textContent='0'; countUp(el,v); }
      }
    }else if(prev!==undefined && prev!==txt){
      el.classList.remove('chg');
      void el.offsetWidth;
      el.classList.add('chg');
    }
    PREV[key]=txt;
  }
}

/* Live download progress. Polled on its own 1s timer, independent of the 5s
   whole-page refresh: a progress bar that only moved every five seconds would
   not be a progress bar. It keeps polling while idle (at a slower cadence) so a
   run that starts while the page is open appears on its own -- an earlier
   version stopped the timer on idle and the panel then stayed dead until the
   user navigated away and back. */
var LIVE_T=null, LIVE_BUSY=false, LIVE_IDLE_TICKS=0;
function startLiveProgress(){
  // Always repaint: the 5s refresh replaces #body, so the panel div is brand new
  // and empty every time, and waiting for the next tick would make it blink.
  updateLiveProgress();
  if(LIVE_T) return;                    // don't stack timers
  LIVE_T=setInterval(function(){
    // While idle, only actually poll every 5th tick.
    if(LIVE_IDLE_TICKS>0 && (LIVE_IDLE_TICKS%5)!==0){ LIVE_IDLE_TICKS++; return; }
    updateLiveProgress();
  },1000);
}
function stopLiveProgress(){
  if(LIVE_T){ clearInterval(LIVE_T); LIVE_T=null; }
}
function fmtDur(s){
  s=Math.max(0,Math.round(s||0));
  if(s<60) return s+' 秒';
  var m=Math.floor(s/60);
  if(m<60) return m+' 分 '+(s%60)+' 秒';
  return Math.floor(m/60)+' 小时 '+(m%60)+' 分';
}
var PHASES={starting:'启动中',enumerating:'解析归档索引',looking_up:'查询情报',
            downloading:'下载样本',uploading:'上传 VirusTotal',
            rate_wait:'限速等待'};
function rate(bps){
  // Auto-scaling matters here: this collector is paced to a couple of VT calls a
  // minute, so real figures land around a few hundred bytes per second and a
  // fixed MB/s display would read 0.00 for the entire run.
  bps=Number(bps||0);
  if(bps<=0) return '<span class="z">—</span>';
  if(bps<1024) return '<b>'+bps.toFixed(0)+'</b> B/s';
  if(bps<1048576) return '<b>'+(bps/1024).toFixed(1)+'</b> KB/s';
  return '<b>'+(bps/1048576).toFixed(2)+'</b> MB/s';
}
function pbar(pct,cls){
  // Reuses the quota bar markup so the live bars animate and theme identically.
  pct=Math.max(0,Math.min(100,pct||0));
  return '<div class="bar '+(cls||'')+'"><i style="width:'+pct.toFixed(1)+'%"></i></div>';
}
function updateLiveProgress(){
  var el=$('#live_progress');
  if(!el){ stopLiveProgress(); return; }
  if(LIVE_BUSY) return;                 // never let requests pile up
  LIVE_BUSY=true;
  fetch('/api/downloads/progress',{cache:'no-store'}).then(function(r){
    if(!r.ok) throw new Error('HTTP '+r.status);
    return r.json();
  }).then(function(p){
    if(!p.running){
      LIVE_IDLE_TICKS=1;
      var why = p.phase==='stale'
        ? '<span class="tag mid">上一轮未正常收尾</span> 最后进度 '+
          esc(p.slot||'')+' 第 '+n(p.done||0)+' 个，'+fmtDur(p.age_sec)+'前'
        : '<span class="z">当前没有采集任务在运行。定时器触发后这里会自动开始刷新。</span>';
      el.innerHTML='<div class="lphead">实时进度</div>'+why;
      return;
    }
    LIVE_IDLE_TICKS=0;
    var slotPct = p.slot_total ? 100*p.slot_done/p.slot_total : 0;
    var runPct  = p.cap ? 100*p.done/p.cap : 0;
    var waiting = p.phase==='rate_wait';
    var phase = PHASES[p.phase]||p.phase||'-';
    // Only claim a transfer rate while bytes are actually moving. During a
    // rate-limit wait the honest answer is "idle", not "0.00 MB/s".
    var speed = waiting ? '<span class="z">限速等待中</span>' : rate(p.speed_bps);
    el.innerHTML='<div class="lphead">实时进度 '+
        '<span class="tag '+(waiting?'gray':'on')+'">'+esc(phase)+'</span>'+
        (p.phase_detail?' <span class="z">'+esc(p.phase_detail)+'</span>':'')+
      '</div>'+
      '<div class="lpgrid">'+
        '<div><span class="z">网速</span><div class="lpv">'+speed+'</div></div>'+
        '<div><span class="z">已传输</span><div class="lpv">'+sz(p.bytes)+'</div></div>'+
        '<div><span class="z">平均</span><div class="lpv">'+rate(p.avg_bps)+'</div></div>'+
        '<div><span class="z">已用时</span><div class="lpv">'+fmtDur(p.elapsed_sec)+'</div></div>'+
        '<div><span class="z">本槽预计剩余</span><div class="lpv">'+
          (p.eta_sec!=null?fmtDur(p.eta_sec):'<span class="z">—</span>')+'</div></div>'+
        '<div><span class="z">归档槽</span><div class="lpv mono">'+esc(p.slot||'-')+'</div></div>'+
      '</div>'+
      '<div class="lprow"><span class="z">本槽进度</span> '+n(p.slot_done)+' / '+n(p.slot_total)+
        ' 个候选样本</div>'+pbar(slotPct)+
      '<div class="lprow"><span class="z">本轮上限</span> '+n(p.done)+' / '+n(p.cap)+
        ' 个（第 '+n(p.slot_index)+' / '+n(p.slot_count)+' 个归档）</div>'+pbar(runPct,'y')+
      // Per-file bar only while bytes are actually being pulled: outside the
      // download phase there is no file transfer to show and an idle bar reads
      // like a stall.
      (p.phase==='downloading'&&p.current_size
        ? '<div class="lprow"><span class="z">当前文件</span> '+sz(p.file_bytes)+
          ' / '+sz(p.current_size)+'</div>'+
          pbar(100*(p.file_bytes||0)/p.current_size,'r')
        : '')+
      '<div class="lpfile mono">'+(p.current_file?esc(p.current_file):'')+
        (p.current_size?' <span class="z">('+sz(p.current_size)+')</span>':'')+'</div>';
  }).catch(function(e){
    el.innerHTML='<div class="lphead">实时进度</div>'+
      '<span class="bad">进度读取失败：'+esc(e.message)+'</span>';
  }).then(function(){ LIVE_BUSY=false; });
}

function load(){
  var fresh=FIRST;
  FIRST=false;
  fetch(CUR.api,{cache:'no-store'}).then(function(r){
    if(!r.ok) throw new Error('HTTP '+r.status); return r.json();
  }).then(function(d){
    head(d); RENDER[CUR.k](d); afterRender(fresh);
    if(CUR.k==='downloads') startLiveProgress();
    else stopLiveProgress();
  }).catch(function(e){
    $('#err').innerHTML='<div class="err">读取失败：'+esc(e.message)+'</div>';
  });
}
nav(null);
var t=5;
setInterval(function(){
  t--;
  if(t<=0){
    t=5;
    // Never re-render underneath someone who is mid-typing: load() replaces the
    // whole body, which would wipe a partially entered API key.
    var a=document.activeElement;
    var typing = a && (a.tagName==='INPUT' || a.tagName==='TEXTAREA');
    var dirty = $('#nk') && $('#nk').value.trim() !== '';
    // 上传页【不再】因为正在上传而暂停刷新。
    //
    // 之前是暂停的,理由是 load() 会整块换掉 #body、抹掉勾选状态、并让 pump() 去操作
    // 已脱离文档的按钮。代价却是:传一个 400 MB 的目录要好几分钟,这几分钟里整个服务端
    // 那半边(6 张计数卡 + 队列表 + 顶栏时钟)全冻在上传开始前的那份「0」上,而且没有
    // 任何迹象说明它是旧的 —— 实测就是这样被读成「上传完了没动静」,而队列其实一直在跑。
    //
    // 现在的做法是把上传状态全部放进 UP(pend/skip/fails/done/submit),渲染完再按 UP
    // 重建按钮禁用态,pump() 也改成每次按 id 取节点。于是刷新在上传中途也是安全的。
    var staged = false;
    if(typing || dirty || staged){ $('#tick').textContent='暂停'; return; }
    load();
  }
  $('#tick').textContent=t;
},1000);
load();
</script></body></html>
"""

# Every route serves the same shell; the client picks the view from location.pathname,
# so there is no server-side templating to get wrong.
HTML_ROUTES = ("/", "/index.html", "/queries", "/queue", "/downloads", "/uploads",
               "/transfers", "/benign", "/vtkeys", "/submit")
API_ROUTES = {
    "/api/summary": v_summary,
    "/api/stats": v_summary,        # kept as an alias for anything already polling it
    "/api/queries": v_queries,
    "/api/queue": v_queue,
    "/api/downloads": lambda: v_files("download"),
    "/api/downloads/progress": v_downloads_progress,
    "/api/uploads": lambda: v_files("upload"),
    "/api/transfers": v_transfers,
    "/api/benign": v_benign,
    "/api/vtkeys": v_vtkeys,
    "/api/submit": v_upload,
}
# Write endpoints. Kept in their own table so the GET dispatcher can never reach
# them and a future read-only route can never accidentally become writable.
#   /api/vtkeys/add   small JSON body
#   /api/submit/file  raw sample bytes -- own body handling, see _do_submit
#   /api/vtkeys/remove  {"fp": "abc123"} -- 只排队,真正的判据在 root 侧
#   /api/vtkeys/probe   {} -- 让 root 侧立刻重探一次
POST_ROUTES = ("/api/vtkeys/add", "/api/vtkeys/remove", "/api/vtkeys/probe",
               "/api/submit/file")


class Handler(BaseHTTPRequestHandler):
    server_version = "bulwark-dash"

    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _authed(self):
        want = dash_token()
        if not want:
            return False
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer ") and auth[7:].strip() == want:
            return True
        for part in (self.headers.get("Cookie", "") or "").split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                if k.strip() == "bw_dash" and v.strip() == want:
                    return True
        return False

    def do_GET(self):
        path, _, query = self.path.partition("?")
        qs = dict(p.split("=", 1) for p in query.split("&") if "=" in p)
        if path == "/health":
            return self._send(200, {"status": "ok", "service": "bulwark-dash"})
        want = dash_token()
        if not want:
            return self._send(503, "dashboard token not configured; refusing to serve",
                              "text/plain; charset=utf-8")
        if qs.get("token") == want:
            # Swap the token for a cookie and bounce, so it stops riding along in
            # URLs (and in the Referer of any link) on every page navigation.
            dest = path if path in HTML_ROUTES else "/"
            return self._send(302, b"", "text/plain", extra=[
                ("Set-Cookie",
                 "bw_dash=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800" % want),
                ("Location", dest)])
        if not self._authed():
            return self._send(401, "unauthorized -- open /?token=YOURTOKEN once",
                              "text/plain; charset=utf-8")
        fn = API_ROUTES.get(path)
        if fn:
            try:
                return self._send(200, fn())
            except Exception as e:
                return self._send(500, {"error": "%s: %s" % (type(e).__name__, str(e)[:200])})
        if path in HTML_ROUTES:
            return self._send(200, PAGE, "text/html; charset=utf-8")
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        path, _, _ = self.path.partition("?")
        want = dash_token()
        if not want:
            return self._send(503, {"ok": False, "error": "dashboard token not configured"})
        # No ?token= handoff on POST: a token in a URL ends up in logs and
        # Referer headers, and a write endpoint is the last place that should
        # happen. The caller must already hold the cookie or send a Bearer header.
        if not self._authed():
            return self._send(401, {"ok": False, "error": "unauthorized"})
        if path not in POST_ROUTES:
            return self._send(404, {"ok": False, "error": "not found"})

        # 样本上传自己管请求体:它是原始字节、可以到几十 MB,而下面那条 4096 的上限是
        # 为「一把 64 字节的密钥」定的。两者共用一个读法必然要放宽那个上限,而放宽它
        # 等于让密钥端点也能收几十 MB —— 所以在这里分岔,各自守各自的尺寸。
        if path == "/api/submit/file":
            _, _, query = self.path.partition("?")
            qs = {}
            for p in query.split("&"):
                if "=" in p:
                    k, v = p.split("=", 1)
                    qs[k] = urllib.parse.unquote_plus(v)
            return self._do_submit(qs)

        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n <= 0 or n > 4096:      # a key is 64 bytes; anything larger is not one
            return self._send(400, {"ok": False, "error": "bad request body size"})
        try:
            body = json.loads(self.rfile.read(n).decode("utf-8", "replace"))
        except Exception:
            return self._send(400, {"ok": False, "error": "body must be JSON"})

        try:
            if path == "/api/vtkeys/remove":
                ok, msg = vtkey_remove(body.get("fp", ""))
            elif path == "/api/vtkeys/probe":
                ok, msg = vtkey_probe_now()
            else:
                ok, msg = vtkey_submit(body.get("key", ""))
        except Exception as e:
            return self._send(500, {"ok": False,
                                    "error": "%s: %s" % (type(e).__name__, str(e)[:200])})
        return self._send(200 if ok else 400, {"ok": ok, "message": msg})

    # 拒收一个请求之前要排掉的最大字节数。
    #
    # 为什么不是 0:请求体还在路上,一个字节都不读就回包并关连接,对端写不完就会收到 RST,
    # 于是客户端拿到的是「连接被重置」而不是那段解释原因的 JSON(Windows 上实测
    # ConnectionResetError / ConnectionAbortedError 两种都出现过)。一条本来能自解释的
    # 拒绝会变成看不懂的故障。
    # 为什么不是无限:读完才说「太大了」等于允许任何持令牌的人用磁盘把节点写满 ——
    # 而这台机器上还躺着情报库。所以只陪它走一小段;真正巨大的请求体宁可让它被重置。
    DRAIN_CAP = 262144

    def _drain(self, n):
        """有上限地排掉请求体,好让拒收的回包能被对端读到。返回实际排掉的字节数。"""
        drained = 0
        try:
            while drained < self.DRAIN_CAP and drained < n:
                chunk = self.rfile.read(min(65536, n - drained))
                if not chunk:
                    break
                drained += len(chunk)
        except Exception:
            pass
        return drained

    def _do_submit(self, qs):
        """收一个样本:流式落 inbox 边算哈希 -> 写一条排队记录 -> 立刻返回。

        这个请求【不再查询任何东西】。查询归 bulwark-submit.py:它每 3 分钟一轮,并且
        在记录落地的那一刻被 bulwark-submit.path 立刻唤醒一次。这样分工的理由:
          · 一个文件夹几百个文件,内联查询会把几百个浏览器连接挂住几小时(VT 在本节点
            被限速到每分钟两次)。
          · VT 没收录的样本要先提交再等分析,分析本身几分钟 —— 上传这一刻根本没有结论
            可回,内联就只能阻塞或者撒谎。
          · 切页面必须不丢进度。导航是真链接、整页重载,进度只有落在磁盘上才活得下来。

        为什么哈希还是在服务端算:这个仪表盘是明文 HTTP,浏览器里 crypto.subtle 在非
        安全上下文下压根不存在(app.py 那个控制台就是因此直接报「需要 HTTPS 才能本地
        算哈希」)。顺带少一条前端能算错的路。

        为什么每个文件一次请求:批量的并发与重试留给前端,服务端一次只处理一个文件。
        这样一个大文件失败不会带走整批,也不必在服务端实现 multipart 解析。
        """
        u = upload_cfg()
        if not u["enabled"]:
            return self._send(403, {"ok": False, "error": "送检功能已在配置里关闭"})
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        cap = u["max_mb"] * 1048576
        if n <= 0:
            return self._send(400, {"ok": False, "error": "空请求体"})
        if n > cap:
            self._drain(n)
            return self._send(413, {
                "ok": False,
                "error": "%.1f MB 超过上限 %d MB" % (n / 1048576.0, u["max_mb"])},
                extra=[("Connection", "close")])

        # 数量不设上限,但磁盘有。两道闸门都必须在【读之前】判,理由和上面的 413 一样。
        sp_bytes, _ = spool_bytes()
        if sp_bytes + n > u["spool_max_mb"] * 1048576:
            # 和 413 同样要先排一点再回,否则客户端拿到的是连接被重置、而不是这段说明
            # 「排队区满了」的 JSON。上一版只在 413 那条分支排空,于是把队列传满的人
            # 看到的是「连接失败」—— 一条本来能自解释的拒绝变成了看不懂的故障。
            self._drain(n)
            return self._send(507, {
                "ok": False,
                "error": "排队区已占用 %.0f MB,接近上限 %d MB;等队列消化后再传"
                         % (sp_bytes / 1048576.0, u["spool_max_mb"])},
                extra=[("Connection", "close")])
        # 真实空闲空间是最后一道,也是唯一一道不依赖配置写得对的:单文件能到 650 MB、
        # 数量又不限,只靠上面那个可配的字节上限,一个配错的值就能把情报库所在的盘写满。
        free = disk_free_mb()
        if free >= 0 and (free - n / 1048576.0) < u["disk_floor_mb"]:
            self._drain(n)
            return self._send(507, {
                "ok": False,
                "error": "磁盘只剩 %d MB,收下这个 %.0f MB 的文件会低于保留下限 %d MB"
                         % (free, n / 1048576.0, u["disk_floor_mb"])},
                extra=[("Connection", "close")])

        name = (qs.get("name") or "").strip()[:180]
        # 文件夹上传时前端会带相对路径。它只用于显示,所以做最保守的清洗:去掉盘符、
        # 反斜杠、`..`,永远不参与拼真实路径 —— 真实文件名由服务端生成的 id 决定。
        rel = (qs.get("path") or "").strip().replace("\\", "/")[:400]
        rel = "/".join(seg for seg in rel.split("/") if seg not in ("", ".", ".."))
        want_submit = (qs.get("submit") == "1") and u["allow_submit"]

        try:
            os.makedirs(SUBMIT_INBOX, exist_ok=True)
            os.makedirs(SUBMIT_STAGING, exist_ok=True)
        except OSError as e:
            return self._send(500, {"ok": False,
                                    "error": "排队目录不可写: %s" % str(e)[:120]})

        item_id = uuid.uuid4().hex
        blob_path = os.path.join(SUBMIT_INBOX, item_id + ".bin")
        # 写在 staging,不在 inbox —— 见 SUBMIT_STAGING 处的说明。
        part = os.path.join(SUBMIT_STAGING, item_id + ".bin.part")
        h = hashlib.sha256()
        got = 0
        try:
            # 边收边写、块大小固定 -> 峰值内存与文件大小无关。这是「不限数量」能成立的
            # 前提:旧实现把整个文件读进内存,一批就能把 MemoryMax 顶穿。
            with open(part, "wb") as f:
                while got < n:
                    chunk = self.rfile.read(min(1048576, n - got))
                    if not chunk:
                        break
                    got += len(chunk)
                    h.update(chunk)
                    f.write(chunk)
            if got != n:
                raise IOError("请求体不完整 (%d/%d 字节)" % (got, n))
            sha = h.hexdigest()
            os.replace(part, blob_path)
            rec = {
                "id": item_id, "at": now_utc().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "name": name or (rel.split("/")[-1] if rel else "sample.bin"),
                "path": rel, "size": got, "sha256": sha,
                "state": "queued", "want_submit": bool(want_submit),
                "verdict": "", "malicious": 0, "total_engines": 0,
                "threat_label": "", "source": "", "attempts": 0,
                "submitted": False, "vt_unknown": False, "master_hit": False,
                "error": "", "history": [{"at": now_utc().strftime("%Y-%m-%dT%H:%M:%SZ"),
                                          "from": "", "to": "queued", "note": "收到上传"}],
            }
            # 记录【最后写】:它的出现就是「这个文件已经完整落地」的信号,也是
            # bulwark-submit.path 的触发条件。先写记录再写字节会让 worker 看到一条
            # 指向半个文件的记录。
            tmp = os.path.join(SUBMIT_INBOX, item_id + ".json.tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(rec, f, ensure_ascii=False)
            os.replace(tmp, os.path.join(SUBMIT_INBOX, item_id + ".json"))
            return self._send(200, {"ok": True, "id": item_id, "sha256": sha,
                                    "size": got, "name": rec["name"],
                                    "path": rel, "state": "queued"})
        except Exception as e:
            for p in (part, blob_path):
                try:
                    if os.path.exists(p):
                        os.remove(p)
                except OSError:
                    pass
            return self._send(500, {"ok": False,
                                    "error": "%s: %s" % (type(e).__name__, str(e)[:200])})

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args), flush=True)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def get_request(self):
        s, a = self.socket.accept()
        s.settimeout(20)
        return s, a


def main():
    if not dash_token():
        print("WARNING: no token in %s -- all requests refused" % DASH_CONFIG, flush=True)
    print("bulwark-dash listening on http://%s:%d" % (LISTEN_HOST, LISTEN_PORT), flush=True)
    Server((LISTEN_HOST, LISTEN_PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
