#!/usr/bin/env python3
"""Bulwark hourly MalwareBazaar -> VirusTotal harvester.

Pulls the most-recent MalwareBazaar samples (last hour), runs each hash through
the LOCAL bulwark-intel service (/vt/lookup) so the shared cache + permanent
vt_reports table get populated (threats only are persisted, per the service's
retention policy). Samples that VirusTotal does not know yet are downloaded
(abuse.ch get_file, AES zip, password 'infected'), extracted, submitted to VT
via /vt/upload, and then DELETED immediately. No sample binaries are kept.

Design notes:
  * Talks to the running service on loopback (https://127.0.0.1:8787) which is
    exempt from the public per-IP throttle; VT upstream quota is still enforced
    centrally by the service, so this can never blow the shared budget.
  * A state file dedups across runs so the same hash is not reprocessed hourly.
  * download_mode: 'unknown' (default) downloads only VT-unknown samples (the
    only ones whose binary we actually need, to upload); 'all' downloads every
    recent sample then deletes it; 'off' never downloads (lookup only).
  * Query pacing is a hard rate limit (queries_per_minute, default 4). Anything
    that does not fit in one run is PERSISTED TO A QUEUE and drained oldest-first
    on later runs. Before the queue existed, `fresh[:max_per_run]` silently threw
    the overflow away -- and because get_recent(selector='time') only looks back
    60 minutes, those hashes were gone for good.
  * Two append-only ledgers make the run observable to the dashboard without it
    needing journal access: harvest_queue.jsonl (what is waiting) and
    harvest_files.jsonl (which sample binaries were actually fetched/uploaded).
  * Everything is best-effort and capped: one bad sample never aborts the run.
"""

import fcntl
import json
import os
import shutil
import sqlite3
import ssl
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

CONFIG_PATH = os.environ.get("BULWARK_INTEL_CONFIG", "/etc/bulwark-intel/config.json")
MB_API = "https://mb-api.abuse.ch/api/v1/"

# Loopback to our own service: the TLS cert is for the public domain, so skip
# verification for 127.0.0.1 (loopback = no MITM surface).
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


def log(*a):
    print("[harvest %s]" % datetime.now(timezone.utc).strftime("%H:%M:%S"), *a, flush=True)


def single_instance(path="/var/lib/bulwark-intel/harvest.lock"):
    """Refuse to run twice at once.

    Returns the held fd on success, False when another run already owns the lock
    (caller should exit quietly), or None when no lock could be created at all
    (caller should proceed anyway).

    VtRate is per-process state, so two overlapping runs would each pace themselves
    at N/min and put 2N/min on VirusTotal -- silently breaking the one guarantee the
    rate limit exists to make. systemd already refuses to start a second instance of
    the unit, so this only covers the manual/ad-hoc path, which is exactly where the
    overlap tends to come from.

    The fd is deliberately leaked for the process lifetime: closing it releases the
    lock, and the kernel drops it on exit however we exit, including SIGKILL.
    """
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd = open(path, "a+")
    except OSError as e:
        # A lock we cannot even create must not be a reason to skip the harvest.
        log("cannot open lock %s (%s) -> continuing unlocked" % (path, e))
        return None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fd.seek(0)
        other = (fd.read(32) or "").strip()
        fd.close()
        log("another harvest run holds the lock (%s) -> exit; the rate limit is "
            "per-process, so overlapping runs would double the VT call rate"
            % (("pid " + other) if other else "pid unknown"))
        return False
    fd.seek(0)
    fd.truncate()
    fd.write(str(os.getpid()))
    fd.flush()
    return fd


class VtRate:
    """Sliding-window limiter over everything that reaches VirusTotal.

    Counts lookups AND uploads. A VT-unknown sample costs two upstream calls back
    to back, so pacing only the lookups let the upload that immediately followed
    slip past the per-minute limit -- the previous fixed-gap pacer could not see it
    at all.

    N calls per 60 s window naturally yields 'N back to back, then wait until the
    oldest one leaves the window', i.e. a burst of N followed by a pause, rather
    than a metronome. That is the intended shape."""

    def __init__(self, per_min, window=60.0):
        self.n = max(1, int(per_min))
        self.window = float(window)
        self.hits = []
        self.total = 0

    def acquire(self, what=""):
        while True:
            now = time.monotonic()
            self.hits = [t for t in self.hits if now - t < self.window]
            if len(self.hits) < self.n:
                self.hits.append(now)
                self.total += 1
                return
            wait = self.window - (now - self.hits[0]) + 0.05
            log("vt rate %d/%.0fs reached, waiting %.1fs%s"
                % (self.n, self.window, wait, (" for " + what) if what else ""))
            time.sleep(max(0.1, wait))


def day_age_days(sday, today):
    """How many days older than `today` a sample's day is. None when unknown."""
    if not sday:
        return None
    try:
        a = datetime.strptime(sday, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        b = datetime.strptime(today, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return (b - a).days
    except Exception:
        return None


def vt_remaining(cfg, reserve):
    """(remaining, cap, used) for today's shared VT allowance, or (None, ..) when it
    cannot be determined. Read-only against the service's DB -- the intel service is
    what actually meters this, so its counter is the authority, not ours."""
    vt = cfg.get("virustotal", {}) or {}
    keys = [k for k in (str(x).split(":")[0].strip() for x in (vt.get("api_keys") or []))
            if len(k) == 64]
    cap = int(vt.get("requests_per_day", 0) or 0) * max(1, len(keys))
    if cap <= 0:
        return None, 0, 0
    try:
        p = cfg.get("db_path", "/var/lib/bulwark-intel/cache.db")
        c = sqlite3.connect("file:%s?mode=ro" % p, uri=True, timeout=10)
        c.execute("PRAGMA busy_timeout=8000")
        row = c.execute("SELECT count FROM quota WHERE day=? AND source='VirusTotal'",
                        (utc_day(),)).fetchone()
        c.close()
        used = int(row[0]) if row and row[0] is not None else 0
    except Exception as e:
        log("could not read the VT quota counter (%s) -> not sizing the run by it" % e)
        return None, cap, 0
    return max(0, cap - used - max(0, reserve)), cap, used


def iso_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_cfg():
    with open(CONFIG_PATH) as f:
        return json.load(f)


def mb_post(data, timeout, auth):
    body = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(MB_API, data=body, headers={"Auth-Key": auth})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def get_recent(auth, selector, attempts=3):
    """Fetch recent samples; retry transient upstream failures, never raise.

    A single 5xx / 403 / timeout from the feed used to propagate out of main()
    and abort the whole hourly run, losing that hour's samples entirely.
    Now transient errors are retried with backoff and finally degrade to an
    empty list so the run completes cleanly.
    """
    delay = 5
    for i in range(1, attempts + 1):
        try:
            raw = mb_post({"query": "get_recent", "selector": selector}, 60, auth)
            d = json.loads(raw)
            if d.get("query_status") != "ok":
                log("get_recent status:", d.get("query_status"))
                return []
            return d.get("data") or []
        except Exception as e:
            log("get_recent attempt %d/%d failed: %s %s"
                % (i, attempts, type(e).__name__, str(e)[:120]))
            if i < attempts:
                time.sleep(delay)
                delay *= 2
    log("get_recent giving up after %d attempts -> no samples this run" % attempts)
    return []


def get_backfill(auth, tags, types, limit):
    """Older candidates, for when the last hour did not produce enough to spend the
    day's VT allowance.

    get_recent cannot help here: it only serves the last 60 minutes (selector=time)
    or the last 100 uploads. tag / file_type queries do return first_seen and reach
    much further back, so they are what the age window gets filtered against.
    Every source is best-effort -- one failing query must not cost us the others."""
    out, sources = [], 0
    for query, key, values in (("get_taginfo", "tag", tags),
                               ("get_file_type", "file_type", types)):
        for v in values:
            if not v:
                continue
            try:
                d = json.loads(mb_post({"query": query, key: v, "limit": str(limit)},
                                       60, auth))
            except Exception as e:
                log("backfill %s=%s failed: %s %s" % (key, v, type(e).__name__, str(e)[:80]))
                continue
            if d.get("query_status") != "ok":
                log("backfill %s=%s status=%s" % (key, v, d.get("query_status")))
                continue
            rows = d.get("data") or []
            out.extend(rows)
            sources += 1
            log("backfill %s=%s -> %d row(s)" % (key, v, len(rows)))
    log("backfill: %d source(s) answered, %d raw row(s)" % (sources, len(out)))
    return out


def download_sample(sha, dst_zip, auth):
    """Fetch the (AES) sample zip. Returns True if a real zip landed (not a JSON error)."""
    body = urllib.parse.urlencode({"query": "get_file", "sha256_hash": sha}).encode("utf-8")
    req = urllib.request.Request(MB_API, data=body, headers={"Auth-Key": auth})
    with urllib.request.urlopen(req, timeout=180) as r, open(dst_zip, "wb") as f:
        shutil.copyfileobj(r, f)
    with open(dst_zip, "rb") as f:
        return f.read(2) == b"PK"


# MalwareBazaar 的样本是 AES 加密 zip(密码 infected)。Python 标准库 zipfile 不支持 AES,
# 必须借外部解压器。可执行名在各发行版并不统一:Ubuntu 22.04 及以前的 p7zip-full 给的是 7z,
# 24.04 起真包改叫 7zip、有的镜像只给 7zz。所以【探测】而不是写死一个名字。
_EXTRACTOR = None
_EXTRACTOR_CHECKED = False


def find_extractor():
    """找一个可用的解压器;找不到返回 None。结果缓存,不必每个样本探一次。"""
    global _EXTRACTOR, _EXTRACTOR_CHECKED
    if _EXTRACTOR_CHECKED:
        return _EXTRACTOR
    _EXTRACTOR_CHECKED = True
    for name in ("7z", "7zz", "7za"):
        p = shutil.which(name)
        if p:
            _EXTRACTOR = p
            break
    return _EXTRACTOR


def extract(zip_path, outdir):
    exe = find_extractor()
    if not exe:
        # 明确抛出可读原因。别让它退化成 FileNotFoundError: '7z' —— 那行日志看不出
        # 「装个包就能修」,结果被当成偶发错误忽略了好几周。
        raise RuntimeError(
            "没有可用的解压器(找过 7z / 7zz / 7za)。MalwareBazaar 的样本是 AES 加密 zip,"
            "必须外部解压器。修法:apt-get install -y 7zip")
    os.makedirs(outdir, exist_ok=True)
    subprocess.run([exe, "x", "-pinfected", "-y", "-o" + outdir, zip_path],
                   check=True, capture_output=True)
    files = [os.path.join(outdir, x) for x in os.listdir(outdir)]
    return files[0] if files else None


def svc_lookup(base, sha):
    body = json.dumps({"hash": sha}).encode("utf-8")
    req = urllib.request.Request(base + "/vt/lookup", data=body,
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=180, context=_CTX) as r:
        return json.loads(r.read())


def svc_upload(base, path, sha):
    with open(path, "rb") as f:
        data = f.read()
    url = base + "/vt/upload?name=" + urllib.parse.quote(sha + ".bin")
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/octet-stream"}, method="POST")
    with urllib.request.urlopen(req, timeout=300, context=_CTX) as r:
        return json.loads(r.read())


def load_seen(path):
    try:
        with open(path) as f:
            return set(x.strip() for x in f if x.strip())
    except OSError:
        return set()


def save_seen(path, seen, cap=50000):
    items = list(seen)[-cap:]
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write("\n".join(items))
    os.replace(tmp, path)


def _chmod_readable(path):
    """Ledgers exist to be read by the dashboard service; never let a stray umask
    make them private."""
    try:
        os.chmod(path, 0o644)
    except OSError:
        pass


def load_queue(path):
    """Pending samples, oldest first. Malformed lines are dropped, not fatal."""
    out, seen_sha = [], set()
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
    except OSError:
        return out
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except Exception:
            continue
        sha = str(r.get("sha256", "")).lower()
        if len(sha) != 64 or sha in seen_sha:
            continue
        seen_sha.add(sha)
        out.append(r)
    return out


def save_queue(path, items, cap=5000):
    """Whole-file rewrite (atomic). Called after every item so a crash or a
    timer-kill mid-run cannot lose the backlog."""
    keep = items[:cap]
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            for r in keep:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        os.replace(tmp, path)
        _chmod_readable(path)
    except OSError as e:
        log("could not persist queue: %s" % e)


def append_file_log(path, rec, limit_bytes=524288, keep_lines=1000):
    """One line per sample whose binary we touched. This is the only record of
    WHICH files were downloaded -- the run summary only ever had counters."""
    rec["ts"] = iso_now()
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        _chmod_readable(path)
        if os.path.getsize(path) > limit_bytes:
            with open(path, encoding="utf-8") as f:
                tail = f.readlines()[-keep_lines:]
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.writelines(tail)
            os.replace(tmp, path)
            _chmod_readable(path)
    except OSError as e:
        log("could not persist file log: %s" % e)


def utc_day():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def sample_day(item):
    """The sample's own day, from MalwareBazaar's first_seen ('YYYY-MM-DD HH:MM:SS',
    UTC). Falls back to when we queued it. Returns '' when neither is usable -- the
    caller treats unknown as current rather than skipping, because losing a fresh
    sample to missing metadata is worse than fetching one stale binary."""
    fs = str(item.get("first_seen") or "")
    if len(fs) >= 10 and fs[4] == "-" and fs[7] == "-":
        return fs[:10]
    qa = str(item.get("queued_at") or "")
    if len(qa) >= 10 and qa[4] == "-" and qa[7] == "-":
        return qa[:10]
    return ""


def queue_record(s):
    """Normalise a MalwareBazaar feed entry down to what we need later. Storing
    the metadata now means the queue can be displayed (name/type/size) without
    re-querying the feed, which would not work anyway: get_recent only reaches
    back 60 minutes."""
    return {
        "sha256": str(s.get("sha256_hash", "")).lower(),
        "name": s.get("file_name") or "",
        "type": s.get("file_type") or "",
        "size": int(s.get("file_size") or 0),
        "sig": s.get("signature") or "",
        "first_seen": s.get("first_seen") or "",
        "queued_at": iso_now(),
    }


def load_upload_budget(path):
    """(utc_day, uploads_used_today). Rolls over automatically at UTC midnight."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    try:
        with open(path) as f:
            d = json.load(f)
        if d.get("day") == today:
            return today, max(0, int(d.get("used", 0)))
    except Exception:
        pass
    return today, 0


def save_upload_budget(path, day, used):
    tmp = path + ".tmp"
    try:
        with open(tmp, "w") as f:
            json.dump({"day": day, "used": used}, f)
        os.replace(tmp, path)
    except OSError as e:
        log("could not persist upload budget: %s" % e)


def is_vt_unknown(resp):
    if resp.get("ok"):
        return False
    err = str(resp.get("error", ""))
    return "404" in err or "\u65e0\u6b64\u6587\u4ef6" in err  # "无此文件"


def main():
    cfg = load_cfg()
    mb = cfg.get("malwarebazaar", {}) or {}
    auth = mb.get("auth_key", "")
    if not auth:
        log("no malwarebazaar auth_key configured -> abort")
        return 1

    h = cfg.get("harvest", {}) or {}
    # Take the lock before anything that spends quota. Exit 0 when another run owns
    # it: a skipped overlapping run is the correct outcome, not a failure, and a
    # non-zero exit here would mark the unit failed and suppress OnSuccess=sync.
    _lock = single_instance(h.get("lock_file", "/var/lib/bulwark-intel/harvest.lock"))
    if _lock is False:  # False = held by another run; None = no lock available, proceed
        return 0
    # env overrides (handy for manual/dry runs and the timer) take precedence over config.
    selector = os.environ.get("HARVEST_SELECTOR") or str(h.get("selector", "time"))  # 'time' = last 60 min
    max_run = int(os.environ.get("HARVEST_MAX") or h.get("max_per_run", 100))
    base = os.environ.get("HARVEST_SERVICE_URL") or h.get("service_url", "https://127.0.0.1:8787")
    state = h.get("state_file", "/var/lib/bulwark-intel/harvest_seen.txt")
    work = h.get("work_dir", "/var/lib/bulwark-intel/harvest_work")
    queue_path = h.get("queue_file", "/var/lib/bulwark-intel/harvest_queue.jsonl")
    files_path = h.get("file_log", "/var/lib/bulwark-intel/harvest_files.jsonl")
    dmode = os.environ.get("HARVEST_MODE") or str(h.get("download_mode", "unknown"))  # unknown | all | off
    upload_unknown = bool(h.get("upload_unknown", True))
    # Daily ceiling on VT uploads. 0 = uploads disabled entirely (lookup-only);
    # negative = no local ceiling, in which case the only limit is the shared VT
    # quota the intel service meters centrally, so we can never blow the budget by
    # removing this cap. Note `x or default` would eat a configured 0, hence the
    # explicit None check.
    _ub = os.environ.get("HARVEST_UPLOAD_BUDGET")
    if _ub is None:
        _ub = h.get("vt_upload_budget_per_day")
    upload_budget = 20 if _ub is None or _ub == "" else int(_ub)
    upload_unlimited = upload_budget < 0
    budget_path = h.get("upload_budget_state",
                        "/var/lib/bulwark-intel/harvest_upload_budget.json")
    # Hard query rate. queries_per_minute is authoritative; sleep_seconds stays as
    # the fallback so an old config keeps its previous pacing instead of silently
    # jumping to a faster rate.
    # VT calls per minute, covering lookups AND uploads. sleep_seconds stays as a
    # fallback only so an old config keeps roughly its previous pacing.
    qpm = os.environ.get("HARVEST_QPM")
    if qpm is None:
        qpm = h.get("queries_per_minute")
    if qpm is None or qpm == "":
        sl = float(os.environ.get("HARVEST_SLEEP") or h.get("sleep_seconds", 0) or 0)
        qpm = (60.0 / sl) if sl > 0 else 3
    rate = VtRate(float(qpm))
    # Wall-clock guard so a long queue drain cannot still be running when the
    # timer fires the next one.
    max_secs = float(os.environ.get("HARVEST_MAX_SECONDS") or h.get("max_run_seconds", 3000))
    # How old a sample may be for its binary to be worth fetching. 0 = today only.
    # The goal is to spend the whole daily VT allowance: today's samples come first,
    # and when the last hour did not produce enough to fill the allowance we reach
    # back up to this many days rather than leaving quota unused. The window gates
    # the download/upload step only, never the lookup -- the hash is already in hand
    # by then, so storing the report is free, while fetching the binary costs
    # abuse.ch bandwidth.
    max_age = int(os.environ.get("HARVEST_MAX_AGE_DAYS")
                  or h.get("download_max_age_days", 30))
    # Backfill sources. get_recent only reaches back one hour (selector=time) or the
    # last 100 samples, so older candidates have to come from tag / file_type
    # queries, which do return first_seen and reach back a long way.
    bf_tags = h.get("backfill_tags") or ["elf", "exe", "mirai", "AgentTesla", "RedLineStealer"]
    bf_types = h.get("backfill_file_types") or ["elf", "exe", "dll"]
    bf_limit = int(h.get("backfill_limit", 1000))
    # Leave a little VT headroom so an interactive lookup still works late in the day.
    vt_reserve = int(h.get("vt_reserve", 25))
    if os.environ.get("HARVEST_NO_STATE") == "1":  # dry runs: don't persist dedup state
        state = None
        queue_path = None

    os.makedirs(work, exist_ok=True)
    os.chmod(work, 0o700)
    seen = load_seen(state) if state else set()

    # Queue first (oldest backlog), then whatever the feed just published.
    queued = load_queue(queue_path) if queue_path else []
    queued = [r for r in queued if r.get("sha256") not in seen]
    known = set(r["sha256"] for r in queued)
    carried = len(queued)

    samples = get_recent(auth, selector)
    added = 0
    for s in samples:
        sha = str(s.get("sha256_hash", "")).lower()
        if len(sha) != 64 or sha in seen or sha in known:
            continue
        known.add(sha)
        queued.append(queue_record(s))
        added += 1

    # Report the extractor unconditionally, every run. Without it no VT-unknown
    # sample can be unpacked and uploaded, yet the failure used to surface only as a
    # single error line at unpack time while the run still reported "done" -- so
    # upload_budget could sit at 0 for weeks with nobody noticing.
    # Kept ASCII on purpose: this line is the alarm, and it has to stay readable in
    # journalctl on a host whose locale is not UTF-8.
    _ex = find_extractor()
    log("extractor " + (_ex if _ex else
        "MISSING -> VT-unknown samples cannot be unpacked or uploaded; "
        "fix with: apt-get install -y 7zip"))
    today_utc = utc_day()
    remaining, vt_cap, vt_used = vt_remaining(cfg, vt_reserve)
    # Size the run by what the shared VT allowance still has, so the day's quota
    # actually gets spent instead of being left on the table.
    target = max_run
    if remaining is not None:
        target = max(0, min(max_run, remaining))
        log("vt allowance %d/%d used, %d left after a %d reserve -> run targets %d call(s)"
            % (vt_used, vt_cap, remaining, vt_reserve, target))
    else:
        log("vt allowance unknown -> run capped by max_per_run=%d only" % max_run)
    log("recent=%d new=%d carried=%d queue=%d rate=%d/min(lookup+upload) mode=%s "
        "window=%dd upload_budget=%s"
        % (len(samples), added, carried, len(queued), rate.n, dmode, max_age,
           "unlimited" if upload_unlimited else upload_budget))

    # Today first: the queue is drained newest-first so fresh samples always get the
    # allowance before anything historical does.
    def _sort_key(r):
        return (sample_day(r) or "0000-00-00", str(r.get("first_seen") or ""))
    queued.sort(key=_sort_key, reverse=True)

    fresh_enough = len([r for r in queued
                        if (day_age_days(sample_day(r), today_utc) or 0) <= 0])
    if len(queued) < target and max_age > 0:
        log("only %d candidate(s) queued (%d from today) but the run can do %d -> "
            "reaching back up to %d day(s)" % (len(queued), fresh_enough, target, max_age))
        added_bf = 0
        ceiling = max(target * 2, target + 50)
        for s in get_backfill(auth, bf_tags, bf_types, bf_limit):
            sha = str(s.get("sha256_hash", "")).lower()
            if len(sha) != 64 or sha in seen or sha in known:
                continue
            rec = queue_record(s)
            age = day_age_days(sample_day(rec), today_utc)
            if age is None or age < 0 or age > max_age:
                continue
            known.add(sha)
            queued.append(rec)
            added_bf += 1
            if len(queued) >= ceiling:
                break
        log("backfill queued %d extra candidate(s), queue now %d" % (added_bf, len(queued)))
        queued.sort(key=_sort_key, reverse=True)
    if queue_path:
        save_queue(queue_path, queued)

    bday, used_today = load_upload_budget(budget_path)
    budget_warned = False
    log("vt uploads today: %d used, ceiling %s (%s)"
        % (used_today, "none (shared VT quota is the only limit)" if upload_unlimited
           else upload_budget, bday))

    st = {"looked": 0, "stored": 0, "unknown": 0, "downloaded": 0, "uploaded": 0,
          "upload_skipped": 0, "stale_skipped": 0, "errors": 0}
    deadline = time.monotonic() + max_secs if max_secs > 0 else None
    processed = 0
    stop = ""

    while queued:
        if processed >= max_run:
            stop = "max_per_run"
            break
        if remaining is not None and rate.total >= remaining:
            stop = "vt_quota"
            break
        if deadline and time.monotonic() >= deadline:
            stop = "time_budget"
            break

        item = queued.pop(0)
        sha = item.get("sha256", "")
        processed += 1
        wdir = os.path.join(work, sha[:16])
        fl = None
        # Derived from feed metadata alone, so compute before the lookup: every
        # ledger path (including the error path) can then report the age gate.
        sday = sample_day(item)
        sage = day_age_days(sday, today_utc)
        # Unknown day counts as in-window: better to fetch one stale binary than
        # to silently drop a fresh sample whose feed metadata was missing.
        in_window = sage is None or (0 <= sage <= max_age) or sage < 0
        try:
            rate.acquire("lookup " + sha[:12])
            resp = svc_lookup(base, sha)
            st["looked"] += 1
            if resp.get("ok") and resp.get("stored"):
                st["stored"] += 1
            unknown = is_vt_unknown(resp)
            if unknown:
                st["unknown"] += 1

            can_upload = upload_unknown and (upload_unlimited or used_today < upload_budget)
            if unknown and upload_unknown and not can_upload:
                st["upload_skipped"] += 1
                fl = {"sha256": sha, "name": item.get("name", ""), "type": item.get("type", ""),
                      "size": item.get("size", 0), "sig": item.get("sig", ""),
                      "day": sday, "vt_unknown": True, "downloaded": False, "uploaded": False,
                      "skipped_budget": True}
                if not budget_warned:
                    log("vt upload budget spent (%d/%d) -> lookup-only for the rest of today"
                        % (used_today, upload_budget))
                    budget_warned = True
            elif unknown and not in_window:
                # Worth a ledger line: otherwise a sample silently gets a report but
                # never a binary, and the downloads page cannot explain the gap.
                st["stale_skipped"] += 1
                fl = {"sha256": sha, "name": item.get("name", ""), "type": item.get("type", ""),
                      "size": item.get("size", 0), "sig": item.get("sig", ""),
                      "day": sday, "vt_unknown": True, "downloaded": False, "uploaded": False,
                      "skipped_budget": False, "skipped_stale": True}
                log("older than the %dd window (%s, %s d) -> lookup only, no download %s"
                    % (max_age, sday, sage, sha[:12]))

            # In 'unknown' mode the binary is only fetched so it can be uploaded,
            # so once the budget is gone skip the download too (saves abuse.ch
            # bandwidth and local disk churn as well as VT quota).
            want_dl = ((dmode == "all") or (dmode == "unknown" and unknown and can_upload)) \
                and in_window
            if want_dl:
                os.makedirs(wdir, exist_ok=True)
                zp = os.path.join(wdir, "s.zip")
                fl = {"sha256": sha, "name": item.get("name", ""), "type": item.get("type", ""),
                      "size": item.get("size", 0), "sig": item.get("sig", ""),
                      "day": sday, "vt_unknown": unknown, "downloaded": False,
                      "uploaded": False, "skipped_budget": False}
                if download_sample(sha, zp, auth):
                    st["downloaded"] += 1
                    fl["downloaded"] = True
                    fl["zip_kb"] = round(os.path.getsize(zp) / 1024.0, 1)
                    if unknown and can_upload:
                        binf = extract(zp, os.path.join(wdir, "ex"))
                        if binf:
                            # An upload is a VT call too, and it lands moments after
                            # the lookup for the same sample -- without its own slot
                            # the pair would exceed the per-minute limit.
                            rate.acquire("upload " + sha[:12])
                            up = svc_upload(base, binf, sha)
                            st["uploaded"] += 1
                            used_today += 1
                            fl["uploaded"] = True
                            fl["upload_ok"] = bool(up.get("ok"))
                            save_upload_budget(budget_path, bday, used_today)
                            log("uploaded unknown %s ok=%s (%d uploaded today, ceiling %s)"
                                % (sha[:12], up.get("ok"), used_today,
                                   "none" if upload_unlimited else upload_budget))
                else:
                    fl["zip_bad"] = True
                    log("get_file not-a-zip %s" % sha[:12])
            seen.add(sha)
        except Exception as e:
            st["errors"] += 1
            if fl is not None:
                fl["error"] = "%s: %s" % (type(e).__name__, str(e)[:100])
            log("error %s %s %s" % (sha[:12], type(e).__name__, str(e)[:120]))
        finally:
            shutil.rmtree(wdir, ignore_errors=True)  # delete sample immediately
            if fl is not None:
                # Stamped in one place so every ledger line can explain the age
                # gate the same way, instead of each branch remembering to add it.
                fl["age_days"] = sage
                fl["in_window"] = in_window
                fl["window_days"] = max_age
                append_file_log(files_path, fl)
            # Persist the shrinking backlog every item: the queue is the only
            # place these hashes still exist.
            if queue_path:
                save_queue(queue_path, queued)

    if state:
        save_seen(state, seen)
    if queue_path:
        save_queue(queue_path, queued)
    # belt-and-suspenders: leave no sample bytes behind
    shutil.rmtree(work, ignore_errors=True)
    st["upload_budget"] = ("%d/unlimited" % used_today if upload_unlimited
                           else "%d/%d" % (used_today, upload_budget))
    st["queued"] = len(queued)
    st["rate_per_min"] = rate.n
    st["vt_calls"] = rate.total
    st["max_age_days"] = max_age
    if remaining is not None:
        st["vt_left"] = max(0, remaining - rate.total)
    if stop:
        st["stopped_by"] = stop
        log("stopped by %s -> %d still queued for the next run" % (stop, len(queued)))
    log("done", json.dumps(st))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        log("FATAL", type(e).__name__, str(e)[:200])
        sys.exit(1)
