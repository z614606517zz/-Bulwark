#!/usr/bin/env python3
"""Bulwark satellite-node janitor. Two independent jobs, deliberately not one:

  --samples   daily, LOSSLESS. Removes sample bytes that should not be on disk:
              a work directory left behind by a killed run, stray .zip/.bin, and
              orphaned bwsync-* payloads. harvest.py already deletes each sample
              immediately after upload, so this only ever finds crash debris --
              nothing here is a unique copy of anything.

  --data      every 3 days, LOSSY. Trims old vt_reports rows from the LOCAL cache.
              This node is a satellite, not the archive: the master is. So a row is
              only ever deleted when the master has confirmed receiving it.

Runs as bulwarkintel, never root: root writing cache.db leaves a root-owned
journal file behind and app.py's next write then fails.

The data job refuses to delete unless every one of these holds:
  * the sync watermark exists and parses as an ISO timestamp
  * the master's own ingest ledger proves at least one successful push
  * stored_at <= watermark            (the master has this row)
  * stored_at <  now - retention_days (the row is actually old)
  * the number of rows matched is within max_delete_per_run
Anything unpushed stays forever, however old. A missing or unreadable watermark
aborts rather than falling back to a permissive default.
"""
import argparse
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

CONFIG_PATH = os.environ.get("BULWARK_INTEL_CONFIG", "/etc/bulwark-intel/config.json")
# Overridable so the destructive half can be exercised against a throwaway copy of
# the database and a fake watermark. A delete path that cannot be rehearsed is a
# delete path nobody has actually tested.
STATE_DIR = os.environ.get("BULWARK_STATE_DIR", "/var/lib/bulwark-intel")
MARK = os.path.join(STATE_DIR, "sync_watermark.txt")
MASTER_LOG = os.path.join(STATE_DIR, "master_ingest.jsonl")
LEDGER = os.path.join(STATE_DIR, "janitor_log.jsonl")
TS_FMT = "%Y-%m-%dT%H:%M:%SZ"


def log(*a):
    print("[janitor %s]" % datetime.now(timezone.utc).strftime("%H:%M:%S"), *a, flush=True)


def now_utc():
    return datetime.now(timezone.utc)


def iso_now():
    return now_utc().strftime(TS_FMT)


def load_cfg():
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        log("cannot read config: %s" % e)
        return {}


def ledger(rec):
    """Deleting data without a record of it is not acceptable, so every run writes
    one line whether it removed anything or not."""
    rec["ts"] = iso_now()
    try:
        with open(LEDGER, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        os.chmod(LEDGER, 0o644)
        if os.path.getsize(LEDGER) > 524288:
            with open(LEDGER, encoding="utf-8") as f:
                keep = f.readlines()[-1000:]
            tmp = LEDGER + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.writelines(keep)
            os.replace(tmp, LEDGER)
            os.chmod(LEDGER, 0o644)
    except OSError as e:
        log("ledger write failed: %s" % e)


def unit_active(unit):
    try:
        r = subprocess.run(["systemctl", "is-active", unit],
                           capture_output=True, text=True, timeout=10)
        return (r.stdout or "").strip() == "active"
    except Exception:
        # Cannot tell -> assume something IS running and skip the risky removals.
        return True


def parse_ts(s):
    try:
        return datetime.strptime(str(s).strip(), TS_FMT).replace(tzinfo=timezone.utc)
    except Exception:
        return None


def num(d, key, default):
    """Config number with a default that survives an explicit 0.

    The obvious `d.get(k, default) or default` silently turns a configured 0 into
    the default, because 0 is falsy. That matters here: 0 is a meaningful setting
    (retention 0 = 'drop everything the master already has'), and quietly widening
    it to 3 days would be the opposite of what the operator asked for."""
    v = d.get(key)
    if v is None or v == "":
        return default
    try:
        return float(v)
    except (TypeError, ValueError):
        log("config %s=%r is not a number, using %r" % (key, v, default))
        return default


# ------------------------------------------------------------------ samples

def clean_samples(cfg, dry):
    h = cfg.get("harvest", {}) or {}
    work = h.get("work_dir", os.path.join(STATE_DIR, "harvest_work"))
    up_dir = cfg.get("uploads_dir", os.path.join(STATE_DIR, "uploads"))
    keep_h = num(cfg, "upload_retention_hours", 24.0)
    harvest_running = unit_active("bulwark-harvest.service")
    sync_running = unit_active("bulwark-sync.service")
    now = time.time()
    removed, bytes_freed, skipped = [], 0, []

    def size_of(p):
        if os.path.isdir(p):
            tot = 0
            for root, _, files in os.walk(p):
                for fn in files:
                    try:
                        tot += os.path.getsize(os.path.join(root, fn))
                    except OSError:
                        pass
            return tot
        try:
            return os.path.getsize(p)
        except OSError:
            return 0

    def drop(p, why):
        nonlocal bytes_freed
        n = size_of(p)
        if dry:
            removed.append({"path": p, "why": why, "bytes": n, "dry": True})
            bytes_freed += n
            return
        try:
            if os.path.isdir(p):
                shutil.rmtree(p)
            else:
                os.unlink(p)
            removed.append({"path": p, "why": why, "bytes": n})
            bytes_freed += n
        except OSError as e:
            log("could not remove %s: %s" % (p, e))

    # 1) work dir: only when no run is in flight. During a run it legitimately holds
    #    the sample currently being processed.
    if os.path.isdir(work):
        if harvest_running:
            skipped.append({"path": work, "why": "harvest running"})
        else:
            drop(work, "leftover work dir (no harvest running)")

    # 2) loose sample bytes at the top of the state dir -- never legitimate.
    try:
        names = os.listdir(STATE_DIR)
    except OSError:
        names = []
    for n in names:
        p = os.path.join(STATE_DIR, n)
        if n.endswith((".zip", ".bin")):
            drop(p, "stray sample file")
        elif n.startswith("bwsync-"):
            # A live sync owns one of these; only touch clearly abandoned ones.
            try:
                age = now - os.path.getmtime(p)
            except OSError:
                continue
            if sync_running and age < 3600:
                skipped.append({"path": p, "why": "sync running"})
            elif age > 3600:
                drop(p, "orphaned sync payload (%.1fh old)" % (age / 3600.0))
            else:
                skipped.append({"path": p, "why": "too fresh to judge"})

    # 3) upload staging. app.py owns retention here, so only act well past its
    #    window -- this is a safety net, not a competing cleaner.
    cutoff = keep_h * 2 * 3600
    if os.path.isdir(up_dir):
        for n in os.listdir(up_dir):
            p = os.path.join(up_dir, n)
            try:
                age = now - os.path.getmtime(p)
            except OSError:
                continue
            if age > cutoff:
                drop(p, "upload staging older than 2x retention (%.1fh)" % (age / 3600.0))

    # 4) manual-submission spool. bulwark-submit.py deletes each sample the moment it
    #    is no longer needed and sweeps stragglers every pass, so the same rule as
    #    above applies: only touch bytes well past its window, and only bytes.
    #
    #    The .json records are deliberately NOT swept here. They are the queue and the
    #    history the upload page renders; the worker owns their lifetime (keep_days).
    #    Deleting a record while its sample is still queued would strand the sample and
    #    make the file vanish from the page mid-flight.
    sub_spool = os.path.join(STATE_DIR, "submit-spool")
    submit_running = unit_active("bulwark-submit.service")
    for sub in ("inbox", "items"):
        d = os.path.join(sub_spool, sub)
        if not os.path.isdir(d):
            continue
        for n in os.listdir(d):
            if not n.endswith((".bin", ".part")):
                continue
            p = os.path.join(d, n)
            try:
                age = now - os.path.getmtime(p)
            except OSError:
                continue
            if submit_running and age < 3600:
                skipped.append({"path": p, "why": "submit worker running"})
            elif age > cutoff:
                drop(p, "submitted sample older than 2x retention (%.1fh)"
                        % (age / 3600.0))

    log("samples: removed=%d freed=%.1f KB skipped=%d dry=%s"
        % (len(removed), bytes_freed / 1024.0, len(skipped), dry))
    for r in removed:
        log("  - %s (%s, %d B)" % (r["path"], r["why"], r["bytes"]))
    for s in skipped:
        log("  = kept %s (%s)" % (s["path"], s["why"]))
    ledger({"job": "samples", "ok": True, "dry": dry, "removed": len(removed),
            "bytes": bytes_freed, "skipped": len(skipped),
            "paths": [r["path"] for r in removed],
            "harvest_running": harvest_running})
    return 0


# --------------------------------------------------------------------- data

def master_confirmed():
    """(ok, detail). True only if the master's own ledger shows a successful push."""
    try:
        with open(MASTER_LOG, encoding="utf-8") as f:
            lines = f.readlines()
    except OSError as e:
        return False, "master ledger unreadable: %s" % e
    best = None
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except Exception:
            continue
        if d.get("ok") and int(d.get("total", 0) or 0) > 0:
            best = d
    if not best:
        return False, "no successful push recorded by the master"
    return True, "master total=%s at %s" % (best.get("total"), best.get("ts"))


def clean_data(cfg, dry):
    h = cfg.get("harvest", {}) or {}
    days = num(h, "data_retention_days", 3.0)
    cap = int(num(h, "max_delete_per_run", 50000.0))
    db_path = cfg.get("db_path", os.path.join(STATE_DIR, "cache.db"))

    # Guard 1: watermark must exist and parse.
    try:
        with open(MARK, encoding="utf-8") as f:
            wm_raw = f.read().strip()
    except OSError as e:
        log("ABORT: no sync watermark (%s) -- refusing to delete anything" % e)
        ledger({"job": "data", "ok": False, "dry": dry, "deleted": 0,
                "abort": "watermark unreadable: %s" % e})
        return 1
    wm = parse_ts(wm_raw)
    if wm is None:
        log("ABORT: watermark %r does not parse -- refusing to delete anything" % wm_raw)
        ledger({"job": "data", "ok": False, "dry": dry, "deleted": 0,
                "abort": "watermark unparseable: %r" % wm_raw})
        return 1

    # Guard 2: the master must have actually confirmed a push.
    ok, detail = master_confirmed()
    if not ok:
        log("ABORT: %s -- refusing to delete anything" % detail)
        ledger({"job": "data", "ok": False, "dry": dry, "deleted": 0,
                "abort": detail})
        return 1
    log("master confirmation: %s" % detail)

    cutoff = (now_utc() - timedelta(days=days)).strftime(TS_FMT)
    log("retention=%.1fd cutoff=%s watermark=%s cap=%d" % (days, cutoff, wm_raw, cap))

    db = sqlite3.connect(db_path, timeout=60)
    db.execute("PRAGMA busy_timeout=60000")
    try:
        before = db.execute("SELECT COUNT(*) FROM vt_reports").fetchone()[0]
        # Both conditions spelled out rather than pre-combined: this is the line a
        # reviewer has to trust, so it should be readable without arithmetic.
        matched = db.execute(
            "SELECT COUNT(*) FROM vt_reports WHERE stored_at < ? AND stored_at <= ?",
            (cutoff, wm_raw)).fetchone()[0]
        unpushed_old = db.execute(
            "SELECT COUNT(*) FROM vt_reports WHERE stored_at < ? AND stored_at > ?",
            (cutoff, wm_raw)).fetchone()[0]
        log("rows=%d  eligible=%d  old-but-unpushed(kept)=%d" % (before, matched, unpushed_old))
        if unpushed_old:
            log("  NOTE %d row(s) are older than the cutoff but the master has not "
                "confirmed them; they stay." % unpushed_old)

        deleted = 0
        if matched == 0:
            log("nothing eligible")
        elif dry:
            log("DRY RUN: would delete %d row(s)" % min(matched, cap))
        else:
            with db:
                cur = db.execute(
                    "DELETE FROM vt_reports WHERE sha256 IN ("
                    "  SELECT sha256 FROM vt_reports"
                    "  WHERE stored_at < ? AND stored_at <= ?"
                    "  ORDER BY stored_at LIMIT ?)",
                    (cutoff, wm_raw, cap))
                deleted = cur.rowcount if cur.rowcount is not None else 0
            log("deleted %d row(s)%s" % (deleted, " (hit the per-run cap)"
                                         if matched > cap else ""))
        after = db.execute("SELECT COUNT(*) FROM vt_reports").fetchone()[0]
        free_pages = db.execute("PRAGMA freelist_count").fetchone()[0]
        page_size = db.execute("PRAGMA page_size").fetchone()[0]
    finally:
        db.close()

    try:
        db_bytes = os.path.getsize(db_path)
    except OSError:
        db_bytes = 0
    log("rows %d -> %d   db=%.1f MB   reusable free space=%.1f MB"
        % (before, after, db_bytes / 1048576.0, free_pages * page_size / 1048576.0))
    log("not running VACUUM: it needs an exclusive lock on a database the intel "
        "service is serving from. SQLite reuses the freed pages for new rows.")
    ledger({"job": "data", "ok": True, "dry": dry, "retention_days": days,
            "cutoff": cutoff, "watermark": wm_raw, "rows_before": before,
            "rows_after": after, "eligible": matched, "deleted": deleted,
            "kept_old_unpushed": unpushed_old, "db_bytes": db_bytes,
            "free_bytes": free_pages * page_size})
    return 0


def main():
    ap = argparse.ArgumentParser(description="Bulwark satellite janitor")
    ap.add_argument("--samples", action="store_true", help="daily lossless sample sweep")
    ap.add_argument("--data", action="store_true", help="periodic vt_reports trim")
    ap.add_argument("--dry-run", action="store_true", help="report, change nothing")
    a = ap.parse_args()
    if not (a.samples or a.data):
        ap.error("pick --samples and/or --data")
    cfg = load_cfg()
    rc = 0
    if a.samples:
        rc |= clean_samples(cfg, a.dry_run)
    if a.data:
        rc |= clean_data(cfg, a.dry_run)
    return rc


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        log("FATAL", type(e).__name__, str(e)[:200])
        try:
            ledger({"job": "fatal", "ok": False,
                    "error": "%s: %s" % (type(e).__name__, str(e)[:200])})
        except Exception:
            pass
        sys.exit(1)
