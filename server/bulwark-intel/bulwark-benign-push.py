#!/usr/bin/env python3
"""Push quarantine-cleared white samples to the master node.

The master address comes from BULWARK_MASTER with no literal fallback -- this file
is public, so a baked-in host would leak infrastructure and could also send data to
an unintended place if a unit file forgets the variable.

Only rows that bulwark-benign-verify.py has marked verified_at leave this node: a
sample that has merely been *seen* clean once is never exported. See that script's
header for why a single clean verdict is not trustworthy.

Watermark is INCLUSIVE (verified_at >= mark), matching bulwark-sync.py: verified_at
has 1-second resolution, so '>' would silently drop rows sharing the boundary
second. Re-sending costs nothing because the master ingests with INSERT OR IGNORE.
The mark only advances after the master answers OK.

RUNS AS ROOT, AND THEREFORE MUST NOT WRITE cache.db.
cache.db is journal_mode=delete: a root-owned journal file beside it makes app.py's
next write fail (app.py runs as bulwarkintel). So this script opens the database
read-only via a mode=ro URI -- not merely "only issues SELECTs", but actually
incapable of writing -- and keeps all of its own state in its watermark and ledger
files. Marking rows as exported is deliberately NOT done here; the watermark is the
export cursor precisely so that no DB write is needed on this side.
"""
import gzip
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

DB = os.environ.get("BULWARK_DB", "/var/lib/bulwark-intel/cache.db")
MARK = os.environ.get("BULWARK_BENIGN_MARK",
                      "/var/lib/bulwark-intel/benign_sync_watermark.txt")
LEDGER = os.environ.get("BULWARK_BENIGN_SYNC_LOG",
                        "/var/lib/bulwark-intel/benign_sync_log.jsonl")
MASTER = os.environ.get("BULWARK_MASTER", "")
# Same key and same forced-command channel as bulwark-sync.py; the master's
# wrapper dispatches on SSH_ORIGINAL_COMMAND, so no new credential is introduced.
KEY = os.environ.get("BULWARK_SYNC_KEY", "/root/.ssh/id_sync23")
REMOTE_CMD = os.environ.get("BULWARK_BENIGN_REMOTE_CMD", "ingest-benign")
LIMIT = int(os.environ.get("BULWARK_BENIGN_PUSH_LIMIT", "2000"))
EPOCH = "1970-01-01T00:00:00Z"

# 245 predates the has_behaviour column, so it is not in this list. The master
# derives that flag from report.behaviour_available on ingest.
COLS = ("sha256", "stored_at", "type_tag", "name", "signed", "markers", "report")


def log(*a):
    print("[benign-push %s]" % datetime.now(timezone.utc).strftime("%H:%M:%S"),
          *a, flush=True)


def read_mark():
    try:
        v = open(MARK).read().strip()
        return v or EPOCH
    except OSError:
        return EPOCH


def write_mark(v):
    tmp = MARK + ".tmp"
    open(tmp, "w").write(v)
    os.replace(tmp, MARK)


def _i(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def ledger(rec):
    """Mode 644 on purpose: this runs as root while the dashboard runs as
    bulwarkintel and would otherwise have no way to see these runs at all."""
    rec["ts"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
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


def ssh_args(cmd):
    return ["ssh", "-T", "-i", KEY, "-o", "IdentitiesOnly=yes",
            "-o", "BatchMode=yes", "-o", "ConnectTimeout=20",
            "-o", "StrictHostKeyChecking=accept-new", MASTER, cmd]


def main():
    # No baked-in fallback host (see module docstring), so an ssh with an empty
    # destination is the failure mode to guard against. Checked before opening the
    # database so a misconfigured unit fails identically on every tick.
    if not MASTER.strip():
        log("BULWARK_MASTER is not set -- refusing to push. Set it in the systemd "
            "unit, e.g. Environment=BULWARK_MASTER=root@master.example")
        return 2
    mark = read_mark()
    # mode=ro: cannot create a journal even if a stray write were attempted.
    db = sqlite3.connect("file:%s?mode=ro" % DB, uri=True, timeout=30)
    db.execute("PRAGMA busy_timeout=30000")
    try:
        # verified_at rides along as a trailing column and is stripped before
        # serialising. Fetching it in a second query would risk the two result
        # sets disagreeing about which rows the LIMIT covered.
        rows = db.execute(
            "SELECT %s, q.verified_at FROM benign_reports b "
            "JOIN benign_quarantine q ON q.sha256=b.sha256 "
            "WHERE q.verified_at<>'' AND q.rejected_at='' AND q.verified_at>=? "
            "ORDER BY q.verified_at LIMIT ?"
            % ",".join("b." + c for c in COLS), (mark, LIMIT)).fetchall()
        total_ver = db.execute(
            "SELECT COUNT(*) FROM benign_quarantine WHERE verified_at<>'' "
            "AND rejected_at=''").fetchone()[0]
    except sqlite3.Error as e:
        log("read failed (has verify run yet? benign_quarantine may not exist): %s" % e)
        return 1
    finally:
        db.close()

    log("watermark=%s verified_total=%d candidates=%d" % (mark, total_ver, len(rows)))
    if not rows:
        log("nothing to push")
        return 0

    newest = max((r[len(COLS)] or EPOCH) for r in rows)
    fd, path = tempfile.mkstemp(prefix="bwbenign-", suffix=".jsonl.gz",
                                dir="/var/lib/bulwark-intel")
    os.close(fd)
    kb = 0.0
    try:
        with gzip.open(path, "wt", encoding="utf-8", compresslevel=6) as gz:
            for r in rows:
                gz.write(json.dumps(dict(zip(COLS, r[:len(COLS)])),
                                    ensure_ascii=False) + "\n")
        kb = os.path.getsize(path) / 1024.0
        log("payload %d rows, %.1f KB gzipped, newest_verified=%s"
            % (len(rows), kb, newest))
        with open(path, "rb") as f:
            p = subprocess.run(ssh_args(REMOTE_CMD), stdin=f,
                               capture_output=True, timeout=900)
        out = (p.stdout or b"").decode("utf-8", "replace").strip()
        if p.returncode != 0 or not out.startswith("OK"):
            err = (p.stderr or b"").decode("utf-8", "replace")[:200]
            log("push FAILED rc=%d out=%r err=%r" % (p.returncode, out[:200], err))
            ledger({"ok": False, "rows": len(rows), "kb": round(kb, 1),
                    "newest_verified": newest, "master": MASTER,
                    "error": (out[:120] or err[:120] or "rc=%d" % p.returncode)})
            log("watermark left at %s so this range retries next run" % mark)
            return 1
        log("master says: %s" % out)
        st = dict(kv.split("=", 1) for kv in out.split()[1:] if "=" in kv)
        ledger({"ok": True, "rows": len(rows), "kb": round(kb, 1),
                "received": _i(st.get("received")), "inserted": _i(st.get("inserted")),
                "skipped": _i(st.get("skipped")), "malformed": _i(st.get("malformed")),
                "master_benign_total": _i(st.get("total")),
                "newest_verified": newest, "master": MASTER})
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass

    write_mark(newest)
    log("watermark advanced to %s" % newest)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        log("FATAL", type(e).__name__, str(e)[:200])
        sys.exit(1)
