#!/usr/bin/env python3
"""Receive quarantine-cleared white samples (gzip JSONL on stdin) from a collector
node and merge them into this master's benign_reports.

Counterpart of bulwark-benign-push.py on node 245. Reached only through the forced
command in root's authorized_keys, which matches SSH_ORIGINAL_COMMAND exactly and
drops to bulwarkintel before exec'ing this -- that key cannot get a shell, and root
never writes cache.db (journal_mode=delete would leave a root-owned journal and
break app.py's next write).

INSERT OR IGNORE, like bulwark-ingest.py: a satellite may add white samples we lack,
never overwrite ours.

stdout is the reply protocol -- the pusher checks startswith("OK") and parses the
k=v pairs. NOTHING else may go to stdout; diagnostics go to stderr.

SECOND LINE OF DEFENCE
----------------------
The sending node already quarantined each sample for 24h and rechecked it, but this
side refuses any hash that THIS master's threat archive already calls malicious or
suspicious. The two sides see different feeds, so the master frequently knows about
a flip before the collector does. Without this check, one satellite could refill the
corpus with the exact malware that was just purged from it (51 of 64 rows on this
box were malware that nothing ever rechecked).
"""
import gzip
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone

DB = os.environ.get("BULWARK_DB", "/var/lib/bulwark-intel/cache.db")
LEDGER = os.environ.get("BULWARK_BENIGN_INGEST_LOG",
                        "/var/lib/bulwark-intel/benign_ingest_log.jsonl")
COLS = ("sha256", "stored_at", "type_tag", "name", "signed", "markers",
        "report", "has_behaviour")
MAX_ROWS = int(os.environ.get("BULWARK_BENIGN_MAX_ROWS", "20000"))
MAX_BYTES = int(os.environ.get("BULWARK_BENIGN_MAX_BYTES", str(128 * 1024 * 1024)))
# One slim report is a few KB; anything far past that is not a slim report.
MAX_REPORT_CHARS = int(os.environ.get("BULWARK_BENIGN_MAX_REPORT_CHARS", "262144"))
MAX_LOG_SHAS = int(os.environ.get("BULWARK_BENIGN_LOG_SHAS", "500"))

BENIGN_DDL = ("CREATE TABLE IF NOT EXISTS benign_reports ("
              "sha256 TEXT PRIMARY KEY, stored_at TEXT, type_tag TEXT, name TEXT, "
              "signed INTEGER DEFAULT 0, markers INTEGER DEFAULT 0, report TEXT, "
              "has_behaviour INTEGER DEFAULT 0)")
HEXSET = set("0123456789abcdef")


def peer():
    parts = os.environ.get("SSH_CONNECTION", "").split()
    return parts[0] if parts else ""


def ledger(rec):
    rec["ts"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        with open(LEDGER, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        os.chmod(LEDGER, 0o644)
        if os.path.getsize(LEDGER) > 2 * 1024 * 1024:
            with open(LEDGER, encoding="utf-8") as f:
                keep = f.readlines()[-2000:]
            tmp = LEDGER + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.writelines(keep)
            os.replace(tmp, LEDGER)
            os.chmod(LEDGER, 0o644)
    except OSError as e:
        print("ledger write failed: %s" % e, file=sys.stderr)


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def main():
    raw = sys.stdin.buffer.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        print("ERR too large", file=sys.stderr)
        ledger({"ok": False, "peer": peer(), "error": "too large", "bytes": len(raw)})
        return 2
    if not raw:
        print("OK received=0 inserted=0 skipped=0 malformed=0 threat_refused=0 total=0")
        ledger({"ok": True, "peer": peer(), "received": 0, "inserted": 0,
                "skipped": 0, "malformed": 0, "threat_refused": 0, "empty": True})
        return 0
    try:
        text = gzip.decompress(raw).decode("utf-8")
    except Exception as e:
        print("ERR not gzip: %s" % e, file=sys.stderr)
        ledger({"ok": False, "peer": peer(),
                "error": "not gzip: %s" % str(e)[:100], "bytes": len(raw)})
        return 2

    parsed, bad = [], 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
            sha = str(d.get("sha256", "")).lower()
            if len(sha) != 64 or any(c not in HEXSET for c in sha):
                bad += 1
                continue
            rep = d.get("report") or ""
            if not isinstance(rep, str):
                rep = json.dumps(rep, ensure_ascii=False)
            if len(rep) > MAX_REPORT_CHARS:
                bad += 1
                continue
            # has_behaviour is not a column on the older collector schema, so derive
            # it from the slim report. engine_build.collect_benign filters on this;
            # defaulting it to 1 would smuggle un-sandboxed rows into the corpus and
            # deflate every occurrence rate computed from it.
            hb = d.get("has_behaviour")
            if hb is None:
                try:
                    hb = 1 if (json.loads(rep) or {}).get("behaviour_available") else 0
                except Exception:
                    hb = 0
            parsed.append((sha, str(d.get("stored_at") or ""),
                           str(d.get("type_tag") or ""), str(d.get("name") or ""),
                           _int(d.get("signed")), _int(d.get("markers")),
                           rep, 1 if hb else 0))
        except Exception:
            bad += 1
        if len(parsed) >= MAX_ROWS:
            break

    db = sqlite3.connect(DB, timeout=60)
    db.execute("PRAGMA busy_timeout=60000")
    with db:
        db.execute(BENIGN_DDL)
    cols = [r[1] for r in db.execute("PRAGMA table_info(benign_reports)")]
    if "has_behaviour" not in cols:
        with db:
            db.execute("ALTER TABLE benign_reports ADD COLUMN "
                       "has_behaviour INTEGER DEFAULT 0")

    shas = [r[0] for r in parsed]

    # Refuse anything our own threat archive already condemns (see header).
    condemned = set()
    try:
        for i in range(0, len(shas), 400):
            chunk = shas[i:i + 400]
            condemned.update(x[0] for x in db.execute(
                "SELECT sha256 FROM vt_reports WHERE sha256 IN (%s) "
                "AND verdict IN ('malicious','suspicious')"
                % ",".join("?" * len(chunk)), chunk))
    except sqlite3.Error as e:
        print("threat pre-scan failed: %s" % e, file=sys.stderr)

    rows = [r for r in parsed if r[0] not in condemned]

    have = set()
    try:
        keep_shas = [r[0] for r in rows]
        for i in range(0, len(keep_shas), 400):
            chunk = keep_shas[i:i + 400]
            have.update(x[0] for x in db.execute(
                "SELECT sha256 FROM benign_reports WHERE sha256 IN (%s)"
                % ",".join("?" * len(chunk)), chunk))
    except sqlite3.Error as e:
        print("pre-scan failed: %s" % e, file=sys.stderr)
    fresh = [r[0] for r in rows if r[0] not in have]

    before = db.execute("SELECT COUNT(*) FROM benign_reports").fetchone()[0]
    with db:
        db.executemany("INSERT OR IGNORE INTO benign_reports (%s) VALUES (%s)"
                       % (",".join(COLS), ",".join("?" * len(COLS))), rows)
    after = db.execute("SELECT COUNT(*) FROM benign_reports").fetchone()[0]
    with_beh = db.execute("SELECT COUNT(*) FROM benign_reports "
                          "WHERE has_behaviour=1").fetchone()[0]
    db.close()

    inserted = after - before
    print("OK received=%d inserted=%d skipped=%d malformed=%d threat_refused=%d total=%d"
          % (len(parsed), inserted, len(rows) - inserted, bad,
             len(condemned), after))
    sa = [r[1] for r in rows if r[1]]
    ledger({"ok": True, "peer": peer(), "received": len(parsed),
            "inserted": inserted, "skipped": len(rows) - inserted,
            "malformed": bad, "threat_refused": len(condemned),
            "refused_shas": sorted(condemned)[:MAX_LOG_SHAS],
            "total": after, "with_behaviour": with_beh,
            "bytes": len(raw), "kb": round(len(raw) / 1024.0, 1),
            "oldest": min(sa) if sa else "", "newest": max(sa) if sa else "",
            "new_count": len(fresh), "new": fresh[:MAX_LOG_SHAS]})
    return 0


if __name__ == "__main__":
    sys.exit(main())
