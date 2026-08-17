#!/usr/bin/env python3
"""Receive a vt_reports delta (gzip JSONL on stdin) from the harvesting node and
merge it into this master DB. INSERT OR IGNORE: a satellite can only add hashes
we lack, never overwrite ours. busy_timeout because cache.db is journal_mode=delete.

Reached only through a forced command in root's authorized_keys
(restrict,command="/usr/local/sbin/bulwark-ingest-wrapper.sh"), which drops to
bulwarkintel before exec'ing this. That key therefore cannot get a shell.

stdout is the reply protocol -- the pusher checks it startswith("OK") and parses
the k=v pairs. NOTHING else may ever be printed to stdout; diagnostics go to stderr."""
import gzip, json, os, sqlite3, sys
from datetime import datetime, timezone
DB = os.environ.get("BULWARK_DB", "/var/lib/bulwark-intel/cache.db")
LEDGER = os.environ.get("BULWARK_INGEST_LOG", "/var/lib/bulwark-intel/ingest_log.jsonl")
COLS = ("sha256","md5","sha1","name","verdict","malicious","total_engines",
        "stored_at","report","threat_label","category","silverfox")
MAX_ROWS = int(os.environ.get("BULWARK_INGEST_MAX_ROWS","20000"))
MAX_BYTES = int(os.environ.get("BULWARK_INGEST_MAX_BYTES", str(256*1024*1024)))
# Cap on hashes recorded per ledger line: enough to audit a normal hourly delta
# without a 20k-row backfill writing a megabyte-long line.
MAX_LOG_SHAS = int(os.environ.get("BULWARK_INGEST_LOG_SHAS","500"))
def peer():
    """SSH_CONNECTION = '<client ip> <client port> <server ip> <server port>'."""
    parts = os.environ.get("SSH_CONNECTION","").split()
    return parts[0] if parts else ""
def ledger(rec):
    """The master's own record of every push. Without it the only trace of an ingest
    is sshd's 'Accepted publickey' line: vt_reports has no origin column, and the
    'OK ...' summary is sent to the pusher and kept only there."""
    rec["ts"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        with open(LEDGER,"a",encoding="utf-8") as f:
            f.write(json.dumps(rec,ensure_ascii=False)+"\n")
        os.chmod(LEDGER,0o644)
        if os.path.getsize(LEDGER) > 2*1024*1024:
            with open(LEDGER,encoding="utf-8") as f: keep=f.readlines()[-2000:]
            tmp=LEDGER+".tmp"
            with open(tmp,"w",encoding="utf-8") as f: f.writelines(keep)
            os.replace(tmp,LEDGER); os.chmod(LEDGER,0o644)
    except OSError as e:
        print("ledger write failed: %s"%e, file=sys.stderr)
def main():
    raw = sys.stdin.buffer.read(MAX_BYTES+1)
    if len(raw) > MAX_BYTES:
        print("ERR too large", file=sys.stderr)
        ledger({"ok":False,"peer":peer(),"error":"too large","bytes":len(raw)})
        return 2
    if not raw:
        print("OK received=0 inserted=0 skipped=0")
        ledger({"ok":True,"peer":peer(),"received":0,"inserted":0,"skipped":0,
                "malformed":0,"bytes":0,"empty":True})
        return 0
    try: text = gzip.decompress(raw).decode("utf-8")
    except Exception as e:
        print("ERR not gzip: %s"%e, file=sys.stderr)
        ledger({"ok":False,"peer":peer(),"error":"not gzip: %s"%str(e)[:100],"bytes":len(raw)})
        return 2
    rows, bad = [], 0
    for line in text.splitlines():
        line=line.strip()
        if not line: continue
        try:
            d=json.loads(line); sha=str(d.get("sha256","")).lower()
            if len(sha)!=64 or any(c not in "0123456789abcdef" for c in sha): bad+=1; continue
            rows.append(tuple(d.get(c) for c in COLS))
        except Exception: bad+=1
        if len(rows)>=MAX_ROWS: break
    db=sqlite3.connect(DB, timeout=60); db.execute("PRAGMA busy_timeout=60000")
    # Which hashes are genuinely new has to be answered BEFORE the insert; afterwards
    # INSERT OR IGNORE cannot tell us which of the batch it actually took.
    shas = [r[0] for r in rows]
    have = set()
    try:
        for i in range(0, len(shas), 400):
            chunk = shas[i:i+400]
            have.update(x[0] for x in db.execute(
                "SELECT sha256 FROM vt_reports WHERE sha256 IN (%s)" % ",".join("?"*len(chunk)),
                chunk))
    except sqlite3.Error as e:
        print("pre-scan failed: %s"%e, file=sys.stderr)
    fresh = [s for s in shas if s not in have]
    sa = [r[COLS.index("stored_at")] for r in rows if r[COLS.index("stored_at")]]
    before=db.execute("SELECT COUNT(*) FROM vt_reports").fetchone()[0]
    with db:
        db.executemany("INSERT OR IGNORE INTO vt_reports (%s) VALUES (%s)"
                       % (",".join(COLS), ",".join("?"*len(COLS))), rows)
    after=db.execute("SELECT COUNT(*) FROM vt_reports").fetchone()[0]; db.close()
    print("OK received=%d inserted=%d skipped=%d malformed=%d total=%d"
          % (len(rows), after-before, len(rows)-(after-before), bad, after))
    ledger({"ok":True,"peer":peer(),"received":len(rows),"inserted":after-before,
            "skipped":len(rows)-(after-before),"malformed":bad,"total":after,
            "bytes":len(raw),"kb":round(len(raw)/1024.0,1),
            "oldest":min(sa) if sa else "","newest":max(sa) if sa else "",
            "new_count":len(fresh),"new":fresh[:MAX_LOG_SHAS]})
    return 0
if __name__=="__main__":
    sys.exit(main())
