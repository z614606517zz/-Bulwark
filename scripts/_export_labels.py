#!/usr/bin/env python3
# ASCII-only: piped to a remote `python3 -` through a PowerShell pipeline that
# re-encodes in the console codepage (GBK on zh-CN) and would corrupt non-ASCII.
#
# Export every label the server already holds, as JSONL on stdout. Read-only, and it
# spends ZERO VirusTotal quota -- these verdicts were paid for long ago and archived.
#
# This replaces the plan of re-querying /vt/lookup for 3338 hashes: the shared key pool
# is a single free key at 500/day, so re-asking VT for answers already in vt_reports
# would take a week and starve the collectors and real ReputationProxy clients.
#
# type_tag lives inside the report JSON blob rather than a column, so it has to be
# parsed out row by row. 12k rows is nothing; do it here and ship a compact result.
import json
import sqlite3
import sys

c = sqlite3.connect("file:/var/lib/bulwark-intel/cache.db?mode=ro", uri=True, timeout=20)
c.execute("PRAGMA busy_timeout=8000")

n = 0
bad = 0
for sha, mal, tot, label, cat, rep in c.execute(
        "SELECT sha256, malicious, total_engines, threat_label, category, report "
        "FROM vt_reports"):
    tag = ""
    desc = ""
    size = 0
    if rep:
        try:
            f = (json.loads(rep) or {}).get("file") or {}
            if isinstance(f, dict):
                tag = f.get("type_tag") or ""
                desc = f.get("type_description") or ""
                size = f.get("size") or 0
                if not mal:
                    st = f.get("last_analysis_stats") or {}
                    mal = int(st.get("malicious", 0) or 0)
                    tot = sum(int(v or 0) for v in st.values()) if st else 0
        except Exception:
            bad += 1
    sys.stdout.write(json.dumps({
        "sha256": (sha or "").lower(),
        "mal": int(mal or 0),
        "total": int(tot or 0),
        "label": label or "",
        "category": cat or "",
        "type_tag": tag,
        "type_desc": desc,
        "size": size,
    }, ensure_ascii=False) + "\n")
    n += 1

sys.stderr.write("exported %d rows (%d unparsable report blobs)\n" % (n, bad))
