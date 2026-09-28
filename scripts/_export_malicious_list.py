#!/usr/bin/env python3
# ASCII-only: piped to a remote `python3 -` through a PowerShell pipeline, which
# re-encodes in the console codepage (GBK on zh-CN) and corrupts non-ASCII bytes.
#
# Export the malicious-PE training target list from vt_reports to stdout as JSONL.
# Read-only; touches nothing on the server.
#
# Filter rationale:
#   type_tag in (peexe, pedll) -- a static PE model cannot use ELF/JS/VBA/shell,
#       and this cache is over half non-PE (ELF Mirai botnet dominates it).
#   verdict == malicious       -- 'suspicious' rows are not a trustworthy label.
#   malicious >= 5 engines     -- single-vendor hits are too noisy to train on.
#
# Emitted per row: sha256, family/category for GROUP split, first_seen for TIME
# split, size + type so the fetcher can sanity-check what it pulled back.
import sqlite3
import json
import sys

c = sqlite3.connect("file:/var/lib/bulwark-intel/cache.db?mode=ro", uri=True)

n_out = 0
for sha, verdict, mal, tot, label, cat, sfox, stored, raw in c.execute(
        "select sha256, verdict, malicious, total_engines, threat_label, "
        "category, silverfox, stored_at, report from vt_reports "
        "where verdict = 'malicious' and malicious >= 5"):
    try:
        f = (json.loads(raw) or {}).get("file") or {}
    except Exception:
        continue
    if not isinstance(f, dict):
        continue
    t = f.get("type_tag") or ""
    if t not in ("peexe", "pedll"):
        continue
    rec = {
        "sha256": sha,
        "label": "malicious",
        "type_tag": t,
        "pe_type": "exe" if t == "peexe" else "dll",
        "malicious": mal,
        "total_engines": tot,
        "family": label or "",
        "category": cat or "",
        "silverfox": bool(sfox),
        "size": f.get("size") or 0,
        "first_seen": f.get("first_submission_date")
                      or f.get("first_seen_itw_date") or 0,
        "stored_at": stored or "",
        "tlsh": f.get("tlsh") or "",
        "ssdeep": f.get("ssdeep") or "",
        "packers": list((f.get("packers") or {}).keys()),
    }
    sys.stdout.write(json.dumps(rec) + "\n")
    n_out += 1

sys.stderr.write("exported %d rows\n" % n_out)
