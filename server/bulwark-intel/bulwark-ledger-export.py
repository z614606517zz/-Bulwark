#!/usr/bin/env python3
"""Emit the calling node's OWN ingest-ledger lines, so a satellite can reconcile
what it thinks it pushed against what the master actually recorded.

Reached only through root's forced command with SSH_ORIGINAL_COMMAND=export-ledger.
Filtered by peer on purpose: the ledger holds every node's contributions and the
hashes they carried, and one satellite has no business reading another's. The
filter is the connection's real source address from SSH_CONNECTION, not anything
the caller can set.

stdout is JSONL, one ledger record per line. Nothing else is ever printed there."""
import json, os, sys
LOG = os.environ.get("BULWARK_INGEST_LOG", "/var/lib/bulwark-intel/ingest_log.jsonl")
LIMIT = int(os.environ.get("BULWARK_EXPORT_LIMIT", "300"))
def main():
    parts = os.environ.get("SSH_CONNECTION", "").split()
    peer = parts[0] if parts else ""
    if not peer:
        print("no SSH_CONNECTION; refusing to export", file=sys.stderr)
        return 1
    try:
        with open(LOG, encoding="utf-8") as f:
            lines = f.readlines()
    except OSError:
        return 0            # no ledger yet is not an error
    out = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except Exception:
            continue
        if d.get("peer") == peer:
            out.append(line)
    for line in out[-LIMIT:]:
        sys.stdout.write(line + "\n")
    return 0
if __name__ == "__main__":
    sys.exit(main())
