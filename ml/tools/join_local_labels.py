#!/usr/bin/env python3
"""Join locally-held malware bytes against labels the server already paid for.

Why this exists
---------------
The malicious side of the training set was originally going to be rebuilt by
re-downloading bytes from the datalake and re-querying /vt/lookup for verdicts. Both
halves of that plan were wrong for this corpus:

  * bytes -- the intel server deletes sample bytes by design (see bulwark-janitor-
    samples), so it cannot serve them. But 21,308 samples are already sitting on local
    disk, every one of them named by its own sha256.
  * labels -- the shared VirusTotal key pool is a SINGLE FREE KEY at 500 lookups/day.
    Re-asking VT for 3,338 hashes would take a week of the entire fleet's budget and
    would starve the datalake collector, bulwark-benign-verify, and the ReputationProxy
    cloud queries that shipped Bulwark clients depend on. Those clients silently fall
    back to local-only verdicts when the budget is gone -- a real product regression
    in exchange for training data we can get for free.

So: labels come out of the server's vt_reports archive (verdicts bought long ago,
zero marginal cost) and bytes come off local disk. Nothing is downloaded and no quota
is spent.

Label trustworthiness
---------------------
vt_reports only persists threats, so presence in it is not by itself proof of a
malicious verdict -- the engine count is. Positives require BOTH:

  * type_tag in {peexe, pedll} -- the model is a static PE classifier; ELF/scripts
    would be noise and a shortcut (see below).
  * malicious >= MIN_ENGINES -- a handful of engines flagging something is often a
    generic-packer or PUA disagreement, not consensus malware.

Samples between 1 and MIN_ENGINES-1 engines are dropped rather than labelled either
way. Calling them benign would poison the negative class with real malware; calling
them malicious would train on the AV industry's noise floor.

No path, filename, day-directory or signer information reaches the feature vector --
those all correlate perfectly with the label here (malware lives in D:\...(9)/(10),
benign lives elsewhere) and a model handed that shortcut learns the directory layout
instead of the file format.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re

SHA = re.compile(r"^[0-9a-f]{64}$")
PE_TAGS = {"peexe", "pedll"}


def load_labels(paths: list[str]) -> dict[str, dict]:
    """sha256 -> label record. Later files win, so a fresh lookup can supersede the
    archive row for the same hash."""
    out: dict[str, dict] = {}
    for p in paths:
        if not p or not os.path.exists(p):
            continue
        n = 0
        with open(p, encoding="utf-8-sig") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("STDERR"):
                    continue
                try:
                    r = json.loads(line)
                except Exception:
                    continue
                sha = (r.get("sha256") or "").lower()
                if not SHA.match(sha):
                    continue
                # a 404/error row carries no verdict; do not let it overwrite a good one
                if r.get("error") and not r.get("mal"):
                    out.setdefault(sha, r)
                else:
                    out[sha] = r
                n += 1
        print("  labels from %-28s %6d rows" % (os.path.basename(p), n))
    return out


def scan_local(roots: list[str]) -> dict[str, str]:
    """sha256 -> full path, for every sha256-named file under the roots."""
    found: dict[str, str] = {}
    for root in roots:
        if not os.path.isdir(root):
            print("  !! missing root: %s" % root)
            continue
        n = 0
        for dp, _dn, fn in os.walk(root):
            for name in fn:
                if name.startswith("_"):
                    continue
                stem = os.path.splitext(name)[0].lower()
                if SHA.match(stem):
                    found.setdefault(stem, os.path.join(dp, name))
                    n += 1
        print("  local files under %-24s %6d" % (os.path.basename(root) or root, n))
    return found


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--labels", nargs="+", required=True)
    ap.add_argument("--roots", nargs="+", required=True)
    ap.add_argument("--out", required=True, help="JSONL of usable positives")
    ap.add_argument("--min-engines", type=int, default=5)
    ap.add_argument("--report", default="")
    args = ap.parse_args()

    print("== labels ==")
    labels = load_labels(args.labels)
    print("  unique hashes with a label: %d" % len(labels))
    print("== local bytes ==")
    local = scan_local(args.roots)
    print("  unique sha256-named files : %d" % len(local))

    both = set(local) & set(labels)
    print("\n== overlap ==")
    print("  local AND labelled        : %d" % len(both))
    print("  local, NO label           : %d" % (len(local) - len(both)))
    print("  labelled, bytes not local : %d" % (len(labels) - len(both)))

    tags = collections.Counter()
    eng = collections.Counter()
    kept: list[dict] = []
    drop_tag = drop_eng = 0
    for sha in both:
        r = labels[sha]
        tag = (r.get("type_tag") or "").lower()
        tags[tag or "(none)"] += 1
        mal = int(r.get("mal") or 0)
        if tag not in PE_TAGS:
            drop_tag += 1
            continue
        if mal < args.min_engines:
            drop_eng += 1
            eng[mal] += 1
            continue
        kept.append({
            "sha256": sha,
            "path": local[sha],
            "label": 1,
            "mal": mal,
            "total": int(r.get("total") or 0),
            "type_tag": tag,
            "threat_label": r.get("label") or "",
            "category": r.get("category") or "",
        })

    print("\n== type_tag of the overlap ==")
    for t, n in tags.most_common(12):
        print("  %-24s %6d" % (t, n))
    print("\n== filtering ==")
    print("  dropped, not peexe/pedll  : %d" % drop_tag)
    print("  dropped, <%d engines       : %d  %s"
          % (args.min_engines, drop_eng, dict(sorted(eng.items()))))
    print("  KEPT usable positives     : %d" % len(kept))

    pe = collections.Counter(k["type_tag"] for k in kept)
    print("  of which peexe / pedll    : %d / %d" % (pe["peexe"], pe["pedll"]))

    kept.sort(key=lambda k: k["sha256"])
    with open(args.out, "w", encoding="utf-8") as f:
        for k in kept:
            f.write(json.dumps(k, ensure_ascii=False) + "\n")
    print("\nwrote %s (%d rows)" % (args.out, len(kept)))

    if args.report:
        miss = sorted(set(local) - both)
        with open(args.report, "w", encoding="ascii") as f:
            f.write("\n".join(miss))
        print("wrote %s (%d unlabelled local hashes)" % (args.report, len(miss)))

    fam = collections.Counter(
        (k["threat_label"].split(".")[0] or "(none)") for k in kept)
    print("\n== top threat families among positives ==")
    for t, n in fam.most_common(15):
        print("  %-28s %5d" % (t, n))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
