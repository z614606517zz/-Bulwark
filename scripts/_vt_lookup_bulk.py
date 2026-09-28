#!/usr/bin/env python3
# ASCII-only: piped to a remote `python3 -` through a PowerShell pipeline, which
# re-encodes in the console codepage (GBK on zh-CN) and corrupts non-ASCII bytes.
#
# Bulk /vt/lookup against the LOCAL intel service. Sends NO file bytes -- hashes only.
#
# Lookup, never upload, on purpose:
#   * /vt/lookup does not spend the daily upload budget (default 20/day); /vt/upload
#     does. Uploading something VirusTotal already knows would burn a scarce shared
#     quota for nothing. Measured on a 14-sample batch: 13 of 14 were already known
#     to VT, so uploads would have been almost entirely wasted.
#   * this is the same order harvest.py and bulwark-datalake.py use, so the service's
#     own quota accounting stays consistent.
#
# The master serves TLS on 8787 and the cert is self-signed (the repo's own checks
# use `curl -sk`). Verification is skipped ONLY because this is a loopback call to
# our own service on the same host -- there is no network path for a MITM. Never do
# this for the datalake fetches, which cross the public internet.
#
# Resumable: every answer is appended to --out as JSONL and already-done hashes are
# skipped on restart. A run that dies at hash 2000 of 3438 must not start over.
import argparse
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request

BASE = "https://127.0.0.1:8787"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def dig(report):
    """Pull the few fields that decide whether this hash is usable as a positive."""
    f = (report or {}).get("file") or {}
    if not isinstance(f, dict):
        return {}
    stats = f.get("last_analysis_stats") or {}
    ptc = f.get("popular_threat_classification") or {}
    return {
        "type_tag": f.get("type_tag") or "",
        "type_desc": f.get("type_description") or "",
        "mal": int(stats.get("malicious", 0) or 0),
        "total": sum(int(v or 0) for v in stats.values()) if stats else 0,
        "label": ptc.get("suggested_threat_label") or "",
        "first_seen": f.get("first_submission_date") or f.get("first_seen_itw_date") or 0,
        "size": f.get("size") or 0,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hashes", required=True, help="file with one sha256 per line")
    ap.add_argument("--out", required=True, help="append-only JSONL results")
    ap.add_argument("--limit", type=int, default=0, help="0 = all")
    ap.add_argument("--sleep", type=float, default=0.4,
                    help="base pause between lookups; the service throttles too")
    ap.add_argument("--max-429", type=int, default=25,
                    help="give up after this many consecutive rate-limit answers")
    args = ap.parse_args()

    want = []
    with open(args.hashes) as f:
        for line in f:
            h = line.strip().lower()
            if len(h) == 64 and all(c in "0123456789abcdef" for c in h):
                want.append(h)

    done = set()
    if os.path.exists(args.out):
        with open(args.out, encoding="utf-8") as f:
            for line in f:
                try:
                    done.add(json.loads(line)["sha256"])
                except Exception:
                    pass
    todo = [h for h in want if h not in done]
    if args.limit:
        todo = todo[:args.limit]
    print("hashes=%d  already_done=%d  this_run=%d" % (len(want), len(done), len(todo)))
    sys.stdout.flush()

    outf = open(args.out, "a", encoding="utf-8")
    n_stored = n_cached = n_404 = n_429 = n_err = 0
    n_pe = n_mal5 = 0
    consec_429 = 0
    sleep = args.sleep
    t0 = time.time()

    for i, h in enumerate(todo, 1):
        body = json.dumps({"hash": h}).encode("utf-8")
        req = urllib.request.Request(BASE + "/vt/lookup", data=body,
                                     headers={"Content-Type": "application/json"},
                                     method="POST")
        code = -1
        obj = {}
        try:
            with urllib.request.urlopen(req, timeout=180, context=CTX) as r:
                code = r.status
                obj = json.loads(r.read())
        except urllib.error.HTTPError as e:
            code = e.code
            try:
                obj = json.loads(e.read())
            except Exception:
                obj = {"error": str(e.reason)}
        except Exception as e:
            obj = {"error": "%s: %s" % (type(e).__name__, e)}

        err = str(obj.get("error") or "")
        rec = {"sha256": h, "http": code,
               "cached": bool(obj.get("cached")),
               "stored": bool(obj.get("stored")),
               "error": err}
        rec.update(dig(obj.get("report")))
        outf.write(json.dumps(rec, ensure_ascii=False) + "\n")

        if code == 429 or "429" in err or "rate" in err.lower():
            n_429 += 1
            consec_429 += 1
            sleep = min(sleep * 2, 30.0)      # back off, do not hammer
            if consec_429 >= args.max_429:
                print("giving up: %d consecutive rate-limit answers" % consec_429)
                break
        else:
            consec_429 = 0
            sleep = max(args.sleep, sleep * 0.9)
            if rec["stored"]:
                n_stored += 1
            if rec["cached"]:
                n_cached += 1
            if "404" in err:
                n_404 += 1
            elif err:
                n_err += 1
            if rec.get("type_tag") in ("peexe", "pedll"):
                n_pe += 1
                if rec.get("mal", 0) >= 5:
                    n_mal5 += 1

        if i % 25 == 0 or i == len(todo):
            outf.flush()
            el = time.time() - t0
            print("%5d/%d  stored=%d cached=%d 404=%d 429=%d err=%d | "
                  "PE=%d usable(PE,>=5eng)=%d | %.1f/min sleep=%.1fs"
                  % (i, len(todo), n_stored, n_cached, n_404, n_429, n_err,
                     n_pe, n_mal5, i / max(el, 0.001) * 60, sleep))
            sys.stdout.flush()
        time.sleep(sleep)

    outf.close()
    el = time.time() - t0
    print("\n=== done in %.1f min ===" % (el / 60))
    print("stored(newly cached)= %d" % n_stored)
    print("already cached      = %d" % n_cached)
    print("VT 404 (unknown)    = %d" % n_404)
    print("rate limited        = %d" % n_429)
    print("other errors        = %d" % n_err)
    print("PE (peexe/pedll)    = %d" % n_pe)
    print("usable positives    = %d   <- PE and >=5 engines" % n_mal5)


if __name__ == "__main__":
    main()
