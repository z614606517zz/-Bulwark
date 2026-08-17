#!/usr/bin/env python3
"""Quarantine + re-verify this node's benign (white) samples before they are
allowed to leave for the master.

WHY THIS EXISTS
---------------
A "clean" verdict from VirusTotal is only clean *as of that moment*. The samples
this node looks up come from malware feeds (abuse.ch datalake), so a fresh sample
routinely scores 0/75 simply because no engine has caught up yet. Storing it as a
white sample then bakes malware into the corpus that engine_build.py uses as its
NEGATIVE CONTROL -- the one dataset whose whole job is to say "normal software
does this too". Measured on the master: 51 of 64 white samples were in fact
malware (Mirai, Prometei, RemusStealer, stealers), because nothing ever rechecked
them and nothing removed a row once its verdict flipped.

So: no sample is exported on the strength of a single lookup. Each one sits in
quarantine for QUARANTINE_HOURS, is then re-queried, and only a sample that is
*still* clean after that wait becomes exportable. One that flipped is deleted
from benign_reports outright -- leaving it there is what produced the mess above.

DIVISION OF LABOUR (deliberate, do not merge these two jobs)
------------------------------------------------------------
This script owns every cache.db WRITE, and therefore runs as bulwarkintel.
cache.db is journal_mode=delete, so a root-owned journal file left beside it makes
app.py's next write fail -- the same trap documented in the janitor units.
The export half (bulwark-benign-push.py) needs root's SSH key instead, so it runs
as root and never writes cache.db: it only reads, and keeps its progress in its
own watermark file. Neither job can do the other's part.

STATE
-----
benign_quarantine holds the clock and the outcome:
    first_seen    when the sample was first seen clean (quarantine starts)
    verified_at   passed the >=QUARANTINE_HOURS recheck -> exportable
    rejected_at   recheck found it malicious -> deleted from benign_reports
Note first_seen is seeded from benign_reports.stored_at and then NEVER updated:
app.py's upsert refreshes stored_at on every re-lookup, so trusting stored_at as
the clock would let a frequently-queried sample reset its own quarantine forever.
"""
import json
import os
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

DB = os.environ.get("BULWARK_DB", "/var/lib/bulwark-intel/cache.db")
LEDGER = os.environ.get("BULWARK_BENIGN_LOG",
                        "/var/lib/bulwark-intel/benign_verify_log.jsonl")
# Local intel service. Plain http on purpose: this node runs with tls_cert=""
# (verified: http/8787 -> 200, https/8787 -> connection refused).
BASE = os.environ.get("BULWARK_INTEL_URL", "http://127.0.0.1:8787")
QUARANTINE_HOURS = int(os.environ.get("BULWARK_BENIGN_QUARANTINE_HOURS", "24"))
# Rechecks per run. The backlog (211 rows on first run) is worked off across runs
# rather than in one burst, so a single run can never eat the day's VT budget.
BATCH = int(os.environ.get("BULWARK_BENIGN_BATCH", "40"))
# Hard stop on VirusTotal's daily counter. The datalake collector shares this
# budget and is the node's primary job; the recheck must yield to it.
QUOTA_CEILING = int(os.environ.get("BULWARK_BENIGN_QUOTA_CEILING", "900"))
# Seconds between lookups. Each lookup spends 1 call on the file-report key pool
# (the behaviour summary uses a separate pool), and a free VT key allows 4/min.
PACE = float(os.environ.get("BULWARK_BENIGN_PACE", "20"))
HTTP_TIMEOUT = int(os.environ.get("BULWARK_BENIGN_HTTP_TIMEOUT", "180"))

# ---- fast track: skip the wait for files VT has long since settled on ---------
#
# The 24h hold exists to give engines time to catch up on a sample nobody has
# scanned yet. A file VirusTotal has held for months AND re-scanned recently with
# zero detections has already served a far longer quarantine in the wild, so making
# it wait another day buys no information and costs a lookup we do not have to
# spare. Such a sample is verified with NO upstream call at all.
#
# The evidence comes from vt_lookup_cache, which holds the FULL VT report (the slim
# benign row does not carry the date fields). Measured on this node: all 168 pending
# rows had a cached report, so this decision is free for every candidate.
#
# The decisive field is last_analysis_date, not age. Sampled rows on this node look
# like this:
#     first_submission_date == last_analysis_date, times_submitted=2, reputation=-1
# i.e. VT scanned it once at submission and never again -- "0 detections" from a
# single stale scan is nearly worthless. Requiring a re-analysis strictly after
# submission is what separates "the world has vetted this" from "nobody looked".
FAST_TRACK = os.environ.get("BULWARK_BENIGN_FAST_TRACK", "1") not in ("0", "", "no")
# How stale our own copy of the verdict may be. Beyond this the detection counts are
# not current enough to skip a recheck on.
FT_FRESH_HOURS = float(os.environ.get("BULWARK_BENIGN_FT_FRESH_HOURS", "48"))
# Second, looser freshness tier for genuinely ancient files. Measured on this node,
# 109 of 179 pending rows were blocked on copy staleness alone, and many of those are
# nine-year-old signed system DLLs (apisetstub, msvcp140.dll). For a file VT has held
# over a year, re-scanned recently and cleared by 60+ engines, the chance of a flip
# inside a few weeks is far lower than for the 2-day-old feed samples this hold was
# designed for -- so an older copy is still good enough to skip the wait.
FT_ANCIENT_DAYS = float(os.environ.get("BULWARK_BENIGN_FT_ANCIENT_DAYS", "365"))
FT_ANCIENT_FRESH_HOURS = float(
    os.environ.get("BULWARK_BENIGN_FT_ANCIENT_FRESH_HOURS", "720"))
FT_MIN_AGE_DAYS = float(os.environ.get("BULWARK_BENIGN_FT_MIN_AGE_DAYS", "90"))
# A valid signature is independent corroboration, so it earns a shorter minimum age.
FT_MIN_AGE_DAYS_SIGNED = float(
    os.environ.get("BULWARK_BENIGN_FT_MIN_AGE_DAYS_SIGNED", "30"))
# The re-scan must itself be recent, or "clean" reflects signatures from years ago.
#
# 365 rather than 180: VirusTotal simply does not re-scan settled old files often.
# Measured on this node, the Universal CRT stubs shipped inside QQNT
# (api-ms-win-crt-*.dll, 3485 days old, Microsoft-signed, 65-71 engines, 0/0) were
# last analysed 187.6 days ago and so missed a 180-day ceiling by a week -- ten rows
# held back on nothing but an arbitrary cutoff. Within a year still means engines
# carrying modern signatures cleared it, and it only ever applies together with the
# other five conditions (age, re-analysed at all, 40+ engines, no detections,
# non-negative reputation).
FT_MAX_LAST_SCAN_DAYS = float(os.environ.get("BULWARK_BENIGN_FT_MAX_LAST_SCAN_DAYS", "365"))
# Engines that actually returned a result. A 0/3 verdict is not coverage.
FT_MIN_ENGINES = int(os.environ.get("BULWARK_BENIGN_FT_MIN_ENGINES", "40"))

THREAT_VERDICTS = ("malicious", "suspicious")

QUARANTINE_DDL = """
CREATE TABLE IF NOT EXISTS benign_quarantine(
  sha256       TEXT PRIMARY KEY,
  first_seen   TEXT NOT NULL,
  verified_at  TEXT DEFAULT '',
  rejected_at  TEXT DEFAULT '',
  reject_reason TEXT DEFAULT '',
  last_recheck TEXT DEFAULT '',
  recheck_n    INTEGER DEFAULT 0
)"""


def now():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def log(*a):
    print("[benign-verify %s]" % now().strftime("%H:%M:%S"), *a, flush=True)


def ledger(rec):
    """Append-only audit trail. The point of this pipeline is that a sample was
    demonstrably rechecked before export, which is only credible if each verdict
    change is recorded somewhere durable."""
    rec["ts"] = iso(now())
    try:
        with open(LEDGER, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        if os.path.getsize(LEDGER) > 1024 * 1024:
            with open(LEDGER, encoding="utf-8") as f:
                keep = f.readlines()[-2000:]
            tmp = LEDGER + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.writelines(keep)
            os.replace(tmp, LEDGER)
    except OSError as e:
        log("ledger write failed: %s" % e)


def connect():
    db = sqlite3.connect(DB, timeout=60)
    db.execute("PRAGMA busy_timeout=60000")
    db.row_factory = sqlite3.Row
    return db


def vt_used_today(db):
    r = db.execute("SELECT count FROM quota WHERE source='VirusTotal' "
                   "AND day=date('now')").fetchone()
    return int(r["count"]) if r else 0


def enroll(db):
    """Put every benign row not yet tracked into quarantine.

    first_seen comes from benign_reports.stored_at, so the 211 rows that predate
    this pipeline are immediately due -- correct, since they were accepted under
    the old no-recheck policy and are exactly the ones under suspicion."""
    with db:
        db.execute(QUARANTINE_DDL)
        cur = db.execute(
            "INSERT OR IGNORE INTO benign_quarantine(sha256, first_seen) "
            "SELECT b.sha256, COALESCE(NULLIF(b.stored_at,''), ?) FROM benign_reports b",
            (iso(now()),))
        added = cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
    # Clean up rows whose benign row is gone -- but NEVER a rejected one.
    #
    # This used to drop every orphan, which quietly erased the pipeline's whole
    # record of its own work: reject() deletes the benign row, so on the next run the
    # quarantine row looked like an orphan and went too. Measured after a day: the
    # ledger held 42 rejections while the table reported 0.
    #
    # Worse than a wrong counter, it also erased the memory. A hash that was caught
    # as malware could be re-enrolled the next time the collector looked it up, and
    # if VirusTotal happened to answer "clean" in that moment it could be verified
    # and exported all over again. Keeping the rejected row as a tombstone makes
    # INSERT OR IGNORE below a permanent bar: once rejected, never re-enrolled.
    with db:
        db.execute("DELETE FROM benign_quarantine WHERE rejected_at='' AND sha256 NOT IN "
                   "(SELECT sha256 FROM benign_reports)")
    return added


def due_rows(db, limit):
    cutoff = iso(now() - timedelta(hours=QUARANTINE_HOURS))
    return db.execute(
        "SELECT q.sha256, q.first_seen, q.recheck_n, b.name "
        "FROM benign_quarantine q JOIN benign_reports b ON b.sha256=q.sha256 "
        "WHERE q.verified_at='' AND q.rejected_at='' AND q.first_seen<=? "
        "ORDER BY q.first_seen LIMIT ?", (cutoff, limit)).fetchall()


def local_threat_verdict(db, sha):
    """Already filed as a threat here? Then no VT call is needed to reject it.
    vt_reports is fed by the datalake collector and by the master's own findings,
    so this catches a good share of the backlog for free."""
    r = db.execute("SELECT verdict, malicious, total_engines, threat_label "
                   "FROM vt_reports WHERE sha256=?", (sha,)).fetchone()
    if r and (r["verdict"] or "") in THREAT_VERDICTS:
        return dict(r)
    return None


def cached_full_report(db, sha):
    """The full VT report we already hold for this hash, plus how old our copy is.

    Read straight from the table rather than through app.py's getter: that one
    returns nothing once expires_at has passed, while here the row is still useful
    -- we need its age precisely so we can judge whether to trust it.
    """
    r = db.execute("SELECT stored_at, report FROM vt_lookup_cache WHERE ident=?",
                   (sha,)).fetchone()
    if not r or not r["report"]:
        return None, None
    try:
        rep = json.loads(r["report"])
    except Exception:
        return None, None
    if not isinstance(rep, dict) or not rep:
        return None, None
    age_h = None
    try:
        ts = datetime.strptime(r["stored_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc)
        age_h = (now() - ts).total_seconds() / 3600.0
    except (TypeError, ValueError):
        pass
    return rep, age_h


def established_clean(rep, copy_age_h):
    """Has VirusTotal long since settled that this file is clean?

    Returns (True, evidence) only when every one of these holds:
      * VT has known the file for at least FT_MIN_AGE_DAYS (less if validly signed);
      * it was re-analysed STRICTLY AFTER first submission -- proof that engines
        looked again, rather than one scan at upload and nothing since;
      * that re-analysis is no older than FT_MAX_LAST_SCAN_DAYS;
      * zero malicious and zero suspicious, from at least FT_MIN_ENGINES engines
        that actually answered;
      * community reputation is not negative;
      * our copy of the verdict is current enough -- FT_FRESH_HOURS normally, or the
        looser FT_ANCIENT_FRESH_HOURS once the file is older than FT_ANCIENT_DAYS.
    Anything short of that falls through to the normal 24h recheck.
    """
    if copy_age_h is None:
        return False, {"why": "our copy has no timestamp"}
    f = rep.get("file") or {}
    st = f.get("last_analysis_stats") or {}
    mal = int(st.get("malicious", 0) or 0)
    susp = int(st.get("suspicious", 0) or 0)
    if mal or susp:
        return False, {"why": "not clean (%d mal / %d susp)" % (mal, susp)}
    engines = int(st.get("undetected", 0) or 0) + int(st.get("harmless", 0) or 0)
    if engines < FT_MIN_ENGINES:
        return False, {"why": "only %d engines answered" % engines}

    fsd = f.get("first_submission_date")
    lad = f.get("last_analysis_date")
    if not fsd or not lad:
        return False, {"why": "no submission/analysis dates"}
    nowts = now().timestamp()
    age_days = (nowts - float(fsd)) / 86400.0
    scan_age_days = (nowts - float(lad)) / 86400.0

    signed = str((f.get("signature_info") or {}).get("verified", "")).lower() == "signed"
    need_age = FT_MIN_AGE_DAYS_SIGNED if signed else FT_MIN_AGE_DAYS
    if age_days < need_age:
        return False, {"why": "only known %.1f days (need %.0f)" % (age_days, need_age)}
    if float(lad) <= float(fsd):
        return False, {"why": "never re-analysed after submission"}
    if scan_age_days > FT_MAX_LAST_SCAN_DAYS:
        return False, {"why": "last scan %.0f days ago" % scan_age_days}

    # Freshness last, because how fresh our copy must be depends on how long the
    # file has been settled (see FT_ANCIENT_DAYS).
    allowed_copy_age = (FT_ANCIENT_FRESH_HOURS if age_days >= FT_ANCIENT_DAYS
                        else FT_FRESH_HOURS)
    if copy_age_h > allowed_copy_age:
        return False, {"why": "our copy is stale (%.0fh > %.0fh allowed)"
                              % (copy_age_h, allowed_copy_age)}

    rep_score = f.get("reputation")
    if rep_score is not None:
        try:
            if int(rep_score) < 0:
                return False, {"why": "negative reputation (%s)" % rep_score}
        except (TypeError, ValueError):
            pass

    return True, {"age_days": round(age_days, 1),
                  "last_scan_days_ago": round(scan_age_days, 1),
                  "engines": engines, "signed": signed,
                  "reputation": rep_score,
                  "copy_age_h": round(copy_age_h, 1),
                  "times_submitted": f.get("times_submitted")}


def lookup(sha):
    """Force a fresh verdict through the local service.

    Going through /vt/lookup rather than straight to VirusTotal is deliberate: the
    service owns the API keys, the quota accounting and the rate limiter, and it
    files anything malicious into vt_reports on the way past. refresh=true is what
    makes this a real recheck instead of a cache read."""
    body = json.dumps({"hash": sha, "refresh": True}).encode()
    req = urllib.request.Request(BASE + "/vt/lookup", data=body,
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def reject(db, sha, reason, detail=None):
    """Mark rejected AND remove it from the corpus.

    The delete is the whole point. The master's corpus rotted precisely because a
    flipped verdict only ever *added* a vt_reports row and left the stale white
    sample in place."""
    with db:
        db.execute("UPDATE benign_quarantine SET rejected_at=?, reject_reason=?, "
                   "last_recheck=?, recheck_n=recheck_n+1 WHERE sha256=?",
                   (iso(now()), reason[:120], iso(now()), sha))
        db.execute("DELETE FROM benign_reports WHERE sha256=?", (sha,))
    rec = {"event": "reject", "sha256": sha, "reason": reason}
    if detail:
        rec.update(detail)
    ledger(rec)


def verify(db, sha, how="recheck", evidence=None):
    with db:
        db.execute("UPDATE benign_quarantine SET verified_at=?, last_recheck=?, "
                   "recheck_n=recheck_n+1 WHERE sha256=?",
                   (iso(now()), iso(now()), sha))
    rec = {"event": "verify", "sha256": sha, "how": how}
    if evidence:
        rec["evidence"] = evidence
    ledger(rec)


def fast_track(db):
    """Clear the already-settled files before spending a single upstream call.

    Runs over every pending row, not just the ones past their 24h mark: the point is
    to avoid the lookup the recheck would otherwise make, so the earlier a row is
    cleared the more it saves.
    """
    if not FAST_TRACK:
        log("fast track disabled")
        return 0, 0
    rows = db.execute(
        "SELECT q.sha256, b.name FROM benign_quarantine q "
        "JOIN benign_reports b ON b.sha256=q.sha256 "
        "WHERE q.verified_at='' AND q.rejected_at='' "
        "ORDER BY q.first_seen").fetchall()
    passed = 0
    reasons = {}
    for row in rows:
        sha, nm = row["sha256"], (row["name"] or "")
        rep, copy_age_h = cached_full_report(db, sha)
        if rep is None:
            reasons["no cached report"] = reasons.get("no cached report", 0) + 1
            continue
        ok, ev = established_clean(rep, copy_age_h)
        if ok:
            verify(db, sha, how="fast_track_established_clean", evidence=ev)
            passed += 1
            log("  FAST-TRACK %s %-28s known %.0fd, rescanned %.0fd ago, %d engines%s"
                % (sha[:12], nm[:28], ev["age_days"], ev["last_scan_days_ago"],
                   ev["engines"], " (signed)" if ev["signed"] else ""))
        else:
            w = ev.get("why", "?")
            # Collapse the numeric detail so the summary stays readable.
            key = w.split("(")[0].strip()
            for pref in ("only known", "only ", "last scan", "our copy is stale"):
                if w.startswith(pref):
                    key = pref.rstrip()
                    break
            reasons[key] = reasons.get(key, 0) + 1
    log("fast track: %d verified with no VT call, %d left for recheck"
        % (passed, len(rows) - passed))
    if reasons:
        log("  held back because: %s"
            % ", ".join("%s x%d" % (k, v) for k, v in
                        sorted(reasons.items(), key=lambda kv: -kv[1])))
    ledger({"event": "fast_track", "verified": passed,
            "remaining": len(rows) - passed, "reasons": reasons})
    return passed, len(rows) - passed


def defer(db, sha, why):
    """Could not decide this round (VT unreachable / degraded). Leave it pending so
    a later run retries: guessing 'clean' here would defeat the whole quarantine."""
    with db:
        db.execute("UPDATE benign_quarantine SET last_recheck=?, "
                   "recheck_n=recheck_n+1 WHERE sha256=?", (iso(now()), sha))
    ledger({"event": "defer", "sha256": sha, "why": why[:120]})


def main():
    db = connect()
    added = enroll(db)
    used = vt_used_today(db)

    total = db.execute("SELECT COUNT(*) n FROM benign_reports").fetchone()["n"]
    pend = db.execute("SELECT COUNT(*) n FROM benign_quarantine "
                      "WHERE verified_at='' AND rejected_at=''").fetchone()["n"]
    ver = db.execute("SELECT COUNT(*) n FROM benign_quarantine "
                     "WHERE verified_at<>''").fetchone()["n"]
    rej = db.execute("SELECT COUNT(*) n FROM benign_quarantine "
                     "WHERE rejected_at<>''").fetchone()["n"]
    log("benign=%d enrolled_new=%d pending=%d verified=%d rejected=%d vt_used=%d"
        % (total, added, pend, ver, rej, used))

    # Free pass first: anything VT settled long ago never reaches the paid path.
    n_fast, _ = fast_track(db)

    rows = due_rows(db, BATCH)
    log("due for recheck (>=%dh old): %d (batch cap %d)"
        % (QUARANTINE_HOURS, len(rows), BATCH))

    n_ver = n_rej = n_def = n_free = 0
    for i, row in enumerate(rows, 1):
        sha, nm = row["sha256"], (row["name"] or "")

        hit = local_threat_verdict(db, sha)
        if hit:
            reject(db, sha, "local_threat_archive",
                   {"verdict": hit["verdict"], "malicious": hit["malicious"],
                    "total_engines": hit["total_engines"],
                    "threat_label": hit["threat_label"], "name": nm})
            n_rej += 1
            n_free += 1
            log("[%d/%d] %s %-28s REJECT (already a threat locally, no VT call)"
                % (i, len(rows), sha[:12], nm[:28]))
            continue

        used = vt_used_today(db)
        if used >= QUOTA_CEILING:
            log("stopping: VT daily counter %d >= ceiling %d; %d left for next run"
                % (used, QUOTA_CEILING, len(rows) - i + 1))
            ledger({"event": "quota_stop", "vt_used": used,
                    "ceiling": QUOTA_CEILING, "remaining_due": len(rows) - i + 1})
            break

        try:
            res = lookup(sha)
        except (urllib.error.URLError, OSError, ValueError) as e:
            defer(db, sha, "%s: %s" % (type(e).__name__, e))
            n_def += 1
            log("[%d/%d] %s %-28s DEFER (%s)"
                % (i, len(rows), sha[:12], nm[:28], type(e).__name__))
            time.sleep(PACE)
            continue

        # Authoritative check: did the service just file it as a threat? Reading
        # vt_reports back is schema-independent, unlike trusting a response field.
        hit = local_threat_verdict(db, sha)
        if hit:
            reject(db, sha, "vt_flipped",
                   {"verdict": hit["verdict"], "malicious": hit["malicious"],
                    "total_engines": hit["total_engines"],
                    "threat_label": hit["threat_label"], "name": nm})
            n_rej += 1
            log("[%d/%d] %s %-28s REJECT flipped -> %s %s/%s %s"
                % (i, len(rows), sha[:12], nm[:28], hit["verdict"],
                   hit["malicious"], hit["total_engines"], hit["threat_label"][:24]))
        elif res.get("stored"):
            # Same conclusion by the response's own account; keep it as a fallback
            # in case vt_reports lags behind within this transaction's view.
            reject(db, sha, "vt_flipped_response", {"name": nm})
            n_rej += 1
            log("[%d/%d] %s %-28s REJECT flipped (per response)"
                % (i, len(rows), sha[:12], nm[:28]))
        elif not res.get("ok") or res.get("degraded"):
            defer(db, sha, "degraded/not-ok: %s" % str(res.get("error", ""))[:80])
            n_def += 1
            log("[%d/%d] %s %-28s DEFER (degraded or error)"
                % (i, len(rows), sha[:12], nm[:28]))
        else:
            verify(db, sha, how="recheck")
            n_ver += 1
            log("[%d/%d] %s %-28s VERIFIED clean after %dh"
                % (i, len(rows), sha[:12], nm[:28], QUARANTINE_HOURS))

        if i < len(rows):
            time.sleep(PACE)

    exportable = db.execute(
        "SELECT COUNT(*) n FROM benign_quarantine q "
        "JOIN benign_reports b ON b.sha256=q.sha256 "
        "WHERE q.verified_at<>'' AND q.rejected_at=''").fetchone()["n"]
    log("done: fast_tracked=%d verified=%d rejected=%d (free=%d) deferred=%d "
        "| exportable_total=%d vt_calls_spent=%d"
        % (n_fast, n_ver, n_rej, n_free, n_def, exportable,
           n_ver + n_rej - n_free + n_def))
    ledger({"event": "run", "fast_tracked": n_fast, "verified": n_ver,
            "rejected": n_rej, "free_rejects": n_free, "deferred": n_def,
            "exportable_total": exportable, "vt_used": vt_used_today(db)})
    db.close()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        log("FATAL", type(e).__name__, str(e)[:200])
        sys.exit(1)
