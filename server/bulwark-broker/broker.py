#!/usr/bin/env python3
"""Bulwark reputation broker (phase 1).

A tiny, dependency-free VirusTotal reputation cache/proxy for a fleet of
Bulwark endpoints. Endpoints query this broker by SHA-256 instead of hitting
VirusTotal directly, so:
  * VT API keys live only here (never on endpoints),
  * one shared SQLite cache is reused fleet-wide (a hash queried once is known
    to everyone), and
  * one central per-key quota pool is used efficiently (quotas truly stack).

Pure Python stdlib only (http.server + sqlite3 + urllib). Config via env vars,
see /etc/bulwark/broker.env. Fail-open: any VT error yields verdict "unknown".
"""
import json
import os
import re
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---- config (from environment / systemd EnvironmentFile) --------------------
DB_PATH = os.environ.get("BULWARK_DB", "/var/lib/bulwark/reputation.db")
KEYS_PATH = os.environ.get("BULWARK_VT_KEYS", "/etc/bulwark/vt_keys")
TOKEN = os.environ.get("BULWARK_BROKER_TOKEN", "").strip()
BIND = os.environ.get("BULWARK_BIND", "127.0.0.1")
PORT = int(os.environ.get("BULWARK_PORT", "8787"))

VT_URL = "https://www.virustotal.com/api/v3/files/"
VT_TIMEOUT = 15
MAL_THRESHOLD = 5                 # detecting engines >= this => malicious
DEFAULT_RPD = 500                 # VT free tier per key
DEFAULT_RPM = 4
PRIORITY_RESERVE = 50             # daily quota per key reserved for priority verifies

# verdict -> cache TTL seconds (None = permanent). Mirrors the endpoint's tiered cache.
TTL = {"malicious": None, "clean": 7 * 86400, "suspicious": 86400, "unknown": 3600}

SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


# ---- per-key VT quota pool (port of the C++ VirusTotalClient key pool) -------
class KeyState:
    """One VT API key with its own minute token bucket + daily quota + cooldown."""

    def __init__(self, key, rpd, rpm):
        self.key = key
        self.rpd = max(1, rpd)
        self.rpm = max(1, rpm)
        self.day = None                 # UTC date string of the current quota window
        self.day_count = 0
        self.tokens = float(self.rpm)   # minute bucket, starts full
        self.last_refill = time.time()
        self.disabled_until = 0.0       # cooldown deadline (epoch); 429 / auth-fail
        self.lock = threading.Lock()


class KeyPool:
    """Round-robin over keys; each request picks a key that still has daily quota
    and a minute token and is not cooling down. Non-blocking: if no key is ready
    right now it returns None (caller fails open)."""

    def __init__(self, entries):
        self.keys = []
        for raw in entries:
            raw = raw.strip()
            if not raw:
                continue
            # "KEY" | "KEY:rpd" | "KEY:rpd:rpm"  (VT keys are 64 hex, no colon)
            parts = raw.split(":")
            key = parts[0].strip()
            if not key:
                continue
            rpd = int(parts[1]) if len(parts) > 1 and parts[1].strip().isdigit() else DEFAULT_RPD
            rpm = int(parts[2]) if len(parts) > 2 and parts[2].strip().isdigit() else DEFAULT_RPM
            self.keys.append(KeyState(key, rpd, rpm))
        self.rr = 0
        self.lock = threading.Lock()

    def count(self):
        return len(self.keys)

    def acquire(self, priority=False):
        now = time.time()
        n = len(self.keys)
        if n == 0:
            return None
        with self.lock:
            start = self.rr
            self.rr = (self.rr + 1) % n
        today = time.strftime("%Y-%m-%d", time.gmtime())
        for i in range(n):
            ks = self.keys[(start + i) % n]
            with ks.lock:
                if now < ks.disabled_until:
                    continue                                    # cooling down (429 / auth fail)
                if ks.day != today:
                    ks.day, ks.day_count = today, 0             # daily rollover (UTC)
                reserve = min(PRIORITY_RESERVE, ks.rpd - 1) if ks.rpd > 1 else 0
                eff_limit = ks.rpd if priority else (ks.rpd - reserve)
                if ks.day_count >= eff_limit:
                    continue                                    # daily quota exhausted for this key
                refill = int((now - ks.last_refill) / (60.0 / ks.rpm))
                if refill > 0:
                    ks.tokens = min(ks.rpm, ks.tokens + refill)
                    ks.last_refill = now
                if ks.tokens < 1.0:
                    continue                                    # no minute token right now, try next key
                ks.tokens -= 1.0
                ks.day_count += 1
                return ks
        return None

    def note(self, ks, http_code):
        if not ks:
            return
        with ks.lock:
            if http_code == 429:
                ks.disabled_until = time.time() + 60            # rate-limited: short cooldown
            elif http_code in (401, 403):
                ks.disabled_until = time.time() + 6 * 3600      # auth failure: long cooldown
            elif http_code in (200, 404):
                ks.disabled_until = 0.0                         # healthy: clear cooldown

    def usage(self):
        today = time.strftime("%Y-%m-%d", time.gmtime())
        used = limit = 0
        cooling = 0
        for ks in self.keys:
            with ks.lock:
                limit += ks.rpd
                used += ks.day_count if ks.day == today else 0
                if time.time() < ks.disabled_until:
                    cooling += 1
        return {"keys": len(self.keys), "used_today": used, "daily_limit": limit, "cooling": cooling}


# ---- VirusTotal query + parse -----------------------------------------------
def vt_query(key, sha):
    """Return (http_code, body_text_or_None). Never raises."""
    req = urllib.request.Request(VT_URL + sha, headers={"x-apikey": key})
    try:
        with urllib.request.urlopen(req, timeout=VT_TIMEOUT) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception:
        return 0, None


def parse_vt(sha, body):
    """VT v3 files/{id} attributes -> reputation dict. Returns None on parse failure."""
    try:
        attr = json.loads(body).get("data", {}).get("attributes", {})
    except Exception:
        return None
    if not attr:
        return None
    stats = attr.get("last_analysis_stats", {}) or {}
    mal = int(stats.get("malicious", 0))
    susp = int(stats.get("suspicious", 0))
    total = mal + susp + int(stats.get("undetected", 0)) + int(stats.get("harmless", 0)) \
        + int(stats.get("timeout", 0)) + int(stats.get("failure", 0)) \
        + int(stats.get("type-unsupported", 0))
    label = attr.get("suggested_threat_label") \
        or attr.get("popular_threat_classification", {}).get("suggested_threat_label", "") \
        or ""
    last = attr.get("last_analysis_date")
    if mal >= MAL_THRESHOLD:
        verdict = "malicious"
    elif (mal + susp) >= 1:
        verdict = "suspicious"
    else:
        verdict = "clean"
    pe = attr.get("pe_info", {}) or {}
    return {
        "sha256": sha.lower(), "verdict": verdict, "malicious": mal, "total": total,
        "label": label, "source": "VirusTotal",
        "last_analysis_utc": int(last) if isinstance(last, (int, float)) else None,
        # similarity fingerprints for variant detection (same VT response, no extra call):
        "imphash": (pe.get("imphash", "") or "").lower(),   # PE import-table hash (family/builder)
        "ssdeep": attr.get("ssdeep", "") or "",             # fuzzy hash (phase B)
        "tlsh": attr.get("tlsh", "") or "",                 # locality-sensitive hash (phase B)
        "vhash": attr.get("vhash", "") or "",               # VT's own structural hash
    }


# ---- SQLite store (keyed by sha256) -----------------------------------------
class Store:
    def __init__(self, path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.con = sqlite3.connect(path, check_same_thread=False)
        self.con.execute("PRAGMA journal_mode=WAL")
        self.con.execute("PRAGMA synchronous=NORMAL")
        self.con.execute(
            "CREATE TABLE IF NOT EXISTS reputation("
            "sha256 TEXT PRIMARY KEY, verdict TEXT, malicious INTEGER, total INTEGER,"
            "label TEXT, source TEXT, fetched_utc INTEGER, last_analysis_utc INTEGER,"
            "hits INTEGER DEFAULT 0)")
        # Idempotent migration: similarity fields for variant detection (phase A+).
        for col in ("imphash", "ssdeep", "tlsh", "vhash"):
            try:
                self.con.execute("ALTER TABLE reputation ADD COLUMN %s TEXT DEFAULT ''" % col)
            except sqlite3.OperationalError:
                pass                                   # column already exists
        self.con.execute("CREATE INDEX IF NOT EXISTS idx_imphash ON reputation(imphash)")
        # fleet first-seen: earliest sighting + sighting count across all endpoints.
        self.con.execute(
            "CREATE TABLE IF NOT EXISTS firstseen("
            "sha256 TEXT PRIMARY KEY, first_seen_utc INTEGER, last_seen_utc INTEGER,"
            "sightings INTEGER DEFAULT 0)")
        # central telemetry: alerts shipped by endpoints (AlertExporter).
        self.con.execute(
            "CREATE TABLE IF NOT EXISTS alerts("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, ts_utc INTEGER, endpoint TEXT,"
            "actor TEXT, event_type TEXT, verdict TEXT, raw TEXT)")
        self.con.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts_utc)")
        self.con.commit()
        self.lock = threading.Lock()

    def get(self, sha):
        with self.lock:
            cur = self.con.execute(
                "SELECT sha256,verdict,malicious,total,label,source,fetched_utc,last_analysis_utc,hits,"
                "imphash,ssdeep,tlsh,vhash "
                "FROM reputation WHERE sha256=?", (sha.lower(),))
            row = cur.fetchone()
        if not row:
            return None
        cols = ("sha256", "verdict", "malicious", "total", "label", "source",
                "fetched_utc", "last_analysis_utc", "hits",
                "imphash", "ssdeep", "tlsh", "vhash")
        return dict(zip(cols, row))

    def put(self, rep):
        with self.lock:
            self.con.execute(
                "INSERT INTO reputation(sha256,verdict,malicious,total,label,source,fetched_utc,last_analysis_utc,hits,"
                "imphash,ssdeep,tlsh,vhash)"
                " VALUES(?,?,?,?,?,?,?,?,0,?,?,?,?)"
                " ON CONFLICT(sha256) DO UPDATE SET verdict=excluded.verdict,malicious=excluded.malicious,"
                " total=excluded.total,label=excluded.label,source=excluded.source,"
                " fetched_utc=excluded.fetched_utc,last_analysis_utc=excluded.last_analysis_utc,"
                # keep an existing fingerprint if a later writer (e.g. endpoint POST) lacks it:
                " imphash=COALESCE(NULLIF(excluded.imphash,''),reputation.imphash),"
                " ssdeep=COALESCE(NULLIF(excluded.ssdeep,''),reputation.ssdeep),"
                " tlsh=COALESCE(NULLIF(excluded.tlsh,''),reputation.tlsh),"
                " vhash=COALESCE(NULLIF(excluded.vhash,''),reputation.vhash)",
                (rep["sha256"].lower(), rep["verdict"], rep["malicious"], rep["total"],
                 rep.get("label", ""), rep.get("source", "VirusTotal"),
                 int(time.time()), rep.get("last_analysis_utc"),
                 rep.get("imphash", ""), rep.get("ssdeep", ""), rep.get("tlsh", ""), rep.get("vhash", "")))
            self.con.commit()

    def bump_hit(self, sha):
        with self.lock:
            self.con.execute("UPDATE reputation SET hits=hits+1 WHERE sha256=?", (sha.lower(),))
            self.con.commit()

    def total_records(self):
        with self.lock:
            return self.con.execute("SELECT COUNT(*) FROM reputation").fetchone()[0]

    def register_firstseen(self, sha):
        """Record a fleet sighting. Returns (was_new, first_seen_utc, sightings).
        was_new=True means the whole fleet had never seen this hash before now."""
        sha = sha.lower()
        now = int(time.time())
        with self.lock:
            row = self.con.execute(
                "SELECT first_seen_utc, sightings FROM firstseen WHERE sha256=?", (sha,)).fetchone()
            if row:
                self.con.execute(
                    "UPDATE firstseen SET last_seen_utc=?, sightings=sightings+1 WHERE sha256=?",
                    (now, sha))
                self.con.commit()
                return (False, row[0], row[1] + 1)
            self.con.execute(
                "INSERT INTO firstseen(sha256, first_seen_utc, last_seen_utc, sightings) VALUES(?,?,?,1)",
                (sha, now, now))
            self.con.commit()
            return (True, now, 1)

    def add_alert(self, endpoint, actor, event_type, verdict, raw):
        with self.lock:
            self.con.execute(
                "INSERT INTO alerts(ts_utc, endpoint, actor, event_type, verdict, raw) VALUES(?,?,?,?,?,?)",
                (int(time.time()), endpoint, actor, event_type, verdict, raw))
            self.con.commit()

    def recent_alerts(self, limit=50):
        with self.lock:
            rows = self.con.execute(
                "SELECT id, ts_utc, endpoint, actor, event_type, verdict FROM alerts "
                "ORDER BY id DESC LIMIT ?", (int(limit),)).fetchall()
        cols = ("id", "ts_utc", "endpoint", "actor", "event_type", "verdict")
        return [dict(zip(cols, r)) for r in rows]

    def alert_count(self):
        with self.lock:
            return self.con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    def similar_by_imphash(self, imphash):
        """Aggregate verdicts + top families among stored samples sharing this imphash."""
        with self.lock:
            rows = self.con.execute(
                "SELECT verdict, label, COUNT(*) FROM reputation "
                "WHERE imphash=? AND imphash!='' GROUP BY verdict, label", (imphash,)).fetchall()
        counts = {"malicious": 0, "suspicious": 0, "clean": 0, "unknown": 0}
        labels = {}
        for verdict, label, n in rows:
            counts[verdict] = counts.get(verdict, 0) + n
            if verdict in ("malicious", "suspicious") and label:
                labels[label] = labels.get(label, 0) + n
        top = [l for l, _ in sorted(labels.items(), key=lambda kv: -kv[1])[:5]]
        return counts, top


def is_fresh(row):
    ttl = TTL.get(row["verdict"], 3600)
    if ttl is None:
        return True                                   # malicious verdicts never expire
    return (time.time() - (row["fetched_utc"] or 0)) < ttl


# ---- globals + core lookup ---------------------------------------------------
STORE = None
POOL = None
STATS = {"queries": 0, "hits": 0, "misses": 0, "vt_calls": 0, "vt_errors": 0, "posts": 0}
STATS_LOCK = threading.Lock()


def bump(name, n=1):
    with STATS_LOCK:
        STATS[name] = STATS.get(name, 0) + n


def lookup(sha, priority=False):
    """Cache-first reputation lookup. On fresh cache -> hit. On miss/stale ->
    query VT via the key pool, store, return. Fail-open to stale/unknown."""
    sha = sha.lower()
    bump("queries")
    cached = STORE.get(sha)
    if cached and is_fresh(cached):
        STORE.bump_hit(sha)
        bump("hits")
        cached["cache"] = "hit"
        return cached
    bump("misses")

    ks = POOL.acquire(priority)
    if not ks:
        # No key with quota/token right now -> return stale cache if any, else unknown.
        if cached:
            cached["cache"] = "stale"
            return cached
        return {"sha256": sha, "verdict": "unknown", "malicious": 0, "total": 0,
                "label": "", "source": "broker", "cache": "quota_exhausted"}

    bump("vt_calls")
    code, body = vt_query(ks.key, sha)
    POOL.note(ks, code)

    if code == 200 and body:
        rep = parse_vt(sha, body)
        if rep:
            STORE.put(rep)
            rep["cache"] = "miss"
            return rep
    if code == 404:
        rep = {"sha256": sha, "verdict": "unknown", "malicious": 0, "total": 0,
               "label": "", "source": "VirusTotal", "last_analysis_utc": None}
        STORE.put(rep)                                 # authoritative "not found" is cacheable
        rep["cache"] = "miss"
        return rep

    bump("vt_errors")
    if cached:                                         # VT failed -> serve stale rather than nothing
        cached["cache"] = "stale"
        return cached
    return {"sha256": sha, "verdict": "unknown", "malicious": 0, "total": 0,
            "label": "", "source": "broker", "cache": "vt_error", "http": code}


# ---- HTTP API ----------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "BulwarkBroker/1.0"

    def _send(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authed(self):
        if not TOKEN:
            return True                                # no token configured -> open (localhost only)
        supplied = self.headers.get("X-Api-Token", "") or \
            self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        return supplied == TOKEN

    def log_message(self, fmt, *args):
        pass                                           # quiet; systemd journal already timestamps

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/ping":
            return self._send(200, {"ok": True})
        if not self._authed():
            return self._send(401, {"error": "unauthorized"})
        if path == "/healthz":
            return self._send(200, {"ok": True, "records": STORE.total_records(),
                                    "alerts": STORE.alert_count(),
                                    "pool": POOL.usage(), "stats": dict(STATS)})
        if path.startswith("/rep/"):
            sha = path[len("/rep/"):].strip()
            if not SHA256_RE.match(sha):
                return self._send(400, {"error": "invalid sha256"})
            priority = self.headers.get("X-Priority", "") == "1"
            return self._send(200, lookup(sha, priority))
        if path.startswith("/similar/imphash/"):
            imphash = path[len("/similar/imphash/"):].strip().lower()
            if not re.fullmatch(r"[0-9a-f]{32}", imphash):
                return self._send(400, {"error": "invalid imphash (want 32 hex)"})
            counts, families = STORE.similar_by_imphash(imphash)
            mal, susp = counts.get("malicious", 0), counts.get("suspicious", 0)
            clean = counts.get("clean", 0)
            total = mal + susp + clean + counts.get("unknown", 0)
            # imphash is shared by benign packers/runtimes too, so this is a SOFT signal:
            # only "strong" when malicious clearly dominates. The endpoint adds score and
            # corroborates (VT/AI) rather than blocking on this alone.
            if mal >= 3 and mal >= clean:
                signal = "strong"
            elif (mal + susp) >= 1 and mal > clean:
                signal = "weak"
            else:
                signal = "none"
            return self._send(200, {"imphash": imphash, "total": total, "malicious": mal,
                                    "suspicious": susp, "clean": clean, "families": families,
                                    "signal": signal})
        if path == "/alerts":
            import urllib.parse as up
            qs = up.parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
            limit = 50
            try:
                limit = min(max(int(qs.get("limit", ["50"])[0]), 1), 500)
            except Exception:
                pass
            return self._send(200, {"alerts": STORE.recent_alerts(limit)})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._authed():
            return self._send(401, {"error": "unauthorized"})
        path = self.path.split("?", 1)[0]
        try:
            length = int(self.headers.get("Content-Length", "0"))
            data = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
        except Exception:
            return self._send(400, {"error": "bad json"})

        if path == "/rep":
            sha = str(data.get("sha256", "")).strip()
            if not SHA256_RE.match(sha):
                return self._send(400, {"error": "invalid sha256"})
            STORE.put({"sha256": sha, "verdict": data.get("verdict", "unknown"),
                       "malicious": int(data.get("malicious", 0)), "total": int(data.get("total", 0)),
                       "label": data.get("label", ""), "source": data.get("source", "endpoint"),
                       "last_analysis_utc": data.get("last_analysis_utc"),
                       "imphash": data.get("imphash", ""), "ssdeep": data.get("ssdeep", ""),
                       "tlsh": data.get("tlsh", ""), "vhash": data.get("vhash", "")})
            bump("posts")
            return self._send(200, {"ok": True})

        if path == "/firstseen":
            sha = str(data.get("sha256", "")).strip().lower()
            if not SHA256_RE.match(sha):
                return self._send(400, {"error": "invalid sha256"})
            was_new, first_utc, sightings = STORE.register_firstseen(sha)
            bump("firstseen")
            return self._send(200, {"sha256": sha, "fleet_new": was_new,
                                    "first_seen_utc": first_utc, "sightings": sightings})

        if path == "/alert":
            STORE.add_alert(str(data.get("endpoint", ""))[:128], str(data.get("actor", ""))[:512],
                            str(data.get("event_type", ""))[:64], str(data.get("verdict", ""))[:32],
                            json.dumps(data)[:8192])
            bump("alerts")
            return self._send(200, {"ok": True})

        return self._send(404, {"error": "not found"})


def main():
    global STORE, POOL
    STORE = Store(DB_PATH)
    entries = []
    if os.path.exists(KEYS_PATH):
        with open(KEYS_PATH, "r", encoding="utf-8") as f:
            raw = f.read()
        entries = [e for e in re.split(r"[,\n\r]+", raw) if e.strip()]
    POOL = KeyPool(entries)
    print("[broker] db=%s records=%d keys=%d bind=%s:%d token=%s" % (
        DB_PATH, STORE.total_records(), POOL.count(), BIND, PORT,
        "yes" if TOKEN else "NO(open)"), flush=True)
    httpd = ThreadingHTTPServer((BIND, PORT), Handler)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
