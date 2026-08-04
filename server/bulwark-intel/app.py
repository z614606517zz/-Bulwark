#!/usr/bin/env python3
"""Bulwark threat-intel aggregation / caching proxy.

Stdlib-only HTTP service that sits in front of VirusTotal + ThreatBook (微步).
All Bulwark endpoints query THIS service instead of the upstreams directly, so:
  * lookups are shared across the whole fleet via a server-side SQLite cache
    (one VT/微步 query serves every machine that later asks for the same hash),
  * upstream API keys live only here (never shipped inside client appsettings),
  * per-source rate limits / daily quotas are enforced centrally.

Responses are normalized to Bulwark's FileReputation / IpReputation shape so the
C++ / .NET ReputationManager can map them 1:1.
"""

import hashlib
import json
import os
import re
import shutil
import sqlite3
import ssl
import threading
import time
import uuid
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONFIG_PATH = os.environ.get("BULWARK_INTEL_CONFIG", "/etc/bulwark-intel/config.json")

SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")

# verdict strength ordering (for aggregating multiple sources: strongest wins)
VERDICT_RANK = {"unknown": 0, "clean": 1, "suspicious": 2, "malicious": 3}


def now_utc():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def mask_ip(ip):
    """Redact a client IP for public display: keep the first two IPv4 octets
    (rough network/ISP grouping), hide the host part -> 123.45.*.*
    IPv6: keep the first hextet -> 2001:****"""
    if not ip:
        return "?.?.?.?"
    if ":" in ip:  # IPv6
        head = ip.split(":", 1)[0]
        return (head or "::") + ":****"
    parts = ip.split(".")
    if len(parts) == 4:
        return "%s.%s.*.*" % (parts[0], parts[1])
    return "***"


def ua_short(ua):
    """Condense a User-Agent into 'Browser / OS' for display. We deliberately store
    only this summary (never the raw UA), which keeps the visitor log far less
    fingerprintable while still useful."""
    s = ua or ""
    if not s.strip():
        return "未知"
    low = s.lower()
    # crawlers / tools first (they often also carry browser tokens)
    for pat, name in (("googlebot", "Googlebot"), ("bingbot", "Bingbot"),
                      ("baiduspider", "Baiduspider"), ("yandexbot", "YandexBot"),
                      ("semrush", "SemrushBot"), ("ahrefs", "AhrefsBot"),
                      ("bot", "机器人"), ("spider", "爬虫"), ("crawl", "爬虫"),
                      ("curl", "curl"), ("wget", "wget"), ("python", "Python"),
                      ("powershell", "PowerShell"), ("go-http", "Go-http"),
                      ("java/", "Java"), ("okhttp", "OkHttp"), ("postman", "Postman")):
        if pat in low:
            browser = name
            break
    else:
        if "edg/" in low:
            browser = "Edge"
        elif "opr/" in low or "opera" in low:
            browser = "Opera"
        elif "firefox" in low:
            browser = "Firefox"
        elif "chrome" in low or "crios" in low:
            browser = "Chrome"
        elif "safari" in low:
            browser = "Safari"
        elif "msie" in low or "trident" in low:
            browser = "IE"
        else:
            browser = "其他"
    if "android" in low:
        osname = "Android"
    elif "iphone" in low or "ipad" in low or "ios" in low:
        osname = "iOS"
    elif "windows" in low:
        osname = "Windows"
    elif "mac os" in low or "macintosh" in low:
        osname = "macOS"
    elif "linux" in low:
        osname = "Linux"
    else:
        osname = ""
    out = browser + (" / " + osname if osname else "")
    return out[:40]


def parse_iso(s):
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except Exception:
        return None


def threat_category(attr, threat_label=""):
    """Broad malware category (trojan / ransomware / worm / ...). Prefer VT's
    popular_threat_category (highest count); fall back to the threat label prefix."""
    ptc = (attr or {}).get("popular_threat_classification") or {}
    if isinstance(ptc, dict):
        cats = ptc.get("popular_threat_category") or []
        if isinstance(cats, list) and cats:
            try:
                best = max(cats, key=lambda c: (c or {}).get("count", 0))
                v = (best or {}).get("value", "")
                if v:
                    return str(v).lower()
            except Exception:
                pass
        if not threat_label:
            threat_label = ptc.get("suggested_threat_label", "") or ""
    if threat_label:
        return str(threat_label).split(".")[0].split("/")[0].lower()
    return ""


# 银狐 (Silver Fox) — a China-targeting crimeware cluster. Its payloads surface under
# several family names; match on any (order = most specific first).
SILVERFOX_ALIASES = [
    ("valleyrat", "ValleyRAT"), ("winos", "Winos"), ("silverfox", "SilverFox"),
    ("silver fox", "SilverFox"), ("sainbox", "Sainbox"), ("fatalrat", "FatalRAT"),
    ("farfli", "Farfli"), ("gh0st", "Gh0st"), ("ghostrat", "Gh0st"),
    ("gh0strat", "Gh0st"), ("银狐", "银狐"),
]


def silverfox_family(report):
    """Return the 银狐 sub-family if this report looks like Silver Fox, else ''.
    Scans VT label, engine results, and every source's family (MalwareBazaar /
    ThreatBook often name it even when VT's own label is generic)."""
    report = report or {}
    f = report.get("file", {}) or {}
    hay = []
    ptc = f.get("popular_threat_classification") or {}
    if isinstance(ptc, dict):
        hay.append(ptc.get("suggested_threat_label", "") or "")
        for n in (ptc.get("popular_threat_name") or []):
            if isinstance(n, dict):
                hay.append(n.get("value", "") or "")
    res = f.get("last_analysis_results") or {}
    if isinstance(res, dict):
        for v in res.values():
            if isinstance(v, dict) and v.get("result"):
                hay.append(str(v.get("result")))
    for s in (report.get("sources") or []):
        if isinstance(s, dict):
            hay.append(str(s.get("threat_label", "") or ""))
    text = " ".join(hay).lower()
    for alias, fam in SILVERFOX_ALIASES:
        if alias in text:
            return fam
    return ""


def load_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def is_private_ipv4(ip):
    m = IPV4_RE.match(ip)
    if not m:
        return True
    b = [int(x) for x in m.groups()]
    if any(x < 0 or x > 255 for x in b):
        return True
    if b[0] == 10:
        return True
    if b[0] == 172 and 16 <= b[1] <= 31:
        return True
    if b[0] == 192 and b[1] == 168:
        return True
    if b[0] == 127 or b[0] == 0:
        return True
    if b[0] == 169 and b[1] == 254:
        return True
    if b[0] == 100 and 64 <= b[1] <= 127:
        return True
    if b[0] >= 224:
        return True
    return False


# --------------------------------------------------------------------------- #
#  Storage: shared SQLite cache + daily quota + hit/miss counters             #
# --------------------------------------------------------------------------- #
class Store:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        self._init()

    def _conn(self):
        c = sqlite3.connect(self.path, timeout=15)
        c.row_factory = sqlite3.Row
        return c

    def _init(self):
        with self.lock, self._conn() as c:
            c.execute("""CREATE TABLE IF NOT EXISTS hash_cache(
                sha256 TEXT PRIMARY KEY, verdict TEXT, malicious INTEGER,
                total_engines INTEGER, threat_label TEXT, source TEXT,
                fetched_at TEXT, expires_at TEXT, raw TEXT)""")
            c.execute("""CREATE TABLE IF NOT EXISTS ip_cache(
                ip TEXT PRIMARY KEY, verdict TEXT, threat_label TEXT, source TEXT,
                fetched_at TEXT, expires_at TEXT, raw TEXT)""")
            c.execute("""CREATE TABLE IF NOT EXISTS quota(
                source TEXT, day TEXT, count INTEGER, PRIMARY KEY(source, day))""")
            c.execute("""CREATE TABLE IF NOT EXISTS counters(
                name TEXT PRIMARY KEY, value INTEGER)""")
            # Connected local clients. Keyed by a stable per-machine id when the
            # client sends X-Bulwark-Client; otherwise by 'ip:'+source-ip (legacy).
            # "online" = last_seen within a short window. ip is kept raw here and
            # masked only at the HTTP layer.
            _cinfo = c.execute("PRAGMA table_info(clients)").fetchall()
            _ccols = [r[1] for r in _cinfo]
            if _cinfo and "id" not in _ccols:
                # migrate legacy schema (PK=ip, no id column) -> id-keyed
                c.execute("ALTER TABLE clients RENAME TO clients_legacy")
                c.execute("""CREATE TABLE clients(
                    id TEXT PRIMARY KEY, ip TEXT, first_seen TEXT, last_seen TEXT,
                    hits INTEGER DEFAULT 0)""")
                c.execute("""INSERT OR IGNORE INTO clients(id, ip, first_seen, last_seen, hits)
                    SELECT 'ip:'||ip, ip, first_seen, last_seen, hits FROM clients_legacy""")
                c.execute("DROP TABLE clients_legacy")
            else:
                c.execute("""CREATE TABLE IF NOT EXISTS clients(
                    id TEXT PRIMARY KEY, ip TEXT, first_seen TEXT, last_seen TEXT,
                    hits INTEGER DEFAULT 0)""")
            c.execute("CREATE INDEX IF NOT EXISTS idx_clients_seen ON clients(last_seen)")
            # Web page visitors (browsers hitting the site), kept separate from the
            # API clients above: one summary row per source IP + a capped detail log.
            # ip is stored raw and masked only at the HTTP layer; the UA is stored
            # already condensed (see ua_short) so no raw fingerprint is retained.
            c.execute("""CREATE TABLE IF NOT EXISTS visitors(
                ip TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT,
                hits INTEGER DEFAULT 0, last_path TEXT, agent TEXT)""")
            c.execute("CREATE INDEX IF NOT EXISTS idx_visitors_seen ON visitors(last_seen)")
            c.execute("""CREATE TABLE IF NOT EXISTS visit_log(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                at TEXT, ip TEXT, path TEXT, agent TEXT)""")
            c.execute("CREATE INDEX IF NOT EXISTS idx_visitlog_at ON visit_log(at)")
            # Permanent VT report store (NO TTL): full file report + behaviour summary.
            c.execute("""CREATE TABLE IF NOT EXISTS vt_reports(
                sha256 TEXT PRIMARY KEY, md5 TEXT, sha1 TEXT, name TEXT,
                verdict TEXT, malicious INTEGER, total_engines INTEGER,
                stored_at TEXT, report TEXT, threat_label TEXT DEFAULT '',
                category TEXT DEFAULT '', silverfox TEXT DEFAULT '')""")
            c.execute("CREATE INDEX IF NOT EXISTS idx_vt_md5 ON vt_reports(md5)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_vt_sha1 ON vt_reports(sha1)")
            # migrate older DBs: add threat_label / category columns + backfill from stored report JSON
            cols = [r[1] for r in c.execute("PRAGMA table_info(vt_reports)").fetchall()]
            if "threat_label" not in cols:
                c.execute("ALTER TABLE vt_reports ADD COLUMN threat_label TEXT DEFAULT ''")
                for sha, rep in c.execute("SELECT sha256, report FROM vt_reports").fetchall():
                    try:
                        attr = (json.loads(rep) or {}).get("file", {}) or {}
                        ptc = attr.get("popular_threat_classification") or {}
                        lbl = ptc.get("suggested_threat_label", "") if isinstance(ptc, dict) else ""
                    except Exception:
                        lbl = ""
                    if lbl:
                        c.execute("UPDATE vt_reports SET threat_label=? WHERE sha256=?", (lbl, sha))
            if "category" not in cols:
                c.execute("ALTER TABLE vt_reports ADD COLUMN category TEXT DEFAULT ''")
                for sha, rep in c.execute("SELECT sha256, report FROM vt_reports").fetchall():
                    try:
                        attr = (json.loads(rep) or {}).get("file", {}) or {}
                        cat = threat_category(attr)
                    except Exception:
                        cat = ""
                    if cat:
                        c.execute("UPDATE vt_reports SET category=? WHERE sha256=?", (cat, sha))
            if "silverfox" not in cols:
                c.execute("ALTER TABLE vt_reports ADD COLUMN silverfox TEXT DEFAULT ''")
                for sha, rep in c.execute("SELECT sha256, report FROM vt_reports").fetchall():
                    try:
                        fam = silverfox_family(json.loads(rep) if rep else {})
                    except Exception:
                        fam = ""
                    if fam:
                        c.execute("UPDATE vt_reports SET silverfox=? WHERE sha256=?", (fam, sha))

    # ---- cache lookups ----------------------------------------------------- #
    def get_hash(self, sha):
        with self.lock, self._conn() as c:
            row = c.execute("SELECT * FROM hash_cache WHERE sha256=?", (sha,)).fetchone()
        if not row:
            return None
        exp = parse_iso(row["expires_at"])
        if exp and exp < now_utc():
            return None  # expired -> treat as miss (caller will refresh)
        return dict(row)

    def put_hash(self, rec):
        with self.lock, self._conn() as c:
            c.execute("""INSERT INTO hash_cache
                (sha256, verdict, malicious, total_engines, threat_label, source, fetched_at, expires_at, raw)
                VALUES (?,?,?,?,?,?,?,?,?)
                ON CONFLICT(sha256) DO UPDATE SET
                    verdict=excluded.verdict, malicious=excluded.malicious,
                    total_engines=excluded.total_engines, threat_label=excluded.threat_label,
                    source=excluded.source, fetched_at=excluded.fetched_at,
                    expires_at=excluded.expires_at, raw=excluded.raw""",
                      (rec["sha256"], rec["verdict"], rec["malicious"], rec["total_engines"],
                       rec["threat_label"], rec["source"], rec["fetched_at"],
                       rec["expires_at"], rec.get("raw", "")))

    def get_ip(self, ip):
        with self.lock, self._conn() as c:
            row = c.execute("SELECT * FROM ip_cache WHERE ip=?", (ip,)).fetchone()
        if not row:
            return None
        exp = parse_iso(row["expires_at"])
        if exp and exp < now_utc():
            return None
        return dict(row)

    def put_ip(self, rec):
        with self.lock, self._conn() as c:
            c.execute("""INSERT INTO ip_cache
                (ip, verdict, threat_label, source, fetched_at, expires_at, raw)
                VALUES (?,?,?,?,?,?,?)
                ON CONFLICT(ip) DO UPDATE SET
                    verdict=excluded.verdict, threat_label=excluded.threat_label,
                    source=excluded.source, fetched_at=excluded.fetched_at,
                    expires_at=excluded.expires_at, raw=excluded.raw""",
                      (rec["ip"], rec["verdict"], rec["threat_label"], rec["source"],
                       rec["fetched_at"], rec["expires_at"], rec.get("raw", "")))

    # ---- daily quota ------------------------------------------------------- #
    def quota_used(self, source):
        day = now_utc().strftime("%Y-%m-%d")
        with self.lock, self._conn() as c:
            row = c.execute("SELECT count FROM quota WHERE source=? AND day=?", (source, day)).fetchone()
        return row["count"] if row else 0

    def quota_incr(self, source, n=1):
        day = now_utc().strftime("%Y-%m-%d")
        n = max(1, int(n))
        with self.lock, self._conn() as c:
            c.execute("""INSERT INTO quota(source, day, count) VALUES (?,?,?)
                ON CONFLICT(source, day) DO UPDATE SET count=count+?""", (source, day, n, n))

    def counter_incr(self, name, n=1):
        with self.lock, self._conn() as c:
            c.execute("""INSERT INTO counters(name, value) VALUES (?,?)
                ON CONFLICT(name) DO UPDATE SET value=value+?""", (name, n, n))

    def counters(self):
        with self.lock, self._conn() as c:
            rows = c.execute("SELECT name, value FROM counters").fetchall()
            hc = c.execute("SELECT COUNT(*) n FROM hash_cache").fetchone()["n"]
            ic = c.execute("SELECT COUNT(*) n FROM ip_cache").fetchone()["n"]
        out = {r["name"]: r["value"] for r in rows}
        out["hash_cache_rows"] = hc
        out["ip_cache_rows"] = ic
        return out

    # ---- connected local clients ------------------------------------------ #
    def touch_client(self, ip, client_id=None):
        """Record a heartbeat from a local client (called on each reputation query).
        Dedup key: the stable per-machine client_id when supplied, else 'ip:'+ip
        (so NAT-shared IPs still collapse to one row until the client ships an id)."""
        cid = (client_id or "").strip()
        key = cid if cid else ("ip:" + (ip or "?"))
        now = iso(now_utc())
        with self.lock, self._conn() as c:
            c.execute("""INSERT INTO clients(id, ip, first_seen, last_seen, hits)
                VALUES (?,?,?,?,1)
                ON CONFLICT(id) DO UPDATE SET ip=excluded.ip,
                    last_seen=excluded.last_seen, hits=hits+1""",
                      (key, ip or "", now, now))

    def clients_stats(self, window_min=15, limit=500):
        """online = distinct clients seen within window_min minutes. A client is a
        machine (when it sends a stable id) or a source IP (legacy fallback).
        Returns raw IPs; the HTTP layer masks them before display."""
        cutoff = (now_utc() - timedelta(minutes=window_min)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self.lock, self._conn() as c:
            online = c.execute("SELECT COUNT(*) n FROM clients WHERE last_seen>=?",
                               (cutoff,)).fetchone()["n"]
            total = c.execute("SELECT COUNT(*) n FROM clients").fetchone()["n"]
            hits = c.execute("SELECT COALESCE(SUM(hits),0) s FROM clients").fetchone()["s"]
            identified = c.execute("SELECT COUNT(*) n FROM clients WHERE id NOT LIKE 'ip:%'").fetchone()["n"]
            rows = c.execute("""SELECT id, ip, first_seen, last_seen, hits FROM clients
                ORDER BY last_seen DESC LIMIT ?""", (limit,)).fetchall()
        clients = [{"ip": r["ip"], "first_seen": r["first_seen"], "last_seen": r["last_seen"],
                    "hits": r["hits"], "online": r["last_seen"] >= cutoff,
                    "by_machine": not str(r["id"]).startswith("ip:")} for r in rows]
        return {"online": online, "total": total, "total_hits": hits, "identified": identified,
                "window_min": window_min, "clients": clients}

    # ---- web page visitors ------------------------------------------------- #
    LOG_CAP = 500  # keep only the newest N rows of visit_log (bounded growth)

    def touch_visitor(self, ip, path, agent):
        """Record one web page view. agent must already be condensed (ua_short)."""
        now = iso(now_utc())
        p = (path or "/")[:120]
        a = (agent or "")[:40]
        with self.lock, self._conn() as c:
            c.execute("""INSERT INTO visitors(ip, first_seen, last_seen, hits, last_path, agent)
                VALUES (?,?,?,1,?,?)
                ON CONFLICT(ip) DO UPDATE SET last_seen=excluded.last_seen, hits=hits+1,
                    last_path=excluded.last_path, agent=excluded.agent""",
                      (ip or "", now, now, p, a))
            c.execute("INSERT INTO visit_log(at, ip, path, agent) VALUES (?,?,?,?)",
                      (now, ip or "", p, a))
            # trim the detail log so it can never grow without bound
            c.execute("""DELETE FROM visit_log WHERE id NOT IN
                (SELECT id FROM visit_log ORDER BY id DESC LIMIT ?)""", (self.LOG_CAP,))

    def visitors_stats(self, window_min=15, top=40, recent=40):
        """Visitor summary: currently-active count, unique totals, today's views,
        the most active visitors and the newest individual views."""
        cutoff = (now_utc() - timedelta(minutes=window_min)).strftime("%Y-%m-%dT%H:%M:%SZ")
        today = now_utc().strftime("%Y-%m-%d")
        with self.lock, self._conn() as c:
            active = c.execute("SELECT COUNT(*) n FROM visitors WHERE last_seen>=?",
                               (cutoff,)).fetchone()["n"]
            uniq = c.execute("SELECT COUNT(*) n FROM visitors").fetchone()["n"]
            views = c.execute("SELECT COALESCE(SUM(hits),0) s FROM visitors").fetchone()["s"]
            today_views = c.execute("SELECT COUNT(*) n FROM visit_log WHERE at LIKE ?",
                                    (today + "%",)).fetchone()["n"]
            vrows = c.execute("""SELECT ip, first_seen, last_seen, hits, last_path, agent
                FROM visitors ORDER BY last_seen DESC LIMIT ?""", (top,)).fetchall()
            lrows = c.execute("""SELECT at, ip, path, agent FROM visit_log
                ORDER BY id DESC LIMIT ?""", (recent,)).fetchall()
        visitors = [{"ip": r["ip"], "first_seen": r["first_seen"], "last_seen": r["last_seen"],
                     "hits": r["hits"], "last_path": r["last_path"], "agent": r["agent"],
                     "active": r["last_seen"] >= cutoff} for r in vrows]
        log = [{"at": r["at"], "ip": r["ip"], "path": r["path"], "agent": r["agent"]}
               for r in lrows]
        return {"active": active, "unique": uniq, "views": views, "today_views": today_views,
                "window_min": window_min, "visitors": visitors, "log": log}

    # ---- 攻击链组合引擎(表由 engine_build.py 建立/刷新) --------------------- #
    # 本服务只【读】这些表:构建由 engine_build.py 每日跑一次。这样 HTTP 层永远不会
    # 因为挖掘计算而卡顿,构建脚本挂了也只是特征库不更新,不影响在线查询。
    def engine_tables_ready(self):
        with self.lock, self._conn() as c:
            n = c.execute("""SELECT COUNT(*) n FROM sqlite_master
                             WHERE type='table' AND name IN
                             ('engine_markers','engine_patterns','engine_versions')""").fetchone()["n"]
        return n == 3

    def engine_manifest(self):
        """当前特征库版本与统计。未构建过则 version=0(客户端据此判断"无库可拉")。"""
        empty = {"version": 0, "label": "", "built_at": "", "samples": 0, "markers": 0,
                 "patterns": 0, "grades": {}, "stats": {}}
        if not self.engine_tables_ready():
            return dict(empty)
        with self.lock, self._conn() as c:
            # label 是后加的列(展示用版本号,0.1 起 +0.1);老库没有这列时降级为空串,
            # 客户端会回退显示内部整数版本号。
            cols = [r[1] for r in c.execute("PRAGMA table_info(engine_versions)")]
            lab = ", label" if "label" in cols else ""
            v = c.execute("""SELECT version, built_at, samples, markers, patterns, stats%s
                             FROM engine_versions ORDER BY version DESC LIMIT 1""" % lab).fetchone()
            grades = {r["grade"]: r["n"] for r in c.execute(
                "SELECT grade, COUNT(*) n FROM engine_patterns GROUP BY grade")}
        if not v:
            return dict(empty)
        try:
            stats = json.loads(v["stats"] or "{}")
        except Exception:
            stats = {}
        return {"version": v["version"], "label": (v["label"] if lab else "") or "",
                "built_at": v["built_at"], "samples": v["samples"],
                "markers": v["markers"], "patterns": v["patterns"],
                "grades": grades, "stats": stats}

    def engine_patterns(self, min_grade=None):
        """组合规则 + 用到的标记定义。客户端一次拉全量(体量很小,不必做增量分块)。"""
        if not self.engine_tables_ready():
            return {"patterns": [], "markers": {}}
        want = {"hard", "strong", "ask"}
        if min_grade == "hard":
            want = {"hard"}
        elif min_grade == "strong":
            want = {"hard", "strong"}
        with self.lock, self._conn() as c:
            # benign_support / benign_samples 是后加的列(区分度)。老库缺列时降级为 0 ——
            # 这与「还没有正常语料」语义一致,页面会照实显示「区分度未知」。
            pcols = [r[1] for r in c.execute("PRAGMA table_info(engine_patterns)")]
            bsup_sel = ", benign_support" if "benign_support" in pcols else ""
            rows = c.execute("""SELECT markers, n, support, grade, max_level, families%s
                                FROM engine_patterns ORDER BY support DESC, n DESC"""
                             % bsup_sel).fetchall()
            # match_json 是后加的列;老库可能还没有,缺列时降级为不下发匹配条件。
            cols = [r[1] for r in c.execute("PRAGMA table_info(engine_markers)")]
            extra = ", observable, bulwark_event, match_json" if "match_json" in cols else ""
            bsam = ", benign_samples" if "benign_samples" in cols else ""
            mrows = c.execute("SELECT id, title, level, source, samples%s%s "
                              "FROM engine_markers" % (extra, bsam)).fetchall()
        pats = []
        used = set()
        for r in rows:
            if r["grade"] not in want:
                continue
            ids = [x for x in (r["markers"] or "").split("|") if x]
            used.update(ids)
            pats.append({"markers": ids, "n": r["n"], "support": r["support"],
                         "grade": r["grade"], "max_level": r["max_level"],
                         "families": r["families"] or "",
                         "benign_support": (r["benign_support"] if bsup_sel else 0) or 0})
        markers = {}
        for m in mrows:
            if m["id"] not in used:
                continue
            rec = {"title": m["title"], "level": m["level"],
                   "source": m["source"], "samples": m["samples"],
                   "benign_samples": (m["benign_samples"] if bsam else 0) or 0}
            if extra:
                # 客户端据此自行判定标记是否置位。match 的字段名与 DefenseRule 一致
                # (actor/target/cmdline/parent/unsigned),故客户端可直接复用现成的匹配实现。
                rec["observable"] = bool(m["observable"])
                rec["event"] = m["bulwark_event"] or ""
                try:
                    rec["match"] = json.loads(m["match_json"] or "{}")
                except Exception:
                    rec["match"] = {}
            markers[m["id"]] = rec
        return {"patterns": pats, "markers": markers}

    # ---- permanent VT report store (no TTL) -------------------------------- #
    # ---- sandbox behaviour store ------------------------------------------- #
    BEHAVIOUR_DDL = ("CREATE TABLE IF NOT EXISTS behaviour_reports ("
                     "sha256 TEXT PRIMARY KEY, source TEXT, fetched_at TEXT, report TEXT)")

    def save_behaviour(self, sha, report):
        with self.lock, self._conn() as c:
            c.execute(self.BEHAVIOUR_DDL)
            c.execute("INSERT INTO behaviour_reports(sha256, source, fetched_at, report) "
                      "VALUES (?,?,?,?) ON CONFLICT(sha256) DO UPDATE SET "
                      "source=excluded.source, fetched_at=excluded.fetched_at, "
                      "report=excluded.report",
                      (sha, report.get("source", ""), iso(now_utc()),
                       json.dumps(report, ensure_ascii=False)))

    def get_behaviour(self, sha):
        with self.lock, self._conn() as c:
            c.execute(self.BEHAVIOUR_DDL)
            row = c.execute("SELECT * FROM behaviour_reports WHERE sha256=?", (sha,)).fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["report"] = json.loads(d["report"]) if d["report"] else {}
        except Exception:
            d["report"] = {}
        return d

    def behaviour_count(self):
        with self.lock, self._conn() as c:
            c.execute(self.BEHAVIOUR_DDL)
            return c.execute("SELECT COUNT(*) n FROM behaviour_reports").fetchone()["n"]

    # ---- benign corpus (正常样本语料) --------------------------------------- #
    #
    # 为什么要单独一张表,而不是放开 vt_reports 的留存策略:
    #   1. vt_reports 是【威胁归档】—— 归档列表、计数器、家族分布、分类统计全都假定
    #      里面每一行都是威胁。混进干净文件会让那些数字全部失真。
    #   2. lookup_hash 命中 vt_reports 就直接当缓存返回。若为了省空间存精简报告,
    #      后续查询就会拿到被削过的报告,威胁分析台的展示随之退化。
    #   3. 留存上限与清理策略跟威胁归档完全不同 —— 威胁要永久留,语料是滚动窗口。
    #
    # 只存挖掘真正用得到的字段,一行几 KB 而非上百 KB。字段形状与完整报告保持一致
    # (file/behaviour 两层),这样 engine_build.py 的 extract_markers 可以原样复用。
    BENIGN_DDL = ("CREATE TABLE IF NOT EXISTS benign_reports ("
                  "sha256 TEXT PRIMARY KEY, stored_at TEXT, type_tag TEXT, name TEXT, "
                  "signed INTEGER DEFAULT 0, markers INTEGER DEFAULT 0, report TEXT)")

    # 滚动窗口上限。语料是用来算出现率的,不需要无限留存;超出后按入库时间淘汰最旧的。
    BENIGN_MAX_ROWS = 20000

    @staticmethod
    def slim_benign_report(sha256, attr, behaviour):
        """把完整 VT 报告削成语料需要的最小形状。

        刻意保留 signature_info:后面要做「按签名状态给正常样本分层」时用得上,
        而重新去 VT 拉一遍代价远高于现在多存几百字节。
        """
        sig = attr.get("signature_info") or {}
        return {
            "id": sha256,
            "file": {
                "type_tag": attr.get("type_tag") or "",
                "meaningful_name": attr.get("meaningful_name") or "",
                "last_analysis_stats": attr.get("last_analysis_stats") or {},
                "popular_threat_classification": {},
                "signature_info": {k: sig.get(k) for k in
                                   ("verified", "signers", "product", "description")
                                   if sig.get(k)},
            },
            # sigma_analysis_results 是挖掘唯一消费的行为字段(见 engine_build.extract_markers)
            "behaviour": {"sigma_analysis_results":
                          (behaviour.get("sigma_analysis_results") or [])},
            "behaviour_available": True,
        }

    def save_benign_report(self, sha256, attr, behaviour):
        """留存一个正常样本。返回 True 表示确实入库了。

        【没有 sigma 命中的样本也要存】。它不是"无用样本",而是分母的一部分 ——
        「这个行为在正常软件里并不普遍」的正面证据。只存有命中的会系统性高估出现率,
        那比没有语料更危险(会把真规则砍掉、把假规则留下)。
        """
        slim = self.slim_benign_report(sha256, attr, behaviour)
        sig = slim["file"]["signature_info"]
        n_marks = len(slim["behaviour"]["sigma_analysis_results"])
        with self.lock, self._conn() as c:
            c.execute(self.BENIGN_DDL)
            c.execute("INSERT INTO benign_reports(sha256, stored_at, type_tag, name, "
                      "signed, markers, report) VALUES (?,?,?,?,?,?,?) "
                      "ON CONFLICT(sha256) DO UPDATE SET stored_at=excluded.stored_at, "
                      "type_tag=excluded.type_tag, name=excluded.name, "
                      "signed=excluded.signed, markers=excluded.markers, "
                      "report=excluded.report",
                      (sha256, iso(now_utc()), slim["file"]["type_tag"],
                       slim["file"]["meaningful_name"],
                       1 if str(sig.get("verified", "")).lower() == "signed" else 0,
                       n_marks, json.dumps(slim, ensure_ascii=False)))
            n = c.execute("SELECT COUNT(*) n FROM benign_reports").fetchone()["n"]
            if n > self.BENIGN_MAX_ROWS:
                c.execute("DELETE FROM benign_reports WHERE sha256 IN ("
                          "SELECT sha256 FROM benign_reports ORDER BY stored_at ASC LIMIT ?)",
                          (n - self.BENIGN_MAX_ROWS,))
        return True

    def benign_stats(self):
        """语料概况。网页与引擎页都要显示 —— 语料规模直接决定区分度能不能用。"""
        with self.lock, self._conn() as c:
            c.execute(self.BENIGN_DDL)
            r = c.execute("SELECT COUNT(*) n, "
                          "SUM(CASE WHEN markers>0 THEN 1 ELSE 0 END) with_marks, "
                          "SUM(signed) signed, MIN(stored_at) oldest, MAX(stored_at) newest "
                          "FROM benign_reports").fetchone()
        return {"total": r["n"] or 0, "with_markers": r["with_marks"] or 0,
                "signed": r["signed"] or 0, "oldest": r["oldest"] or "",
                "newest": r["newest"] or "", "cap": self.BENIGN_MAX_ROWS}

    def save_vt_report(self, meta, report):
        with self.lock, self._conn() as c:
            c.execute("""INSERT INTO vt_reports
                (sha256, md5, sha1, name, verdict, malicious, total_engines, stored_at, report, threat_label, category, silverfox)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(sha256) DO UPDATE SET
                    md5=excluded.md5, sha1=excluded.sha1, name=excluded.name,
                    verdict=excluded.verdict, malicious=excluded.malicious,
                    total_engines=excluded.total_engines, stored_at=excluded.stored_at,
                    report=excluded.report, threat_label=excluded.threat_label,
                    category=excluded.category, silverfox=excluded.silverfox""",
                      (meta["sha256"], meta.get("md5", ""), meta.get("sha1", ""),
                       meta.get("name", ""), meta.get("verdict", "unknown"),
                       int(meta.get("malicious", 0)), int(meta.get("total_engines", 0)),
                       iso(now_utc()), json.dumps(report, ensure_ascii=False),
                       meta.get("threat_label", ""), meta.get("category", ""),
                       silverfox_family(report)))

    def get_vt_report(self, ident):
        key = ident.strip().lower()
        with self.lock, self._conn() as c:
            row = c.execute("SELECT * FROM vt_reports WHERE sha256=? OR md5=? OR sha1=?",
                            (key, key, key)).fetchone()
        if not row:
            return None
        d = dict(row)
        try:
            d["report"] = json.loads(d["report"]) if d["report"] else {}
        except Exception:
            d["report"] = {}
        return d

    def list_vt_reports(self, limit=300):
        with self.lock, self._conn() as c:
            rows = c.execute(
                """SELECT sha256, md5, sha1, name, verdict, malicious, total_engines, stored_at, threat_label, category, silverfox
                   FROM vt_reports ORDER BY stored_at DESC LIMIT ?""", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def vt_report_count(self):
        with self.lock, self._conn() as c:
            return c.execute("SELECT COUNT(*) n FROM vt_reports").fetchone()["n"]

    def archive_stats(self, recent_days=7):
        """Absolute counters over the whole vt_reports table.

        The archive list is capped (list_vt_reports LIMIT), so counting in the
        browser over that slice made every figure move whenever the harvester
        ran. Counting here keeps them stable and truthful.
        """
        cutoff = (now_utc() - timedelta(days=recent_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self.lock, self._conn() as c:
            r = c.execute(
                """SELECT COUNT(*) total,
                          SUM(CASE WHEN verdict='malicious'  THEN 1 ELSE 0 END) malicious,
                          SUM(CASE WHEN verdict='suspicious' THEN 1 ELSE 0 END) suspicious,
                          SUM(CASE WHEN silverfox IS NOT NULL AND silverfox<>'' THEN 1 ELSE 0 END) silverfox,
                          SUM(CASE WHEN stored_at>=? THEN 1 ELSE 0 END) recent
                   FROM vt_reports""", (cutoff,)).fetchone()
            fam = c.execute(
                """SELECT silverfox fam, COUNT(*) n FROM vt_reports
                   WHERE silverfox IS NOT NULL AND silverfox<>''
                   GROUP BY silverfox ORDER BY n DESC""").fetchall()
        return {"total": r["total"] or 0,
                "malicious": r["malicious"] or 0,
                "suspicious": r["suspicious"] or 0,
                "silverfox": r["silverfox"] or 0,
                "recent": r["recent"] or 0,
                "recent_days": recent_days,
                "silverfox_families": [{"family": x["fam"], "count": x["n"]} for x in fam]}

    def list_silverfox(self, limit=800):
        """Every SilverFox-family hit, including ones older than the archive window."""
        with self.lock, self._conn() as c:
            rows = c.execute(
                """SELECT sha256, md5, sha1, name, verdict, malicious, total_engines,
                          stored_at, threat_label, category, silverfox
                   FROM vt_reports
                   WHERE silverfox IS NOT NULL AND silverfox<>''
                   ORDER BY stored_at DESC LIMIT ?""", (limit,)).fetchall()
        return [dict(r) for r in rows]


# --------------------------------------------------------------------------- #
#  Per-source rate limiter: per-minute sliding window + per-day quota          #
# --------------------------------------------------------------------------- #
class RateLimiter:
    def __init__(self, store):
        self.store = store
        self.lock = threading.Lock()
        self.minute_hits = {}  # source -> [timestamps]

    def allow(self, source, per_minute, per_day):
        now = time.time()
        with self.lock:
            hits = [t for t in self.minute_hits.get(source, []) if now - t < 60]
            if per_minute and len(hits) >= per_minute:
                return False, "per-minute limit"
            if per_day and self.store.quota_used(source) >= per_day:
                return False, "per-day quota"
            hits.append(now)
            self.minute_hits[source] = hits
        self.store.quota_incr(source)
        return True, ""


class IPThrottle:
    """Per-client-IP sliding-window limiter for the open endpoints (anti-abuse).
    Keeps the public web tool / client working while stopping a single IP from
    hammering the shared upstream quota."""
    def __init__(self, per_minute=60, per_hour=600):
        self.per_minute = per_minute
        self.per_hour = per_hour
        self.lock = threading.Lock()
        self.hits = {}  # ip -> [timestamps]

    def allow(self, ip):
        now = time.time()
        with self.lock:
            arr = [t for t in self.hits.get(ip, []) if now - t < 3600]
            if self.per_minute and sum(1 for t in arr if now - t < 60) >= self.per_minute:
                self.hits[ip] = arr
                return False, 60
            if self.per_hour and len(arr) >= self.per_hour:
                self.hits[ip] = arr
                return False, 3600
            arr.append(now)
            self.hits[ip] = arr
            if len(self.hits) > 5000:  # opportunistic cleanup
                self.hits = {k: v for k, v in self.hits.items() if v and now - v[-1] < 3600}
            return True, 0


# --------------------------------------------------------------------------- #
#  Upstream clients                                                            #
# --------------------------------------------------------------------------- #
def http_get(url, headers, timeout):
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read()


def http_post(url, data, headers, timeout):
    body = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read()


class VirusTotalClient:
    NAME = "VirusTotal"
    VT_FILES = "https://www.virustotal.com/api/v3/files/"

    def __init__(self, cfg):
        self.cfg = cfg
        raw = cfg.get("api_keys")
        if not raw:
            single = cfg.get("api_key", "")
            raw = [single] if single else []
        seen, self.keys = set(), []
        for item in raw:
            k = str(item).split(":")[0].strip()          # accept "KEY" or "KEY:perday:permin"
            if len(k) == 64 and all(c in "0123456789abcdefABCDEF" for c in k) and k not in seen:
                seen.add(k)
                self.keys.append(k)
        self._lock = threading.Lock()
        self._idx = 0
        self._cooldown = {}                               # key -> epoch until usable again

    def has_key(self):
        return len(self.keys) > 0

    def key_count(self):
        return len(self.keys)

    def _next_key(self):
        now = time.time()
        chosen = None
        with self._lock:
            n = len(self.keys)
            for _ in range(n):
                k = self.keys[self._idx % n]
                self._idx += 1
                if self._cooldown.get(k, 0) <= now:
                    chosen = k
                    break
        # Deliberately outside the lock: quota_incr writes to SQLite and must not
        # serialise key handout. Only a real handout is charged -- returning None
        # (all keys cooling down) spends nothing.
        if chosen is not None:
            _vt_spend()
        return chosen

    def _note(self, key, code):
        if code == 429:
            self._cooldown[key] = time.time() + 60         # rate limited -> rest this key 60s
        elif code in (401, 403):
            self._cooldown[key] = time.time() + 6 * 3600   # bad/blocked key -> park it 6h

    def query_hash(self, sha):
        if not self.keys:
            return {"querySucceeded": False, "reason": "no api key"}
        timeout = self.cfg.get("timeout_seconds", 10)
        threshold = int(self.cfg.get("malicious_threshold", 5))
        reason = "all keys cooling down"
        for _ in range(min(5, len(self.keys))):            # rotate through a few keys on 429/auth
            key = self._next_key()
            if key is None:
                return {"querySucceeded": False, "reason": "all keys cooling down"}
            try:
                status, body = http_get(self.VT_FILES + sha, {"x-apikey": key}, timeout)
            except urllib.error.HTTPError as e:
                self._note(key, e.code)
                if e.code == 404:
                    return {"querySucceeded": True, "verdict": "unknown", "malicious": 0,
                            "total_engines": 0, "threat_label": "", "source": self.NAME}
                if e.code in (429, 401, 403):
                    reason = "http %d" % e.code
                    continue                               # rotate to next key
                return {"querySucceeded": False, "reason": "http %d" % e.code}
            except Exception as e:
                reason = str(e)
                continue
            try:
                attr = json.loads(body)["data"]["attributes"]
                stats = attr.get("last_analysis_stats", {}) or {}
                mal = int(stats.get("malicious", 0))
                susp = int(stats.get("suspicious", 0))
                total = (mal + susp + int(stats.get("harmless", 0))
                         + int(stats.get("undetected", 0)) + int(stats.get("timeout", 0)))
                label = ""
                ptc = attr.get("popular_threat_classification") or {}
                if isinstance(ptc, dict):
                    label = ptc.get("suggested_threat_label", "") or ""
                if mal >= threshold:
                    verdict = "malicious"
                elif mal > 0 or susp > 0:
                    verdict = "suspicious"
                else:
                    verdict = "clean"
                return {"querySucceeded": True, "verdict": verdict, "malicious": mal,
                        "total_engines": total, "threat_label": label, "source": self.NAME}
            except Exception as e:
                return {"querySucceeded": False, "reason": "parse: %s" % e}
        return {"querySucceeded": False, "reason": reason}

    def vt_api_get(self, path):
        """GET an arbitrary VT v3 API path (e.g. '/files/<id>' or
        '/files/<id>/behaviour_summary'), rotating keys on 429/auth.
        Returns (http_status, text); status 0 => transport error / no key."""
        if not self.keys:
            return (0, "")
        url = "https://www.virustotal.com/api/v3" + path
        timeout = int(self.cfg.get("report_timeout_seconds",
                                   max(20, int(self.cfg.get("timeout_seconds", 10)))))
        last = 0
        for _ in range(min(6, len(self.keys))):
            key = self._next_key()
            if key is None:
                return (429, "")
            try:
                status, body = http_get(url, {"x-apikey": key}, timeout)
                text = body.decode("utf-8", "replace") if isinstance(body, (bytes, bytearray)) else str(body)
                return (status, text)
            except urllib.error.HTTPError as e:
                self._note(key, e.code)
                if e.code in (429, 401, 403):
                    last = e.code
                    continue  # rotate to another key
                try:
                    return (e.code, e.read().decode("utf-8", "replace"))
                except Exception:
                    return (e.code, "")
            except Exception:
                last = 0
                continue
        return (last, "")

    def submit_file_path(self, path, filename, size):
        """Upload a spooled sample file to VirusTotal for analysis. The multipart
        body is built on disk and streamed, so large samples (up to VT's 650MB
        limit) never sit fully in RAM. Returns (analysis_id, error)."""
        if not self.keys:
            return (None, "no api key")
        safe = "".join(ch for ch in (filename or "sample.bin")
                       if ch.isprintable() and ch not in '"\\\r\n')[:120] or "sample.bin"
        boundary = "----bulwark%s" % uuid.uuid4().hex
        pre = ("--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"
               "Content-Type: application/octet-stream\r\n\r\n" % (boundary, safe)).encode("utf-8")
        post = ("\r\n--%s--\r\n" % boundary).encode("utf-8")
        mp_path = path + ".mp"
        try:
            with open(mp_path, "wb") as out:
                out.write(pre)
                with open(path, "rb") as src:
                    shutil.copyfileobj(src, out, 1024 * 1024)
                out.write(post)
            mp_size = os.path.getsize(mp_path)
            for _ in range(min(3, len(self.keys))):
                key = self._next_key()
                if key is None:
                    return (None, "all keys cooling down")
                upload_url = "https://www.virustotal.com/api/v3/files"
                try:
                    if size > 32 * 1024 * 1024:            # >32MB needs a dedicated upload URL
                        st, b = http_get("https://www.virustotal.com/api/v3/files/upload_url",
                                         {"x-apikey": key}, 30)
                        upload_url = json.loads(b)["data"]
                        _vt_spend()   # the upload_url GET is a second VT request
                except urllib.error.HTTPError as e:
                    self._note(key, e.code)
                    if e.code in (429, 401, 403):
                        continue
                    return (None, "upload_url http %d" % e.code)
                except Exception as e:
                    return (None, "upload_url: %s" % e)
                try:
                    with open(mp_path, "rb") as body:      # streamed by http.client in blocks
                        req = urllib.request.Request(
                            upload_url, data=body, method="POST",
                            headers={"x-apikey": key,
                                     "Content-Type": "multipart/form-data; boundary=%s" % boundary,
                                     "Content-Length": str(mp_size)})
                        with urllib.request.urlopen(req, timeout=600) as r:
                            j = json.loads(r.read().decode("utf-8", "replace"))
                            return (j.get("data", {}).get("id"), None)
                except urllib.error.HTTPError as e:
                    self._note(key, e.code)
                    if e.code in (429, 401, 403):
                        continue
                    return (None, "upload http %d" % e.code)
                except Exception as e:
                    return (None, str(e))
            return (None, "all keys busy")
        finally:
            try:
                os.remove(mp_path)
            except OSError:
                pass

    def get_analysis(self, analysis_id):
        """Poll a VT analysis. Returns {status, stats, sha256}."""
        st, body = self.vt_api_get("/analyses/" + analysis_id)
        if st != 200:
            return {"status": "error", "http": st}
        try:
            d = json.loads(body)
            attr = (d.get("data", {}) or {}).get("attributes", {}) or {}
            sha = ((d.get("meta", {}) or {}).get("file_info", {}) or {}).get("sha256", "")
            return {"status": attr.get("status", "unknown"), "stats": attr.get("stats", {}), "sha256": sha}
        except Exception as e:
            return {"status": "error", "reason": str(e)}


def _vt_spend(n=1):
    """Record VirusTotal API spend in the daily quota table (best-effort).

    Called from the one place every VT request passes through, so the figure the
    UI shows finally includes upload + analysis-polling traffic and not just
    reputation lookups. Never allowed to break a request: quota accounting is
    bookkeeping, not correctness.
    """
    try:
        svc = globals().get("SERVICE")
        if svc is not None and getattr(svc, "store", None) is not None:
            svc.store.quota_incr("VirusTotal", n)
    except Exception:
        pass


class ThreatBookClient:
    NAME = "ThreatBook"

    def __init__(self, cfg):
        self.cfg = cfg

    def has_key(self):
        return bool(self.cfg.get("api_key"))

    def key_count(self):
        return 1 if self.cfg.get("api_key") else 0

    def query_hash(self, sha):
        key = self.cfg.get("api_key", "")
        if not key:
            return {"querySucceeded": False, "reason": "no api key"}
        # 微步 v3 file report (validated against the live API): /v3/file/report.
        url = "https://api.threatbook.cn/v3/file/report"
        try:
            status, body = http_post(url, {"apikey": key, "sha256": sha},
                                      {"Content-Type": "application/x-www-form-urlencoded"},
                                      self.cfg.get("timeout_seconds", 10))
        except Exception as e:
            return {"querySucceeded": False, "reason": str(e)}
        try:
            data = json.loads(body)
        except Exception as e:
            return {"querySucceeded": False, "reason": "parse: %s" % e}
        rc = data.get("response_code")
        msg = str(data.get("verbose_msg", ""))
        if rc == 0:
            return {"querySucceeded": True, **self._parse_report(data), "source": self.NAME}
        # endpoint works but ThreatBook has no record for this hash -> unknown, NOT a failure
        if rc == -1 and "SAMPLE_NOT_FOUND" in msg.upper():
            return {"querySucceeded": True, "verdict": "unknown", "malicious": 0,
                    "total_engines": 0, "threat_label": "", "source": self.NAME}
        return {"querySucceeded": False, "reason": msg or ("rc=%s" % rc)}

    def query_ip(self, ip):
        key = self.cfg.get("api_key", "")
        if not key:
            return {"querySucceeded": False, "reason": "no api key"}
        url = "https://api.threatbook.cn/v3/scene/ip_reputation"
        try:
            status, body = http_post(url, {"apikey": key, "resource": ip},
                                      {"Content-Type": "application/x-www-form-urlencoded"},
                                      self.cfg.get("timeout_seconds", 10))
        except Exception as e:
            return {"querySucceeded": False, "reason": str(e)}
        try:
            data = json.loads(body)
        except Exception as e:
            return {"querySucceeded": False, "reason": "parse: %s" % e}
        if data.get("response_code") != 0:
            return {"querySucceeded": False, "reason": str(data.get("verbose_msg", "rc!=0"))}
        node = (data.get("data", {}) or {}).get(ip, {}) or {}
        judgments = node.get("judgments", []) or []
        sev = str(node.get("severity", "")).lower()
        label = judgments[0] if judgments else ""
        if node.get("is_malicious") or sev in ("critical", "high"):
            verdict = "malicious"
        elif judgments or sev in ("medium", "low"):
            verdict = "suspicious"
        else:
            verdict = "clean"
        return {"querySucceeded": True, "verdict": verdict,
                "threat_label": str(label), "source": self.NAME}

    @staticmethod
    def _map_level(tl, is_white, score):
        tl = str(tl).lower()
        if is_white:
            return "clean"
        if tl in ("malicious", "malice"):
            return "malicious"
        if tl in ("suspicious", "gray", "grey"):
            return "suspicious"
        if tl in ("clean", "safe", "secure", "white"):
            return "clean"
        try:
            s = int(score)
            if s >= 60:
                return "malicious"
            if s > 0:
                return "suspicious"
        except Exception:
            pass
        return "unknown"

    @staticmethod
    def _parse_report(data):
        """Parse /v3/file/report -> data.summary.{threat_level,malware_family,threat_score,is_whitelist}."""
        d = data.get("data", {}) or {}
        summary = d.get("summary", {}) or {}
        fam = summary.get("malware_family") or summary.get("malware_type") or ""
        if isinstance(fam, list):
            fam = fam[0] if fam else ""
        verdict = ThreatBookClient._map_level(summary.get("threat_level", ""),
                                              bool(summary.get("is_whitelist", False)),
                                              summary.get("threat_score", 0))
        return {"verdict": verdict, "malicious": 0, "total_engines": 0, "threat_label": str(fam)}


class MalwareBazaarClient:
    """abuse.ch MalwareBazaar: a known-malware DB (positive hits only)."""
    NAME = "MalwareBazaar"

    def __init__(self, cfg):
        self.cfg = cfg
        self.url = cfg.get("base_url", "https://mb-api.abuse.ch/api/v1/")

    def has_key(self):
        return bool(self.cfg.get("auth_key"))

    def key_count(self):
        return 1 if self.cfg.get("auth_key") else 0

    def query_hash(self, sha):
        key = self.cfg.get("auth_key", "")
        if not key:
            return {"querySucceeded": False, "reason": "no auth key"}
        try:
            status, body = http_post(self.url, {"query": "get_info", "hash": sha},
                                      {"Auth-Key": key}, self.cfg.get("timeout_seconds", 10))
        except urllib.error.HTTPError as e:
            return {"querySucceeded": False, "reason": "http %d" % e.code}
        except Exception as e:
            return {"querySucceeded": False, "reason": str(e)}
        try:
            data = json.loads(body)
        except Exception as e:
            return {"querySucceeded": False, "reason": "parse: %s" % e}
        if not isinstance(data, dict):
            data = {}
        st = str(data.get("query_status", "")).lower()
        if st == "ok":
            label, mal, total = "", 1, 1
            arr = data.get("data") or []
            if arr and isinstance(arr[0], dict):
                first = arr[0]
                if first.get("signature"):
                    label = str(first.get("signature"))
                vi = first.get("vendor_intel") or {}
                if isinstance(vi, dict) and vi:
                    mal = total = len(vi)
            return {"querySucceeded": True, "verdict": "malicious", "malicious": mal,
                    "total_engines": total, "threat_label": label, "source": self.NAME}
        if st in ("hash_not_found", "no_results"):
            return {"querySucceeded": True, "verdict": "unknown", "malicious": 0,
                    "total_engines": 0, "threat_label": "", "source": self.NAME}
        return {"querySucceeded": False, "reason": "status=%s" % st}


class OtxClient:
    """AlienVault OTX: pulse-count based reputation."""
    NAME = "OTX"

    def __init__(self, cfg):
        self.cfg = cfg
        self.base = cfg.get("base_url", "https://otx.alienvault.com/api/v1/indicators/file/")
        self.threshold = int(cfg.get("malicious_pulse_threshold", 3))

    def has_key(self):
        return bool(self.cfg.get("api_key"))

    def key_count(self):
        return 1 if self.cfg.get("api_key") else 0

    def query_hash(self, sha):
        key = self.cfg.get("api_key", "")
        if not key:
            return {"querySucceeded": False, "reason": "no api key"}
        try:
            status, body = http_get(self.base + sha + "/general", {"X-OTX-API-KEY": key},
                                     self.cfg.get("timeout_seconds", 10))
        except urllib.error.HTTPError as e:
            if e.code == 404:  # OTX reachable but no record -> authoritative unknown
                return {"querySucceeded": True, "verdict": "unknown", "malicious": 0,
                        "total_engines": 0, "threat_label": "", "source": self.NAME}
            return {"querySucceeded": False, "reason": "http %d" % e.code}
        except Exception as e:
            return {"querySucceeded": False, "reason": str(e)}
        try:
            data = json.loads(body)
        except Exception as e:
            return {"querySucceeded": False, "reason": "parse: %s" % e}
        if not isinstance(data, dict):
            data = {}
        pi = data.get("pulse_info") or {}
        count = int(pi.get("count", 0) or 0)
        label = ""
        pulses = pi.get("pulses") or []
        if pulses and isinstance(pulses[0], dict):
            label = str(pulses[0].get("name", "") or "")
        if count >= self.threshold:
            verdict = "malicious"
        elif count >= 1:
            verdict = "suspicious"
        else:
            verdict = "clean"
        return {"querySucceeded": True, "verdict": verdict, "malicious": count,
                "total_engines": count, "threat_label": label, "source": self.NAME}


class MetaDefenderClient:
    """OPSWAT MetaDefender Cloud: multi-engine hash lookup."""
    NAME = "MetaDefender"

    def __init__(self, cfg):
        self.cfg = cfg
        self.base = cfg.get("base_url", "https://api.metadefender.com/v4/hash/")
        self.threshold = int(cfg.get("malicious_threshold", 3))

    def has_key(self):
        return bool(self.cfg.get("api_key"))

    def key_count(self):
        return 1 if self.cfg.get("api_key") else 0

    def query_hash(self, sha):
        key = self.cfg.get("api_key", "")
        if not key:
            return {"querySucceeded": False, "reason": "no api key"}
        try:
            status, body = http_get(self.base + sha, {"apikey": key},
                                     self.cfg.get("timeout_seconds", 10))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {"querySucceeded": True, "verdict": "unknown", "malicious": 0,
                        "total_engines": 0, "threat_label": "", "source": self.NAME}
            return {"querySucceeded": False, "reason": "http %d" % e.code}
        except Exception as e:
            return {"querySucceeded": False, "reason": str(e)}
        try:
            data = json.loads(body)
        except Exception as e:
            return {"querySucceeded": False, "reason": "parse: %s" % e}
        if not isinstance(data, dict):
            data = {}
        if "error" in data:  # reachable + authoritative, but hash not indexed
            return {"querySucceeded": True, "verdict": "unknown", "malicious": 0,
                    "total_engines": 0, "threat_label": "", "source": self.NAME}
        sr = data.get("scan_results") or {}
        detected = int(sr.get("total_detected_avs", 0) or 0)
        total = int(sr.get("total_avs", 0) or 0)
        label = data.get("threat_name") or sr.get("scan_all_result_a") or ""
        if detected >= self.threshold:
            verdict = "malicious"
        elif detected >= 1:
            verdict = "suspicious"
        else:
            verdict = "clean"
        return {"querySucceeded": True, "verdict": verdict, "malicious": detected,
                "total_engines": total, "threat_label": str(label), "source": self.NAME}


class HybridAnalysisClient:
    """CrowdStrike Falcon Sandbox (Hybrid Analysis): sandbox verdict + threat score."""
    NAME = "HybridAnalysis"

    def __init__(self, cfg):
        self.cfg = cfg
        self.base = cfg.get("base_url", "https://www.hybrid-analysis.com/api/v2/overview/")
        self.score_threshold = int(cfg.get("malicious_threat_score", 70))

    def has_key(self):
        return bool(self.cfg.get("api_key"))

    def key_count(self):
        return 1 if self.cfg.get("api_key") else 0

    def query_hash(self, sha):
        key = self.cfg.get("api_key", "")
        if not key:
            return {"querySucceeded": False, "reason": "no api key"}
        headers = {"User-Agent": "Falcon Sandbox", "api-key": key}
        try:
            status, body = http_get(self.base + sha, headers, self.cfg.get("timeout_seconds", 10))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {"querySucceeded": True, "verdict": "unknown", "malicious": 0,
                        "total_engines": 0, "threat_label": "", "source": self.NAME}
            return {"querySucceeded": False, "reason": "http %d" % e.code}
        except Exception as e:
            return {"querySucceeded": False, "reason": str(e)}
        try:
            data = json.loads(body)
        except Exception as e:
            return {"querySucceeded": False, "reason": "parse: %s" % e}
        if not isinstance(data, dict):
            data = {}
        score = int(data.get("threat_score", 0) or 0)
        multiscan = int(data.get("multiscan_result", 0) or 0)
        v = str(data.get("verdict", "") or "").strip().lower()
        label = str(data.get("vx_family", "") or "")
        if v == "malicious":
            verdict = "malicious"
        elif v == "suspicious":
            verdict = "suspicious"
        elif v in ("whitelisted", "no specific threat"):
            verdict = "clean"
        elif score >= self.score_threshold:
            verdict = "malicious"
        elif score > 0:
            verdict = "suspicious"
        else:
            verdict = "clean"
        return {"querySucceeded": True, "verdict": verdict, "malicious": multiscan,
                "total_engines": 0, "threat_label": label, "source": self.NAME}

    # ---- Falcon Sandbox behaviour reports ---------------------------------- #
    API_ROOT = "https://www.hybrid-analysis.com/api/v2"

    def _ha_headers(self):
        return {"User-Agent": "Falcon Sandbox",
                "api-key": self.cfg.get("api_key", ""),
                "accept": "application/json"}

    def fetch_behaviour(self, sha, max_reports=1):
        """Condensed sandbox behaviour for a hash. None if no sandbox report."""
        if not self.cfg.get("api_key"):
            return None
        timeout = int(self.cfg.get("behaviour_timeout_seconds", 30))
        try:
            status, body = http_get(self.API_ROOT + "/overview/" + sha,
                                    self._ha_headers(), timeout)
            ov = json.loads(body)
        except Exception:
            return None
        if not isinstance(ov, dict):
            return None
        reports = [r for r in (ov.get("reports") or []) if r]
        if not reports:
            return None
        out = {"source": self.NAME, "sha256": sha,
               "tags": ov.get("tags") or [],
               "vx_family": ov.get("vx_family") or "",
               "threat_score": ov.get("threat_score"),
               "verdict": ov.get("verdict") or "",
               "jobs": []}
        for jid in reports[:max_reports]:
            try:
                st, b = http_get(self.API_ROOT + "/report/%s/summary" % jid,
                                 self._ha_headers(), timeout)
                d = json.loads(b)
            except Exception:
                continue
            if isinstance(d, dict):
                out["jobs"].append(self._condense_job(jid, d))
        return out if out["jobs"] else None

    @staticmethod
    def _condense_job(jid, d):
        def _mitre(items):
            res = []
            for m in (items or [])[:60]:
                if not isinstance(m, dict):
                    continue
                res.append({"tactic": m.get("tactic", ""),
                            "technique": m.get("technique", ""),
                            "attck_id": m.get("attck_id") or "",
                            "malicious": m.get("malicious_identifiers_count", 0),
                            "suspicious": m.get("suspicious_identifiers_count", 0)})
            return res

        def _sigs(items):
            res = []
            for s in (items or []):
                if not isinstance(s, dict):
                    continue
                try:
                    thr = int(s.get("threat_level") or 0)
                except Exception:
                    thr = 0
                if thr <= 0:
                    continue
                res.append({"name": s.get("name", ""), "threat_level": thr,
                            "category": s.get("category", ""),
                            "description": (s.get("description") or "")[:300]})
            res.sort(key=lambda x: -x["threat_level"])
            return res[:40]

        def _procs(items):
            res = []
            for p in (items or [])[:40]:
                if not isinstance(p, dict):
                    continue
                res.append({"name": p.get("name", ""),
                            "pid": p.get("uid") or p.get("pid"),
                            "cmd": (p.get("command_line") or "")[:400],
                            "parent": p.get("parentuid") or "",
                            "sha256": p.get("sha256", "")})
            return res

        def _files(items):
            res = []
            for f in (items or [])[:30]:
                if not isinstance(f, dict):
                    continue
                res.append({"name": f.get("name", ""),
                            "type": f.get("type_tags") or f.get("file_type", ""),
                            "sha256": f.get("sha256", ""),
                            "threat_level": f.get("threat_level")})
            return res

        return {"job_id": jid,
                "environment": d.get("environment_description", ""),
                "state": d.get("state", ""),
                "threat_level": d.get("threat_level"),
                "av_detect": d.get("av_detect"),
                "total_processes": d.get("total_processes"),
                "total_network_connections": d.get("total_network_connections"),
                "hosts": (d.get("hosts") or [])[:30],
                "domains": (d.get("domains") or [])[:30],
                "compromised_hosts": (d.get("compromised_hosts") or [])[:20],
                "extracted_files": _files(d.get("extracted_files")),
                "mitre_attcks": _mitre(d.get("mitre_attcks")),
                "signatures": _sigs(d.get("signatures")),
                "processes": _procs(d.get("processes")),
                "crowdstrike_ai": d.get("crowdstrike_ai") or {},
                "imphash": d.get("imphash", ""),
                "ssdeep": d.get("ssdeep", ""),
                "classification_tags": d.get("classification_tags") or []}


# --------------------------------------------------------------------------- #
#  Aggregation service                                                         #
# --------------------------------------------------------------------------- #
class IntelService:
    def __init__(self, cfg):
        self.cfg = cfg
        self.store = Store(cfg["db_path"])
        self.rl = RateLimiter(self.store)
        self.vt = VirusTotalClient(cfg.get("virustotal", {}))
        self.tb = ThreatBookClient(cfg.get("threatbook", {}))
        self.mb = MalwareBazaarClient(cfg.get("malwarebazaar", {}))
        self.otx = OtxClient(cfg.get("otx", {}))
        self.md = MetaDefenderClient(cfg.get("metadefender", {}))
        self.ha = HybridAnalysisClient(cfg.get("hybridanalysis", {}))
        # Query order: VirusTotal (70+ engines) and ThreatBook first, then the four
        # supplementary sources. A confirmed-malicious hit short-circuits the rest.
        self._hash_sources = [
            (self.vt, "virustotal"), (self.tb, "threatbook"),
            (self.mb, "malwarebazaar"), (self.otx, "otx"),
            (self.md, "metadefender"), (self.ha, "hybridanalysis"),
        ]
        self.ttl = cfg.get("cache_ttl", {})

    def _expiry_for(self, verdict):
        t = self.ttl
        if verdict == "malicious":
            return now_utc() + timedelta(days=int(t.get("malicious_days", 3650)))
        if verdict == "clean":
            return now_utc() + timedelta(days=int(t.get("clean_days", 7)))
        if verdict == "suspicious":
            return now_utc() + timedelta(hours=int(t.get("suspicious_hours", 24)))
        return now_utc() + timedelta(hours=int(t.get("unknown_hours", 24)))

    def reputation_hash(self, sha):
        sha = sha.lower()
        cached = self.store.get_hash(sha)
        if cached:
            self.store.counter_incr("hash_cache_hit")
            return self._hash_response(cached, cached=True)
        self.store.counter_incr("hash_cache_miss")

        best = None
        succeeded = False
        # All configured sources; strongest verdict wins, confirmed-malicious short-circuits.
        for client, scfg_name in self._hash_sources:
            scfg = self.cfg.get(scfg_name, {})
            if not scfg.get("enabled", True):
                continue
            if not client.has_key():
                continue  # no key -> skip (don't burn rate-limit/quota on a no-op)
            kc = max(1, client.key_count())  # a key pool multiplies the effective quota
            ok, why = self.rl.allow(client.NAME, scfg.get("requests_per_minute", 0) * kc,
                                     scfg.get("requests_per_day", 0) * kc)
            if not ok:
                self.store.counter_incr("ratelimited")
                continue
            res = client.query_hash(sha)
            if not res.get("querySucceeded"):
                continue
            succeeded = True
            if "verdict" not in res:
                continue
            if best is None or VERDICT_RANK.get(res["verdict"], 0) > VERDICT_RANK.get(best["verdict"], 0):
                best = res
            # a confirmed-malicious hit is decisive; stop querying more upstreams
            if best and best["verdict"] == "malicious":
                break

        if best is None:
            best = {"verdict": "unknown", "malicious": 0, "total_engines": 0,
                    "threat_label": "", "source": "aggregate"}
        rec = {
            "sha256": sha, "verdict": best["verdict"], "malicious": best.get("malicious", 0),
            "total_engines": best.get("total_engines", 0), "threat_label": best.get("threat_label", ""),
            "source": best.get("source", "aggregate"), "fetched_at": iso(now_utc()),
            "expires_at": iso(self._expiry_for(best["verdict"])), "raw": "",
        }
        # only persist when at least one upstream actually answered (don't cache blind unknowns forever)
        if succeeded or best["verdict"] != "unknown":
            self.store.put_hash(rec)
        resp = self._hash_response(rec, cached=False)
        resp["querySucceeded"] = succeeded
        return resp

    def reputation_ip(self, ip):
        cached = self.store.get_ip(ip)
        if cached:
            self.store.counter_incr("ip_cache_hit")
            return {"ip": ip, "verdict": cached["verdict"], "threatLabel": cached["threat_label"],
                    "source": cached["source"], "querySucceeded": True, "cached": True,
                    "fetchedAt": cached["fetched_at"]}
        self.store.counter_incr("ip_cache_miss")
        scfg = self.cfg.get("threatbook", {})
        succeeded = False
        verdict, label, source = "unknown", "", "aggregate"
        if scfg.get("enabled", True) and scfg.get("api_key"):
            ok, why = self.rl.allow(self.tb.NAME, scfg.get("requests_per_minute", 0),
                                     scfg.get("requests_per_day", 0))
            if ok:
                res = self.tb.query_ip(ip)
                if res.get("querySucceeded"):
                    succeeded = True
                    verdict = res.get("verdict", "unknown")
                    label = res.get("threat_label", "")
                    source = res.get("source", "ThreatBook")
        rec = {"ip": ip, "verdict": verdict, "threat_label": label, "source": source,
               "fetched_at": iso(now_utc()),
               "expires_at": iso(now_utc() + timedelta(days=int(self.ttl.get("ip_days", 7)))), "raw": ""}
        if succeeded or verdict != "unknown":
            self.store.put_ip(rec)
        return {"ip": ip, "verdict": verdict, "threatLabel": label, "source": source,
                "querySucceeded": succeeded, "cached": False, "fetchedAt": rec["fetched_at"]}

    def secondary_sources_hash(self, sha):
        """Query every non-VirusTotal source for this hash in parallel (no
        short-circuit) so the web report can show a multi-source consensus.
        Returns a list of per-source result dicts."""
        sha = sha.lower()
        out = []
        lock = threading.Lock()
        threads = []

        def run(client, cfgname):
            scfg = self.cfg.get(cfgname, {}) or {}
            if not scfg.get("enabled", True) or not client.has_key():
                return
            kc = max(1, client.key_count())
            ok, why = self.rl.allow(client.NAME, scfg.get("requests_per_minute", 0) * kc,
                                     scfg.get("requests_per_day", 0) * kc)
            if not ok:
                with lock:
                    out.append({"source": client.NAME, "verdict": "unknown",
                                "querySucceeded": False, "reason": why})
                return
            try:
                r = client.query_hash(sha)
            except Exception as e:
                r = {"querySucceeded": False, "reason": str(e)}
            with lock:
                out.append({"source": client.NAME, "verdict": r.get("verdict", "unknown"),
                            "malicious": r.get("malicious", 0), "total_engines": r.get("total_engines", 0),
                            "threat_label": r.get("threat_label", ""),
                            "querySucceeded": bool(r.get("querySucceeded")), "reason": r.get("reason", "")})

        for client, cfgname in self._hash_sources:
            if client is self.vt:
                continue
            t = threading.Thread(target=run, args=(client, cfgname))
            t.start()
            threads.append(t)
        for t in threads:
            t.join(timeout=20)
        order = {c.NAME: i for i, (c, _) in enumerate(self._hash_sources)}
        out.sort(key=lambda x: order.get(x["source"], 99))
        return out

    def _degraded_lookup(self, ident, why):
        """VT unavailable (no key / banned / rate-limited / error): still answer
        from the other configured sources instead of failing the whole query.

        Before this existed, any non-200 from VirusTotal returned an error and
        secondary_sources_hash() was never reached, so a single dead VT key took
        the entire file-lookup feature down with it.
        """
        srcs = self.secondary_sources_hash(ident)
        ok_srcs = [s for s in srcs if s.get("querySucceeded")]
        # Counts must come from ONE source and only from a source that actually
        # reports a denominator: HybridAnalysis returns total_engines=0 (its
        # multiscan_result is not an "x of y engines" figure), so picking it
        # would render a nonsensical "94/0".
        rated = [s for s in ok_srcs if int(s.get("total_engines") or 0) > 0]
        best = None
        for s in (rated or []):
            if best is None or int(s.get("malicious") or 0) > int(best.get("malicious") or 0):
                best = s
        mal = int((best or {}).get("malicious") or 0)
        tot = int((best or {}).get("total_engines") or 0)
        verdicts = [s.get("verdict") for s in ok_srcs]
        if "malicious" in verdicts:
            verdict = "malicious"
        elif "suspicious" in verdicts:
            verdict = "suspicious"
        elif "clean" in verdicts:
            verdict = "clean"
        else:
            verdict = "unknown"
        label = ""
        for s in ok_srcs:
            if s.get("threat_label"):
                label = s["threat_label"]
                break
        report = {"id": ident, "file": {}, "behaviour": {}, "behaviour_available": False,
                  "degraded": True, "degraded_reason": why,
                  "sources": ([{"source": "VirusTotal", "verdict": "unknown", "malicious": 0,
                                "total_engines": 0, "threat_label": "",
                                "querySucceeded": False, "reason": why}] + srcs)}
        meta = {"sha256": ident, "md5": "", "sha1": "", "name": "",
                "verdict": verdict, "malicious": mal, "total_engines": tot,
                "threat_label": label, "category": ""}
        is_threat = verdict in ("malicious", "suspicious")
        if is_threat:
            self.store.save_vt_report(meta, report)
        return {"ok": True, "cached": False, "degraded": True, "stored": is_threat,
                "stored_at": iso(now_utc()) if is_threat else "",
                "verdict": verdict, "malicious": mal, "total_engines": tot,
                "sources_ok": len(ok_srcs), "report": report}

    # ---- full VT report (file report + sandbox behaviour), permanently stored --- #
    def vt_lookup(self, ident, refresh=False):
        ident = ident.strip().lower()
        if not refresh:
            stored = self.store.get_vt_report(ident)
            if stored:
                return {"ok": True, "cached": True, "stored": True,
                        "stored_at": stored["stored_at"], "report": stored["report"]}
        if not self.vt.has_key():
            return self._degraded_lookup(ident, "no VirusTotal key configured")
        st, body = self.vt.vt_api_get("/files/" + ident)
        if st == 404:
            return {"ok": False, "error": "VirusTotal 无此文件记录 (404)"}
        if st != 200:
            return self._degraded_lookup(ident, "VirusTotal HTTP %s" % st)
        try:
            attr = (json.loads(body).get("data", {}) or {}).get("attributes", {}) or {}
        except Exception as e:
            return {"ok": False, "error": "解析文件报告失败: %s" % e}
        # Behaviour summary (merged across sandboxes). 404 when no sandbox report exists.
        beh, bst = {}, 0
        bst, bbody = self.vt.vt_api_get("/files/" + ident + "/behaviour_summary")
        if bst == 200:
            try:
                beh = json.loads(bbody).get("data", {}) or {}
            except Exception:
                beh = {}
        sha256 = str(attr.get("sha256", ident)).lower()
        stats = attr.get("last_analysis_stats", {}) or {}
        mal = int(stats.get("malicious", 0) or 0)
        susp = int(stats.get("suspicious", 0) or 0)
        total = sum(int(v or 0) for v in stats.values()) if stats else 0
        threshold = int((self.cfg.get("virustotal", {}) or {}).get("malicious_threshold", 5))
        verdict = "malicious" if mal >= threshold else ("suspicious" if (mal > 0 or susp > 0) else "clean")
        names = attr.get("names") or []
        name = attr.get("meaningful_name") or (names[0] if names else "")
        ptc = attr.get("popular_threat_classification") or {}
        threat_label = ptc.get("suggested_threat_label", "") if isinstance(ptc, dict) else ""
        report = {"id": sha256, "file": attr, "behaviour": beh, "behaviour_available": bst == 200}
        # multi-source consensus: VT (from this report) + every other configured source
        report["sources"] = ([{"source": "VirusTotal", "verdict": verdict, "malicious": mal,
                               "total_engines": total, "threat_label": threat_label,
                               "querySucceeded": True, "reason": ""}]
                             + self.secondary_sources_hash(sha256))
        meta = {"sha256": sha256, "md5": str(attr.get("md5", "")), "sha1": str(attr.get("sha1", "")),
                "name": name, "verdict": verdict, "malicious": mal, "total_engines": total,
                "threat_label": threat_label, "category": threat_category(attr, threat_label)}
        # Retention policy: only threats (malicious / suspicious) go to the threat
        # archive. Clean files are returned for viewing but not kept there.
        is_threat = verdict in ("malicious", "suspicious")
        if is_threat:
            self.store.save_vt_report(meta, report)
        elif bst == 200:
            # 干净【且真在沙箱里跑过】-> 留一份精简报告当正常语料。
            #
            # 以前这里什么都不做,干净文件的沙箱行为抓到手就扔 —— 于是攻击链引擎只有
            # 恶意语料,只能算出「多少病毒有这个组合」,算不出「多少正常软件也有」,
            # 区分度无从计算。实测因此漏过一条退化组合(两个标记的条件都只是
            # 「未签名的进程创建」),命中的是 ripgrep 和本产品自己的 UI。
            #
            # 存入 benign_reports 而非 vt_reports:后者是威胁归档,混进干净文件会让
            # 归档计数与家族分布全部失真,而且会污染 lookup 缓存(见 BENIGN_DDL 处说明)。
            try:
                self.store.save_benign_report(sha256, attr, beh)
            except Exception:
                pass        # 语料是锦上添花,绝不能因为它失败而影响一次信誉查询
        return {"ok": True, "cached": False, "stored": is_threat,
                "stored_at": iso(now_utc()) if is_threat else "", "report": report}

    def get_vt_report(self, ident):
        return self.store.get_vt_report(ident)

    def list_vt_reports(self):
        return self.store.list_vt_reports()

    def vt_submit_path(self, path, sha256, filename, size):
        """Given an already-hashed, spooled sample file: return the stored/known VT
        report if present, else stream the file to VT for analysis and return the
        analysis id. The caller owns/cleans up `path`."""
        stored = self.store.get_vt_report(sha256)
        if stored:
            return {"ok": True, "found": True, "cached": True, "stored": True, "sha256": sha256,
                    "stored_at": stored["stored_at"], "report": stored["report"]}
        r = self.vt_lookup(sha256, refresh=False)   # does VT already know this hash? (also stores it)
        # A degraded answer carrying no verdict at all is not a "found" report:
        # fall through so the sample is still submitted once VT is reachable, or
        # so a real error surfaces, instead of showing the user an empty report.
        degraded_blank = (bool(r.get("degraded"))
                          and str(r.get("verdict") or "unknown") == "unknown")
        if r.get("ok") and not degraded_blank:
            r["found"] = True
            r["sha256"] = sha256
            r["degraded"] = bool(r.get("degraded"))
            return r
        if not self.vt.has_key():
            return {"ok": False, "error": "服务端未配置 VirusTotal 密钥", "sha256": sha256}
        analysis_id, err = self.vt.submit_file_path(path, filename, size)
        if not analysis_id:
            return {"ok": False, "error": "上传 VirusTotal 失败: %s" % (err or "unknown"), "sha256": sha256}
        return {"ok": True, "found": False, "submitted": True, "sha256": sha256, "analysis_id": analysis_id}

    def vt_analysis(self, analysis_id):
        return self.vt.get_analysis(analysis_id)

    @staticmethod
    def _hash_response(rec, cached):
        return {
            "sha256": rec["sha256"], "verdict": rec["verdict"], "malicious": rec["malicious"],
            "totalEngines": rec["total_engines"], "threatLabel": rec["threat_label"],
            "source": rec["source"], "querySucceeded": True, "cached": cached,
            "fetchedAt": rec["fetched_at"],
        }


# --------------------------------------------------------------------------- #
#  HTTP layer                                                                  #
# --------------------------------------------------------------------------- #
SERVICE = None
CONFIG = None
THROTTLE = None
WEBUI_PATH = os.environ.get("BULWARK_INTEL_WEBUI", "/opt/bulwark-intel/webui.html")

API_DOCS_HTML = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Bulwark 威胁情报 API</title>
<style>
:root{--bg:#eef1f7;--card:#fff;--soft:#f6f8fc;--line:#e4e8f0;--ink:#1b2230;--muted:#6b7688;--brand:#6366f1;--mal:#e5484d;--clean:#0f9d58;--mono:"Cascadia Mono",Consolas,monospace;--sans:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14.5px/1.65 var(--sans)}
.wrap{max-width:900px;margin:0 auto;padding:30px 20px 70px}
h1{font-size:24px;margin:0 0 4px}.lead{color:var(--muted);margin:0 0 24px}
h2{font-size:17px;margin:30px 0 12px;padding-bottom:7px;border-bottom:1px solid var(--line)}
code{font-family:var(--mono);background:var(--soft);border:1px solid var(--line);border-radius:5px;padding:1px 6px;font-size:12.5px}
pre{background:#0f1424;color:#d6deec;border-radius:11px;padding:14px 16px;overflow:auto;font-family:var(--mono);font-size:12.5px;line-height:1.6}
pre .k{color:#89b4fa}pre .s{color:#a6e3a1}
.ep{background:var(--card);border:1px solid var(--line);border-radius:13px;padding:15px 17px;margin-bottom:13px;box-shadow:0 1px 2px rgba(16,24,40,.05)}
.ep .m{display:inline-block;font-weight:800;font-size:11.5px;padding:2px 9px;border-radius:6px;color:#fff;margin-right:9px;font-family:var(--mono)}
.m.get{background:var(--clean)}.m.post{background:var(--brand)}
.ep .p{font-family:var(--mono);font-weight:700;font-size:13.5px}
.ep .d{color:var(--muted);font-size:13px;margin:7px 0 0}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:6px}th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line)}th{color:var(--muted);font-size:11px;text-transform:uppercase}
.tag{display:inline-block;background:var(--soft);border:1px solid var(--line);border-radius:20px;padding:2px 10px;font-size:12px;color:var(--muted);margin-right:6px}
.note{background:#fff7e8;border:1px solid #fbe8c4;border-radius:11px;padding:12px 15px;font-size:13px;color:#7a5b16;margin:16px 0}
a{color:var(--brand);text-decoration:none}
</style></head><body><div class="wrap">
<h1>🛡️ Bulwark 威胁情报 API</h1>
<p class="lead">基于 VirusTotal + 微步 + MalwareBazaar + MetaDefender + HybridAnalysis 的聚合威胁情报接口。</p>
<h2>认证</h2>
<p>每个请求都要带 API Key,放在请求头 <code>X-API-Key</code>(也支持 <code>Authorization: Bearer &lt;key&gt;</code> 或 <code>?key=</code>)。找管理员申请 Key。</p>
<pre><span class="k">curl</span> -H <span class="s">"X-API-Key: YOUR_KEY"</span> https://vt.bulwark.icu:8787/api/v1/hash/&lt;sha256&gt;</pre>
<div class="note">共享额度有限,每个 Key 有每分钟 / 每天调用上限。恶意/可疑样本的报告会永久缓存,重复查询极快;安全文件不缓存。</div>
<h2>端点</h2>
<div class="ep"><div><span class="m get">GET</span><span class="p">/api/v1/hash/{md5|sha1|sha256}</span></div>
<div class="d">哈希信誉摘要(多源:判定 / 检出比 / 家族 / 类型 / 各情报源结论)。</div>
<pre><span class="k">curl</span> -H <span class="s">"X-API-Key: KEY"</span> https://vt.bulwark.icu:8787/api/v1/hash/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa</pre></div>
<div class="ep"><div><span class="m get">GET</span><span class="p">/api/v1/file/{hash}</span></div>
<div class="d">完整报告:逐引擎检测 + 沙箱行为 + 多源情报(原始 JSON)。</div></div>
<div class="ep"><div><span class="m get">GET</span><span class="p">/api/v1/ip/{ipv4}</span></div>
<div class="d">IP 信誉(微步)。</div>
<pre><span class="k">curl</span> -H <span class="s">"X-API-Key: KEY"</span> https://vt.bulwark.icu:8787/api/v1/ip/8.8.8.8</pre></div>
<div class="ep"><div><span class="m post">POST</span><span class="p">/api/v1/scan?name={filename}</span></div>
<div class="d">上传文件扫描(原始字节作为请求体)。已知则直接返回报告,未知则提交 VT 分析并返回 analysis_id。</div>
<pre><span class="k">curl</span> -H <span class="s">"X-API-Key: KEY"</span> --data-binary @sample.exe <span class="s">"https://vt.bulwark.icu:8787/api/v1/scan?name=sample.exe"</span></pre></div>
<div class="ep"><div><span class="m get">GET</span><span class="p">/api/v1/analysis/{id}</span></div>
<div class="d">轮询上传后返回的 analysis_id,查看分析状态。</div></div>
<div class="ep"><div><span class="m get">GET</span><span class="p">/api/v1/quota</span></div>
<div class="d">查看当前 Key 的今日用量与限额。</div></div>
<h2>返回示例(hash 摘要)</h2>
<pre>{
  <span class="k">"ok"</span>: true,
  <span class="k">"sha256"</span>: <span class="s">"ed01ebfb..."</span>,
  <span class="k">"verdict"</span>: <span class="s">"malicious"</span>,
  <span class="k">"malicious"</span>: 65, <span class="k">"total_engines"</span>: 74,
  <span class="k">"threat_label"</span>: <span class="s">"ransomware.wannacry/wanna"</span>,
  <span class="k">"category"</span>: <span class="s">"ransomware"</span>,
  <span class="k">"sources"</span>: [ {<span class="k">"source"</span>:<span class="s">"VirusTotal"</span>,<span class="k">"verdict"</span>:<span class="s">"malicious"</span>}, ... ]
}</pre>
<p style="color:var(--muted);font-size:12.5px;margin-top:24px">verdict 取值:<span class="tag">malicious</span><span class="tag">suspicious</span><span class="tag">clean</span><span class="tag">unknown</span> · 错误码:401 未授权 / 429 限流 / 404 未找到。</p>
</div></body></html>"""


# ---- /engine 页面模板 -------------------------------------------------------- #
#
# 数据由 _serve_engine() 以 JSON 注入 /*__DATA__*/null 处,筛选/排序/搜索全在前端做。
# 走服务端会让每次按键都打一次 HTTPS 往返,而这台机器同时在扛信誉查询,不该浪费在这上面;
# 组合几十条、标记几十个,一次发过去也只有几十 KB。
#
# 版式的三条硬规矩(上一版就是没守住这三条才显得乱):
#   1. 【诊断压成一行】。原来顶部堆了两块共 11 行的黄红警告,占掉近三分之一屏才见到内容。
#      现在只留一行「N 条生效 · M 条剔除 · 区分度状态」,长解释收进「说明」展开。
#   2. 【生效与剔除分开放】。原来混在一张表里,白底行与黄底行交替,看着像坏了;而且每行都得
#      挂一个「启用/已剔除」标签。拆成两个页签后,主表全都是生效的,标签自然消失。
#   3. 【一行只留一个数字】。原来右侧挤 4 个元素(作证 21 / 正常软件 0 / 启用 / 换行的原因
#      徽标),行高忽高忽低。现在只留右对齐的作证数,列名提到表头 —— 32 个一模一样的
#      「正常软件 0」是纯噪音,只在真有命中时才出现。
_ENGINE_PAGE = r'''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>磐垒 · 攻击链组合引擎</title>
<style>
:root{--bg:#eef1f7;--card:#fff;--soft:#f7f9fc;--line:#e4e8f0;--line2:#eef1f6;
--ink:#1b2230;--ink2:#3b475c;--muted:#6b7688;--dim:#9aa4b2;
--brand:#6366f1;--brand2:#8b5cf6;--mal:#e5484d;--susp:#e08600;--clean:#0f9d58;
--mono:"Cascadia Mono",Consolas,ui-monospace,monospace;
--sans:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14.5px/1.6 var(--sans)}
a{color:var(--brand)}
b{font-weight:700}

/* ---- 顶栏 ---- */
.top{position:sticky;top:0;z-index:30;background:rgba(255,255,255,.94);
backdrop-filter:blur(8px);border-bottom:1px solid var(--line)}
.topin{max-width:1020px;margin:0 auto;padding:10px 20px;display:flex;align-items:center;gap:12px}
.back{display:inline-flex;align-items:center;gap:7px;text-decoration:none;font-size:13.5px;
font-weight:700;color:var(--ink2);background:var(--soft);border:1px solid var(--line);
border-radius:9px;padding:7px 14px;transition:.15s;white-space:nowrap}
.back:hover{background:#fff;border-color:var(--brand);color:var(--brand)}
.tt{font-size:15px;font-weight:800}
.ver{margin-left:auto;font-size:12px;font-weight:800;color:#fff;
background:linear-gradient(135deg,var(--brand),var(--brand2));
border-radius:20px;padding:4px 12px;white-space:nowrap}

.wrap{max-width:1020px;margin:0 auto;padding:16px 20px 70px}

/* ---- 状态行:全部诊断信息压在这一行,长解释收进展开 ---- */
.st{background:var(--card);border:1px solid var(--line);border-radius:12px;
padding:11px 15px;display:flex;align-items:center;gap:9px;flex-wrap:wrap;font-size:13.2px}
.st b{font-size:15px}
.dot{width:7px;height:7px;border-radius:50%;flex:none}
.dot.ok{background:var(--clean)}.dot.warn{background:var(--susp)}.dot.bad{background:var(--mal)}
.st .sep{color:var(--line);margin:0 3px}
.st .why{margin-left:auto;font:600 12.5px var(--sans);color:var(--ink2);cursor:pointer;
background:var(--soft);border:1px solid var(--line);border-radius:8px;padding:5px 11px}
.st .why:hover{border-color:var(--brand);color:var(--brand)}
.notes{margin-top:9px;background:var(--card);border:1px solid var(--line);border-radius:12px;
padding:14px 16px;font-size:12.8px;line-height:1.85;color:var(--muted)}
.notes h4{margin:0 0 4px;font-size:13.2px;color:var(--ink)}
.notes .n+.n{margin-top:13px;padding-top:13px;border-top:1px solid var(--line2)}
.notes b{color:var(--ink2)}

/* ---- 页签 ---- */
.tabs{display:flex;gap:4px;border-bottom:1px solid var(--line);margin:18px 0 13px}
.tabs button{appearance:none;background:none;border:none;border-bottom:2px solid transparent;
cursor:pointer;font:600 14px/1 var(--sans);color:var(--muted);padding:10px 13px;transition:.15s}
.tabs button:hover{color:var(--ink)}
.tabs button.on{color:var(--brand);border-bottom-color:var(--brand);font-weight:800}
.tabs .n{font-size:11.5px;font-weight:700;color:var(--dim);margin-left:5px}
.tabs button.on .n{color:var(--brand)}

/* ---- 工具条 ---- */
.bar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:10px}
.bar input{flex:1;min-width:200px;font:14px var(--sans);padding:9px 13px;
border:1px solid var(--line);border-radius:10px;background:var(--card);color:var(--ink)}
.bar input:focus{outline:none;border-color:var(--brand)}
.chips{display:flex;gap:4px;flex-wrap:wrap}
.chip{cursor:pointer;user-select:none;font-size:12.3px;font-weight:700;padding:6px 11px;
border-radius:8px;border:1px solid var(--line);background:var(--card);color:var(--ink2);transition:.15s}
.chip:hover{border-color:var(--brand);color:var(--brand)}
.chip.on{background:var(--brand);border-color:var(--brand);color:#fff}
select{font:13px var(--sans);padding:8px 10px;border:1px solid var(--line);
border-radius:9px;background:var(--card);color:var(--ink);cursor:pointer}

/* ---- 意图分组:给长列表提供可定位的锚点 ---- */
.grp+.grp{margin-top:20px}
.ghd{display:flex;align-items:baseline;gap:9px;padding:0 2px 8px;
border-bottom:1px solid var(--line);margin-bottom:9px}
.gnm{font-size:14px;font-weight:800}
.gct{font:700 11.5px var(--mono);color:var(--brand);background:rgba(99,102,241,.1);
border-radius:20px;padding:2px 9px}
.gds{font-size:12px;color:var(--dim);margin-left:auto;text-align:right}

/* ---- 表头:把「作证」「强度」这类列名从每一行提到表头,行里只留值 ---- */
.head{display:flex;align-items:center;gap:10px;padding:0 15px 6px;
font-size:11.5px;font-weight:700;color:var(--dim)}
.head .h-g{width:52px;flex:none}
.head .h-c{flex:1}
.head .h-n{width:64px;flex:none;text-align:right}
.head .h-r{width:86px;flex:none;text-align:right}
.head .h-u{width:76px;flex:none;text-align:right}
.head .h-e{width:74px;flex:none;text-align:right}
/* 两组筛选条件挨在一起会看成同一组,加一道竖线分开 */
.divx{width:1px;height:20px;background:var(--line);margin:0 3px}

/* ---- 列表:统一行高,左侧色条表强度 ---- */
.list{display:flex;flex-direction:column;gap:6px}
.r{background:var(--card);border:1px solid var(--line);border-left:3px solid var(--line);
border-radius:10px;overflow:hidden}
.r.g-hard{border-left-color:var(--mal)}
.r.g-strong{border-left-color:var(--susp)}
.r.g-ask{border-left-color:var(--brand)}
.r>summary{list-style:none;cursor:pointer;display:flex;align-items:center;gap:10px;
padding:10px 15px;user-select:none}
.r>summary::-webkit-details-marker{display:none}
.r>summary:hover{background:var(--soft)}
.chev{flex:none;width:7px;height:7px;border-right:2px solid var(--dim);
border-bottom:2px solid var(--dim);transform:rotate(-45deg);transition:transform .15s}
.r[open]>summary .chev{transform:rotate(45deg)}
.gl{flex:none;width:52px;font-size:11.5px;font-weight:800;color:var(--muted)}
.r.g-hard .gl{color:var(--mal)}.r.g-strong .gl{color:var(--susp)}.r.g-ask .gl{color:var(--brand)}
.chain{flex:1;min-width:0;font-size:13.6px;font-weight:600;line-height:1.5}
.plus{color:var(--dim);font-weight:400;margin:0 3px}
.val{flex:none;width:64px;text-align:right;font:700 13px var(--mono);color:var(--ink2)}
.rsn{flex:none;width:86px;text-align:right;font-size:11.5px;font-weight:700;color:var(--susp)}
.ben{flex:none;font-size:11px;font-weight:800;color:var(--susp);
background:#fff4e0;border-radius:6px;padding:2px 7px;white-space:nowrap}

/* ---- 展开体 ---- */
.body{border-top:1px solid var(--line2);padding:2px 15px 12px}
.why2{background:#fff8e6;border:1px solid #f0d896;border-radius:9px;padding:10px 12px;
margin:11px 0 2px;font-size:12.3px;color:#6b5300;line-height:1.7}
.why2 div+div{margin-top:6px}
.why2 b{color:#8a5a00;margin-right:6px}
ul.mk{margin:0;padding:0;list-style:none}
ul.mk li{padding:9px 0;border-bottom:1px solid var(--line2);display:flex;align-items:flex-start;gap:10px}
ul.mk li:last-child{border-bottom:none}
.lv{flex:none;font-size:10.5px;font-weight:800;padding:2px 7px;border-radius:6px;
min-width:28px;text-align:center;margin-top:2px}
.lv.critical{background:var(--mal);color:#fff}
.lv.high{background:#fde8e8;color:var(--mal)}
.lv.medium{background:var(--soft);color:var(--muted);border:1px solid var(--line)}
.mt{flex:1;min-width:0}
.mt .cn{font-size:13.2px;font-weight:600}
.mt .en{font-size:11px;color:var(--dim);font-family:var(--mono);margin-top:2px;word-break:break-word}
.cd{font-family:var(--mono);font-size:11.4px;color:var(--muted);margin-top:3px;word-break:break-all}
.cd .dim{color:var(--dim);font-family:var(--sans)}
.ev{flex:none;font-size:11px;font-weight:700;padding:2px 9px;border-radius:7px;
background:rgba(99,102,241,.1);color:var(--brand);white-space:nowrap}
.ev.no{background:#fdecec;color:var(--mal)}
.fam{margin-top:9px;font-size:11.8px;color:var(--muted);font-family:var(--mono);
background:var(--soft);border-radius:8px;padding:7px 10px;word-break:break-all}
.fam b{font-family:var(--sans);color:var(--ink2);margin-right:7px}

/* ---- 行为标记(不可展开,直接一行到底) ---- */
.mrow{background:var(--card);border:1px solid var(--line);border-radius:10px;
padding:9px 15px;display:flex;align-items:flex-start;gap:10px}
.mrow.dead{background:#fffdf8;border-color:#ecd9b0}
.muse{flex:none;width:76px;text-align:right;font-size:11.5px;font-weight:700;
color:var(--ink2);white-space:nowrap}
.muse .z{color:var(--dim);font-weight:600}
.mnum{flex:none;width:64px;text-align:right;font:700 12.5px var(--mono);color:var(--ink2)}
.mev{flex:none;width:74px;text-align:right}

/* ---- 构建详情 ---- */
.funnel{background:var(--card);border:1px solid var(--line);border-radius:12px;
padding:14px 16px;display:flex;align-items:center;gap:11px;flex-wrap:wrap}
.fs{display:flex;flex-direction:column;min-width:70px}
.fv{font-size:22px;font-weight:800;line-height:1.1}
.fs.hl .fv{color:var(--brand)}
.fs.cut .fv{color:var(--mal)}
.fk{color:var(--muted);font-size:11.5px;margin-top:2px;white-space:nowrap}
.farr{color:var(--dim);font-size:16px}
table.t{width:100%;border-collapse:collapse;font-size:13px;background:var(--card);
border:1px solid var(--line);border-radius:12px;overflow:hidden}
table.t td{padding:8px 15px;border-bottom:1px solid var(--line2)}
table.t tr:last-child td{border-bottom:none}
table.t td:first-child{color:var(--muted);width:52%}
table.t td:last-child{font-family:var(--mono);font-weight:600}
.sec{font-size:13.2px;font-weight:800;margin:19px 0 8px}
.note{background:var(--card);border:1px solid var(--line);border-radius:12px;
padding:13px 16px;font-size:12.6px;color:var(--muted);line-height:1.85}
.note b{color:var(--ink2)}
.cnt{font-size:12px;color:var(--muted);margin:0 0 8px 2px}
.cnt b{color:var(--ink)}

/* ---- 原理页:编号步骤 + 反例框 ---- */
.stp{background:var(--card);border:1px solid var(--line);border-radius:12px;
padding:15px 18px;margin-bottom:9px;display:flex;gap:14px;align-items:flex-start}
.stn{flex:none;width:26px;height:26px;border-radius:8px;background:var(--brand);color:#fff;
font:800 13px/26px var(--mono);text-align:center;margin-top:1px}
.stb{flex:1;min-width:0}
.stt{font-size:14.2px;font-weight:800;margin-bottom:5px}
.stx{font-size:13px;line-height:1.9;color:var(--ink2)}
.stx b{color:var(--ink)}
.stx code{font-size:11.8px}
.stx p{margin:9px 0 0}
.stx ul{margin:8px 0 0;padding-left:20px}
.stx li+li{margin-top:5px}
/* 反例框:讲「不这么做会怎样」比讲「这么做很好」更能说明设计取舍 */
.bad{background:#fdf3f3;border:1px solid #f0cfd0;border-radius:9px;
padding:10px 13px;margin-top:10px;font-size:12.4px;line-height:1.8;color:#8a2b2e}
.good{background:#f2f8f4;border:1px solid #cbe5d5;border-radius:9px;
padding:10px 13px;margin-top:10px;font-size:12.4px;line-height:1.8;color:#155e35}
.bad b{color:#a3272b}.good b{color:#0f7a3d}
/* 只有【首个】 b 当标题成块。写成 `.bad b{display:block}` 会把句中的行内强调也拆成块,
   于是「这类是<b>软信号</b>。」被切成三行 —— 已踩过一次。 */
.bad>b:first-child,.good>b:first-child{display:block;margin-bottom:2px}
/* 流水线示意:纯文本,不引任何图表库 */
.flow{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-top:11px;
background:var(--soft);border:1px solid var(--line);border-radius:9px;padding:11px 13px}
.fbox{background:#fff;border:1px solid var(--line);border-radius:7px;padding:5px 10px;
font-size:12.2px;font-weight:700;white-space:nowrap}
.fbox.hl{border-color:var(--brand);color:var(--brand)}
.fsep{color:var(--dim);font-size:14px}
.empty{background:var(--card);border:1px solid var(--line);border-radius:12px;
padding:32px;text-align:center;color:var(--muted)}
code{font-family:var(--mono);background:var(--soft);border:1px solid var(--line);
border-radius:5px;padding:1px 6px;font-size:12px}
.foot{color:var(--muted);font-size:12px;margin-top:22px}
@media(max-width:720px){.head .h-n,.head .h-r{width:52px}.val{width:52px}.rsn{width:70px}}
</style></head><body>
<div class="top"><div class="topin">
<a class="back" href="/">← 返回威胁分析台</a>
<span class="tt">攻击链组合引擎</span>
<span class="ver" id="ver"></span>
</div></div>
<div class="wrap">
<div class="st" id="st"></div>
<div class="notes" id="notes" hidden></div>

<div class="tabs" id="tabs">
<button data-tab="live">生效规则<span class="n" id="n-live"></span></button>
<button data-tab="cut">已剔除<span class="n" id="n-cut"></span></button>
<button data-tab="mk">行为标记<span class="n" id="n-mk"></span></button>
<button data-tab="build">构建详情</button>
<button data-tab="how">原理</button>
</div>

<section id="tab-live">
<div class="bar">
<input type="search" id="q" placeholder="搜索动作名 / Sigma 规则原名 / 判定条件 / 家族">
<div class="chips" id="gchips"></div>
<select id="sort">
<option value="sup">组内按作证样本数</option>
<option value="n">组内按动作数</option>
<option value="g">组内按强度</option>
<option value="ben">组内按正常软件出现数</option>
</select>
</div>
<div class="bar" id="tacbar"><div class="chips" id="tchips"></div></div>
<div class="cnt" id="cnt1"></div>
<div id="list1"></div>
</section>

<section id="tab-cut" hidden>
<div class="note" id="cutnote"></div>
<div class="bar" style="margin-top:12px">
<input type="search" id="q2" placeholder="搜索动作名 / Sigma 规则原名 / 判定条件">
<div class="chips" id="rchips"></div>
</div>
<div class="cnt" id="cnt2"></div>
<div class="head"><span class="chev" style="visibility:hidden"></span>
<span class="h-g">强度</span><span class="h-c">动作链</span>
<span class="h-r">剔除原因</span></div>
<div class="list" id="list2"></div>
</section>

<section id="tab-mk" hidden>
<div class="bar">
<input type="search" id="mq" placeholder="搜索标记中文名 / Sigma 原名 / 判定条件 / 意图">
<div class="chips" id="lchips"></div>
<span class="divx"></span>
<div class="chips" id="dchips"></div>
</div>
<div class="bar"><div class="chips" id="mtchips"></div></div>
<div class="cnt" id="cnt3"></div>
<div id="list3"></div>
</section>

<section id="tab-build" hidden>
<div class="sec">压缩流程</div>
<div class="funnel" id="funnel"></div>
<div class="note" id="pipe" style="margin-top:9px"></div>
<div class="sec">阈值（写死在 engine_build.py，不是学出来的参数）</div>
<table class="t" id="thr"></table>
<div class="sec">本轮构建统计</div>
<table class="t" id="raw"></table>
</section>

<section id="tab-how" hidden><div id="how"></div></section>

<p class="foot" id="foot"></p>
</div>
<script>
const D = /*__DATA__*/null;
const $ = s => document.querySelector(s);
const esc = s => String(s==null?'':s).replace(/[&<>"]/g,
  c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
/* 强度用短标签 + 左侧色条。原来「阻断或强提示」六个字占掉一大块,还得配个彩色胶囊,
   一行里就有两处抢注意力;短标签配色条同样能扫,完整含义放 title。 */
const G = {hard:{s:'拦断', t:'可直接阻断：单独命中即可定性，客户端直接拦', c:'g-hard'},
           strong:{s:'强提示', t:'阻断或给出强提示', c:'g-strong'},
           ask:{s:'询问', t:'弹窗交给用户确认', c:'g-ask'}};
const GORD = {hard:3, strong:2, ask:1};
const RSN = {unobservable:'不可观测', actor:'主体冲突', redundant:'证据重复', single:'单动作'};
const S = {q:'', grade:'', tac:'', sort:'sup', q2:'', rsn:'', mq:'', mlv:'', mdead:'', mtac:''};

const LIVE = () => D.patterns.filter(p => p.live);
const CUT  = () => D.patterns.filter(p => !p.live);

/* ---- 状态行 ---- */
function status(){
  const b = D.benign, cut = D.served - D.live;
  const bits = [];
  bits.push('<span class="dot ok"></span><b>' + D.live + '</b> 条规则生效');
  bits.push('<span class="sep">|</span><span class="dot ' + (cut ? 'warn' : 'ok')
    + '"></span><b>' + cut + '</b> 条被剔除');
  if(!b.total)
    bits.push('<span class="sep">|</span><span class="dot bad"></span>区分度未启用（无正常样本语料）');
  else if(b.total < D.benign_min)
    bits.push('<span class="sep">|</span><span class="dot warn"></span>区分度积累中（正常语料 '
      + b.total + '/' + D.benign_min + '）');
  else
    bits.push('<span class="sep">|</span><span class="dot ok"></span>区分度已启用（正常语料 '
      + b.total + '）');
  bits.push('<button class="why" id="why">说明</button>');
  $('#st').innerHTML = bits.join('');

  const n = [];
  if(!b.total){
    n.push(['区分度未启用', '所有组合目前只由恶意样本证据定档 —— 能算出「多少病毒有这个组合」，'
      + '算不出「多少正常软件也有」，而后者才是误报的直接预测量。'
      + '信誉查询本来就为每个 hash 抓了沙箱行为，干净文件的留存已放开，语料会随客户端查询自动积累，'
      + '不需要人工投喂样本。攒到 <b>' + D.benign_min + '</b> 个即自动参与定级。']);
  } else if(b.total < D.benign_min){
    n.push(['区分度积累中', '已有 <b>' + b.total + '</b> 个正常样本（' + b.with_markers
      + ' 个有沙箱行为命中、' + b.signed + ' 个带有效签名），出现率已在统计并显示，'
      + '但<b>不参与定级</b> —— 几个样本算出的比率噪声大于信号，拿它去砍规则会砍错真规则、留下假规则。'
      + '门槛 <b>' + D.benign_min + '</b> 个。']);
  } else {
    let x = '正常语料 <b>' + b.total + '</b> 个作分母（' + b.with_markers + ' 个有沙箱行为命中、'
          + b.signed + ' 个带有效签名）。';
    if(D.benign_capped) x += '已有 <b>' + D.benign_capped + '</b> 条组合因在正常软件中出现而被降档。';
    if(D.benign_dropped) x += '<b>' + D.benign_dropped + '</b> 条被整条丢弃。';
    if(D.benign_generic) x += '另有 <b>' + D.benign_generic + '</b> 个标记因在正常软件里过于普遍而被剔除。';
    if(!D.benign_capped && !D.benign_dropped) x += '尚无组合被正常语料降档。';
    n.push(['区分度已启用', x]);
  }
  if(cut){
    const parts = [];
    for(const k in D.issues) parts.push((RSN[k]||k) + ' <b>' + D.issues[k] + '</b> 条');
    n.push(['为什么有 ' + cut + ' 条被剔除',
      '服务器挖的是「样本做了什么」，客户端装载时还要过一遍「本机能不能判、算不算互证」：'
      + parts.join('、') + '。这些组合留着是死规则或伪互证，不会用于拦截。详见「已剔除」页签。']);
  }
  $('#notes').innerHTML = n.map(x =>
    '<div class="n"><h4>' + x[0] + '</h4>' + x[1] + '</div>').join('');
  $('#why').onclick = () => { $('#notes').hidden = !$('#notes').hidden; };
}

/* ---- 组合行 ---- */
const TAC = {};
function hay(p){
  let h = (p.fam || '').toLowerCase() + ' ' + (TAC[p.tac] || '');
  for(const m of p.mk)
    h += ' ' + m.cn.toLowerCase() + ' ' + m.en.toLowerCase() + ' ' + m.evcn
       + ' ' + m.cond.join(' ').toLowerCase() + ' ' + (TAC[m.tac] || '');
  return h;
}
function markerList(p){
  return '<ul class="mk">' + p.mk.map(m =>
    '<li><span class="lv ' + m.lv + '">' + m.lvcn + '</span><div class="mt">'
    + '<div class="cn">' + esc(m.cn) + '</div>'
    + (m.en ? '<div class="en">' + esc(m.en) + '</div>' : '')
    + '<div class="cd">' + (m.cond.length
        ? '判定条件：' + esc(m.cond.join(' · '))
        : '<span class="dim">无具体条件（仅按事件类型）</span>') + '</div></div>'
    + (m.obs && m.ev ? '<span class="ev">' + esc(m.evcn) + '</span>'
                     : '<span class="ev no">不可观测</span>') + '</li>').join('') + '</ul>';
}
function row(p, cut){
  const g = G[p.g] || {s:p.g, t:'', c:''};
  const chain = p.mk.map(m => esc(m.cn)).join('<span class="plus">＋</span>');
  /* 正常侧只在【真有命中】时出现。语料为 0 时每行都挂个「正常软件 0」等于 32 遍噪音,
     而且「0」在没查过的情况下是个假结论。 */
  const ben = (!cut && p.ben > 0)
    ? '<span class="ben" title="这条组合在正常软件里也出现过，越高越可能误伤">正常 '
      + p.ben + '/' + D.benign.total + '</span>' : '';
  const right = cut
    ? '<span class="rsn" title="客户端按固定顺序判定，撞上第一条即丢弃">'
      + esc(RSN[(p.iss[0]||{}).k] || '—') + '</span>'
    : '<span class="val" title="有多少个恶意样本同时具备这几个动作">' + p.sup + '</span>';
  return '<details class="r ' + g.c + '"><summary><span class="chev"></span>'
    + '<span class="gl" title="' + esc(g.t) + '">' + g.s + '</span>'
    + '<span class="chain">' + chain + '</span>' + ben + right
    + '</summary><div class="body">'
    + (p.iss.length ? '<div class="why2">' + p.iss.map((i, ix) =>
        '<div><b>' + esc(i.t) + (ix === 0 ? '（决定性）' : '') + '</b>' + esc(i.d)
        + '</div>').join('') + '</div>' : '')
    + markerList(p)
    + (p.fam ? '<div class="fam"><b>常见家族</b>' + esc(p.fam) + '</div>' : '')
    + '</div></details>';
}

function cmp(a, b){
  return S.sort==='n'   ? (b.n - a.n) || (b.sup - a.sup)
       : S.sort==='ben' ? (b.ben - a.ben) || (b.sup - a.sup)
       : S.sort==='g'   ? ((GORD[b.g]||0) - (GORD[a.g]||0)) || (b.sup - a.sup)
       :                  (b.sup - a.sup) || (b.n - a.n);
}

/* 分组渲染。扁平 28 行时每行长得都差不多、标记名反复出现,滚起来没有锚点;
   按意图切成 2~9 条一组后,每屏都有标题可定位,也顺带答了「这套库在防什么」。
   空组不渲染 —— 搜索/筛选后剩几组就只显示几组,不留一排「0 条」的空标题。 */
function grouped(rows, host, emptyMsg, mkRow, headHtml){
  const by = {};
  rows.forEach(p => { (by[p.tac] = by[p.tac] || []).push(p); });
  const out = [];
  for(const t of D.tactics){
    const g = by[t.k];
    if(!g || !g.length) continue;
    g.sort(cmp);
    // 列名只在第一组给一次。七个组各印一遍纯属重复 —— 列本身(短词/动作链/数字)
    // 一眼就能认出来,而且各组列宽一致,对齐关系不会因为没有表头而丢。
    out.push('<section class="grp"><div class="ghd">'
      + '<span class="gnm">' + esc(t.t) + '</span>'
      + '<span class="gct">' + g.length + ' 条</span>'
      + '<span class="gds">' + esc(t.d) + '</span></div>'
      + (out.length === 0 ? (headHtml || '') : '')
      + '<div class="list">' + g.map(mkRow).join('') + '</div></section>');
  }
  host.innerHTML = out.length ? out.join('') : '<div class="empty">' + emptyMsg + '</div>';
}

const HEAD1 = '<div class="head"><span class="chev" style="visibility:hidden"></span>'
  + '<span class="h-g">强度</span><span class="h-c">动作链（凑齐即命中）</span>'
  + '<span class="h-n">作证样本</span></div>';

function renderLive(){
  const q = S.q.trim().toLowerCase();
  const rows = LIVE().filter(p =>
    (!S.grade || p.g === S.grade) && (!S.tac || p.tac === S.tac)
    && (!q || hay(p).indexOf(q) >= 0));
  $('#cnt1').innerHTML = '显示 <b>' + rows.length + '</b> / 生效 ' + D.live + ' 条'
    + '　·　按攻击意图分组';
  grouped(rows, $('#list1'), '没有符合条件的规则。', p => row(p, false), HEAD1);
}

function renderCut(){
  const cut = CUT();
  const parts = [];
  for(const k in D.issues) parts.push((RSN[k]||k) + ' <b>' + D.issues[k] + '</b> 条');
  $('#cutnote').innerHTML = '这些组合服务器挖出来了、也下发到客户端了，但客户端装载时会丢弃 —— '
    + '它们要么本机没有可判条件（死规则），要么多个「动作」其实是同一个条件（伪互证）。'
    + '判定顺序与 <code>AttackChainEngine::applyPayload</code> 一致，撞上第一条即丢弃。'
    + (parts.length ? '<br>分布：' + parts.join('、') + '（一条可能有多个毛病，故之和可能大于 '
        + cut.length + '）。' : '');
  const q = S.q2.trim().toLowerCase();
  const rows = cut.filter(p =>
    (!S.rsn || (p.iss[0] && p.iss[0].k === S.rsn)) && (!q || hay(p).indexOf(q) >= 0));
  rows.sort((a,b) => (b.sup - a.sup) || (b.n - a.n));
  $('#cnt2').innerHTML = '显示 <b>' + rows.length + '</b> / 剔除 ' + cut.length + ' 条';
  $('#list2').innerHTML = rows.length ? rows.map(p => row(p, true)).join('')
    : '<div class="empty">没有符合条件的组合。</div>';
}

/* ---- 行为标记 ---- */
/* 正常侧那一列【只在真能说明问题时才出现】。语料还只有几个的时候它恒为 0,
   摆出来就是把「32 个正常软件 0」的噪音换个位置又来一遍,而且 0 在没查过时是假结论。
   判据:语料已达定级门槛,或者确实有标记命中过正常样本。 */
const BENCOL = () => D.benign.total >= D.benign_min || D.mk.some(m => m.ben > 0);

function renderMk(){
  const q = S.mq.trim().toLowerCase();
  const bc = BENCOL();
  const rows = D.mk.filter(m => {
    if(S.mlv && m.lv !== S.mlv) return false;
    if(S.mtac && m.tac !== S.mtac) return false;
    if(S.mdead === 'dead' && (m.obs && m.ev)) return false;
    if(S.mdead === 'unused' && m.uselive > 0) return false;
    if(q && (m.cn + ' ' + m.en + ' ' + m.cond.join(' ')
             + ' ' + (TAC[m.tac] || '')).toLowerCase().indexOf(q) < 0) return false;
    return true;
  });
  $('#cnt3').innerHTML = '显示 <b>' + rows.length + '</b> / 下发给客户端 ' + D.mk.length
    + ' 个（词表总量 ' + D.markers_total + '）　·　按攻击意图分组';
  /* 表头随列数变化 —— 早先右侧两个裸数字没有列名,读者分不清哪个是恶意哪个是正常 */
  const head = '<div class="head"><span class="h-g" style="width:36px">强度</span>'
    + '<span class="h-c">行为标记</span><span class="h-u">用于规则</span>'
    + '<span class="h-n">恶意样本</span>'
    + (bc ? '<span class="h-n">正常样本</span>' : '')
    + '<span class="h-e">事件</span></div>';
  const mkRow = m => {
    const dead = !(m.obs && m.ev);
    return '<div class="mrow' + (dead ? ' dead' : '') + '">'
      + '<span class="lv ' + m.lv + '">' + m.lvcn + '</span>'
      + '<div class="mt"><div class="cn">' + esc(m.cn) + '</div>'
      + (m.en ? '<div class="en">' + esc(m.en) + '</div>' : '')
      + '<div class="cd">' + (m.cond.length
          ? '判定条件：' + esc(m.cond.join(' · '))
          : '<span class="dim">无具体条件（仅按事件类型）</span>') + '</div></div>'
      + '<span class="muse" title="被多少条生效规则用到">'
      + (m.uselive ? m.uselive + ' 条' : '<span class="z">未使用</span>') + '</span>'
      + '<span class="mnum" title="出现该行为的恶意样本数">' + m.sam + '</span>'
      + (bc ? '<span class="mnum" title="出现该行为的正常样本数">' + m.ben + '</span>' : '')
      + '<span class="mev">' + (dead ? '<span class="ev no">不可观测</span>'
              : '<span class="ev">' + esc(m.evcn) + '</span>') + '</span></div>';
  };
  /* 标记表同样分组:39 个平铺时同一主题的标记散落各处(四种计划任务、三种 Defender
     排除项),分组后一眼能看出「这个意图下引擎认得几种手法」。
     排序用「用于生效规则数」降序 —— 组内最要紧的是哪个标记真在干活。 */
  const by = {};
  rows.forEach(m => { (by[m.tac] = by[m.tac] || []).push(m); });
  const out = [];
  for(const t of D.tactics){
    const g = by[t.k];
    if(!g || !g.length) continue;
    g.sort((a,b) => (b.uselive - a.uselive) || (b.sam - a.sam) || a.cn.localeCompare(b.cn));
    out.push('<section class="grp"><div class="ghd"><span class="gnm">' + esc(t.t) + '</span>'
      + '<span class="gct">' + g.length + ' 个</span>'
      + '<span class="gds">' + esc(t.d) + '</span></div>'
      + (out.length === 0 ? head : '')
      + '<div class="list">' + g.map(mkRow).join('') + '</div></section>');
  }
  $('#list3').innerHTML = out.length ? out.join('')
    : '<div class="empty">没有符合条件的标记。</div>';
}

/* ---- 构建详情 ---- */
function renderBuild(){
  const cut = D.served - D.live;
  $('#funnel').innerHTML =
    '<div class="fs"><span class="fv">' + D.mined + '</span><span class="fk">挖出原始组合</span></div>'
  + '<span class="farr">→</span>'
  + '<div class="fs"><span class="fv">' + D.dedup + '</span><span class="fk">去冗余后</span></div>'
  + '<span class="farr">→</span>'
  + '<div class="fs"><span class="fv">' + D.served + '</span><span class="fk">下发客户端</span></div>'
  + '<span class="farr">→</span>'
  + '<div class="fs hl"><span class="fv">' + D.live + '</span><span class="fk">实际生效</span></div>'
  + (cut ? '<div class="fs cut"><span class="fv">-' + cut + '</span><span class="fk">装载时剔除</span></div>' : '');
  $('#pipe').innerHTML = '恶意作证样本 <b>' + D.samples + '</b> 个 · 行为标记 <b>' + D.mk.length
    + '</b> 个 · 正常语料 <b>' + D.benign.total + '</b> 个（上限 ' + (D.benign.cap||0) + '）。'
    + '<br>去冗余是折叠掉「子集且支持度接近」的组合，再由贪心集合覆盖挑出能解释最多样本的最小子集。'
    + (D.benign.total >= D.benign_min
        ? '<br>区分度<b>已参与</b>定级。'
        : '<br>区分度<b>未参与</b>定级：语料 ' + D.benign.total + ' 个，门槛 ' + D.benign_min + ' 个。');
  const thr = [
    ['一条组合最少要多少样本作证', 'MIN_SUPPORT = 5'],
    ['组合最多几个动作', 'MAX_ITEMSET = 4'],
    ['判「拦断」所需样本数', 'SUPPORT_FOR_HARD = 10'],
    ['判「强提示」所需样本数', 'SUPPORT_FOR_STRONG = 8'],
    ['判「询问」所需样本数', 'SUPPORT_FOR_ASK = 5'],
    ['恶意样本内出现率超此值视为通用行为', 'GENERIC_DF_RATIO = 0.45'],
    ['正常样本内出现率超此值即剔除该标记', 'BENIGN_GENERIC_RATIO = 0.30'],
    ['组合在正常软件出现率超此值 → 只能询问', 'BENIGN_ASK_RATIO = 0.02'],
    ['组合在正常软件出现率超此值 → 整条丢弃', 'BENIGN_DROP_RATIO = 0.10'],
    ['正常语料少于此数则不参与定级', 'BENIGN_MIN_CORPUS = ' + D.benign_min],
  ];
  $('#thr').innerHTML = thr.map(r =>
    '<tr><td>' + esc(r[0]) + '</td><td>' + esc(r[1]) + '</td></tr>').join('');
  const keys = Object.keys(D.stats).sort();
  $('#raw').innerHTML = keys.length
    ? keys.map(k => '<tr><td>' + esc(k) + '</td><td>' + esc(D.stats[k]) + '</td></tr>').join('')
    : '<tr><td>（本轮没有统计数据）</td><td>—</td></tr>';
}

/* ---- 原理 ---- */
/* 这一页刻意多用「反例」:讲「不这么做会怎样」比讲「这么做很好」更能说明设计取舍,
   而且这些反例全是实测撞出来的,不是假想。数字用当前库的真实值,免得文档和现实脱节。 */
function renderHow(){
  const S1 = [];
  const step = (t, x) => S1.push('<div class="stp"><div class="stn">' + (S1.length + 1)
    + '</div><div class="stb"><div class="stt">' + t + '</div><div class="stx">' + x
    + '</div></div></div>');

  step('为什么非要「几个动作凑齐」',
    '单个动作说明不了问题 —— 正常安装程序也写开机自启动项、也往磁盘落 exe、也建计划任务。'
    + '但<b>若干动作凑在一起</b>就足以定性：一个程序既给 Defender 加排除项、又从 Temp 跑脚本、'
    + '又往 lsass 里塞未签名模块，这个组合正常软件不会有。'
    + '<p>所以本引擎的输出不是「哪个动作可疑」，而是「哪几个动作凑在一起就是病毒」。'
    + '一条组合至少要 <b>2</b> 个动作，最多 <b>4</b> 个。</p>'
    + '<div class="bad"><b>单动作为什么不行</b>'
    + '「未签名」「从可疑路径运行」「本机首见」这类是<b>软信号</b>。'
    + '本产品的底线是：软信号单独出现绝不触发拦截或弹窗，必须由硬指标互证。'
    + '一条只靠软信号的规则，等于把软信号提拔成了处置依据。</div>');

  step('语料从哪来：真实样本的沙箱记录',
    '归档里每份 VirusTotal 报告都自带沙箱行为记录 —— 该样本在虚拟机里跑起来后做过什么。'
    + '当前有 <b>' + D.samples + '</b> 个带行为记录的 Windows 恶意样本作证。'
    + '<p>只取 <code>sigma_analysis_results</code>（社区 Sigma 规则命中，自带严重度），'
    + '<b>不用</b> <code>processes_created</code> / <code>files_written</code> / '
    + '<code>registry_keys_set</code> 这些原始字段。</p>'
    + '<div class="bad"><b>用原始字段会怎样（实测）</b>'
    + '沙箱记录里<b>环境噪音压倒性多数</b>。按频次排序，冠军是 services.exe、svchost.exe、'
    + 'lsass.exe、/bin/gzip、/var/log/*.gz —— 全是虚拟机自己的正常活动，跟样本无关。'
    + '所以判断交给社区 Sigma 规则做，不自己从噪音里猜。</div>');

  step('另外两个实测踩到的坑',
    '<ul><li><b>归档里 42% 是 Linux/ELF 样本</b>（mirai 家族霸榜），对 Windows 端点无用，'
    + '先按文件类型剔除。本轮剔掉 <b>' + (D.stats.skipped_other_platform || 0) + '</b> 份。</li>'
    + '<li><b>同义标记与蕴含标记</b>会让组合虚高。'
    + '「Powershell Defender Exclusion」与「Windows Defender Exclusions Added - PowerShell」'
    + '实测共现 44 次，本是同一个动作，算成两个等于凭一个动作就凑够一组；'
    + '「New RUN Key Pointing to Suspicious Folder」必然同时命中'
    + '「CurrentVersion Autorun Keys Modification」（前者是后者的特例），两者同现不构成互证。</li></ul>'
    + '<p>同义靠人工表归一；<b>蕴含靠数据自动识别</b> —— 条件概率 P(B|A) &gt; 0.90 即判定 A 蕴含 B '
    + '并折叠掉 B，这样新出现的蕴含关系不必等人去发现。本轮自动识别出 <b>'
    + (D.stats.implications || 0) + '</b> 条蕴含关系。</p>');

  step('怎么把组合数出来（纯计数，没有模型）',
    '<div class="flow"><span class="fbox">Apriori 频繁项集</span><span class="fsep">→</span>'
    + '<span class="fbox">折叠冗余组合</span><span class="fsep">→</span>'
    + '<span class="fbox">贪心集合覆盖</span><span class="fsep">→</span>'
    + '<span class="fbox hl">' + D.served + ' 条下发</span></div>'
    + '<p><b>Apriori</b>：只扩展已达支持度的项集，避免组合爆炸。本轮挖出 <b>'
    + D.mined + '</b> 条原始组合。</p>'
    + '<p><b>折叠冗余</b>：若某组合是另一个组合的子集、且支持度接近（比值 ≥ 0.80），'
    + '说明命中前者的样本几乎都把超集里的动作全做了，单独留它只会让规则库变大、'
    + '而且更容易误伤（要求的动作更少）。剩 <b>' + D.dedup + '</b> 条。</p>'
    + '<p><b>集合覆盖</b>：去冗余后仍彼此高度重叠 —— 一个命中 8 个标记的样本能派生出 56 个三元组。'
    + '于是每轮挑「能新覆盖最多样本」的那条，直到没有组合还能新增覆盖。最终 <b>'
    + D.served + '</b> 条，覆盖率没变，说明删掉的确实是冗余。</p>'
    + '<div class="good"><b>为什么强调「纯计数」</b>'
    + '全流程没有任何模型、没有训练、没有学出来的权重。所有阈值都写死在 '
    + '<code>engine_build.py</code> 里（见「构建详情」页签）。'
    + '样本越多组合越准，每天增量重算即可，不需要重新训练。</div>');

  step('怎么定强度：三个维度都要够',
    '强度决定「能不能不问就拦」，宁保守勿激进。动作数（链条多长）× 最高严重度 × '
    + '支持度（多少真实样本作证），三者都要够：'
    + '<ul><li><b>拦断</b>：≥3 动作 + 含高/严重 + ≥10 个样本作证</li>'
    + '<li><b>强提示</b>：≥3 动作 + ≥8 个样本</li>'
    + '<li><b>询问</b>：≥2 动作 + 含高/严重 + ≥5 个样本</li>'
    + '<li>其余一律丢弃</li></ul>'
    + '<div class="bad"><b>只按动作数分级会怎样（实测）</b>'
    + '1729 条仅 5~13 个样本支撑的组合全被判成「可直接拦」。证据这么薄就敢直接阻断即是过拟合，'
    + '所以越是要「不问就拦」，越要更多样本作证。<br>'
    + '另外：两个「中」级动作绝不下判断 —— 实测正常安装程序确实会「写 Run 键 + 落 exe」，'
    + '凭这个就拦必然误伤。</div>');

  step('区分度：为什么必须有正常样本语料',
    '上面所有阈值都只看恶意样本，答的是「<b>多少病毒</b>有这个组合」。'
    + '真正决定误报的是另一个问题：「<b>多少正常软件</b>也有」。缺了后者，'
    + '一条组合是真特征还是普遍现象根本区分不出来。'
    + '<p>正常语料来自信誉查询本身 —— 每次查 hash 时顺带抓到的沙箱行为，'
    + '干净文件的那份留下来当分母。当前 <b>' + D.benign.total + '</b> 个，门槛 <b>'
    + D.benign_min + '</b> 个'
    + (D.benign.total >= D.benign_min ? '（<b>已参与</b>定级）。' : '（<b>未参与</b>定级）。') + '</p>'
    + '<p>参与定级时<b>只降不升</b>：恶意侧证据再多，也不能抵消「正常软件也这么干」这个事实。'
    + '命中过正常样本就不许「不问就拦」；出现率 &gt; 2% 只能询问；&gt; 10% 整条丢弃。'
    + '标记层面，正常软件里出现率 &gt; 30% 的直接剔除。</p>'
    + '<div class="bad"><b>没有区分度会怎样（实测）</b>'
    + '曾有一条组合，两个标记的判定条件都退化成「未签名的进程创建」，支持度 13、严重度「高」，'
    + '顺利进档。实际命中的是 ripgrep 和<b>本产品自己的界面程序</b>。'
    + '<br>另一个陷阱：恶意样本内部的出现率（<code>GENERIC_DF_RATIO</code>）答不了这个问题 —— '
    + '一个标记完全可以只出现在 5% 的病毒里、却出现在 90% 的正常软件里，照样过门槛。</div>');

  step('客户端拿到规则后怎么用',
    '服务器只下发「哪几个动作凑一起是病毒」，客户端还得知道「这个动作在我这儿长什么样」。'
    + '所以每个标记都带一份匹配条件（主体 / 目标 / 命令行 / 父进程 / 未签名），'
    + '字段名与本产品的防御规则完全一致 —— 客户端<b>直接复用现成的规则匹配实现</b>，'
    + '不为本引擎另写一套。'
    + '<p>装载时还要过一遍「本机能不能判、算不算互证」，四条判据按顺序走，撞上第一条即丢弃：'
    + '本轮 ' + D.served + ' 条里丢掉了 ' + (D.served - D.live) + ' 条，实际生效 <b>'
    + D.live + '</b> 条。详见「已剔除」页签。</p>'
    + '<div class="good"><b>命中之后并不直接等于拦截</b>'
    + '命中只是决策流水线上的一步。流水线前面还有几道无条件放行：本产品自身组件、'
    + '用户信任的文件与目录、已安装的第三方安全软件。'
    + '也就是说 —— 写一条拦截规则并不能越过那几道放行。</div>');

  $('#how').innerHTML = S1.join('');
}

/* ---- 筛选 chip ---- */
function chips(host, items, cur, cb){
  host.innerHTML = items.map(it =>
    '<span class="chip' + (it[0]===cur ? ' on' : '') + '" data-v="' + it[0] + '">'
    + esc(it[1]) + '</span>').join('');
  host.onclick = e => { const c = e.target.closest('.chip'); if(c) cb(c.dataset.v); };
}
function gradeChips(){
  const n = {hard:0, strong:0, ask:0}, live = LIVE();
  live.forEach(p => { if(n[p.g] !== undefined) n[p.g]++; });
  chips($('#gchips'), [['','全部 ' + live.length], ['hard','拦断 ' + n.hard],
                       ['strong','强提示 ' + n.strong], ['ask','询问 ' + n.ask]],
        S.grade, v => { S.grade = v; gradeChips(); renderLive(); });
}
/* 意图既是分组依据、也做筛选:组多的时候「只看这一类」比滚到那个标题更快 */
function tacChips(){
  const n = {};
  LIVE().forEach(p => { n[p.tac] = (n[p.tac] || 0) + 1; });
  const items = [['', '全部意图']];
  for(const t of D.tactics) if(n[t.k]) items.push([t.k, t.t + ' ' + n[t.k]]);
  chips($('#tchips'), items, S.tac, v => { S.tac = v; tacChips(); renderLive(); });
}
function mtacChips(){
  const n = {};
  D.mk.forEach(m => { n[m.tac] = (n[m.tac] || 0) + 1; });
  const items = [['', '全部意图']];
  for(const t of D.tactics) if(n[t.k]) items.push([t.k, t.t + ' ' + n[t.k]]);
  chips($('#mtchips'), items, S.mtac, v => { S.mtac = v; mtacChips(); renderMk(); });
}
function rsnChips(){
  const items = [['','全部 ' + CUT().length]];
  for(const k of ['unobservable','actor','redundant','single'])
    if(D.issues[k]) items.push([k, RSN[k] + ' ' + D.issues[k]]);
  chips($('#rchips'), items, S.rsn, v => { S.rsn = v; rsnChips(); renderCut(); });
}
function lvChips(){
  const n = {critical:0, high:0, medium:0};
  D.mk.forEach(m => { if(n[m.lv] !== undefined) n[m.lv]++; });
  chips($('#lchips'), [['','全部 ' + D.mk.length], ['critical','严重 ' + n.critical],
                       ['high','高 ' + n.high], ['medium','中 ' + n.medium]],
        S.mlv, v => { S.mlv = v; lvChips(); renderMk(); });
}
function deadChips(){
  const dead = D.mk.filter(m => !(m.obs && m.ev)).length;
  const unused = D.mk.filter(m => !m.uselive).length;
  const items = [['','状态不限']];
  if(dead) items.push(['dead','不可观测 ' + dead]);
  if(unused) items.push(['unused','未被使用 ' + unused]);
  chips($('#dchips'), items, S.mdead, v => { S.mdead = v; deadChips(); renderMk(); });
}

/* ---- 装配 ---- */
const TABS = ['live','cut','mk','build','how'];
function setTab(t){
  if(!TABS.includes(t)) t = 'live';
  document.querySelectorAll('#tabs button').forEach(
    x => x.classList.toggle('on', x.dataset.tab === t));
  TABS.forEach(x => { $('#tab-' + x).hidden = (x !== t); });
}
function init(){
  if(!D || !D.version){
    $('#st').innerHTML = '特征库还没有构建过。在服务器上执行 '
      + '<code>python3 /opt/bulwark-intel/engine_build.py</code> 即可生成。';
    $('#tabs').hidden = true;
    document.querySelectorAll('section').forEach(s => s.hidden = true);
    return;
  }
  // 优先显示给人看的版本号(0.1 起 +0.1);老库没有 label 时回退到内部整数版本号。
  $('#ver').textContent = D.label ? ('特征库 ' + D.label) : ('特征库 v' + D.version);
  $('#ver').title = '内部版本号 v' + D.version + '（客户端据此判断是否需要重新下载）';
  $('#n-live').textContent = D.live;
  $('#n-cut').textContent = D.served - D.live;
  $('#n-mk').textContent = D.mk.length;
  // 没有正常语料时「按正常软件出现数」排序是个死控件,直接去掉,不留下来让人点了没反应
  if(!BENCOL()){
    const o = document.querySelector('#sort option[value="ben"]');
    if(o) o.remove();
  }
  $('#foot').innerHTML = '构建于 ' + esc(D.built_at || '—')
    + ' · 下载接口 <code>/v1/engine/manifest</code>、<code>/v1/engine/patterns</code>'
    + ' · <a href="/online">连接与访问</a> · <a href="/">返回威胁分析台</a>';
  D.tactics.forEach(t => { TAC[t.k] = t.t; });
  status(); gradeChips(); tacChips(); rsnChips(); lvChips(); deadChips(); mtacChips();
  renderLive(); renderCut(); renderMk(); renderBuild(); renderHow();

  // 页签支持 #cut / #mk / #build 锚点 —— 排查时要能把「就是这条」的链接直接发给人。
  $('#tabs').onclick = e => {
    const b = e.target.closest('button');
    if(!b) return;
    setTab(b.dataset.tab);
    history.replaceState(null, '', '#' + b.dataset.tab);
  };
  setTab((location.hash || '#live').slice(1));
  addEventListener('hashchange', () => setTab((location.hash || '#live').slice(1)));

  $('#q').oninput   = e => { S.q = e.target.value; renderLive(); };
  $('#sort').onchange = e => { S.sort = e.target.value; renderLive(); };
  $('#q2').oninput  = e => { S.q2 = e.target.value; renderCut(); };
  $('#mq').oninput  = e => { S.mq = e.target.value; renderMk(); };
}
init();
</script></body></html>'''


class Handler(BaseHTTPRequestHandler):
    server_version = "BulwarkIntel/0.1"

    def _send(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, code, body, ctype):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _webui_password(self):
        return CONFIG.get("webui_password", "")

    def _check_webui_cookie(self):
        pw = self._webui_password()
        if not pw:
            return True
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            kv = part.strip().split("=", 1)
            if len(kv) == 2 and kv[0].strip() == "bw_session":
                import hashlib
                expected = hashlib.sha256(("bw_" + pw).encode()).hexdigest()[:32]
                if kv[1].strip() == expected:
                    return True
        return False

    def _serve_login_page(self, error=""):
        err_html = '<p style="color:red">' + error + '</p>' if error else ''
        html = '''<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Bulwark - Login</title>
<style>
body{font-family:system-ui;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#0d1117;color:#c9d1d9}
.box{background:#161b22;padding:40px;border-radius:12px;border:1px solid #30363d;width:320px;text-align:center}
h2{margin:0 0 20px;color:#58a6ff}
input[type=password]{width:100%;padding:12px;margin:8px 0;border:1px solid #30363d;border-radius:6px;background:#0d1117;color:#c9d1d9;font-size:15px;box-sizing:border-box}
button{width:100%;padding:12px;background:#238636;color:#fff;border:none;border-radius:6px;font-size:15px;cursor:pointer;margin-top:8px}
button:hover{background:#2ea043}
</style></head><body>
<div class="box">
<h2>Bulwark VT</h2>
''' + err_html + '''
<form method="POST" action="/login">
<input type="password" name="password" placeholder="请输入密码" autofocus>
<button type="submit">登录</button>
</form>
</div></body></html>'''
        self._send_bytes(200, html.encode("utf-8"), "text/html; charset=utf-8")

    def _serve_webui(self):
        if not self._check_webui_cookie():
            return self._serve_login_page()
        try:
            with open(WEBUI_PATH, "rb") as f:
                html = f.read()
        except Exception:
            html = b"<!doctype html><meta charset=utf-8><h1>Bulwark VT</h1><p>webui.html not found on server.</p>"
        self._send_bytes(200, html, "text/html; charset=utf-8")

    def _client_id(self):
        """Stable anonymous per-machine id from the X-Bulwark-Client header, if the
        client sends one. Sanitised to a conservative charset; empty when absent/junk."""
        raw = (self.headers.get("X-Bulwark-Client", "") or "").strip()
        if not raw:
            return ""
        return re.sub(r"[^A-Za-z0-9._-]", "", raw)[:64]

    def _log_visit(self, path):
        """Record a human page view. Deliberately NOT called for:
          * /online itself -- that page auto-refreshes every 15s and would flood
            the log with its own reloads,
          * /stats, /health -- polled by the dashboard JS / monitors,
          * /favicon.ico and other noise.
        Failures are swallowed: a stats side-effect must never break page serving."""
        try:
            ip = self.client_address[0] if self.client_address else ""
            SERVICE.store.touch_visitor(ip, path, ua_short(self.headers.get("User-Agent", "")))
        except Exception:
            pass

    def _visitors_masked(self, window_min=15):
        """Visitor stats with source IPs masked -- safe for display / JSON."""
        st = SERVICE.store.visitors_stats(window_min=window_min)
        return {"active": st["active"], "unique": st["unique"], "views": st["views"],
                "today_views": st["today_views"], "window_min": st["window_min"],
                "visitors": [{"ip": mask_ip(v["ip"]), "last_seen": v["last_seen"],
                              "hits": v["hits"], "last_path": v["last_path"],
                              "agent": v["agent"], "active": v["active"]}
                             for v in st["visitors"]],
                "log": [{"at": l["at"], "ip": mask_ip(l["ip"]), "path": l["path"],
                         "agent": l["agent"]} for l in st["log"]]}

    def _clients_masked(self, window_min=15):
        """Client stats with source IPs masked -- safe for display / JSON."""
        st = SERVICE.store.clients_stats(window_min=window_min)
        clients = [{"ip": mask_ip(c["ip"]), "last_seen": c["last_seen"], "hits": c["hits"],
                    "online": c["online"], "by_machine": c["by_machine"]} for c in st["clients"]]
        return {"online": st["online"], "total": st["total"], "total_hits": st["total_hits"],
                "identified": st.get("identified", 0), "window_min": st["window_min"],
                "clients": clients}

    def _serve_online(self):
        """Public page: how many local clients are connected, with masked IPs."""
        if not self._check_webui_cookie():
            return self._serve_login_page()

        def rel(ts):
            t = parse_iso(ts)
            if not t:
                return ts or "—"
            secs = int((now_utc() - t).total_seconds())
            if secs < 60:
                return "刚刚"
            if secs < 3600:
                return "%d 分钟前" % (secs // 60)
            if secs < 86400:
                return "%d 小时前" % (secs // 3600)
            return "%d 天前" % (secs // 86400)

        st = SERVICE.store.clients_stats(window_min=15)
        rows = []
        for c in st["clients"]:
            dot = "on" if c["online"] else "off"
            state = "在线" if c["online"] else "离线"
            tag = ('<span class="tag m">机器</span>' if c.get("by_machine")
                   else '<span class="tag i">IP</span>')
            rows.append(
                '<tr><td><span class="dot %s"></span>%s</td><td class="ip">%s</td>'
                '<td>%s</td><td>%s</td><td class="num">%d</td></tr>'
                % (dot, state, mask_ip(c["ip"]), tag, rel(c["last_seen"]), int(c["hits"])))
        rows_html = "\n".join(rows) if rows else (
            '<tr><td colspan="5" class="empty">暂无客户端连接记录</td></tr>')

        # ---- web page visitors ----
        def esc(s):
            return (str(s).replace("&", "&amp;").replace("<", "&lt;")
                    .replace(">", "&gt;").replace('"', "&quot;"))

        vst = SERVICE.store.visitors_stats(window_min=15)
        vrows = []
        for v in vst["visitors"]:
            dot = "on" if v["active"] else "off"
            vrows.append(
                '<tr><td><span class="dot %s"></span>%s</td><td class="ip">%s</td>'
                '<td class="pt">%s</td><td>%s</td><td>%s</td><td class="num">%d</td></tr>'
                % (dot, "活跃" if v["active"] else "—", mask_ip(v["ip"]),
                   esc(v["last_path"] or "/"), esc(v["agent"] or "未知"),
                   rel(v["last_seen"]), int(v["hits"])))
        vrows_html = "\n".join(vrows) if vrows else (
            '<tr><td colspan="6" class="empty">暂无访客记录</td></tr>')

        lrows = []
        for l in vst["log"]:
            lrows.append('<tr><td>%s</td><td class="ip">%s</td><td class="pt">%s</td><td>%s</td></tr>'
                         % (rel(l["at"]), mask_ip(l["ip"]),
                            esc(l["path"] or "/"), esc(l["agent"] or "未知")))
        lrows_html = "\n".join(lrows) if lrows else (
            '<tr><td colspan="4" class="empty">暂无访问明细</td></tr>')

        html = ("""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="15">
<title>磐垒 · 在线客户端</title>
<style>
:root{--bg:#eef1f7;--card:#fff;--soft:#f6f8fc;--line:#e4e8f0;--ink:#1b2230;--muted:#6b7688;
--brand:#6366f1;--brand2:#8b5cf6;--on:#0f9d58;--off:#c2c8d2;--mono:"Cascadia Mono",Consolas,monospace;
--sans:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14.5px/1.6 var(--sans)}
.wrap{max-width:760px;margin:0 auto;padding:34px 20px 70px}
h1{font-size:22px;margin:0 0 4px;display:flex;align-items:center;gap:9px}
.lead{color:var(--muted);margin:0 0 22px;font-size:13px}
.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:22px}
.card{background:var(--card);border:1px solid var(--line);border-radius:15px;padding:16px 18px;box-shadow:0 1px 2px rgba(16,24,40,.05)}
.card .v{font-size:30px;font-weight:800;line-height:1.05;background:linear-gradient(135deg,var(--brand),var(--brand2));-webkit-background-clip:text;background-clip:text;color:transparent}
.card.plain .v{background:none;color:var(--ink);-webkit-text-fill-color:var(--ink)}
.card .k{color:var(--muted);font-size:12.5px;margin-top:6px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:14px;overflow:hidden;box-shadow:0 1px 2px rgba(16,24,40,.05)}
th,td{text-align:left;padding:11px 15px;border-bottom:1px solid var(--line);font-size:13.5px}
th{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.04em;background:var(--soft)}
tr:last-child td{border-bottom:none}
td.ip{font-family:var(--mono)}td.num{text-align:right;font-variant-numeric:tabular-nums;color:var(--muted)}
.tag{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px;line-height:1.5}
.tag.m{background:rgba(99,102,241,.12);color:var(--brand)}.tag.i{background:var(--soft);color:var(--muted)}
td.empty{text-align:center;color:var(--muted);padding:26px}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:7px;vertical-align:middle}
.dot.on{background:var(--on);box-shadow:0 0 0 3px rgba(15,157,88,.15)}.dot.off{background:var(--off)}
h2{font-size:17px;margin:34px 0 4px;display:flex;align-items:center;gap:8px}
h2:first-of-type{margin-top:6px}
h3{font-size:14px;margin:24px 0 10px;color:var(--muted);font-weight:700}
.lead2{color:var(--muted);margin:0 0 16px;font-size:12.5px}
table{margin-bottom:4px}
td.pt{font-family:var(--mono);font-size:12.5px;color:var(--brand)}
.foot{color:var(--muted);font-size:12px;margin-top:16px}
.foot a{color:var(--brand);text-decoration:none}
</style></head><body><div class="wrap">
<h1>🛡️ 连接与访问</h1>
<p class="lead">上半部分是正在使用磐垒、连接到本情报服务器的本地客户端；下半部分是浏览器访客记录。为保护隐私，所有来源 IP 均已打码（仅保留前两段）。</p>
<h2>📡 本地客户端</h2>
<p class="lead2">支持匿名机器 ID 的客户端按机器去重，其余按来源 IP 去重。</p>
<div class="cards">
<div class="card"><div class="v">""" + str(st["online"]) + """</div><div class="k">当前在线（近 """ + str(st["window_min"]) + """ 分钟活跃）</div></div>
<div class="card plain"><div class="v">""" + str(st["total"]) + """</div><div class="k">累计客户端（去重，其中 """ + str(st.get("identified", 0)) + """ 台按机器识别）</div></div>
<div class="card plain"><div class="v">""" + str(st["total_hits"]) + """</div><div class="k">累计情报查询次数</div></div>
</div>
<table><thead><tr><th>状态</th><th>来源 IP（打码）</th><th>识别方式</th><th>最近活跃</th><th>查询次数</th></tr></thead>
<tbody>
""" + rows_html + """
</tbody></table>

<h2>🌐 网页访客</h2>
<p class="lead2">浏览器访问本站页面的记录（威胁分析台 / 关于 / API 文档 / 下载）。自动刷新与后台轮询不计入。</p>
<div class="cards">
<div class="card"><div class="v">""" + str(vst["active"]) + """</div><div class="k">当前活跃访客（近 """ + str(vst["window_min"]) + """ 分钟）</div></div>
<div class="card plain"><div class="v">""" + str(vst["unique"]) + """</div><div class="k">独立访客（按来源 IP 去重）</div></div>
<div class="card plain"><div class="v">""" + str(vst["today_views"]) + """</div><div class="k">今日访问 / 累计 """ + str(vst["views"]) + """</div></div>
</div>
<table><thead><tr><th>状态</th><th>来源 IP（打码）</th><th>最近页面</th><th>浏览器</th><th>最近访问</th><th>次数</th></tr></thead>
<tbody>
""" + vrows_html + """
</tbody></table>

<h3>最近访问明细</h3>
<table><thead><tr><th>时间</th><th>来源 IP（打码）</th><th>页面</th><th>浏览器</th></tr></thead>
<tbody>
""" + lrows_html + """
</tbody></table>

<p class="foot">页面每 15 秒自动刷新 · 同一局域网/NAT 下的多台机器可能共用一个来源 IP · 仅保留最近 """ + str(SERVICE.store.LOG_CAP) + """ 条访问明细 · <a href="/">返回威胁分析台</a></p>
</div></body></html>""")
        self._send_bytes(200, html.encode("utf-8"), "text/html; charset=utf-8")

    # 行为标记的中文名。页面的核心内容就是「哪几个动作凑一起」,原样显示 Sigma 的英文规则名
    # 等于让人看不懂。这里给全部标记配中文,英文原名降级为副标题(便于跟上游规则对照)。
    MARKER_CN = {
        "bypass_uac_via_cmstp": "借 cmstp.exe 绕过 UAC",
        "change_powershell_policies_to_an_insecure_level": "把 PowerShell 执行策略改松",
        "currentversion_autorun_keys_modification": "改开机自启动注册表项",
        "dot_net_compiler_compiles_file_from_suspicious_location": ".NET 编译器编译可疑目录下的文件",
        "dynamic_net_compilation_via_csc_exe": "用 csc.exe 动态编译代码",
        "file_with_uncommon_extension_created_by_an_office_application": "Office 释放异常扩展名文件",
        "files_with_system_process_name_in_unsuspected_locations": "系统进程名出现在非常规目录",
        "hidden_executable_in_ntfs_alternate_data_stream": "可执行体藏在 NTFS 数据流里",
        "new_root_or_ca_or_authroot_certificate_to_store": "往证书存储装新根证书",
        "new_run_key_pointing_to_suspicious_folder": "新增自启动项指向可疑目录",
        "office_application_initiated_network_connection_to_non_local_ip": "Office 主动外联公网 IP",
        "potential_lethalhta_technique_execution": "疑似 LethalHTA 技术执行",
        "potential_powershell_command_line_obfuscation": "PowerShell 命令行疑似混淆",
        "potential_vcruntime140_dll_sideloading": "疑似 vcruntime140.dll 侧载",
        "potentially_suspicious_powershell_script_execution_from_temp_folder": "从 Temp 目录跑 PowerShell 脚本",
        "powershell_defender_exclusion": "用 PowerShell 给 Defender 加排除项",
        "reg_add_suspicious_paths": "reg.exe 写可疑注册表路径",
        "registry_tampering_by_potentially_suspicious_processes": "可疑进程篡改注册表",
        "schedule_system_process": "把系统进程注册成计划任务",
        "schedule_task_creation_from_env_variable_or_potentially_suspicious_pat": "从环境变量/可疑路径建计划任务",
        "scheduled_temp_file_as_task_from_temp_location": "把 Temp 里的文件设成计划任务",
        "script_interpreter_execution_from_suspicious_folder": "脚本解释器从可疑目录执行",
        "service_binary_in_suspicious_folder": "服务程序位于可疑目录",
        "startup_folder_file_write": "往「启动」文件夹写文件",
        "suspicious_binaries_and_scripts_in_public_folder": "Public 目录出现可疑程序/脚本",
        "suspicious_curl_exe_download": "用 curl.exe 下载文件",
        "suspicious_network_connection_to_ip_lookup_service_apis": "连查询公网 IP 的接口",
        "suspicious_powershell_invocation_from_script_engines": "脚本宿主调起 PowerShell",
        "suspicious_scheduled_task_creation_via_masqueraded_xml_file": "用伪装的 XML 建计划任务",
        "suspicious_startup_folder_persistence": "在「启动」文件夹留驻",
        "suspicious_windows_defender_folder_exclusion_added_via_reg_exe": "用 reg.exe 给 Defender 加目录排除",
        "suspicious_windows_service_tampering": "篡改 Windows 服务",
        "system_file_execution_location_anomaly": "系统程序从异常位置启动",
        "uncommon_svchost_command_line_parameter": "svchost 命令行参数异常",
        "uncommon_svchost_parent_process": "svchost 的父进程异常",
        "unsigned_dll_loaded_by_windows_utility": "系统工具加载未签名 DLL",
        "unsigned_image_loaded_into_lsass_process": "lsass 加载未签名模块",
        "windows_defender_exclusions_added_registry": "注册表里加 Defender 排除项",
        "windows_shell_scripting_application_file_write_to_suspicious_folder": "脚本宿主往可疑目录写文件",
        # 下面三个是后来新挖出来的。这张表是手写的,而挖掘每天可能带出新标记 ——
        # 没配中文名的会落到「其他」分组并显示英文原名,页面上看得见,不会被静默吞掉。
        "cmstp_execution_registry_event": "cmstp.exe 执行留下的注册表痕迹",
        "process_creation_using_sysnative_folder": "借 Sysnative 路径别名启动进程",
        "wow6432node_currentversion_autorun_keys_modification": "改 32 位视图的开机自启动项",
    }

    # ---- 攻击意图分组 -------------------------------------------------------- #
    #
    # 为什么需要:组合表里 28 条有 24 条都是「询问」,强度列失去区分作用;而标记名反复
    # 出现(svchost / lsass 那几个在大半条组合里都有),扁平列表滚起来文字糊成一片,
    # 没有任何可抓的锚点。按意图分组后每组只有 2~9 条,每屏都有标题可定位。
    #
    # 这不是 MITRE 战术的实现,是给人看的粗分类 —— 刻意做得比 MITRE 粗:
    # MITRE 那套在 engine_build.py 里已经明确弃用(signature_description 是静态特征
    # 描述而非攻击行为,开启后标记词表从数十个膨胀到 1330 个)。这里只求「一眼知道这组
    # 在防什么」,故合并同源手法:例如四种计划任务、两种启动文件夹都归到「开机留驻」。
    TACTICS = [
        ("evade",   "防御规避",       "关掉或绕开杀软与执行限制"),
        ("persist", "开机留驻",       "让自己在重启后继续运行"),
        ("exec",    "落地执行",       "把载荷放到磁盘再跑起来"),
        ("masq",    "伪装",           "冒充系统程序名或系统所在位置"),
        ("cred",    "注入与凭据窃取", "把模块塞进别人的进程，或读取凭据"),
        ("tamper",  "信任面篡改",     "改证书、服务、注册表等系统信任配置"),
        ("net",     "外联下载",       "联网取回载荷或回传"),
        ("other",   "其他",           "尚未归类的行为"),
    ]

    MARKER_TACTIC = {
        # 防御规避
        "powershell_defender_exclusion": "evade",
        "windows_defender_exclusions_added_registry": "evade",
        "suspicious_windows_defender_folder_exclusion_added_via_reg_exe": "evade",
        "change_powershell_policies_to_an_insecure_level": "evade",
        "potential_powershell_command_line_obfuscation": "evade",
        # 开机留驻
        "currentversion_autorun_keys_modification": "persist",
        "new_run_key_pointing_to_suspicious_folder": "persist",
        "startup_folder_file_write": "persist",
        "suspicious_startup_folder_persistence": "persist",
        "schedule_system_process": "persist",
        "schedule_task_creation_from_env_variable_or_potentially_suspicious_pat": "persist",
        "scheduled_temp_file_as_task_from_temp_location": "persist",
        "suspicious_scheduled_task_creation_via_masqueraded_xml_file": "persist",
        "service_binary_in_suspicious_folder": "persist",
        "wow6432node_currentversion_autorun_keys_modification": "persist",
        # 落地执行
        "potentially_suspicious_powershell_script_execution_from_temp_folder": "exec",
        "script_interpreter_execution_from_suspicious_folder": "exec",
        "suspicious_powershell_invocation_from_script_engines": "exec",
        "dot_net_compiler_compiles_file_from_suspicious_location": "exec",
        "dynamic_net_compilation_via_csc_exe": "exec",
        "potential_lethalhta_technique_execution": "exec",
        "suspicious_binaries_and_scripts_in_public_folder": "exec",
        "windows_shell_scripting_application_file_write_to_suspicious_folder": "exec",
        "file_with_uncommon_extension_created_by_an_office_application": "exec",
        # 伪装
        "files_with_system_process_name_in_unsuspected_locations": "masq",
        "system_file_execution_location_anomaly": "masq",
        "uncommon_svchost_command_line_parameter": "masq",
        "uncommon_svchost_parent_process": "masq",
        "hidden_executable_in_ntfs_alternate_data_stream": "masq",
        "process_creation_using_sysnative_folder": "masq",
        # 注入与凭据窃取
        "unsigned_image_loaded_into_lsass_process": "cred",
        "potential_vcruntime140_dll_sideloading": "cred",
        "unsigned_dll_loaded_by_windows_utility": "cred",
        # 信任面篡改
        "new_root_or_ca_or_authroot_certificate_to_store": "tamper",
        "reg_add_suspicious_paths": "tamper",
        "registry_tampering_by_potentially_suspicious_processes": "tamper",
        "suspicious_windows_service_tampering": "tamper",
        "bypass_uac_via_cmstp": "tamper",
        "cmstp_execution_registry_event": "tamper",
        # 外联下载
        "suspicious_curl_exe_download": "net",
        "suspicious_network_connection_to_ip_lookup_service_apis": "net",
        "office_application_initiated_network_connection_to_non_local_ip": "net",
    }

    def _serve_engine(self):
        """攻击链组合引擎的检查台。

        为什么整页重做:前两版都只是把服务器挖出来的组合平铺出来,读者最想知道的三件事
        一个都答不了 ——
          1. 「这条组合客户端到底会不会用?」实测 32 条里有 7 条在装载时就被剔除
             (不可观测 / 主体冲突 / 证据重复),页面却一律显示生效,数字与实际对不上。
          2. 「这条会不会误伤正常软件?」以前服务器只有恶意语料,无从回答;现在有了
             benign_reports,把正常侧出现率如实摆出来,没语料就明说没有 —— 不装作有。
          3. 「引擎认识哪些行为?」39 个标记只能透过组合间接看到,没法直接翻、没法搜。
        故改成:顶部漏斗(挖出 -> 启用) + 三个页签 + 前端搜索/筛选/排序,而不是一串 <details>。

        剔除判定【必须与 AttackChainEngine::applyPayload 逐条对齐】,否则页面说会用、
        客户端实际不用,比不显示更糟。四条判据见 client_issues() 内注释。
        """
        if not self._check_webui_cookie():
            return self._serve_login_page()

        man = SERVICE.store.engine_manifest()
        data = SERVICE.store.engine_patterns()
        markers = data["markers"]
        st = man.get("stats", {}) or {}
        try:
            benign = SERVICE.store.benign_stats()
        except Exception:
            benign = {"total": 0, "with_markers": 0, "signed": 0, "cap": 0,
                      "oldest": "", "newest": ""}

        LV_CN = {"critical": "严重", "high": "高", "medium": "中"}
        EV_CN = {"ProcessCreate": "进程创建", "RegistryWrite": "注册表写入",
                 "FileWrite": "文件写入", "FileDelete": "文件删除",
                 "ImageLoad": "模块加载", "NetworkConnect": "网络外联",
                 "RemoteThread": "远程线程", "DnsQuery": "DNS 解析"}

        def cond_of(slug):
            return (markers.get(slug, {}).get("match") or {})

        def cn_of(slug):
            md = markers.get(slug, {})
            return self.MARKER_CN.get(slug) or md.get("title") or slug

        def tac_of(slug):
            return self.MARKER_TACTIC.get(slug, "other")

        def pat_tactic(slugs):
            """一条组合归到哪个意图。

            组合天然跨意图(「落地执行 + 开机留驻」才是完整链条),所以必须选一个【主】意图。
            规则:取严重度最高的那个标记的意图;并列时取恶意样本数最多的;仍并列按 slug 排序 ——
            末位兜底是为了让分组结果可复现,否则同一份数据每次刷新可能落到不同组。
            """
            rank = {"critical": 3, "high": 2, "medium": 1}
            best = None
            for s in sorted(slugs):
                md = markers.get(s, {})
                key = (rank.get((md.get("level") or "").lower(), 0),
                       int(md.get("samples") or 0))
                if best is None or key > best[0]:
                    best = (key, s)
            return tac_of(best[1]) if best else "other"

        def fingerprint(slug):
            """标记的判定条件指纹。字段与顺序【照抄】C++ 侧 applyPayload 里的构造:
            事件类型 + actor/target/cmdline/parent + unsigned,全部小写。
            两个标记指纹相同 -> 它们其实是同一个条件,凑在一起不构成互证。"""
            md = markers.get(slug, {})
            c = cond_of(slug)
            return "|".join([(md.get("event") or "").lower(),
                             (c.get("actor") or "").lower(),
                             (c.get("target") or "").lower(),
                             (c.get("cmdline") or "").lower(),
                             (c.get("parent") or "").lower(),
                             "1" if c.get("unsigned") else "0"])

        def cond_bits(slug):
            c = cond_of(slug)
            bits = []
            for k, label in (("actor", "主体"), ("target", "目标"),
                             ("cmdline", "命令行"), ("parent", "父进程")):
                if c.get(k):
                    bits.append("%s=%s" % (label, c[k]))
            if c.get("unsigned"):
                bits.append("未签名")
            return bits

        def client_issues(slugs):
            """客户端装载时会不会剔除这条,以及为什么。顺序与 C++ 侧的判定顺序一致。

            C++ 侧命中第一条就 continue,所以计数上一条组合只会被算进一个原因;
            这里【全部列出】—— 排查时"还有哪些毛病"比"先撞上哪个"更有用。
            """
            out = []
            dead = [s for s in slugs
                    if not markers.get(s, {}).get("observable")
                    or not (markers.get(s, {}).get("event") or "")]
            if dead:
                out.append({"k": "unobservable", "t": "不可观测",
                            "d": "其中 %d 个动作在客户端没有可判条件,这条组合永远凑不齐,"
                                 "属于死规则" % len(dead)})
            if len(slugs) < 2:
                out.append({"k": "single", "t": "单动作",
                            "d": "只有一个动作。凭单个动作定性与本引擎「必须互证」的前提相悖"})
            actors = set()
            for s in slugs:
                a = (cond_of(s).get("actor") or "").lower()
                if a:
                    actors.add(a)
            if len(actors) >= 2:
                out.append({"k": "actor", "t": "主体冲突",
                            "d": "要求 %d 个互不相同的主体程序。客户端按单个进程记账,"
                                 "一个进程不可能同时是两个程序" % len(actors)})
            fps = set(fingerprint(s) for s in slugs)
            if len(fps) < len(slugs):
                out.append({"k": "redundant", "t": "证据重复",
                            "d": "%d 个动作归约后只剩 %d 个不同条件 —— 一个信号冒充多个。"
                                 "软信号不能包装成互证" % (len(slugs), len(fps))})
            return out

        # ---- 组合:算出客户端实际是否启用 ---------------------------------- #
        pats = []
        use_all, use_live = {}, {}
        n_live = 0
        issue_count = {}
        for p in data["patterns"]:
            slugs = list(p["markers"])
            issues = client_issues(slugs)
            live = not issues
            if live:
                n_live += 1
            for i in issues:
                issue_count[i["k"]] = issue_count.get(i["k"], 0) + 1
            for s in slugs:
                use_all[s] = use_all.get(s, 0) + 1
                if live:
                    use_live[s] = use_live.get(s, 0) + 1
            pats.append({
                "g": p["grade"], "n": len(slugs), "sup": p["support"],
                "ben": p.get("benign_support") or 0,
                "fam": p.get("families") or "",
                "lv": p.get("max_level") or "medium",
                "tac": pat_tactic(slugs),
                "live": live, "iss": issues,
                "mk": [{"id": s, "cn": cn_of(s), "en": markers.get(s, {}).get("title") or "",
                        "lv": markers.get(s, {}).get("level") or "medium",
                        "lvcn": LV_CN.get(markers.get(s, {}).get("level") or "", "中"),
                        "ev": markers.get(s, {}).get("event") or "",
                        "evcn": EV_CN.get(markers.get(s, {}).get("event") or "",
                                          markers.get(s, {}).get("event") or ""),
                        "obs": bool(markers.get(s, {}).get("observable")),
                        "cond": cond_bits(s)} for s in slugs],
            })

        # ---- 行为标记词表 -------------------------------------------------- #
        mk_list = []
        for s in sorted(markers.keys(), key=lambda x: (-use_all.get(x, 0), x)):
            md = markers[s]
            mk_list.append({
                "id": s, "cn": cn_of(s), "en": md.get("title") or "",
                "lv": md.get("level") or "medium",
                "lvcn": LV_CN.get(md.get("level") or "", "中"),
                "ev": md.get("event") or "",
                "evcn": EV_CN.get(md.get("event") or "", md.get("event") or ""),
                "obs": bool(md.get("observable")),
                "cond": cond_bits(s),
                "sam": md.get("samples") or 0,
                "ben": md.get("benign_samples") or 0,
                "tac": tac_of(s),
                "use": use_all.get(s, 0), "uselive": use_live.get(s, 0),
            })

        payload = {
            "version": man["version"],
            # 展示版本号(0.1 起 +0.1)。老库没有 label 时为空串,前端回退显示内部整数版本号。
            "label": man.get("label", ""),
            "built_at": man.get("built_at") or "",
            "samples": st.get("usable_samples") or man.get("samples") or 0,
            "markers_total": man.get("markers") or len(markers),
            "mined": st.get("patterns_mined") or 0,
            "dedup": st.get("patterns_after_dedup") or 0,
            "served": len(pats),
            "live": n_live,
            "issues": issue_count,
            "benign": benign,
            "benign_min": 50,          # 与 engine_build.BENIGN_MIN_CORPUS 一致
            "benign_active": bool(st.get("benign_grading_active")),
            "benign_capped": st.get("benign_capped") or 0,
            "benign_dropped": st.get("benign_dropped") or 0,
            "benign_generic": st.get("benign_generic_dropped") or 0,
            "stats": st,
            "tactics": [{"k": k, "t": t, "d": d} for k, t, d in self.TACTICS],
            "patterns": pats,
            "mk": mk_list,
        }
        blob = (json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
                .replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026"))

        html = _ENGINE_PAGE.replace("/*__DATA__*/null", blob)
        self._send_bytes(200, html.encode("utf-8"), "text/html; charset=utf-8")
    def _authed(self):
        token = CONFIG.get("auth_token", "")
        if not token:
            return True  # no token configured -> open (not recommended)
        auth = self.headers.get("Authorization", "")
        return auth == "Bearer " + token

    def _throttle_ok(self):
        ip = self.client_address[0] if self.client_address else ""
        _wl = (CONFIG.get("public_rate_limit", {}) or {}).get("whitelist", []) or []
        if THROTTLE is None or ip in ("127.0.0.1", "::1") or ip in _wl:
            return True
        ok, retry = THROTTLE.allow(ip)
        if not ok:
            self._send(429, {"ok": False, "error": "rate limited; slow down",
                             "retry_after_seconds": retry})
            return False
        return True

    def log_message(self, fmt, *args):
        # keep journald tidy: one compact line, never log auth headers/keys
        print("%s - %s" % (self.address_string(), fmt % args), flush=True)

    # ------------------------------------------------------------------- API #
    def _api_provided_key(self, u):
        k = self.headers.get("X-API-Key")
        if not k:
            auth = self.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                k = auth[7:].strip()
        if not k:
            k = urllib.parse.parse_qs(u.query).get("key", [None])[0]
        return k

    def _api_guard(self, u):
        """Authenticate + rate-limit an /api/v1 request. Returns key info dict, or
        None after already sending the 401/429 error."""
        api = CONFIG.get("api", {}) or {}
        if not api.get("enabled", True):
            self._send(403, {"ok": False, "error": "api disabled"})
            return None
        provided = self._api_provided_key(u)
        keys = {k.get("key"): k for k in api.get("keys", []) if k.get("key")}
        if api.get("require_key", True):
            if not provided:
                self._send(401, {"ok": False, "error": "missing api key (send header X-API-Key)"})
                return None
            info = keys.get(provided)
            if not info or not info.get("enabled", True):
                self._send(401, {"ok": False, "error": "invalid or disabled api key"})
                return None
        else:
            info = keys.get(provided) or {"key": "anonymous", "name": "anonymous"}
        pm = int(info.get("requests_per_minute", api.get("default_requests_per_minute", 30)))
        pd = int(info.get("requests_per_day", api.get("default_requests_per_day", 1000)))
        ok, why = SERVICE.rl.allow("api:" + str(info.get("key", "anon")), pm, pd)
        if not ok:
            self._send(429, {"ok": False, "error": "rate limited (%s)" % why,
                             "limits": {"per_minute": pm, "per_day": pd}})
            return None
        return info

    def _api_index(self):
        return {"ok": True, "service": "bulwark-intel", "api_version": "v1", "docs": "/api/docs",
                "auth": "send your key in header 'X-API-Key' (or Authorization: Bearer, or ?key=)",
                "endpoints": {
                    "GET /api/v1/hash/{md5|sha1|sha256}": "hash reputation summary (multi-source)",
                    "GET /api/v1/file/{hash}": "full report: detections + sandbox behaviour + sources",
                    "GET /api/v1/ip/{ipv4}": "IP reputation",
                    "POST /api/v1/scan?name=<filename>": "upload a file (raw body) to scan",
                    "GET /api/v1/analysis/{id}": "poll a submitted analysis",
                    "GET /api/v1/quota": "your key usage and limits"}}

    def _api_hash_summary(self, r):
        rep = r.get("report", {}) or {}
        f = rep.get("file", {}) or {}
        st = f.get("last_analysis_stats", {}) or {}
        mal = int(st.get("malicious", 0) or 0)
        susp = int(st.get("suspicious", 0) or 0)
        total = sum(int(v or 0) for v in st.values()) if st else 0
        threshold = int((CONFIG.get("virustotal", {}) or {}).get("malicious_threshold", 5))
        verdict = "malicious" if mal >= threshold else ("suspicious" if (mal > 0 or susp > 0) else "clean")
        ptc = f.get("popular_threat_classification") or {}
        label = ptc.get("suggested_threat_label", "") if isinstance(ptc, dict) else ""
        names = f.get("names") or []
        return {"ok": True, "sha256": f.get("sha256", ""), "md5": f.get("md5", ""), "sha1": f.get("sha1", ""),
                "name": f.get("meaningful_name") or (names[0] if names else ""),
                "verdict": verdict, "malicious": mal, "suspicious": susp, "total_engines": total,
                "threat_label": label, "category": threat_category(f, label),
                "type_description": f.get("type_description", ""), "size": f.get("size", 0),
                "behaviour_available": bool(rep.get("behaviour_available")),
                "sources": rep.get("sources", []),
                "cached": bool(r.get("cached")), "stored_at": r.get("stored_at", "")}

    def _read_upload(self, u):
        """Spool the request body to disk while hashing, then submit to VT.
        Returns (http_status, response_obj). Shared by /vt/upload and /api/v1/scan."""
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length <= 0:
            return 400, {"ok": False, "error": "empty body"}
        max_mb = int(CONFIG.get("max_upload_mb", 650))
        if length > max_mb * 1024 * 1024:
            return 400, {"ok": False, "error": "文件过大(最大 %d MB)" % max_mb}
        upl_dir = CONFIG.get("uploads_dir", "/var/lib/bulwark-intel/uploads")
        try:
            os.makedirs(upl_dir, exist_ok=True)
        except OSError:
            pass
        qs = urllib.parse.parse_qs(u.query)
        filename = urllib.parse.unquote(qs.get("name", ["sample.bin"])[0])
        tmp_path = os.path.join(upl_dir, "up-%s.bin" % uuid.uuid4().hex)
        h = hashlib.sha256()
        got = 0
        try:
            with open(tmp_path, "wb") as fobj:
                remaining = length
                while remaining > 0:
                    chunk = self.rfile.read(min(1024 * 1024, remaining))
                    if not chunk:
                        break
                    h.update(chunk)
                    fobj.write(chunk)
                    remaining -= len(chunk)
                    got += len(chunk)
            if got != length:
                return 400, {"ok": False, "error": "上传中断(收到 %d/%d 字节)" % (got, length)}
            return 200, SERVICE.vt_submit_path(tmp_path, h.hexdigest(), filename, got)
        finally:
            try:
                os.remove(tmp_path)
            except OSError:
                pass

    def _api_get(self, u, info):
        rest = u.path[len("/api/v1/"):]
        if rest.startswith("hash/"):
            h = rest[len("hash/"):].strip().lower()
            if not re.match(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$", h):
                return self._send(400, {"ok": False, "error": "invalid hash (md5/sha1/sha256)"})
            r = SERVICE.vt_lookup(h, False)
            if not r.get("ok"):
                return self._send(404, {"ok": False, "error": r.get("error", "not found")})
            return self._send(200, self._api_hash_summary(r))
        if rest.startswith("file/"):
            h = rest[len("file/"):].strip().lower()
            if not re.match(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$", h):
                return self._send(400, {"ok": False, "error": "invalid hash"})
            r = SERVICE.vt_lookup(h, False)
            if not r.get("ok"):
                return self._send(404, {"ok": False, "error": r.get("error", "not found")})
            return self._send(200, {"ok": True, "cached": bool(r.get("cached")),
                                    "stored_at": r.get("stored_at", ""), "report": r.get("report", {})})
        if rest.startswith("ip/"):
            ip = rest[len("ip/"):].strip()
            if not IPV4_RE.match(ip):
                return self._send(400, {"ok": False, "error": "invalid ipv4"})
            if is_private_ipv4(ip):
                return self._send(200, {"ok": True, "ip": ip, "verdict": "unknown", "reason": "private/reserved"})
            try:
                return self._send(200, SERVICE.reputation_ip(ip))
            except Exception as e:
                return self._send(500, {"error": str(e)})
        if rest.startswith("analysis/"):
            aid = urllib.parse.unquote(rest[len("analysis/"):]).strip()
            if not aid:
                return self._send(400, {"ok": False, "error": "missing analysis id"})
            return self._send(200, SERVICE.vt_analysis(aid))
        if rest in ("quota", "whoami"):
            api = CONFIG.get("api", {}) or {}
            pm = int(info.get("requests_per_minute", api.get("default_requests_per_minute", 30)))
            pd = int(info.get("requests_per_day", api.get("default_requests_per_day", 1000)))
            used = SERVICE.store.quota_used("api:" + str(info.get("key", "anon")))
            return self._send(200, {"ok": True, "name": info.get("name", ""), "used_today": used,
                                    "requests_per_minute": pm, "requests_per_day": pd})
        return self._send(404, {"ok": False, "error": "unknown endpoint; see /api/docs"})

    def _api_post(self, u, info):
        rest = u.path[len("/api/v1/"):]
        if rest == "scan":
            st, obj = self._read_upload(u)
            return self._send(st, obj)
        if rest == "hash":
            length = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(length) if length else b"{}"
            try:
                payload = json.loads(raw or b"{}")
            except Exception:
                return self._send(400, {"ok": False, "error": "invalid json"})
            h = str(payload.get("hash", "")).strip().lower()
            if not re.match(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$", h):
                return self._send(400, {"ok": False, "error": "invalid hash"})
            r = SERVICE.vt_lookup(h, bool(payload.get("refresh", False)))
            if not r.get("ok"):
                return self._send(404, {"ok": False, "error": r.get("error", "not found")})
            return self._send(200, self._api_hash_summary(r))
        return self._send(404, {"ok": False, "error": "unknown endpoint; see /api/docs"})

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == "/health":
            return self._send(200, {"status": "ok", "service": "bulwark-intel", "time": iso(now_utc())})
        if u.path in ("/", "/vt", "/vt/", "/index.html", "/webui"):
            self._log_visit("/")
            return self._serve_webui()  # web UI is open; its data calls carry the token
        if u.path in ("/api", "/api/"):
            return self._send(200, self._api_index())
        if u.path == "/api/docs":
            self._log_visit("/api/docs")
            return self._send_bytes(200, API_DOCS_HTML, "text/html; charset=utf-8")
        if u.path.startswith("/api/v1/"):
            info = self._api_guard(u)
            if info is None:
                return
            return self._api_get(u, info)
        if u.path in ("/about", "/about.html"):
            # Static project intro page. Deliberately served before the auth gate
            # so it stays reachable as a public showcase; it contains no secrets.
            try:
                _ap = os.path.join(os.path.dirname(os.path.abspath(__file__)), "about.html")
                with open(_ap, "rb") as _f:
                    _body = _f.read()
            except OSError:
                return self._send(404, {"ok": False, "error": "about page not installed"})
            self._log_visit("/about")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(_body)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            try:
                self.wfile.write(_body)
            except OSError:
                pass
            return
        if u.path in ("/online", "/online/", "/clients"):
            return self._serve_online()
        if u.path in ("/engine", "/engine/"):
            self._log_visit("/engine")
            return self._serve_engine()
        # 特征库下发。客户端先取 manifest 比版本号,版本没变就不必拉规则(省流量)。
        if u.path == "/v1/engine/manifest":
            return self._send(200, SERVICE.store.engine_manifest())
        if u.path == "/v1/engine/patterns":
            qs = urllib.parse.parse_qs(u.query)
            since = 0
            try:
                since = int((qs.get("since") or ["0"])[0])
            except ValueError:
                since = 0
            man = SERVICE.store.engine_manifest()
            if since and since >= man["version"]:
                # 已是最新:不回规则体,只回版本(客户端据此跳过本次更新)
                # label 也要带上 —— 客户端首次装上本版后,若一直没有新内容就再也拿不到 label,
                # 界面会长期回退显示内部整数版本号。
                return self._send(200, {"version": man["version"], "label": man.get("label", ""),
                                        "unchanged": True, "patterns": [], "markers": {}})
            payload = SERVICE.store.engine_patterns((qs.get("min_grade") or [None])[0])
            payload["version"] = man["version"]
            payload["label"] = man.get("label", "")
            payload["unchanged"] = False
            return self._send(200, payload)
        if u.path in ("/download", "/download/", "/Bulwark-Release.zip"):
            # Public download of the packaged release (password-protected zip).
            try:
                _zp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Bulwark-Release.zip")
                _sz = os.path.getsize(_zp)
                _f = open(_zp, "rb")
            except OSError:
                return self._send(404, {"ok": False, "error": "release package not available"})
            self._log_visit("/download")
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Length", str(_sz))
            self.send_header("Content-Disposition", "attachment; filename=\"Bulwark-Release.zip\"")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            try:
                shutil.copyfileobj(_f, self.wfile)
            except OSError:
                pass
            finally:
                _f.close()
            return
        if not self._authed():
            return self._send(401, {"error": "unauthorized"})
        if u.path == "/stats":
            sources = []
            for client, cfgname in SERVICE._hash_sources:
                scfg = SERVICE.cfg.get(cfgname, {}) or {}
                sources.append({"name": client.NAME,
                                "enabled": bool(scfg.get("enabled", True)),
                                "has_key": client.has_key(),
                                "keys": client.key_count()})
            return self._send(200, {"counters": SERVICE.store.counters(),
                                    "vt_reports": SERVICE.store.vt_report_count(),
                                    "max_upload_mb": int(CONFIG.get("max_upload_mb", 650)),
                                    "sources": sources,
                                    "clients": self._clients_masked(),
                                    "visitors": self._visitors_masked(),
                                    "engine": {k: v for k, v in
                                               SERVICE.store.engine_manifest().items()
                                               if k != "stats"},
                                    "quota_today": {
                                        "VirusTotal": SERVICE.store.quota_used("VirusTotal"),
                                        "ThreatBook": SERVICE.store.quota_used("ThreatBook")}})
        if u.path == "/vt/reports":
            return self._send(200, {"count": SERVICE.store.vt_report_count(),
                                    "reports": SERVICE.list_vt_reports(),
                                    "stats": SERVICE.store.archive_stats(),
                                    "silverfox": SERVICE.store.list_silverfox()})
        if u.path.startswith("/ha/behaviour/"):
            ident = urllib.parse.unquote(u.path[len("/ha/behaviour/"):]).strip().lower()
            if not re.match(r"^[0-9a-f]{64}$", ident):
                return self._send(400, {"ok": False, "error": "need sha256"})
            refresh = "refresh=1" in (u.query or "")
            if not refresh:
                cached = SERVICE.store.get_behaviour(ident)
                if cached:
                    return self._send(200, {"ok": True, "cached": True,
                                            "stored_at": cached["fetched_at"],
                                            "behaviour": cached["report"]})
            if not self._throttle_ok():
                return
            data = SERVICE.ha.fetch_behaviour(ident)
            if not data:
                return self._send(404, {"ok": False,
                                        "error": "no sandbox report available for this hash"})
            SERVICE.store.save_behaviour(ident, data)
            return self._send(200, {"ok": True, "cached": False, "behaviour": data})
        if u.path.startswith("/vt/report/"):
            ident = urllib.parse.unquote(u.path[len("/vt/report/"):]).strip()
            rec = SERVICE.get_vt_report(ident)
            if not rec:
                return self._send(404, {"ok": False, "error": "not stored"})
            return self._send(200, {"ok": True, "stored_at": rec["stored_at"], "report": rec["report"]})
        if u.path.startswith("/vt/analysis/"):
            aid = urllib.parse.unquote(u.path[len("/vt/analysis/"):]).strip()
            if not aid:
                return self._send(400, {"error": "missing analysis id"})
            return self._send(200, SERVICE.vt_analysis(aid))
        if u.path.startswith("/v1/reputation/ip/"):
            ip = u.path[len("/v1/reputation/ip/"):]
            if not IPV4_RE.match(ip):
                return self._send(400, {"error": "invalid ipv4"})
            SERVICE.store.touch_client(self.client_address[0] if self.client_address else "",
                                       self._client_id())
            if is_private_ipv4(ip):
                return self._send(200, {"ip": ip, "verdict": "unknown", "querySucceeded": False,
                                        "reason": "private/reserved"})
            try:
                return self._send(200, SERVICE.reputation_ip(ip))
            except Exception as e:
                return self._send(500, {"error": str(e)})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == "/login":
            import hashlib
            length = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(length) if length else b""
            pw = self._webui_password()
            # Parse form data
            form_pw = ""
            for part in raw.decode("utf-8", errors="replace").split("&"):
                kv = part.split("=", 1)
                if len(kv) == 2 and kv[0] == "password":
                    form_pw = urllib.parse.unquote_plus(kv[1])
            if pw and form_pw == pw:
                expected = hashlib.sha256(("bw_" + pw).encode()).hexdigest()[:32]
                self.send_response(302)
                self.send_header("Set-Cookie", "bw_session=" + expected + "; Path=/; HttpOnly; SameSite=Strict")
                self.send_header("Location", "/")
                self.end_headers()
            else:
                self._serve_login_page(error="密码错误")
            return
        if u.path.startswith("/api/v1/"):
            info = self._api_guard(u)
            if info is None:
                return
            return self._api_post(u, info)
        if not self._authed():
            return self._send(401, {"error": "unauthorized"})
        if u.path in ("/vt/upload", "/vt/lookup", "/v1/reputation/hash") and not self._throttle_ok():
            return
        length = int(self.headers.get("Content-Length", 0) or 0)
        # Binary sample upload -> read raw bytes (no JSON). Filename via ?name=<urlencoded>.
        if u.path == "/vt/upload":
            st, obj = self._read_upload(u)
            return self._send(st, obj)
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw or b"{}")
        except Exception:
            return self._send(400, {"error": "invalid json"})
        if u.path == "/v1/reputation/hash":
            sha = str(payload.get("sha256", "")).strip()
            if not SHA256_RE.match(sha):
                return self._send(400, {"error": "invalid sha256"})
            SERVICE.store.touch_client(self.client_address[0] if self.client_address else "",
                                       self._client_id())
            return self._send(200, SERVICE.reputation_hash(sha))
        if u.path == "/vt/lookup":
            h = str(payload.get("hash", "")).strip().lower()
            if not re.match(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$", h):
                return self._send(400, {"ok": False, "error": "invalid hash (need md5/sha1/sha256)"})
            return self._send(200, SERVICE.vt_lookup(h, bool(payload.get("refresh", False))))
        return self._send(404, {"error": "not found"})


class BulwarkHTTPServer(ThreadingHTTPServer):
    """Threaded HTTP(S) server hardened against slow / half-open clients.

    With TLS on, we set do_handshake_on_connect=False on the listening socket so
    accept() returns immediately and the (blocking) TLS handshake runs inside the
    per-connection worker thread via do_handshake(). Otherwise the handshake would
    run in the single-threaded accept loop, where one silent client -- e.g. an
    internet port scanner hitting the open 8787 -- stalls every other connection.
    A per-socket timeout guarantees a stuck client frees its thread rather than
    pinning it forever.
    """
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128
    conn_timeout = 30

    def get_request(self):
        sock, addr = self.socket.accept()
        sock.settimeout(self.conn_timeout)
        return sock, addr

    def finish_request(self, request, client_address):
        if isinstance(request, ssl.SSLSocket):
            try:
                request.do_handshake()
            except OSError:
                return  # incomplete / invalid TLS (scanner or probe) -> drop quietly
        self.RequestHandlerClass(request, client_address, self)


def main():
    global SERVICE, CONFIG, THROTTLE
    CONFIG = load_config()
    SERVICE = IntelService(CONFIG)
    _prl = CONFIG.get("public_rate_limit", {}) or {}
    THROTTLE = IPThrottle(int(_prl.get("per_minute", 60)), int(_prl.get("per_hour", 600)))
    host = CONFIG.get("listen_host", "0.0.0.0")
    port = int(CONFIG.get("listen_port", 8787))
    httpd = BulwarkHTTPServer((host, port), Handler)
    scheme = "http"
    cert, key = CONFIG.get("tls_cert"), CONFIG.get("tls_key")
    if cert and key:
        # Terminate TLS in-process (Let's Encrypt). No nginx / no privileged port.
        # do_handshake_on_connect=False -> handshake runs per worker thread, never
        # in the accept loop (see BulwarkHTTPServer above).
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert, keyfile=key)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True,
                                       do_handshake_on_connect=False)
        scheme = "https"

    # Uploaded samples are spooled here during processing and deleted immediately
    # after. This janitor sweeps hourly and removes anything older than the
    # retention window -- a safety net for uploads interrupted by a crash/restart.
    upl_dir = CONFIG.get("uploads_dir", "/var/lib/bulwark-intel/uploads")
    retention_h = float(CONFIG.get("upload_retention_hours", 24))
    try:
        os.makedirs(upl_dir, exist_ok=True)
    except OSError:
        pass

    def _janitor():
        while True:
            try:
                cutoff = time.time() - retention_h * 3600
                for name in os.listdir(upl_dir):
                    p = os.path.join(upl_dir, name)
                    try:
                        if os.path.isfile(p) and os.path.getmtime(p) < cutoff:
                            os.remove(p)
                    except OSError:
                        pass
            except Exception:
                pass
            time.sleep(3600)

    threading.Thread(target=_janitor, name="uploads-janitor", daemon=True).start()

    print("bulwark-intel listening on %s://%s:%d (db=%s)" % (scheme, host, port, CONFIG["db_path"]), flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
