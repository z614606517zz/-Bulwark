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

import base64
import hashlib
import hmac
import json
import os
import re
import shutil
import sqlite3
import ssl
import sys
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


# --- 反馈截图:允许的图片类型 ------------------------------------------------- #
#
# 【按魔术字节判定,不看扩展名也不信客户端给的 MIME】—— 提交口是公开无鉴权的,
# 客户端说什么都不能当依据。
#
# 【SVG 被刻意排除】。SVG 是 XML,可以内嵌 <script>;而这些图片是给带着
# bw_session 的管理员在同源下打开的,放行 SVG 等于把一条反馈变成管理页上的
# XSS。PNG/JPEG/GIF/WebP 这四种是位图容器,浏览器不会当脚本执行。
IMG_TYPES = (
    (b"\x89PNG\r\n\x1a\n", "png", "image/png"),
    (b"\xff\xd8\xff", "jpg", "image/jpeg"),
    (b"GIF87a", "gif", "image/gif"),
    (b"GIF89a", "gif", "image/gif"),
)
IMG_EXT_MIME = {"png": "image/png", "jpg": "image/jpeg",
                "gif": "image/gif", "webp": "image/webp"}
IMG_NAME_RE = re.compile(r"^fb\d+-\d-[0-9a-f]{16}\.(png|jpg|gif|webp)$")


def sniff_image(data):
    """返回 (ext, mime),识别不出就返回 (None, None)。"""
    for magic, ext, mime in IMG_TYPES:
        if data.startswith(magic):
            return ext, mime
    # WebP: 'RIFF' <4 字节长度> 'WEBP'
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp", "image/webp"
    return None, None


# --- 在线客服附件:图片 + 视频 ------------------------------------------------- #
#
# 判定规则与反馈截图那套【完全一致,而且是刻意复用同一条推理】:按魔术字节认容器,
# 不看扩展名、不信客户端给的 Content-Type。客服的上传口和反馈一样是公开无鉴权的
# (要让还没有账号的人能开口说话),客户端说什么都不能当依据。
#
# 视频只放行浏览器自己能播的三种容器。放行 MKV 之类的意义是负的:存进来占盘,
# <video> 又播不了,用户只会以为功能坏了。
#
# 【SVG 依然排除】,理由同 IMG_TYPES 处:它是 XML,能内嵌 <script>,而这些附件会在
# 同源下被客服(带着 bw_session)打开。
SUP_EXT_MIME = {
    "png": "image/png", "jpg": "image/jpeg", "gif": "image/gif", "webp": "image/webp",
    "mp4": "video/mp4", "mov": "video/quicktime", "webm": "video/webm",
}
SUP_IMAGE_EXT = ("png", "jpg", "gif", "webp")
SUP_VIDEO_EXT = ("mp4", "mov", "webm")
# 文件名整个由服务端生成:sup-<会话媒体前缀 12 位>-<随机 16 位>.<ext>。
# 用户输入一个字节都不参与拼接 —— 没有拼接就没有路径穿越。
SUP_NAME_RE = re.compile(r"^sup-[0-9a-f]{12}-[0-9a-f]{16}\.(png|jpg|gif|webp|mp4|mov|webm)$")


def sniff_media(head):
    """按首部字节判定附件类型。返回 (ext, mime, kind),认不出返回 (None, None, None)。

    kind 只有 "image" / "video" 两种 —— 前端要据此决定渲染 <img> 还是 <video>,
    而这个判断必须由服务端做:让前端按扩展名猜,等于把类型判定权交回给上传者。
    """
    ext, mime = sniff_image(head)
    if ext:
        return ext, mime, "image"
    # ISO BMFF (MP4 / MOV / M4V): 前 4 字节是 box 长度,紧跟 'ftyp'。
    if len(head) >= 12 and head[4:8] == b"ftyp":
        brand = head[8:12]
        if brand[:2] == b"qt":                      # 'qt  ' = QuickTime
            return "mov", "video/quicktime", "video"
        return "mp4", "video/mp4", "video"
    # Matroska/WebM 都是 EBML 头。只认自称 webm 的那一支:MKV 浏览器不播。
    if head[:4] == b"\x1a\x45\xdf\xa3" and b"webm" in head[:128]:
        return "webm", "video/webm", "video"
    return None, None, None


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


# 展示层时区。存储与比较一律走 UTC(now_utc / iso / parse_iso 一个都没动),只在
# 渲染给人看的那一刻换成北京时间 —— 把转换掺进比较逻辑会让窗口统计和「最近活跃」
# 全体偏移 8 小时。
#
# 用固定 +08:00 而不是读服务器本地时区:这两台机器的 /etc/localtime 是 UTC,
# 依赖系统设置意味着换台机器显示就变;中国也不用夏令时,固定偏移没有夏令时坑。
CST = timezone(timedelta(hours=8))


def cst_str(ts, fmt="%Y-%m-%d %H:%M"):
    """UTC ISO 串(或 datetime)-> 北京时间显示串。解析不了就返回空串,不抛。"""
    t = parse_iso(ts) if isinstance(ts, str) else ts
    if not t:
        return ""
    try:
        return t.astimezone(CST).strftime(fmt)
    except Exception:
        return ""


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
            # 用户问题反馈。ip 原样存,只在 HTTP 层做掩码(与 visitors 一致)。
            # message/contact 是【用户可控文本】—— 展示时必须 html.escape,
            # 否则一条反馈就能在管理页里存储型 XSS。
            # images: 截图【文件名】的 JSON 数组,不是图片内容。图片落在
            # feedback_images_dir 下,名字由服务端生成 —— 把二进制塞进 cache.db 会让
            # 这个本来几十 MB 的库涨到几百 MB,而它每次同步、备份都要整份搬。
            c.execute("""CREATE TABLE IF NOT EXISTS feedback(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                at TEXT, ip TEXT, kind TEXT DEFAULT 'other', contact TEXT DEFAULT '',
                message TEXT, agent TEXT DEFAULT '', page TEXT DEFAULT '',
                status TEXT DEFAULT 'new', images TEXT DEFAULT '',
                reply TEXT DEFAULT '', replied_at TEXT DEFAULT '')""")
            c.execute("CREATE INDEX IF NOT EXISTS idx_feedback_at ON feedback(at)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_feedback_status ON feedback(status)")
            # 提交者按 IP 认领自己的反馈(没有账号体系),所以这一列要有索引。
            c.execute("CREATE INDEX IF NOT EXISTS idx_feedback_ip ON feedback(ip)")
            fcols = [r[1] for r in c.execute("PRAGMA table_info(feedback)").fetchall()]
            for col in ("images", "reply", "replied_at"):
                if col not in fcols:
                    c.execute("ALTER TABLE feedback ADD COLUMN %s TEXT DEFAULT ''" % col)
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

    # ---- 用户反馈 ----------------------------------------------------------- #
    # 提交口是公开的(要让没有 token 的普通用户能提),所以必须自带两道限:
    #   · 字段长度上限 —— 否则一次 POST 就能往库里灌几十 MB
    #   · 每 IP 每日条数上限 —— per-IP 滑窗只挡请求频率,挡不住「一天慢慢发一万条」
    FEEDBACK_MAX_MSG = 4000
    FEEDBACK_MAX_CONTACT = 200
    FEEDBACK_PER_IP_PER_DAY = 20
    # 截图:张数与单张大小。乘起来就是一条反馈最多能占的磁盘,再叠上每 IP 每日
    # 20 条,单个 IP 一天最多写 20*3*2MB = 120MB —— 所以还需要目录总量闸门
    # (见 FEEDBACK_IMG_DIR_MAX),否则几个 IP 就能把盘填满。
    # 张数/大小的实际上限改由配置决定(见 HTTP 层的 _fb_limits),默认给得很宽,
    # 正常使用碰不到。这里只留一个绝对兜底,防止配置写成天文数字。
    FEEDBACK_IMG_HARD_CAP = 200

    def add_feedback(self, ip, kind, contact, message, agent="", page="", images=None):
        """写入一条反馈。返回 (id, error)。error 非空表示被拒。

        images 是【文件名列表】,调用方负责先把字节落盘再把名字传进来 —— Store
        不碰文件系统,配置与磁盘配额都归 HTTP 层。"""
        message = (message or "").strip()[: self.FEEDBACK_MAX_MSG]
        contact = (contact or "").strip()[: self.FEEDBACK_MAX_CONTACT]
        kind = (kind or "other").strip()[:32] or "other"
        names = [str(x) for x in (images or [])][: self.FEEDBACK_IMG_HARD_CAP]
        # 一张截图往往比一句话说得清,所以【有图就不强制写文字】。
        if not message and not names:
            return (0, "请填写内容或附上截图")
        day = now_utc().strftime("%Y-%m-%d")
        with self.lock, self._conn() as c:
            n = c.execute("SELECT COUNT(*) n FROM feedback WHERE ip=? AND substr(at,1,10)=?",
                          (ip, day)).fetchone()["n"]
            if n >= self.FEEDBACK_PER_IP_PER_DAY:
                return (0, "今日提交次数已达上限,请明天再试")
            cur = c.execute("""INSERT INTO feedback(at, ip, kind, contact, message, agent, page, images)
                VALUES (?,?,?,?,?,?,?,?)""",
                (iso(now_utc()), ip, kind, contact, message,
                 (agent or "")[:120], (page or "")[:200],
                 json.dumps(names, ensure_ascii=False) if names else ""))
            return (cur.lastrowid, "")

    def set_feedback_images(self, fid, names):
        """回填真正落盘成功的截图文件名(插入时先占位,因为文件名要带记录 id)。"""
        names = [str(x) for x in (names or [])][: self.FEEDBACK_IMG_HARD_CAP]
        with self.lock, self._conn() as c:
            c.execute("UPDATE feedback SET images=? WHERE id=?",
                      (json.dumps(names, ensure_ascii=False) if names else "", int(fid)))

    def feedback_images(self, fid):
        with self.lock, self._conn() as c:
            row = c.execute("SELECT images FROM feedback WHERE id=?", (int(fid),)).fetchone()
        if not row or not row["images"]:
            return []
        try:
            v = json.loads(row["images"])
            return [str(x) for x in v] if isinstance(v, list) else []
        except Exception:
            return []

    def feedback_stats(self):
        with self.lock, self._conn() as c:
            total = c.execute("SELECT COUNT(*) n FROM feedback").fetchone()["n"]
            new = c.execute("SELECT COUNT(*) n FROM feedback WHERE status='new'").fetchone()["n"]
        return {"total": total, "new": new}

    def list_feedback(self, limit=300, status=""):
        sql = "SELECT * FROM feedback"
        args = []
        if status:
            sql += " WHERE status=?"
            args.append(status)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(max(1, min(2000, int(limit))))
        with self.lock, self._conn() as c:
            return [dict(r) for r in c.execute(sql, args).fetchall()]

    def list_feedback_by_ip(self, ip, limit=50):
        """提交者自己的反馈。【刻意只返回能给本人看的字段】——
        contact / ip / agent 全部不出现:这个接口是公开的,按 IP 认领,而 IP 会
        被 NAT 共享。同一出口下的另一个人不该看到别人留的邮箱和 UA。
        截图也不回传:处理完就删了,而且用户自己刚上传的图不需要再看一遍。"""
        with self.lock, self._conn() as c:
            rows = c.execute(
                "SELECT id, at, kind, message, status, reply, replied_at, images "
                "FROM feedback WHERE ip=? ORDER BY id DESC LIMIT ?",
                (ip, max(1, min(200, int(limit))))).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                imgs = json.loads(d.pop("images", "") or "[]")
            except Exception:
                imgs = []
            d["image_count"] = len(imgs) if isinstance(imgs, list) else 0
            out.append(d)
        return out

    def set_feedback_status(self, fid, status, reply=None):
        """标记状态,顺带写处理结果。

        返回 (ok, 需要删除的截图文件名)。标为 done 时截图【连同数据库里的引用
        一起清掉】—— 截图的用途就是让问题被复现和定位,处理完它只剩占盘。这也是
        取消大小/张数限制之后,磁盘不会单向增长的原因。"""
        if status not in ("new", "done"):
            return (False, [])
        drop = self.feedback_images(fid) if status == "done" else []
        with self.lock, self._conn() as c:
            if reply is not None:
                c.execute("UPDATE feedback SET reply=?, replied_at=? WHERE id=?",
                          (str(reply)[: self.FEEDBACK_MAX_MSG], iso(now_utc()), int(fid)))
            if drop:
                c.execute("UPDATE feedback SET images='' WHERE id=?", (int(fid),))
            cur = c.execute("UPDATE feedback SET status=? WHERE id=?", (status, int(fid)))
            return (cur.rowcount > 0, drop)

    def _set_feedback_status_legacy(self, fid, status):
        if status not in ("new", "done"):
            return False
        with self.lock, self._conn() as c:
            cur = c.execute("UPDATE feedback SET status=? WHERE id=?", (status, int(fid)))
            return cur.rowcount > 0

    def delete_feedback(self, fid):
        """返回 (是否删掉, 该条曾挂的截图文件名)。文件名要交回给调用方去 unlink,
        否则删掉记录后图片会永远留在盘上,再没有任何东西引用它。"""
        names = self.feedback_images(fid)
        with self.lock, self._conn() as c:
            cur = c.execute("DELETE FROM feedback WHERE id=?", (int(fid),))
            return (cur.rowcount > 0, names)

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
                  "signed INTEGER DEFAULT 0, markers INTEGER DEFAULT 0, report TEXT, "
                  "has_behaviour INTEGER DEFAULT 0)")

    # 滚动窗口上限。语料是用来算出现率的,不需要无限留存;超出后淘汰。
    #
    # 【淘汰顺序不是单纯按时间】。留存策略放开成「干净就存」之后,没跑过沙箱的行会占
    # 大多数(实测干净文件里约 97% 拿不到沙箱报告),而它们对区分度贡献为零 ——
    # collect_benign 会直接跳过。若仍按 stored_at 单键淘汰,这批零价值的行会把真正
    # 能用的、带沙箱行为的老行挤出去,语料越采越差。故排序键是 (has_behaviour, stored_at):
    # 先清最旧的无行为行,只有无行为行全清完了才会碰到带行为的。
    BENIGN_MAX_ROWS = 20000

    @staticmethod
    def slim_benign_report(sha256, attr, behaviour, has_behaviour=True):
        """把完整 VT 报告削成语料需要的最小形状。

        刻意保留 signature_info:后面要做「按签名状态给正常样本分层」时用得上,
        而重新去 VT 拉一遍代价远高于现在多存几百字节。

        【type_description / type_extension / magic 是补上来的】。原先只留 type_tag,
        而 VT 并不总给这个字段 —— 实测 63 份语料里 39 份(62%)的 type_tag 是空的,
        于是挖掘侧按「type_tag 在 Windows 类型表里」过滤时把它们全判成非本平台,
        可用语料从 63 掉到 13,低于 BENIGN_MIN_CORPUS(50),整个区分度环节因此空转。
        要命的是这三个字段在存库那一刻【是有的】,是被这里削掉的 —— 那 39 行的平台
        信息已经不可恢复,只能从现在起不再丢。每行多存不到一百字节。
        """
        sig = attr.get("signature_info") or {}
        return {
            "id": sha256,
            "file": {
                "type_tag": attr.get("type_tag") or "",
                "type_description": attr.get("type_description") or "",
                "type_extension": attr.get("type_extension") or "",
                "magic": (attr.get("magic") or "")[:160],
                "meaningful_name": attr.get("meaningful_name") or "",
                "last_analysis_stats": attr.get("last_analysis_stats") or {},
                "popular_threat_classification": {},
                "signature_info": {k: sig.get(k) for k in
                                   ("verified", "signers", "product", "description")
                                   if sig.get(k)},
            },
            # sigma_analysis_results 是挖掘唯一消费的行为字段(见 engine_build.extract_markers)
            "behaviour": {"sigma_analysis_results":
                          ((behaviour or {}).get("sigma_analysis_results") or [])},
            # 【必须如实反映,不能恒 True】。engine_build.collect_benign 正是靠这个字段
            # 决定一行要不要计入语料:
            #     if not rep.get("behaviour_available"): continue
            # 现在留存策略放开成「干净就存」(见 vt_lookup),没跑过沙箱的行也会进表。
            # 若这里继续写死 True,那些行就会伪装成有效语料进入 BenignCorpus,把
            # 「这个行为在正常软件里的出现率」算低 —— 等于放过通用行为,比没有语料更糟。
            # 恒 True 在旧策略下是安全的(那时只有 bst==200 才会走到这里),放开后就不是了。
            "behaviour_available": bool(has_behaviour),
        }

    def save_benign_report(self, sha256, attr, behaviour, has_behaviour=True):
        """留存一个正常样本。返回 True 表示确实入库了。

        【没有 sigma 命中的样本也要存】。它不是"无用样本",而是分母的一部分 ——
        「这个行为在正常软件里并不普遍」的正面证据。只存有命中的会系统性高估出现率,
        那比没有语料更危险(会把真规则砍掉、把假规则留下)。

        has_behaviour 区分的是【另一件事】,别和上面那条混起来:
          * sigma 命中数为 0 = 跑过沙箱、什么可疑动作都没做 -> 有效分母,参与定级;
          * has_behaviour=False = 【根本没跑过沙箱】-> 不知道它会做什么,不能计入分母。
        两者都入库,但只有前者会被 collect_benign 取用(它按 behaviour_available 过滤)。
        后者留着的理由是:①「这个哈希已经问过 VT 且是干净的」这个事实值得永久记住,
        而 vt_lookup_cache 只有 7 天 TTL;② 以后若补到了沙箱行为,原地 upsert 即可升级
        成有效语料,不必重新查一遍上游。
        """
        slim = self.slim_benign_report(sha256, attr, behaviour, has_behaviour)
        sig = slim["file"]["signature_info"]
        n_marks = len(slim["behaviour"]["sigma_analysis_results"])
        with self.lock, self._conn() as c:
            c.execute(self.BENIGN_DDL)
            # 幂等迁移:老库没有 has_behaviour 列。既有的 63 行都是在旧策略下入库的,
            # 那时只有 bst==200 才走到这里 —— 所以它们全都确实跑过沙箱,回填 1 是准确的,
            # 不是乐观猜测。
            bcols = [r[1] for r in c.execute("PRAGMA table_info(benign_reports)").fetchall()]
            if "has_behaviour" not in bcols:
                c.execute("ALTER TABLE benign_reports ADD COLUMN has_behaviour INTEGER DEFAULT 0")
                c.execute("UPDATE benign_reports SET has_behaviour=1")
            c.execute("INSERT INTO benign_reports(sha256, stored_at, type_tag, name, "
                      "signed, markers, report, has_behaviour) VALUES (?,?,?,?,?,?,?,?) "
                      "ON CONFLICT(sha256) DO UPDATE SET stored_at=excluded.stored_at, "
                      "type_tag=excluded.type_tag, name=excluded.name, "
                      "signed=excluded.signed, "
                      # 【markers/report 只在「新的不比旧的差」时才覆盖】。
                      # has_behaviour 用 MAX 保住了列,但 report 若无条件覆盖,一次偶发的
                      # behaviour 取回失败(429/超时)就会把 behaviour_available=True 的报告
                      # 换成 False 的 —— 而 collect_benign 读的是【报告里那个字段】,不是这
                      # 一列。结果是列说「有效」、报告说「无效」,语料静默丢失且统计虚高。
                      # 实测复现过:19:10:58 那次取到了行为,19:11:52 重查撞上 VT 4 次/分
                      # 限流,列仍是 1 而报告已被换成无行为的那份。
                      "markers=CASE WHEN excluded.has_behaviour=1 OR "
                      "benign_reports.has_behaviour=0 THEN excluded.markers "
                      "ELSE benign_reports.markers END, "
                      "report=CASE WHEN excluded.has_behaviour=1 OR "
                      "benign_reports.has_behaviour=0 THEN excluded.report "
                      "ELSE benign_reports.report END, "
                      # 只允许 0 -> 1,不允许 1 -> 0。同一个哈希若先在没有沙箱数据时入库、
                      # 后来补到了行为,应当升级;而一次偶发的 behaviour 取回失败(超时/限流)
                      # 绝不能把一份已经有效的语料降级成无效的。
                      "has_behaviour=MAX(benign_reports.has_behaviour, excluded.has_behaviour)",
                      (sha256, iso(now_utc()), slim["file"]["type_tag"],
                       slim["file"]["meaningful_name"],
                       1 if str(sig.get("verified", "")).lower() == "signed" else 0,
                       n_marks, json.dumps(slim, ensure_ascii=False),
                       1 if has_behaviour else 0))
            n = c.execute("SELECT COUNT(*) n FROM benign_reports").fetchone()["n"]
            if n > self.BENIGN_MAX_ROWS:
                # 排序键见 BENIGN_MAX_ROWS 处说明:先淘汰无沙箱行为的最旧行。
                c.execute("DELETE FROM benign_reports WHERE sha256 IN ("
                          "SELECT sha256 FROM benign_reports "
                          "ORDER BY has_behaviour ASC, stored_at ASC LIMIT ?)",
                          (n - self.BENIGN_MAX_ROWS,))
        return True

    def benign_stats(self):
        """语料概况。网页与引擎页都要显示 —— 语料规模直接决定区分度能不能用。"""
        with self.lock, self._conn() as c:
            c.execute(self.BENIGN_DDL)
            bcols = [r[1] for r in c.execute("PRAGMA table_info(benign_reports)").fetchall()]
            # has_behaviour 可能还没迁移(本方法可能在任何一次 save 之前被调用)。
            # 缺列时按旧语义算:那时能入库的行必定都跑过沙箱。
            beh_expr = ("SUM(has_behaviour)" if "has_behaviour" in bcols else "COUNT(*)")
            r = c.execute("SELECT COUNT(*) n, "
                          "SUM(CASE WHEN markers>0 THEN 1 ELSE 0 END) with_marks, "
                          "SUM(signed) signed, " + beh_expr + " with_beh, "
                          "MIN(stored_at) oldest, MAX(stored_at) newest "
                          "FROM benign_reports").fetchone()
        return {"total": r["n"] or 0, "with_markers": r["with_marks"] or 0,
                "signed": r["signed"] or 0,
                # 这个数字才是「区分度能不能用」的真实分母(对齐 engine_build 的
                # BENIGN_MIN_CORPUS 判据)。total 会被没跑过沙箱的行撑大,单看它会误判。
                "with_behaviour": r["with_beh"] or 0,
                "oldest": r["oldest"] or "",
                "newest": r["newest"] or "", "cap": self.BENIGN_MAX_ROWS}

    def list_benign_reports(self, limit=300):
        """正常样本清单,喂给网页的「正常样本」区。形状与 list_vt_reports 对称:
        只回列里就有的轻量字段(不解析 report JSON),300 行的列表零解析开销。
        report 里的完整精简报告留给将来做详情页时按需拉取。"""
        with self.lock, self._conn() as c:
            c.execute(self.BENIGN_DDL)
            # has_behaviour 可能还没迁移(见 benign_stats 的同款说明):缺列时用常量 1
            # 顶替,语义等价于「旧库入库的行都跑过沙箱」。
            bcols = [r[1] for r in c.execute("PRAGMA table_info(benign_reports)").fetchall()]
            beh = "has_behaviour" if "has_behaviour" in bcols else "1 AS has_behaviour"
            rows = c.execute(
                "SELECT sha256, stored_at, type_tag, name, signed, markers, " + beh +
                " FROM benign_reports ORDER BY stored_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

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

    # ---- lookup cache (答案缓存,不是归档) ----------------------------------- #
    #
    # 为什么必须是第三张表,不能复用现有两张:
    #   1. vt_reports 是【威胁归档】。把干净文件放进去,归档计数、家族分布、分类统计
    #      全部失真 —— 正是 BENIGN_DDL 那段注释里点名要避免的事。
    #   2. benign_reports 存的是被 slim_benign_report 削过的语料行,而且有滚动淘汰
    #      上限。拿它当缓存,后续查询就会拿到残缺报告,威胁分析台的展示随之退化。
    #
    # 所以单独一张表,只回答一件事:「这个哈希我们已经问过 VirusTotal,完整报告在此」。
    # 一个标识符一行(sha256/md5/sha1 各存一行),因为 lookup 允许用任意一种哈希查。
    #
    # 修的是什么:vt_lookup 只在 vt_reports 里找缓存,而干净文件按留存策略永远不进
    # vt_reports —— 于是干净哈希【结构性地无法被缓存】,每次重复查询都要再花两次上游
    # 调用(/files 和 /files/behaviour_summary 各一次)。实测同一个已查过的干净文件
    # 连查两次,配额 125->127->129,每次 +2。
    LOOKUP_DDL = ("CREATE TABLE IF NOT EXISTS vt_lookup_cache ("
                  "ident TEXT PRIMARY KEY, sha256 TEXT, stored_at TEXT, "
                  "expires_at TEXT, report TEXT)")
    # 有 TTL 就不需要永久留存;上限只是防止长期运行后无声长大。
    LOOKUP_MAX_ROWS = 60000

    def get_lookup_cache(self, ident):
        key = ident.strip().lower()
        with self.lock, self._conn() as c:
            c.execute(self.LOOKUP_DDL)
            row = c.execute("SELECT * FROM vt_lookup_cache WHERE ident=?", (key,)).fetchone()
        if not row:
            return None
        exp = parse_iso(row["expires_at"] or "")
        if exp and exp < now_utc():
            return None                 # 过期 -> 当未命中,调用方会重新查
        try:
            rep = json.loads(row["report"]) if row["report"] else {}
        except Exception:
            return None
        if not rep:
            return None                 # 空报告不算命中,否则等于缓存了一个空壳
        return {"sha256": row["sha256"] or key, "stored_at": row["stored_at"] or "",
                "report": rep}

    def save_lookup_cache(self, idents, sha256, report, ttl_seconds):
        keys = []
        for i in idents:
            k = str(i or "").strip().lower()
            if k and k not in keys:
                keys.append(k)
        if not keys or not report:
            return
        now = now_utc()
        rows = [(k, sha256, iso(now),
                 iso(now + timedelta(seconds=max(60, int(ttl_seconds)))),
                 json.dumps(report, ensure_ascii=False)) for k in keys]
        with self.lock, self._conn() as c:
            c.execute(self.LOOKUP_DDL)
            c.executemany("INSERT INTO vt_lookup_cache"
                          "(ident, sha256, stored_at, expires_at, report) VALUES (?,?,?,?,?) "
                          "ON CONFLICT(ident) DO UPDATE SET sha256=excluded.sha256, "
                          "stored_at=excluded.stored_at, expires_at=excluded.expires_at, "
                          "report=excluded.report", rows)
            n = c.execute("SELECT COUNT(*) n FROM vt_lookup_cache").fetchone()["n"]
            if n > self.LOOKUP_MAX_ROWS:
                c.execute("DELETE FROM vt_lookup_cache WHERE ident IN ("
                          "SELECT ident FROM vt_lookup_cache ORDER BY stored_at ASC LIMIT ?)",
                          (n - self.LOOKUP_MAX_ROWS,))

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
#  在线客服:会话 + 消息                                                        #
# --------------------------------------------------------------------------- #
class SupportStore:
    """在线客服的会话与消息存储。

    【刻意用独立的数据库文件,不放进 cache.db】。三条理由,每一条单独都足够:

      1. cache.db 是 386MB 的威胁归档,vt_reports 有一份全量校验凭据要在每次部署
         前后比对。对话是「每 3 天整体清空」的高频删除负载 —— 让它和那份归档共用
         同一个文件,就是让删除作业和归档共用同一次备份、同一次同步、同一把锁。

      2. 「每 3 天清空所有对话内容」这条承诺要能被审计。独立文件可以直接证明清理
         一行都没碰到情报库;同库删除要证明这件事,成本高得多,而且没人会去证。

      3. cache.db 会整份镜像到 245。客户的对话和上传的截图不该被复制到第二台机器。

    连接与并发沿用 Store 的约定:每次访问新开连接 + 一把进程级锁。这个服务的对话
    量是人打字的速度,没有必要引入连接池带来的新失败模式。
    """

    # 绝对兜底,防止配置写成天文数字。真实上限由配置决定(见 Handler._sup_cfg)。
    MSG_HARD_CAP = 8000
    MEDIA_HARD_CAP = 12

    def __init__(self, path, media_dir):
        self.path = path
        self.media_dir = media_dir
        self.lock = threading.Lock()
        # 长轮询用:插入消息后广播,等待者立刻醒来重查。
        self.cond = threading.Condition()
        for d in (os.path.dirname(path), media_dir):
            if d:
                try:
                    os.makedirs(d, exist_ok=True)
                except OSError:
                    pass
        self._init()

    def _conn(self):
        c = sqlite3.connect(self.path, timeout=15)
        c.row_factory = sqlite3.Row
        return c

    def _init(self):
        with self.lock, self._conn() as c:
            # token 是访客的【能力凭证】:256 位随机,存在 HttpOnly cookie 里。
            # 认领一次对话不需要账号 —— 客服系统不能要求用户先注册才能提问。
            # mkey 与 token 分开:附件文件名里带 mkey,这样 URL 不泄露 token 的任何
            # 一段。共用的话,媒体链接就等于把 48 位令牌写在了地址栏里。
            c.execute("""CREATE TABLE IF NOT EXISTS conversations(
                token TEXT PRIMARY KEY, mkey TEXT, created_at TEXT, last_at TEXT,
                ip TEXT, agent TEXT DEFAULT '', page TEXT DEFAULT '',
                status TEXT DEFAULT 'open', unread INTEGER DEFAULT 0,
                msgs INTEGER DEFAULT 0)""")
            c.execute("CREATE INDEX IF NOT EXISTS idx_conv_last ON conversations(last_at)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_conv_mkey ON conversations(mkey)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_conv_ip ON conversations(ip)")
            # who: visitor | agent | system。media 是【文件名】的 JSON 数组,不是字节 ——
            # 一段 30MB 的视频塞进 SQLite,会让这个本该是几 MB 的库变成几 GB,而它每
            # 3 天要被整体清空一次。
            c.execute("""CREATE TABLE IF NOT EXISTS messages(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT, at TEXT, who TEXT, body TEXT DEFAULT '',
                media TEXT DEFAULT '')""")
            c.execute("CREATE INDEX IF NOT EXISTS idx_msg_conv ON messages(token, id)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_msg_at ON messages(at)")
            c.execute("""CREATE TABLE IF NOT EXISTS kv(
                k TEXT PRIMARY KEY, v TEXT)""")

    # ---- kv:客服在线状态 --------------------------------------------------- #
    def kv_set(self, k, v):
        with self.lock, self._conn() as c:
            c.execute("INSERT INTO kv(k, v) VALUES (?,?) "
                      "ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, str(v)))

    def kv_get(self, k, default=""):
        with self.lock, self._conn() as c:
            row = c.execute("SELECT v FROM kv WHERE k=?", (k,)).fetchone()
        return row["v"] if row else default

    # ---- 会话 --------------------------------------------------------------- #
    def open_conversation(self, ip, agent, page, per_ip_per_day, greeting=""):
        """新建一个会话。返回 (token, mkey, error)。

        每 IP 每日建会话数要有上限:这个口是公开的,没有上限就等于允许任何人用
        一个脚本把库刷满 —— per-IP 滑窗只挡请求频率,挡不住「一天慢慢开一万个」。
        """
        token = uuid.uuid4().hex + uuid.uuid4().hex     # 256 位
        mkey = uuid.uuid4().hex[:12]
        now = iso(now_utc())
        day = now_utc().strftime("%Y-%m-%d")
        with self.lock, self._conn() as c:
            n = c.execute("SELECT COUNT(*) n FROM conversations "
                          "WHERE ip=? AND substr(created_at,1,10)=?",
                          (ip or "", day)).fetchone()["n"]
            if per_ip_per_day and n >= per_ip_per_day:
                return (None, None, "今日新建会话次数已达上限,请稍后再试")
            c.execute("""INSERT INTO conversations
                (token, mkey, created_at, last_at, ip, agent, page, status, unread, msgs)
                VALUES (?,?,?,?,?,?,?,'open',0,0)""",
                      (token, mkey, now, now, ip or "",
                       (agent or "")[:40], (page or "")[:200]))
            if greeting:
                c.execute("INSERT INTO messages(token, at, who, body, media) "
                          "VALUES (?,?,'system',?,'')", (token, now, greeting))
                c.execute("UPDATE conversations SET msgs=1 WHERE token=?", (token,))
        self._wake()
        return (token, mkey, "")

    def get_conversation(self, token, max_age_days=None):
        """按 token 取会话。

        max_age_days 不为 None 时做【读侧惰性过期】:超过留存期的对话一律当作不存在,
        即便清理定时器坏了也读不出来。承诺是「3 天后没有」,不能只靠一个 timer 兑现。
        """
        t = (token or "").strip().lower()
        if len(t) != 64 or not all(ch in "0123456789abcdef" for ch in t):
            return None
        with self.lock, self._conn() as c:
            row = c.execute("SELECT * FROM conversations WHERE token=?", (t,)).fetchone()
        if not row:
            return None
        d = dict(row)
        if max_age_days is not None:
            last = parse_iso(d.get("last_at") or "")
            if not last or last < now_utc() - timedelta(days=float(max_age_days)):
                return None
        return d

    def conversation_by_mkey(self, mkey):
        m = (mkey or "").strip().lower()
        if len(m) != 12 or not all(ch in "0123456789abcdef" for ch in m):
            return None
        with self.lock, self._conn() as c:
            row = c.execute("SELECT * FROM conversations WHERE mkey=?", (m,)).fetchone()
        return dict(row) if row else None

    def set_status(self, token, status):
        if status not in ("open", "closed"):
            return False
        with self.lock, self._conn() as c:
            cur = c.execute("UPDATE conversations SET status=? WHERE token=?", (status, token))
            return cur.rowcount > 0

    def mark_read(self, token):
        with self.lock, self._conn() as c:
            c.execute("UPDATE conversations SET unread=0 WHERE token=?", (token,))

    def list_conversations(self, limit=200, include_closed=True):
        sql = "SELECT * FROM conversations"
        if not include_closed:
            sql += " WHERE status='open'"
        sql += " ORDER BY last_at DESC LIMIT ?"
        with self.lock, self._conn() as c:
            rows = c.execute(sql, (max(1, min(1000, int(limit))),)).fetchall()
            last = {r["token"]: r["body"] for r in c.execute(
                "SELECT token, body FROM messages WHERE id IN "
                "(SELECT MAX(id) FROM messages GROUP BY token)").fetchall()}
        out = []
        for r in rows:
            d = dict(r)
            d["preview"] = (last.get(d["token"], "") or "")[:60]
            out.append(d)
        return out

    def stats(self, active_min=10):
        cutoff = iso(now_utc() - timedelta(minutes=active_min))
        with self.lock, self._conn() as c:
            r = c.execute("SELECT COUNT(*) total, "
                          "SUM(CASE WHEN status='open' THEN 1 ELSE 0 END) open, "
                          "SUM(CASE WHEN unread>0 THEN 1 ELSE 0 END) waiting, "
                          "SUM(CASE WHEN last_at>=? THEN 1 ELSE 0 END) active "
                          "FROM conversations", (cutoff,)).fetchone()
            m = c.execute("SELECT COUNT(*) n FROM messages").fetchone()["n"]
        return {"conversations": r["total"] or 0, "open": r["open"] or 0,
                "waiting": r["waiting"] or 0, "active": r["active"] or 0,
                "messages": m}

    # ---- 消息 --------------------------------------------------------------- #
    def add_message(self, token, who, body, media=None, per_day_cap=0, max_chars=2000):
        """写一条消息。返回 (id, error)。

        media 是【已经落盘成功】的文件名列表 —— 与 Store.add_feedback 一样,这一层
        不碰文件系统:磁盘配额和类型判定归 HTTP 层,存储层只记引用。
        """
        body = (body or "").strip()[: min(int(max_chars), self.MSG_HARD_CAP)]
        names = [str(x) for x in (media or []) if SUP_NAME_RE.match(str(x))][: self.MEDIA_HARD_CAP]
        # 一张截图往往比一段描述更说明问题,所以【有附件就不强制写文字】。
        if not body and not names:
            return (0, "请输入内容或选择要发送的文件")
        now = iso(now_utc())
        day = now_utc().strftime("%Y-%m-%d")
        with self.lock, self._conn() as c:
            if not c.execute("SELECT 1 FROM conversations WHERE token=?", (token,)).fetchone():
                return (0, "会话不存在或已过期")
            if per_day_cap and who == "visitor":
                n = c.execute("SELECT COUNT(*) n FROM messages WHERE token=? AND who='visitor' "
                              "AND substr(at,1,10)=?", (token, day)).fetchone()["n"]
                if n >= per_day_cap:
                    return (0, "本次会话今日消息数已达上限")
            cur = c.execute("INSERT INTO messages(token, at, who, body, media) VALUES (?,?,?,?,?)",
                            (token, now, who, body,
                             json.dumps(names, ensure_ascii=False) if names else ""))
            # 访客发言 -> 未读 +1;客服发言 -> 清零(他显然已经看过了)。
            if who == "visitor":
                c.execute("UPDATE conversations SET last_at=?, msgs=msgs+1, unread=unread+1, "
                          "status='open' WHERE token=?", (now, token))
            else:
                c.execute("UPDATE conversations SET last_at=?, msgs=msgs+1, unread=0 "
                          "WHERE token=?", (now, token))
        self._wake()
        return (cur.lastrowid, "")

    def messages(self, token, after_id=0, limit=400):
        with self.lock, self._conn() as c:
            rows = c.execute("SELECT id, at, who, body, media FROM messages "
                             "WHERE token=? AND id>? ORDER BY id LIMIT ?",
                             (token, int(after_id), max(1, min(1000, int(limit))))).fetchall()
        out = []
        for r in rows:
            try:
                names = json.loads(r["media"] or "[]")
            except Exception:
                names = []
            files = []
            for n in (names if isinstance(names, list) else []):
                n = str(n)
                if not SUP_NAME_RE.match(n):
                    continue
                ext = n.rsplit(".", 1)[-1]
                files.append({"name": n,
                              "kind": "video" if ext in SUP_VIDEO_EXT else "image"})
            out.append({"id": r["id"], "at": r["at"], "who": r["who"],
                        "body": r["body"] or "", "files": files})
        return out

    def media_names(self, token=None):
        """库里现存的全部附件文件名。清理孤儿文件时要用它当白名单。"""
        sql = "SELECT media FROM messages WHERE media<>''"
        args = []
        if token:
            sql += " AND token=?"
            args.append(token)
        with self.lock, self._conn() as c:
            rows = c.execute(sql, args).fetchall()
        names = []
        for r in rows:
            try:
                v = json.loads(r["media"] or "[]")
            except Exception:
                continue
            if isinstance(v, list):
                names.extend(str(x) for x in v)
        return names

    def media_dir_bytes(self):
        total = 0
        try:
            for n in os.listdir(self.media_dir):
                try:
                    total += os.path.getsize(os.path.join(self.media_dir, n))
                except OSError:
                    pass
        except OSError:
            return 0
        return total

    # ---- 长轮询 ------------------------------------------------------------- #
    def _wake(self):
        with self.cond:
            self.cond.notify_all()

    def wait_messages(self, token, after_id, timeout, admin=False):
        """等到有新消息或超时。返回 (消息列表, 是否等过)。

        为什么是长轮询而不是 WebSocket:这个服务是 stdlib 的 ThreadingHTTPServer,
        没有任何现成的推送通道,手写 WebSocket 握手与帧解析是在一个公网端口上多开
        一整片攻击面,只为省下一次 HTTP 往返。长轮询用现成的请求路径,首字节就是
        新消息,实际延迟是毫秒级。

        等待【切成 2 秒一片再重查】,不是一觉睡到超时:通知有可能落在「查完」和
        「开始等」之间,分片重查让这种漏掉的通知最多只延迟 2 秒,而不需要为此引入
        一套带序号的通知簿。
        """
        deadline = time.time() + max(0.0, float(timeout))
        waited = False
        while True:
            rows = (self.admin_messages(after_id) if admin
                    else self.messages(token, after_id))
            if rows:
                return rows, waited
            left = deadline - time.time()
            if left <= 0:
                return [], waited
            waited = True
            with self.cond:
                self.cond.wait(min(2.0, left))

    def admin_messages(self, after_id=0, limit=400):
        """跨全部会话的新消息(客服台用)。带上会话 token 才能归到对话里去。"""
        with self.lock, self._conn() as c:
            rows = c.execute("SELECT id, token, at, who, body, media FROM messages "
                             "WHERE id>? ORDER BY id LIMIT ?",
                             (int(after_id), max(1, min(1000, int(limit))))).fetchall()
        out = []
        for r in rows:
            out.append({"id": r["id"], "token": r["token"], "at": r["at"],
                        "who": r["who"], "body": r["body"] or ""})
        return out

    def max_message_id(self):
        with self.lock, self._conn() as c:
            row = c.execute("SELECT COALESCE(MAX(id),0) m FROM messages").fetchone()
        return row["m"] or 0


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

    def refund(self, ip):
        """把刚记下的那一次还回去。

        闸门必须在处理请求【之前】判,否则防滥用就是一句空话 —— 那时还不知道这次查询
        会不会命中缓存。而命中缓存的查询既不花上游配额、也几乎不占 CPU,让它扣掉一个
        名额是纯亏:实测计数器 hash_cache_hit 306 / miss 693,三成请求属于这一类,
        而每 IP 每小时的名额本来就不多。

        所以改成「先扣、命中缓存再退」。只弹最后一个时间戳:并发请求之间谁退谁的无关
        紧要,总数才是限流依据。
        """
        with self.lock:
            arr = self.hits.get(ip)
            if arr:
                arr.pop()


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

        # ---- 按用途分配 key ---------------------------------------------------
        # 每查一个新哈希要打【两次】VT，因为文件报告和沙箱行为在两个不同端点上，
        # 拿不到一起（实测过 ?relationships=behaviours：只回 19 个 {type,id} 描述符，
        # 没有属性，要拿真数据得按 id 再请求 19 次，比两次更贵）。
        #
        # 免费版是 4 次/分钟、500 次/天。两次调用共用一个 key，等于每分钟只能查
        # 2 个新哈希，日上限 250 个。
        #
        # 把行为端点分给单独的 key 之后，两条路各有自己的配额和分钟速率：
        # 文件报告走 self.keys，沙箱行为走 self.beh_keys，互不挤占。
        # 没配 behaviour_api_key(s) 时 beh_keys 为空，自动回落到主 key —— 与旧行为一致。
        braw = cfg.get("behaviour_api_keys")
        if not braw:
            single = cfg.get("behaviour_api_key", "")
            braw = [single] if single else []
        bseen, self.beh_keys = set(), []
        for item in braw:
            k = str(item).split(":")[0].strip()
            if (len(k) == 64 and all(c in "0123456789abcdefABCDEF" for c in k)
                    and k not in bseen):
                bseen.add(k)
                self.beh_keys.append(k)
        self._beh_idx = 0

    def has_key(self):
        return len(self.keys) > 0

    def beh_key_count(self):
        return len(self.beh_keys)

    def key_count(self):
        return len(self.keys)

    def _next_key(self):
        return self._next_from(self.keys, False)

    def _next_from(self, pool, use_beh_idx):
        """Hand out the next usable key from `pool`, honouring cooldowns.

        Each pool keeps its own round-robin cursor so the behaviour pool rotating
        does not skip entries in the file-report pool. The cooldown table is
        shared on purpose: a 429 or a revoked key is a property of the key itself,
        not of the endpoint it happened to be used for, so parking it must apply
        everywhere it is used.
        """
        now = time.time()
        chosen = None
        with self._lock:
            n = len(pool)
            if n == 0:
                return None
            for _ in range(n):
                if use_beh_idx:
                    k = pool[self._beh_idx % n]
                    self._beh_idx += 1
                else:
                    k = pool[self._idx % n]
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
        # 行为端点用单独的 key 池，和文件报告互不挤占配额（见 __init__ 里的说明）。
        # 没配行为 key 时 beh_keys 为空，仍然走主池 —— 行为绝不能因为缺这个配置
        # 而静默取不到：那会让攻击链引擎悄悄停止获得新标记。
        is_beh = "/behaviour" in path
        url = "https://www.virustotal.com/api/v3" + path
        timeout = int(self.cfg.get("report_timeout_seconds",
                                   max(20, int(self.cfg.get("timeout_seconds", 10)))))

        def attempt(pool, use_beh_idx):
            last = 0
            for _ in range(min(6, len(pool))):
                key = self._next_from(pool, use_beh_idx)
                if key is None:
                    return (429, "")
                try:
                    status, body = http_get(url, {"x-apikey": key}, timeout)
                    text = (body.decode("utf-8", "replace")
                            if isinstance(body, (bytes, bytearray)) else str(body))
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

        if is_beh and self.beh_keys:
            st, text = attempt(self.beh_keys, True)
            # 【行为专用池鉴权失败 -> 回退主池】。
            #
            # 上面那段注释的本意是「行为绝不能因为缺这个配置而静默取不到」，但它只覆盖了
            # 「没配」，没覆盖【配了但那把 key 是死的】—— 而后者才是实际发生过的：
            # behaviour_api_keys 里唯一一把 key 返回 401，池子只有 1 个成员，循环跑一轮
            # 就退出并返回 401，从不回落主池。于是 vt_lookup 里 `bst == 200` 恒不成立，
            # 干净样本一份都进不了 benign_reports —— 正常语料从 2026-08-07 起原地冻结在
            # 63 份，攻击链引擎的区分度环节整整空转了九天，期间没有任何一行日志报错。
            #
            # 401/403 与 429 必须分开处理，不能一起回落：
            #   * 401/403 是【配置错误】(key 被吊销/填错)。这种情况回落主池是对的 ——
            #     实测主池那把 key 打 behaviour_summary 是 200，能力本来就在。
            #   * 429 是【配额状态】。回落主池会去烧文件报告的配额，而把两个池分开的
            #     全部目的就是不互相挤占。所以 429 保持原样返回，绝不回落。
            if st in (401, 403) and self.keys:
                self._warn_beh_fallback(st)
                return attempt(self.keys, False)
            return (st, text)
        pool = self.keys
        if not pool:
            return (0, "")
        return attempt(pool, False)

    # 回退告警的最近一次打印时间。这条告警必须存在：上面那个故障之所以能潜伏九天，
    # 就是因为它完全无声。但也不能每次请求都打 —— 补库作业一轮几百次调用会把 journal
    # 刷满，于是按 key 状态设一个冷却窗口，够运维在 journalctl 里看见就行。
    _beh_warn_at = 0.0

    def _warn_beh_fallback(self, code):
        now = time.time()
        if now - self._beh_warn_at < 600:
            return
        self._beh_warn_at = now
        print("[vt] behaviour key pool rejected (HTTP %d) -- falling back to the file-report "
              "key pool. Fix or remove 'behaviour_api_keys' in config.json; until then the "
              "two endpoints share one quota." % code, flush=True)

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
        # 接口通、微步就是没这个哈希 -> unknown,【不算查询失败】。
        #
        # 原来只认 SAMPLE_NOT_FOUND,而线上实测微步回的是 verbose_msg="No Report Found"
        # (rc=-1),于是一个权威的「我查了,我这儿没有」被记成「没问到」。后果不只是
        # sources_ok 少算一个:reputation_hash 靠 succeeded 决定要不要落库,客户端靠
        # serverHasRecord 决定要不要回退本地直连 —— 把「问过了」说成「没问到」,两边都
        # 会做出相反的决定。
        # 判据放宽到「消息里说了 not found / no report」:这类措辞只可能是「无记录」,
        # 鉴权与配额问题在微步侧有各自的 rc 与文案,不会落进来。
        up = msg.upper().replace("_", " ")
        if rc != 0 and ("NOT FOUND" in up or "NO REPORT" in up or "NO RECORD" in up):
            return {"querySucceeded": True, "verdict": "unknown", "malicious": 0,
                    "total_engines": 0, "threat_label": "", "source": self.NAME,
                    "reason": msg}
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

    def reputation_hash(self, sha, lookup_only=False):
        sha = sha.lower()
        cached = self.store.get_hash(sha)
        if cached:
            self.store.counter_incr("hash_cache_hit")
            return self._hash_response(cached, cached=True)
        self.store.counter_incr("hash_cache_miss")

        # 「只查收录」:客户端明确要求【不要动服务端的上游情报源】—— 它会用自己的本地密钥去查。
        #
        # 这个分支必须真的 return。客户端从一开始就在发 cacheOnly(配额耗尽时)并在注释里声称
        # 「绝不动用付费上游」,但服务端此前【从未读过这个字段】,未命中一律往下走上游循环。
        # 于是那层保护完全不存在:机队共享的付费配额照烧,而客户端还以为自己省下来了。
        #
        # 未收录时回 unknown + querySucceeded=true:对客户端语义是「我查了我的库,权威地告诉你
        # 没有」(它据 serverHasRecord 判定无实据 -> 转本地直连),区别于「没问到」(HTTP 失败/
        # 熔断/预算用尽)。两者混同的话,日志里就再也分不清这次到底走没走服务器。
        if lookup_only:
            self.store.counter_incr("lookup_only_miss")
            return {"sha256": sha, "verdict": "unknown", "malicious": 0, "totalEngines": 0,
                    "threatLabel": "", "source": "lookup-only", "querySucceeded": True,
                    "cached": False, "recorded": False, "lookupOnly": True,
                    "fetchedAt": iso(now_utc())}

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

    def _degraded_lookup(self, ident, why, vt_unknown=False):
        """VT unavailable (no key / banned / rate-limited / error): still answer
        from the other configured sources instead of failing the whole query.

        Before this existed, any non-200 from VirusTotal returned an error and
        secondary_sources_hash() was never reached, so a single dead VT key took
        the entire file-lookup feature down with it.

        vt_unknown=True means VirusTotal answered authoritatively "I have no record"
        (HTTP 404), as opposed to not answering at all. It has to be recorded INSIDE
        the report, because that distinction is load-bearing for harvest.py: it reads
        `ok == False` plus "404" in the error to decide "VT has never seen this, upload
        the sample". If a cached 404 answer came back as a plain ok=True hit, that
        pipeline would silently stop uploading anything -- and harvest.py is frozen
        byte-identical across nodes, so the compatibility has to be kept on this side.
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
                  "degraded": True, "degraded_reason": why, "vt_unknown": bool(vt_unknown),
                  "sources": ([{"source": "VirusTotal", "verdict": "unknown", "malicious": 0,
                                "total_engines": 0, "threat_label": "",
                                "querySucceeded": False, "reason": why}] + srcs)}
        meta = {"sha256": ident, "md5": "", "sha1": "", "name": "",
                "verdict": verdict, "malicious": mal, "total_engines": tot,
                "threat_label": label, "category": ""}
        is_threat = verdict in ("malicious", "suspicious")
        if is_threat:
            self.store.save_vt_report(meta, report)
        else:
            # 非威胁的降级结论【也必须落缓存】。
            #
            # 以前这里什么都不存:威胁走 vt_reports 占位行(靠 degraded_retry_seconds
            # 节流重试),而 clean/unknown 两手空空 —— 于是 VT 一旦持续 429,同一个哈希
            # 每次查询都要把 5 个备用源重新问一遍。MetaDefender 100/天、
            # HybridAnalysis 200/天,几轮批量就能把它们也打光,「VT 挂了还有备用源」
            # 就变成「VT 挂了连备用源一起挂」。
            #
            # 线上实测正是这个形状:vt_lookup_cache 只有 30 行,而 vt_reports 里有
            # 3301 行是 VirusTotal HTTP 429 留下的降级占位 —— 降级路径几乎没缓存过
            # 任何东西。
            #
            # TTL 刻意远短于正常路径的 7 天(默认 30 分钟):这不是权威结论,VT 恢复后
            # 应该尽快被真报告顶掉。它同时充当降级结论的重试窗口,与威胁侧的
            # degraded_retry_seconds 是同一个意思、两条路径各自的实现。
            try:
                vtc = self.cfg.get("virustotal", {}) or {}
                ttl = int(vtc.get("degraded_cache_ttl_seconds", 1800) or 1800)
                self.store.save_lookup_cache([ident], ident, report, ttl)
            except Exception:
                pass        # 缓存写失败绝不能影响这次查询的返回
        return {"ok": True, "cached": False, "degraded": True, "stored": is_threat,
                "stored_at": iso(now_utc()) if is_threat else "",
                "verdict": verdict, "malicious": mal, "total_engines": tot,
                "sources_ok": len(ok_srcs), "report": report}

    # ---- full VT report (file report + sandbox behaviour), permanently stored --- #
    def vt_lookup(self, ident, refresh=False):
        ident = ident.strip().lower()
        vtc = self.cfg.get("virustotal", {}) or {}
        if not refresh:
            stored = self.store.get_vt_report(ident)
            if stored:
                rep = stored.get("report") or {}
                if not rep.get("degraded"):
                    return {"ok": True, "cached": True, "stored": True,
                            "stored_at": stored["stored_at"], "report": stored["report"]}
                # A DEGRADED row is a placeholder, not a report. _degraded_lookup
                # archives with file={} and md5/sha1/name all empty, so serving it
                # back hands the caller a "threat" with no engine data, no file name
                # and no signature info -- and because the row exists, the real
                # report would never be fetched again. That is how 486 of 3625 rows
                # on the master ended up permanently contentless.
                #
                # Treating it as a miss makes them heal by themselves: save_vt_report
                # is an upsert, so the next successful lookup overwrites the row in
                # place with the full report. No data surgery needed.
                #
                # But not on EVERY query: a long VT outage (the master had one from
                # 2026-07-26 to 08-05) would then re-run the whole secondary-source
                # fan-out every single time and burn those providers' quotas instead.
                # So a placeholder is still honoured while it is fresh, and only
                # retried once it is older than this window.
                retry_after = int(vtc.get("degraded_retry_seconds", 3600) or 3600)
                age = (now_utc() - (parse_iso(stored.get("stored_at") or "") or now_utc()))
                if age.total_seconds() < retry_after:
                    return {"ok": True, "cached": True, "stored": True, "degraded": True,
                            "degraded_reason": rep.get("degraded_reason", ""),
                            "stored_at": stored["stored_at"], "report": stored["report"]}
            # Clean / undetected files are deliberately never archived (vt_reports is
            # the threat archive), which used to leave them with no cache at all.
            hit = self.store.get_lookup_cache(ident)
            if hit:
                # degraded 必须往上层暴露。这张缓存现在也存降级结论(见 _degraded_lookup),
                # 而一个「VT 没答话、靠备用源拼出来的 clean」和一个「VT 70 个引擎都说
                # 干净」在页面与 /api 上必须能分开 —— 否则调用方会把前者当权威结论用。
                hrep = hit["report"] or {}
                out = {"ok": True, "cached": True, "stored": False,
                       "stored_at": hit["stored_at"], "report": hrep}
                if hrep.get("degraded"):
                    out["degraded"] = True
                    out["degraded_reason"] = hrep.get("degraded_reason", "")
                if hrep.get("vt_unknown"):
                    # 复现未缓存时的那一份响应形状。少了这三行,harvest.py 判「VT 从没
                    # 见过它 -> 把样本传上去」的依据(ok=False 且 error 含 404)在命中
                    # 缓存后就消失了,整条补库流水线会无声停摆。
                    out["ok"] = False
                    out["error"] = hrep.get("degraded_reason") or "VirusTotal 无此文件记录 (404)"
                    out["vt_unknown"] = True
                return out
        if not self.vt.has_key():
            return self._degraded_lookup(ident, "no VirusTotal key configured")
        st, body = self.vt.vt_api_get("/files/" + ident)
        if st == 404:
            # VirusTotal genuinely has no record of this file. That is NOT a reason to
            # stop asking the others: 微步 / OTX / HybridAnalysis routinely know samples
            # VT has never seen, and returning a bare "not found" threw that away.
            #
            # 这里的响应形状是承重的,不能改。harvest.py 靠下面这段判断"VT 从没见过它,
            # 把样本传上去":
            #     if resp.get("ok"): return False
            #     return "404" in err or "无此文件" in err
            # 所以 ok 必须保持假值、error 必须继续含 404 字样。因为微步答了就把 ok 翻成
            # True,会无声关掉整条补库流水线 —— 而 harvest.py 是跨节点字节冻结的,兼容
            # 只能在这一侧维持。
            #
            # 备用云的结论因此挂在额外字段上:老调用方看不见,网页与 /api 现在会读。
            if not bool(vtc.get("query_others_on_404", True)):
                return {"ok": False, "error": "VirusTotal 无此文件记录 (404)",
                        "vt_unknown": True}
            out = self._degraded_lookup(ident, "VirusTotal 无此文件记录 (404)",
                                        vt_unknown=True)
            out["ok"] = False
            out["error"] = "VirusTotal 无此文件记录 (404)"
            out["vt_unknown"] = True
            return out
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
        else:
            # 干净 -> 留一份精简报告当正常语料。
            #
            # 以前这里什么都不做,干净文件的沙箱行为抓到手就扔 —— 于是攻击链引擎只有
            # 恶意语料,只能算出「多少病毒有这个组合」,算不出「多少正常软件也有」,
            # 区分度无从计算。实测因此漏过一条退化组合(两个标记的条件都只是
            # 「未签名的进程创建」),命中的是 ripgrep 和本产品自己的 UI。
            #
            # 存入 benign_reports 而非 vt_reports:后者是威胁归档,混进干净文件会让
            # 归档计数与家族分布全部失真,而且会污染 lookup 缓存(见 BENIGN_DDL 处说明)。
            #
            # 【条件从 `elif bst == 200` 放宽成「干净就存」】。原判据要求这次必须成功拿到
            # 沙箱行为,代价是:实测 94 份干净文件的完整报告里 91 份(97%)的
            # behaviour_summary 是取不到的,于是绝大多数干净样本连「我们已经查过、它是
            # 干净的」这个事实都没留下 —— 只进了 vt_lookup_cache,而那张表 7 天就过期。
            # 语料因此只能以干净查询量的 3% 增长,九天一份没长。
            #
            # 放宽是安全的,因为有效性判据落在 has_behaviour 上而不是「在不在表里」:
            # collect_benign 按 behaviour_available 过滤,BenignCorpus.n 只数跑过沙箱的,
            # 所以没跑过沙箱的行不会把 BENIGN_MIN_CORPUS 那道门槛骗开。淘汰顺序也已经
            # 改成优先丢这些行(见 BENIGN_MAX_ROWS)。
            try:
                self.store.save_benign_report(sha256, attr, beh,
                                              has_behaviour=(bst == 200))
            except Exception:
                pass        # 语料是锦上添花,绝不能因为它失败而影响一次信誉查询
        if not is_threat:
            # 非威胁不进威胁归档 -> 必须有别的地方记住"已经问过了",否则每次重复查询
            # 都要再花两次上游调用。TTL 默认 7 天:文件哈希是不变的,一个干净判定不会
            # 天天翻转;真要强制重查,refresh=true 永远绕过这里。
            #
            # 存 ident 是为了让下次用同一种哈希查也能命中 —— VT 报告里可能没给 md5/
            # sha1(降级或字段缺失),那时只靠 meta 的两个键会漏。
            try:
                ttl_h = int(vtc.get("lookup_cache_ttl_hours", 168) or 168)
                self.store.save_lookup_cache(
                    [sha256, meta.get("md5", ""), meta.get("sha1", ""), ident],
                    sha256, report, ttl_h * 3600)
            except Exception:
                pass        # 缓存写失败绝不能影响这次查询的返回
        return {"ok": True, "cached": False, "stored": is_threat,
                "stored_at": iso(now_utc()) if is_threat else "", "report": report}

    def get_vt_report(self, ident):
        return self.store.get_vt_report(ident)

    def list_vt_reports(self):
        return self.store.list_vt_reports()

    def list_benign_reports(self):
        return self.store.list_benign_reports()

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
SUPPORT = None          # SupportStore;建库失败时保持 None,客服路由如实回 503
SUP_WAIT = None         # 长轮询并发闸门(BoundedSemaphore)
WEBUI_PATH = os.environ.get("BULWARK_INTEL_WEBUI", "/opt/bulwark-intel/webui.html")

API_DOCS_HTML = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Bulwark 威胁情报 API</title>
<style>
/* ===== 共享控制台外壳(注入 app.py 内嵌的各页面)=====================
   这些页面各自有一套自己的 class 名和版式。这里不去逐页重写,而是统一
   三件决定"是不是同一个产品"的东西:底子(白底+网格)、顶栏、以及标题/
   表格/瓦片这几个到处都在用的组件。
   放在每页样式块的最前面 —— 页面自己的规则在后面,仍可覆盖它。
   ==================================================================== */
:root{
  /* 页面压暗、面板留纯白。原来两者都是 #ffffff，面板只能靠边框描出来，整页过亮。 */
  --bwbg:#edf0f5; --bwpnl:#ffffff; --bwsoft:#f9fafb;
  --bwln:#e4e7ec; --bwln2:#f2f4f7;
  --bwink:#101828; --bwink2:#344054; --bwmut:#667085; --bwdim:#98a2b3;
  --bwac:#2563eb; --bwvi:#7c3aed;
  --bwmal:#d92d20; --bwsus:#b54708; --bwok:#067647;
  --bwmono:"SFMono-Regular","Cascadia Mono",Consolas,Menlo,monospace;
  --bwsans:-apple-system,"Segoe UI",Roboto,"Microsoft YaHei",system-ui,sans-serif;
}
body{background:var(--bwbg);color:var(--bwink);font-family:var(--bwsans);
  -webkit-font-smoothing:antialiased}
/* 白底上的网格必须是深色低透明度,白线等于不存在 */
body::before{content:"";position:fixed;inset:0;z-index:-2;pointer-events:none;background:
  repeating-linear-gradient(0deg,transparent 0 47px,rgba(16,24,40,.03) 47px 48px),
  repeating-linear-gradient(90deg,transparent 0 47px,rgba(16,24,40,.03) 47px 48px)}
body::after{content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;
  background:radial-gradient(1200px 520px at 50% -12%,rgba(37,99,235,.07),transparent 70%)}

/* ---- 顶栏:和 / 上完全一致,导航才不会每页一个样 ---- */
.bwrail{position:sticky;top:0;z-index:60;background:rgba(255,255,255,.9);
  backdrop-filter:blur(14px);border-bottom:1px solid var(--bwln)}
.bwrail .in{max-width:1440px;margin:0 auto;display:flex;align-items:center;gap:16px;
  padding:10px 22px}
.bwbrand{display:flex;align-items:center;gap:10px;text-decoration:none;flex:none}
.bwbrand .mk{width:30px;height:30px;flex:none;display:grid;place-items:center;
  background:var(--bwac);color:#fff;font-size:15px;
  clip-path:polygon(22% 0,100% 0,100% 78%,78% 100%,0 100%,0 22%)}
.bwbrand b{display:block;font-size:13.5px;font-weight:800;letter-spacing:2.2px;
  color:var(--bwink);line-height:1.1}
.bwbrand s{display:block;text-decoration:none;font-size:9px;color:var(--bwmut);
  letter-spacing:1.3px;margin-top:2px}
.bwgrow{flex:1}
.bwnav{display:flex;align-items:stretch;gap:2px;overflow-x:auto;
  scrollbar-width:none;-ms-overflow-style:none}
.bwnav::-webkit-scrollbar{display:none}
.bwnav a{position:relative;display:inline-flex;align-items:center;gap:7px;
  padding:9px 13px;font-size:12.5px;font-weight:600;letter-spacing:.5px;
  color:var(--bwmut);text-decoration:none;white-space:nowrap}
.bwnav a::after{content:"";position:absolute;left:11px;right:11px;bottom:-1px;height:2px;
  background:var(--bwac);opacity:0;transition:opacity .16s}
.bwnav a:hover{color:var(--bwink);text-decoration:none}
.bwnav a:hover::after{opacity:.5}
.bwnav a.on{color:var(--bwac)}
.bwnav a.on::after{opacity:1}
.bwnav a .i{font-size:13px;line-height:1}

/* ---- 到处都在用的组件 ---- */
h1{font-size:21px;font-weight:800;letter-spacing:-.2px;color:var(--bwink)}
h2{font-size:12px!important;font-weight:800;letter-spacing:1.6px;color:var(--bwink);
  display:flex;align-items:center;gap:9px;border-bottom:1px solid var(--bwln2)!important;
  padding-bottom:9px!important}
h2::before{content:"";width:2px;height:13px;background:var(--bwac);flex:none}
a{color:var(--bwac)}
code{font-family:var(--bwmono);background:var(--bwsoft);border:1px solid var(--bwln);
  border-radius:0;color:#1d4ed8}
pre{border-radius:0!important;border:1px solid var(--bwln)}
table th{color:var(--bwdim)!important;font-size:9.5px!important;font-weight:700;
  text-transform:uppercase;letter-spacing:1.2px;background:var(--bwsoft)}
table td{border-bottom:1px solid var(--bwln2)}
table tbody tr:hover td{background:rgba(37,99,235,.04)}
table tbody tr:hover td:first-child{box-shadow:inset 2px 0 0 var(--bwac)}
/* 统计瓦片:顶部 2px 状态色 + 大号等宽数字,和 / 的 .hstat 同一个样式 */
.bwstats{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,240px));justify-content:start;
  gap:12px;margin:0 0 18px}
.bwstat{background:var(--bwpnl);border:1px solid var(--bwln);border-top:2px solid var(--bwac);
  padding:13px 15px;box-shadow:0 1px 2px rgba(16,24,40,.05)}
.bwstat .v{font-family:var(--bwmono);font-size:25px;font-weight:800;line-height:1.05;
  font-variant-numeric:tabular-nums;letter-spacing:-.5px}
/* background/padding/border-radius 是显式清零的，不是多余代码：这些页面各自留着
   给旧标记用的 .k 药丸样式（圆角底色），而 .bwstat .k 只要不写这几个属性，页面级
   的 .k 就会漏进来，标签变成一颗药丸。清零比去每个页面删旧规则安全 —— 那些旧
   规则可能还有别处在用。 */
.bwstat .k{font-size:10.5px;color:var(--bwmut);margin-top:4px;letter-spacing:1.1px;
  background:none;padding:0;border-radius:0;display:block;width:auto}
.bwstat.mal{border-top-color:var(--bwmal)}.bwstat.mal .v{color:var(--bwmal)}
.bwstat.sus{border-top-color:var(--bwsus)}.bwstat.sus .v{color:var(--bwsus)}
.bwstat.ok{border-top-color:var(--bwok)}.bwstat.ok .v{color:var(--bwok)}
@media(max-width:640px){.bwrail .in{padding:9px 14px}.bwbrand s{display:none}}

:root{--bg:#edf0f5;--card:#fff;--soft:#f9fafb;--line:#e4e7ec;--ink:#101828;--muted:#667085;--brand:#2563eb;--mal:#d92d20;--clean:#067647;--mono:"Cascadia Mono",Consolas,monospace;--sans:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14.5px/1.65 var(--sans)}
.wrap{max-width:900px;margin:0 auto;padding:30px 20px 70px}
h1{font-size:24px;margin:0 0 4px}.lead{color:var(--muted);margin:0 0 24px}
h2{font-size:17px;margin:30px 0 12px;padding-bottom:7px;border-bottom:1px solid var(--line)}
code{font-family:var(--mono);background:var(--soft);border:1px solid var(--line);border-radius:5px;padding:1px 6px;font-size:12.5px}
/* 代码块转浅色。原来是 #101828 深底 + 亮色语法着色 —— 那是暗色主题时期留下的，
   在灰底白卡的页面上，六七块近黑色的大方块是全页最重的元素，读起来像另一个网站
   贴进来的。改成浅底 + 深字，语法色相不变（蓝=关键字、绿=字符串）但换成在白底上
   够对比度的深色版本，亮蓝亮绿在浅底上会糊掉。 */
pre{background:#f8fafc;color:#1f2937;border:1px solid var(--line);
  border-radius:11px;padding:14px 16px;overflow:auto;
  font-family:var(--mono);font-size:12.5px;line-height:1.6}
pre .k{color:#1d4ed8;font-weight:700}pre .s{color:#046c4e}
.ep{background:var(--card);border:1px solid var(--line);border-radius:13px;padding:15px 17px;margin-bottom:13px;box-shadow:0 1px 2px rgba(16,24,40,.05)}
.ep .m{display:inline-block;font-weight:800;font-size:11.5px;padding:2px 9px;border-radius:6px;color:#fff;margin-right:9px;font-family:var(--mono)}
/* GET 原来用 var(--clean)，也就是「安全」判定色。在一个满页都在讲恶意/可疑/安全的
   系统里，用判定绿去表示 HTTP 动词是语义串台：绿色在这里必须只意味着「文件安全」。
   GET 改中性石板色，POST（会改变状态、需要更留意）保留强调蓝。 */
.m.get{background:#475467}.m.post{background:var(--brand)}
.ep .p{font-family:var(--mono);font-weight:700;font-size:13.5px}
.ep .d{color:var(--muted);font-size:13px;margin:7px 0 0}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:6px}th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line)}th{color:var(--muted);font-size:11px;text-transform:uppercase}
.tag{display:inline-block;background:var(--soft);border:1px solid var(--line);border-radius:20px;padding:2px 10px;font-size:12px;color:var(--muted);margin-right:6px}
/* 同理：原来的琥珀底 + 琥珀字是「可疑」判定色。这个框讲的是配额说明，属于中性提示，
   不该长得像一条风险警告。改成强调蓝的淡色版本。 */
.note{background:#f4f7fe;border:1px solid #dbe4f8;border-left:2px solid var(--brand);
  border-radius:11px;padding:12px 15px;font-size:13px;color:var(--ink);margin:16px 0}
a{color:var(--brand);text-decoration:none}
</style></head><body>
<div class="bwrail"><div class="in">
<a class="bwbrand" href="/" title="返回控制台"><span class="mk">🛡️</span>
<span><b>BULWARK</b><s>THREAT ANALYSIS CONSOLE</s></span></a>
<div class="bwgrow"></div>
<nav class="bwnav">
<a href="/"><span class="i">🛡️</span>控制台</a>
<a href="/engine" class=""><span class="i">🧬</span>攻击链引擎</a>
<a href="/online" class=""><span class="i">📡</span>在线客户端</a>
<a href="/support" class=""><span class="i">🎧</span>在线客服</a>
<a href="/feedback" class=""><span class="i">💬</span>反馈</a>
<a href="/api/docs" class="on"><span class="i">&#128268;</span>API 文档</a>
<a href="/about" class=""><span class="i">📥</span>下载</a>
</nav>
<!-- 北京时间读数。这两台机器的系统时区是 UTC,而看页面的人在中国 —— 原来页面上
     没有任何一处告诉你「现在几点」,读时间戳只能靠脑内加 8 小时。
     样式写成内联:顶栏在 4 个页面里是 4 份字面量副本,内联能保证四份永远一致,
     也不用去动那 4 份 CSS 副本、不改变 style 标签计数。 -->
<div style="display:flex;flex-direction:column;align-items:flex-end;line-height:1.2;margin-left:16px">
<b id="bwclk" style="font:600 13px/1.2 ui-monospace,SFMono-Regular,Consolas,monospace;color:var(--ink);font-variant-numeric:tabular-nums">--:--:--</b>
<s id="bwclkd" style="text-decoration:none;font-size:10px;color:var(--mut)">北京时间</s>
</div>
</div></div>
<script>
(function(){
  var b=document.getElementById("bwclk"),d=document.getElementById("bwclkd");
  if(!b)return;
  var DAYS=["\u65e5","\u4e00","\u4e8c","\u4e09","\u56db","\u4e94","\u516d"];
  function p(n){return (n<10?"0":"")+n;}
  function tick(){
    /* Date.now() 是 UTC 毫秒;加 8 小时后再用 getUTC* 读出来,就是北京时间的墙上
       钟面,与浏览器所在时区无关。用固定偏移而不是 toLocaleString("zh-CN") ——
       后者受访问者系统时区影响,在国外打开会显示当地时间。中国无夏令时,
       固定 +08:00 不会错。 */
    var t=new Date(Date.now()+8*3600*1000);
    b.textContent=p(t.getUTCHours())+":"+p(t.getUTCMinutes())+":"+p(t.getUTCSeconds());
    if(d)d.textContent=t.getUTCFullYear()+"-"+p(t.getUTCMonth()+1)+"-"+p(t.getUTCDate())
      +" \u5468"+DAYS[t.getUTCDay()]+" UTC+8";
  }
  tick();setInterval(tick,1000);
})();
</script>
<div class="wrap">
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
_ENGINE_PAGE = r'''<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>攻击链组合引擎 · 磐垒</title>
<style>
:root{
  --bg:#eef1f6; --pnl:#fff; --inset:#f5f7fa; --line:#e3e7ee; --line2:#eef1f6;
  --ink:#0f1729; --ink2:#33405a; --mut:#5b6678; --dim:#8a93a3;
  --acc:#4f46e5; --accbg:rgba(79,70,229,.07); --accln:rgba(79,70,229,.22);
  --risk:#c2281c; --riskbg:rgba(194,40,28,.08);
  --warn:#8a5209; --warnbg:rgba(138,82,9,.09);
  --ok:#046239;
  --mono:"Cascadia Mono",ui-monospace,SFMono-Regular,Consolas,monospace;
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif;
}
*{box-sizing:border-box}
html,body{margin:0}
body{background:var(--bg);color:var(--ink2);font:13px/1.6 var(--sans);
  -webkit-font-smoothing:antialiased}
a{color:var(--acc);text-decoration:none}

/* ---- 顶栏 ---- */
.top{background:rgba(255,255,255,.92);backdrop-filter:blur(12px);
  border-bottom:1px solid var(--line);position:sticky;top:0;z-index:40}
.tin{max-width:1180px;margin:0 auto;padding:0 24px;height:50px;display:flex;
  align-items:center;gap:16px}
.bd{display:flex;align-items:center;gap:8px;font-size:13.5px;font-weight:750;
  color:var(--ink)}
.top nav{display:flex;gap:2px}
.top nav a{font-size:12.5px;font-weight:600;color:var(--mut);padding:6px 10px;
  border-radius:7px;display:inline-flex;align-items:center;gap:6px;white-space:nowrap}
.top nav a:hover{background:var(--accbg);color:var(--acc)}
.top nav a.on{background:var(--accbg);color:var(--acc)}
.sp{flex:1}
.ver{font:700 11.5px var(--mono);color:var(--acc);background:var(--accbg);
  border:1px solid var(--accln);border-radius:20px;padding:3px 11px;white-space:nowrap}

.wrap{max-width:1180px;margin:0 auto;padding:22px 24px 72px}

/* ---- 摘要卡 ----------------------------------------------------------------
   刻意做成【一张卡两栏】,而不是四块独立瓦片:处置能力与流水线是同一件事的两个
   侧面(能拦到什么强度 / 这些规则怎么筛出来的),分成两张卡会让人以为它们无关。 */
.card{background:var(--pnl);border:1px solid var(--line);border-radius:14px;
  padding:20px 22px;box-shadow:0 1px 2px rgba(15,23,41,.04)}
.card h1{margin:0 0 4px;font-size:18px;font-weight:750;color:var(--ink);
  letter-spacing:-.2px}
.card .lead{margin:0 0 18px;font-size:12.5px;color:var(--mut);max-width:76ch}
.split{display:grid;grid-template-columns:minmax(240px,1fr) 2fr;gap:28px}
@media(max-width:820px){.split{grid-template-columns:1fr;gap:20px}}
.blk{min-width:0}
.blk h2{margin:0 0 10px;font-size:10.5px;font-weight:750;letter-spacing:1.1px;
  color:var(--dim);text-transform:uppercase}

/* 处置能力:三行,数字右对齐等宽,一眼看出「最强能到哪一档」。 */
.caps{display:flex;flex-direction:column;gap:1px}
.cap{display:flex;align-items:baseline;gap:10px;padding:6px 0;
  border-bottom:1px solid var(--line2)}
.cap:last-child{border-bottom:none}
.cap b{font:800 20px/1 var(--mono);font-variant-numeric:tabular-nums;
  min-width:2.4em;text-align:right;color:var(--ink)}
.cap span{font-size:12.5px;color:var(--ink2)}
.cap em{font-style:normal;font-size:11px;color:var(--dim);margin-left:auto;
  text-align:right}
.cap.z b{color:var(--dim)}
.cap.hard b{color:var(--risk)}
.cap.strong b{color:var(--warn)}

/* 流水线:横向阶梯 + 每段的损耗就地标注,不另起横带。 */
.pipe{display:flex;align-items:stretch;flex-wrap:wrap;gap:0}
.pst{padding:0 16px 0 0;margin-right:16px;border-right:1px solid var(--line);
  min-width:104px}
.pst:last-child{border-right:none;margin-right:0;padding-right:0}
.pst b{display:block;font:800 19px/1.1 var(--mono);color:var(--ink);
  font-variant-numeric:tabular-nums;letter-spacing:-.5px}
.pst u{display:block;text-decoration:none;font-size:11px;color:var(--dim);
  margin-top:3px;white-space:nowrap}
.pst i{display:block;font-style:normal;font-size:10.5px;color:var(--warn);
  margin-top:3px}
.pst.fin b{color:var(--acc)}

/* 诚实提示。整页只有这一处横带,而且只在真有话要说时出现。 */
.note{margin-top:16px;padding:10px 13px;border-radius:9px;font-size:12px;
  border:1px solid var(--line);border-left:3px solid var(--acc);
  background:var(--accbg);color:var(--ink2)}
.note.warn{border-left-color:var(--warn);background:var(--warnbg)}
.note b{color:var(--ink)}

/* ---- 区块 ---- */
.sec{margin-top:18px;background:var(--pnl);border:1px solid var(--line);
  border-radius:14px;overflow:hidden}
.sh{display:flex;align-items:center;gap:10px;padding:13px 20px;
  border-bottom:1px solid var(--line)}
.sh h2{margin:0;font-size:13px;font-weight:750;color:var(--ink)}
.sh .n{font:700 11px var(--mono);color:var(--acc);background:var(--accbg);
  border-radius:20px;padding:1px 9px}
.sh .hint{margin-left:auto;font-size:11.5px;color:var(--dim);text-align:right}
.sh input{margin-left:auto;width:200px;padding:5px 9px;border:1px solid var(--line);
  border-radius:7px;font:12px var(--sans);color:var(--ink);background:var(--inset);
  outline:none}
.sh input:focus{border-color:var(--accln);background:#fff}

/* ---- 规则表 ---------------------------------------------------------------
   列宽写死并与吸顶表头共用同一组值,是这一版的核心修复:原来每个意图分组下都重印
   一遍列头,26 条规则出了 8 次表头 —— 那是「乱」的主要来源。现在整节只有一行表头,
   吸顶跟随滚动,分组降级成一条细分隔线。 */
.colh{position:sticky;top:50px;z-index:20;display:flex;align-items:center;
  gap:12px;padding:8px 20px;background:var(--inset);
  border-bottom:1px solid var(--line);font-size:10.5px;font-weight:750;
  letter-spacing:.5px;color:var(--dim)}
.cg{flex:none;width:52px}
.cc{flex:1;min-width:0}
.ce{flex:none;width:64px;text-align:right}
.cs{flex:none;width:56px;text-align:right}

.grp{display:flex;align-items:baseline;gap:9px;padding:11px 20px 5px;
  border-top:1px solid var(--line2)}
.grp:first-of-type{border-top:none}
.grp b{font-size:12px;font-weight:750;color:var(--ink)}
.grp i{font-style:normal;font:700 10.5px var(--mono);color:var(--dim)}
.grp s{text-decoration:none;font-size:11px;color:var(--dim);margin-left:auto}

.rule{border-top:1px solid var(--line2)}
.rule>summary{list-style:none;cursor:pointer;display:flex;align-items:center;
  gap:12px;padding:9px 20px}
.rule>summary::-webkit-details-marker{display:none}
.rule>summary:hover{background:var(--accbg)}
.rule[open]>summary{background:var(--accbg)}
.rg{flex:none;width:52px;font:700 11px var(--sans);color:var(--mut)}
.rg.hard{color:var(--risk)}
.rg.strong{color:var(--warn)}
/* ask 走的就是 .rg 的默认灰,但这条规则【必须写出来】:强度是 JS 拼上去的 class,
   而本项目唯一能发现「某块掉了样式」的手段是「渲染后不存在无规则类」。留一个
   只靠继承生效的类名,就等于在那个检查里永久留一条噪音,下次真掉样式时看不出来。 */
.rg.ask{color:var(--mut)}
.rchain{flex:1;min-width:0;font-size:13px;line-height:1.55;color:var(--ink2)}
.rchain b{font-weight:750;color:var(--ink)}
.rchain i{font-style:normal}
.plus{color:var(--dim);margin:0 5px}
/* 事件类型小标:让链条的「形状」(注册表→文件→进程)可以一眼扫出来,
   而不必展开每一条。 */
.ev{display:inline-block;font:600 9.5px var(--sans);color:var(--dim);
  background:var(--inset);border:1px solid var(--line);border-radius:4px;
  padding:0 4px;margin-right:4px;vertical-align:1px}
/* 正常命中 > 0 是误报风险的直接证据,也是整页唯一该用红的地方。为 0 时【什么都不画】
   —— 原来那一列 22 行全是 0。 */
.ben{display:inline-block;margin-left:7px;font:700 10.5px var(--mono);
  color:var(--risk);background:var(--riskbg);border-radius:4px;padding:0 5px}
.re{flex:none;width:64px;text-align:right;font:12px var(--mono);
  font-variant-numeric:tabular-nums;color:var(--ink)}
.re.part{color:var(--warn);font-weight:700}
.rs{flex:none;width:56px;text-align:right;font:12px var(--mono);
  font-variant-numeric:tabular-nums;color:var(--ink)}

.more{padding:2px 20px 14px 84px;font-size:12px}
.mr{display:flex;gap:10px;padding:4px 0;border-top:1px solid var(--line2)}
.mr:first-child{border-top:none}
.mk{flex:none;width:74px;color:var(--dim);font-size:11px}
.mv{flex:1;min-width:0;color:var(--ink2);word-break:break-word}
code{font-family:var(--mono);font-size:11px;background:var(--inset);
  border:1px solid var(--line);border-radius:4px;padding:1px 5px;
  margin:0 4px 3px 0;display:inline-block;color:var(--ink2)}

/* ---- 标记表 ---- */
table{width:100%;border-collapse:collapse;font-size:12.5px}
th,td{text-align:left;padding:8px 12px;border-top:1px solid var(--line2);
  vertical-align:top}
thead th{position:sticky;top:50px;z-index:15;background:var(--inset);
  color:var(--dim);font-size:10.5px;font-weight:750;letter-spacing:.5px;
  border-top:none;border-bottom:1px solid var(--line);white-space:nowrap}
tbody tr:hover td{background:var(--accbg)}
td.cn{font-weight:650;color:var(--ink)}
td.cn s{display:block;text-decoration:none;font:10.5px var(--mono);
  color:var(--dim);margin-top:2px;word-break:break-all}
td.n{text-align:right;font-family:var(--mono);font-variant-numeric:tabular-nums;
  white-space:nowrap;color:var(--ink)}
td.n.z{color:var(--dim)}
td.n.bad{color:var(--risk);font-weight:700}
.sp2,.sp1,.sp0{display:inline-block;font:700 10px var(--sans);border-radius:5px;
  padding:1px 6px;white-space:nowrap;border:1px solid var(--line)}
.sp2{color:var(--ok);background:rgba(4,98,57,.07)}
.sp1{color:var(--mut);background:var(--inset)}
.sp0{color:var(--warn);background:var(--warnbg)}
.lv{display:inline-block;font:700 10px var(--sans);border-radius:5px;
  padding:1px 6px;border:1px solid var(--line);color:var(--mut);
  background:var(--inset);white-space:nowrap}
.lv.hi{color:var(--warn);background:var(--warnbg)}
.dim{color:var(--dim)}
.empty{padding:34px;text-align:center;color:var(--dim);font-size:12.5px}

/* ---- 未生效 / 折叠 ---- */
.cut{display:flex;align-items:center;gap:12px;padding:8px 20px;
  border-top:1px solid var(--line2);font-size:12.5px}
.cutw{flex:none;width:120px;font-size:11px;color:var(--warn)}
details.fold{margin-top:18px;background:var(--pnl);border:1px solid var(--line);
  border-radius:14px;overflow:hidden}
details.fold>summary{cursor:pointer;padding:13px 20px;font-size:13px;
  font-weight:750;color:var(--ink);list-style:none}
details.fold>summary::-webkit-details-marker{display:none}
details.fold>summary::before{content:"\25b8  ";color:var(--dim)}
details.fold[open]>summary::before{content:"\25be  "}
details.fold>summary em{font-style:normal;font-weight:500;font-size:12px;
  color:var(--dim);margin-left:8px}
.kv{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));
  border-top:1px solid var(--line)}
.kv div{display:flex;justify-content:space-between;gap:12px;padding:7px 20px;
  border-bottom:1px solid var(--line2);font-size:12px}
.kv u{text-decoration:none;color:var(--mut)}
.kv b{font-family:var(--mono);color:var(--ink);font-variant-numeric:tabular-nums}
.ft{max-width:1180px;margin:0 auto;padding:0 24px 40px;font-size:11.5px;
  color:var(--dim)}
</style>
</head>
<body>

<header class="top"><div class="tin">
  <div class="bd">&#128737; Bulwark 威胁分析</div>
  <nav>
    <a href="/">&#128737; 控制台</a>
    <a href="/engine" class="on">&#129516; 攻击链引擎</a>
    <a href="/online">&#128225; 在线客户端</a>
    <a href="/support">&#127911; 在线客服</a>
    <a href="/feedback">&#128172; 反馈</a>
    <a href="/api/docs">&#128268; API 文档</a>
    <a href="/about">&#128229; 下载</a>
  </nav>
  <div class="sp"></div>
  <div class="ver" id="ver"></div>
</div></header>

<main class="wrap">

  <section class="card">
    <h1>攻击链组合引擎</h1>
    <p class="lead" id="lead"></p>
    <div class="split">
      <div class="blk">
        <h2>处置能力</h2>
        <div class="caps" id="caps"></div>
      </div>
      <div class="blk">
        <h2>规则是怎么筛出来的</h2>
        <div class="pipe" id="pipe"></div>
      </div>
    </div>
    <div id="notes"></div>
  </section>

  <section class="sec">
    <div class="sh"><h2>生效规则</h2><span class="n" id="liveN"></span>
      <span class="hint">按攻击意图分组 · 点开看匹配条件</span></div>
    <div class="colh">
      <span class="cg">强度</span>
      <span class="cc">动作链（同一进程凑齐即命中）</span>
      <span class="ce">真证据</span>
      <span class="cs">作证</span>
    </div>
    <div id="rules"></div>
  </section>

  <section class="sec">
    <div class="sh"><h2>行为标记</h2><span class="n" id="mkN"></span>
      <input id="mfilt" type="search" placeholder="过滤标记 / 事件 / 条件"></div>
    <table>
      <thead><tr>
        <th>标记</th><th>事件</th><th>严重度</th><th>区分力</th><th>匹配条件</th>
        <th style="text-align:right">恶意样本</th>
        <th style="text-align:right">正常命中</th>
        <th style="text-align:right">被引用</th>
      </tr></thead>
      <tbody id="mkbody"></tbody>
    </table>
  </section>

  <section class="sec" id="cutSec">
    <div class="sh"><h2>未生效</h2><span class="n" id="cutN"></span>
      <span class="hint">服务器挖出来了,但客户端装载时会剔除</span></div>
    <div id="cut"></div>
  </section>

  <details class="fold">
    <summary>构建统计<em>展开备查</em></summary>
    <div class="kv" id="stats"></div>
  </details>

  <details class="fold">
    <summary>阈值与原理<em>写死在 engine_build.py,不是学出来的参数</em></summary>
    <div class="note" id="how"></div>
  </details>

</main>
<footer class="ft" id="foot"></footer>

<script>
const D = /*__DATA__*/null;
const $ = i => document.getElementById(i);
const esc = s => String(s == null ? "" : s).replace(/[&<>"]/g,
  c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));

/* 北京时间。固定 +08:00,不读访问者时区 —— 这是中国服务器的运营台。 */
function cst(iso){
  if(!iso) return "—";
  const ms = Date.parse(iso);
  if(!ms) return String(iso);
  const t = new Date(ms + 8*3600*1000), p = n => (n<10?"0":"")+n;
  return t.getUTCFullYear()+"-"+p(t.getUTCMonth()+1)+"-"+p(t.getUTCDate())
    +" "+p(t.getUTCHours())+":"+p(t.getUTCMinutes());
}

const G = {hard:{s:"拦断", t:"单独命中即可定性,客户端直接拦"},
           strong:{s:"强提示", t:"阻断或给出强提示"},
           ask:{s:"询问", t:"弹窗交给用户确认"}};
/* 一个标记算不算「一份真证据」:区分力 >= 2。判据正本在服务端,这里只做展示。 */
const isEvidence = m => (m.spec == null ? 1 : m.spec) >= 2;
const SPEC = {2:["sp2","可作证据"], 1:["sp1","信息量低"], 0:["sp0","不构成证据"]};

$("ver").textContent = "特征库 " + (D.label || ("v" + D.version));

const live = D.patterns.filter(p => p.live);
const cut  = D.patterns.filter(p => !p.live);

$("lead").textContent =
  "从 " + D.samples + " 个有沙箱行为的恶意样本里数出「哪几个动作凑在一起就足以定性」,"
  + "压缩去重后下发给端点。客户端按单个进程记账,凑齐即把它作为证据喂给裁决流水线 —— "
  + "本引擎不自己下结论。";

/* ---- 处置能力:整页第一件事 --------------------------------------------------
   这是打开这一页最想知道的事,而旧版完全没有:这些规则最强能到哪一档?
   非 hard 档在客户端会被硬钳在「高危阈值 - 1」,单凭自己到不了拦截。 */
(function(){
  const by = {hard:0, strong:0, ask:0};
  live.forEach(p => { if(by[p.g] != null) by[p.g]++; });
  const rows = [
    ["hard",   by.hard,   "可直接阻断", "单独命中即拦"],
    ["strong", by.strong, "阻断或强提示", "落在可疑档"],
    ["ask",    by.ask,    "弹窗询问", "交用户确认"],
  ];
  $("caps").innerHTML = rows.map(r =>
    '<div class="cap ' + (r[1] ? r[0] : "z") + '">'
    + '<b>' + r[1] + '</b><span>' + r[2] + '</span><em>' + r[3] + '</em></div>').join("");
})();

/* ---- 流水线:每段的损耗就地标注,不另起横带 ---- */
(function(){
  const st = D.stats || {};
  const dropObs = (D.issues && (D.issues.unobservable || 0)) || 0;
  const steps = [
    [D.mined, "挖出原始组合", ""],
    [D.dedup, "去重后", D.mined > D.dedup ? ("-" + (D.mined - D.dedup) + " 冗余") : ""],
    [D.served, "下发端点", D.dedup > D.served
      ? ("-" + (D.dedup - D.served) + " 覆盖筛选/证据不足") : ""],
    [D.live, "端点生效", D.served > D.live
      ? ("-" + (D.served - D.live) + " 装载剔除") : "全部装载"],
  ];
  $("pipe").innerHTML = steps.map((s, i) =>
    '<div class="pst' + (i === steps.length-1 ? " fin" : "") + '">'
    + '<b>' + s[0] + '</b><u>' + s[1] + '</u>'
    + (s[2] ? '<i>' + esc(s[2]) + '</i>' : '') + '</div>').join("");
})();

/* ---- 诚实提示。只在真有话要说时出现,最多两条。 ---- */
(function(){
  const out = [];
  const hard = live.filter(p => p.g === "hard").length;
  if(!hard)
    out.push(['warn', "当前没有任何「可直接阻断」档的组合。非 hard 档在端点上被钳在高危阈值"
      + "之下,单凭攻击链命中只会弹窗询问,要到拦截必须有其它独立指标互证 —— "
      + "这是现有语料能支撑的强度,不是配置问题。"]);
  if(!D.benign_active)
    out.push(['warn', "正常软件语料 <b>" + D.benign.total + "</b> 个,其中可用的不足 <b>"
      + D.benign_min + "</b> 个门槛,区分度<b>未参与</b>定级。所以下面「正常命中」列的 0 "
      + "是空分母,不是「不会误伤」的证据。"]);
  $("notes").innerHTML = out.map(o =>
    '<div class="note ' + o[0] + '">' + o[1] + '</div>').join("");
})();

/* ---- 生效规则 ---- */
(function(){
  const byTac = {};
  live.forEach(p => { (byTac[p.tac] = byTac[p.tac] || []).push(p); });
  $("liveN").textContent = live.length + " 条";

  function chain(p){
    return p.mk.map(m => {
      const t = esc(m.cn);
      const ev = m.evcn ? '<span class="ev">' + esc(m.evcn) + '</span>' : '';
      return ev + (m.lv === "high" || m.lv === "critical" ? "<b>"+t+"</b>" : "<i>"+t+"</i>");
    }).join('<span class="plus">+</span>');
  }

  function row(p){
    const g = G[p.g] || {s:p.g, t:""};
    const ev = p.mk.filter(isEvidence).length;
    /* 真证据不足总数时标黄:说明这条组合里有标记只是「搭车」,不构成互证的一份。 */
    const evCls = (ev < p.mk.length) ? "re part" : "re";
    const ben = p.ben ? '<span class="ben">正常命中 ' + p.ben + '</span>' : '';
    const conds = [].concat.apply([], p.mk.map(m => (m.cond||[]).map(c => [m.cn, c])));
    let more = '<div class="mr"><span class="mk">事件</span><span class="mv">'
      + esc(p.mk.map(m => m.evcn).filter((v,i,a) => a.indexOf(v)===i).join(" · "))
      + '</span></div>';
    more += '<div class="mr"><span class="mk">逐个动作</span><span class="mv">'
      + p.mk.map(m => esc(m.cn) + ' <span class="' + SPEC[m.spec==null?1:m.spec][0]
          + '">' + SPEC[m.spec==null?1:m.spec][1] + '</span>').join('<br>')
      + '</span></div>';
    if(conds.length)
      more += '<div class="mr"><span class="mk">匹配条件</span><span class="mv">'
        + conds.map(c => '<code>' + esc(c[1]) + '</code>').join("") + '</span></div>';
    if(p.fam)
      more += '<div class="mr"><span class="mk">作证家族</span><span class="mv dim">'
        + esc(p.fam) + '</span></div>';
    return '<details class="rule"><summary>'
      + '<span class="rg ' + p.g + '" title="' + esc(g.t) + '">' + esc(g.s) + '</span>'
      + '<span class="rchain">' + chain(p) + ben + '</span>'
      + '<span class="' + evCls + '">' + ev + '/' + p.mk.length + '</span>'
      + '<span class="rs">' + p.sup + '</span>'
      + '</summary><div class="more">' + more + '</div></details>';
  }

  const html = D.tactics.filter(t => byTac[t.k]).map(t => {
    const rows = byTac[t.k].slice().sort((a,b) => b.sup - a.sup);
    return '<div class="grp"><b>' + esc(t.t) + '</b><i>' + rows.length + '</i>'
      + '<s>' + esc(t.d) + '</s></div>' + rows.map(row).join("");
  }).join("");
  $("rules").innerHTML = html || '<div class="empty">暂无生效规则</div>';
})();

/* ---- 行为标记 ---- */
(function(){
  const mk = D.mk.slice().sort((a,b) => (b.spec||0)-(a.spec||0) || b.sam-a.sam);
  $("mkN").textContent = mk.length + " 个";
  function tr(m){
    const sp = SPEC[m.spec == null ? 1 : m.spec];
    const cond = (m.cond||[]).length
      ? (m.cond||[]).map(c => '<code>' + esc(c) + '</code>').join("")
      : '<span class="dim">无条件 —— 匹配该类型每一条事件</span>';
    return '<tr><td class="cn">' + esc(m.cn) + '<s>' + esc(m.en) + '</s></td>'
      + '<td>' + esc(m.evcn || "—") + '</td>'
      + '<td><span class="lv' + (m.lv === "high" || m.lv === "critical" ? " hi" : "")
        + '">' + esc(m.lvcn) + '</span></td>'
      + '<td><span class="' + sp[0] + '">' + sp[1] + '</span></td>'
      + '<td>' + cond + '</td>'
      + '<td class="n">' + m.sam + '</td>'
      + '<td class="n ' + (m.ben ? "bad" : "z") + '">' + m.ben + '</td>'
      + '<td class="n ' + (m.uselive ? "" : "z") + '">' + m.uselive + " / " + m.use
        + '</td></tr>';
  }
  const body = $("mkbody");
  body.innerHTML = mk.map(tr).join("");
  $("mfilt").addEventListener("input", e => {
    const q = e.target.value.trim().toLowerCase();
    const rows = mk.filter(m => !q
      || (m.cn + " " + m.en + " " + (m.evcn||"") + " " + (m.cond||[]).join(" "))
           .toLowerCase().indexOf(q) >= 0);
    body.innerHTML = rows.length ? rows.map(tr).join("")
      : '<tr><td colspan="8" class="empty">没有匹配的标记</td></tr>';
  });
})();

/* ---- 未生效 ---- */
(function(){
  const RSN = {redundant:"证据重复", actor:"主体冲突", unobservable:"无法观测",
               single:"单动作"};
  $("cutN").textContent = cut.length + " 条";
  if(!cut.length){ $("cutSec").hidden = true; return; }
  $("cut").innerHTML = cut.map(p => {
    const why = (p.iss||[]).map(i => RSN[i.k] || i.k).join(" · ") || "未标注";
    const ch = p.mk.map(m => m.lv === "high" || m.lv === "critical"
      ? "<b>"+esc(m.cn)+"</b>" : esc(m.cn)).join('<span class="plus">+</span>');
    return '<div class="cut"><span class="cutw">' + esc(why) + '</span>'
      + '<span class="rchain">' + ch + '</span>'
      + '<span class="rs">' + p.sup + '</span></div>';
  }).join("");
})();

/* ---- 构建统计 ---- */
(function(){
  const LB = {
    total_reports:"报告总数", skipped_other_platform:"跳过·非本平台",
    skipped_not_threat:"跳过·非威胁", skipped_no_behaviour:"跳过·无沙箱行为",
    usable_samples:"可用恶意样本", benign_reports:"正常软件报告",
    benign_other_platform:"正常·非本平台", benign_usable:"正常·可用",
    markers_observable:"可观测标记", generic_dropped:"丢弃·泛化",
    benign_generic_dropped:"丢弃·正常泛化", benign_grading_active:"正常分级生效",
    implications:"蕴含关系", markers_effective:"有效标记",
    patterns_mined:"挖出组合", patterns_after_dedup:"去重后",
    patterns_after_cover:"覆盖筛选后", markers_mapped:"已映射标记",
    patterns_kept:"保留组合", benign_capped:"正常语料截断",
    benign_dropped:"正常语料丢弃", stale_patterns_removed:"清理·过期组合",
    stale_markers_removed:"清理·过期标记",
    markers_with_context:"带命中上下文的标记", markers_derived:"推导出条件的标记",
    markers_derived_new:"推导·手写表未覆盖", hand_rules_mismapped:"手写表·填错字段",
    markers_spec_ok:"区分力·可作证据", markers_spec_weak:"区分力·信息量低",
    markers_spec_none:"区分力·不构成证据",
    patterns_dropped_no_evidence:"丢弃·真证据不足两份",
    patterns_dropped_actor_conflict:"丢弃·主体冲突", patterns_dropped_redundant:"丢弃·证据重复",
    patterns_dropped_unobservable:"丢弃·标记不可观测"
  };
  const s = D.stats || {};
  $("stats").innerHTML = Object.keys(s).map(k =>
    '<div><u>' + esc(LB[k] || k) + '</u><b>' + s[k] + '</b></div>').join("");
})();

$("how").innerHTML =
  "组合的定性强度由三件事决定,三者都要够:<b>动作数</b>(链条多长) × <b>最高严重度</b>"
  + " × <b>支持度</b>(多少真实样本作证)。"
  + "另有一道<b>互证闸门</b>:一条组合至少要有两个「区分力可作证据」的标记才下发 —— "
  + "只有一个真判据加一个恒真项(如「任意 svchost 启动」「未签名进程」)不算互证,"
  + "而客户端会把命中登记为硬指标,那等于把软信号提拔成处置依据。"
  + "正常软件语料至少需要 <b>" + D.benign_min + "</b> 个才启用反向校验,当前 <b>"
  + D.benign.total + "</b> 个(带标记 " + D.benign.with_markers + " 个、有签名 "
  + D.benign.signed + " 个)," + (D.benign_active ? "已启用。" : "尚未达到阈值。");

$("foot").innerHTML =
  "特征库 " + esc(D.label || D.version) + " · 构建于 " + cst(D.built_at) + " 北京时间"
  + " · 下发接口 /v1/engine/manifest 与 /v1/engine/patterns"
  + " · 本页只读,不触发任何构建";
</script>
</body>
</html>
'''


# ---- /support 访客页 --------------------------------------------------------- #
#
# 版式只守三条,和 /engine 那一版是同一套取舍:
#   1. 【一列,一条时间线】。客服对话天然是线性的,任何分栏都只会把注意力从"对方
#      说了什么"上引开。
#   2. 【不给每条信息配一条自己的横带】。系统提示是居中的小灰字,不是一条带底色的
#      通告条 —— 上一轮两次被说"乱",共同原因就是横带太多。
#   3. 【只有一处会用红】:发送失败。附件大小、类型这些说明是灰字,它们是常识不是
#      警告。
#
# 配置由服务端注入 /*__CFG__*/null 处(上限、客服名),前端据此提示,而不是把上限
# 写死在两个地方 —— 那样改了配置页面还在说旧数字。
_SUPPORT_PAGE = r'''<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>在线客服 · 磐垒</title>
<style>
:root{
  --bwbg:#edf0f5; --bwpnl:#ffffff; --bwsoft:#f9fafb;
  --bwln:#e4e7ec; --bwln2:#f2f4f7;
  --bwink:#101828; --bwink2:#344054; --bwmut:#667085; --bwdim:#98a2b3;
  --bwac:#2563eb; --bwmal:#d92d20; --bwok:#067647;
  --bwmono:"SFMono-Regular","Cascadia Mono",Consolas,Menlo,monospace;
  --bwsans:-apple-system,"Segoe UI",Roboto,"Microsoft YaHei",system-ui,sans-serif;
}
*{box-sizing:border-box}
html,body{margin:0}
body{background:var(--bwbg);color:var(--bwink);font:14px/1.65 var(--bwsans);
  -webkit-font-smoothing:antialiased}
body::before{content:"";position:fixed;inset:0;z-index:-2;pointer-events:none;background:
  repeating-linear-gradient(0deg,transparent 0 47px,rgba(16,24,40,.03) 47px 48px),
  repeating-linear-gradient(90deg,transparent 0 47px,rgba(16,24,40,.03) 47px 48px)}
body::after{content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;
  background:radial-gradient(1200px 520px at 50% -12%,rgba(37,99,235,.07),transparent 70%)}
a{color:var(--bwac);text-decoration:none}

.bwrail{position:sticky;top:0;z-index:60;background:rgba(255,255,255,.9);
  backdrop-filter:blur(14px);border-bottom:1px solid var(--bwln)}
.bwrail .in{max-width:1440px;margin:0 auto;display:flex;align-items:center;gap:16px;
  padding:10px 22px}
.bwbrand{display:flex;align-items:center;gap:10px;text-decoration:none;flex:none}
.bwbrand .mk{width:30px;height:30px;flex:none;display:grid;place-items:center;
  background:var(--bwac);color:#fff;font-size:15px;
  clip-path:polygon(22% 0,100% 0,100% 78%,78% 100%,0 100%,0 22%)}
.bwbrand b{display:block;font-size:13.5px;font-weight:800;letter-spacing:2.2px;
  color:var(--bwink);line-height:1.1}
.bwbrand s{display:block;text-decoration:none;font-size:9px;color:var(--bwmut);
  letter-spacing:1.3px;margin-top:2px}
.bwgrow{flex:1}
.bwnav{display:flex;align-items:stretch;gap:2px;overflow-x:auto;
  scrollbar-width:none;-ms-overflow-style:none}
.bwnav::-webkit-scrollbar{display:none}
.bwnav a{position:relative;display:inline-flex;align-items:center;gap:7px;
  padding:9px 13px;font-size:12.5px;font-weight:600;letter-spacing:.5px;
  color:var(--bwmut);white-space:nowrap}
.bwnav a::after{content:"";position:absolute;left:11px;right:11px;bottom:-1px;height:2px;
  background:var(--bwac);opacity:0;transition:opacity .16s}
.bwnav a:hover{color:var(--bwink)}
.bwnav a:hover::after{opacity:.5}
.bwnav a.on{color:var(--bwac)}
.bwnav a.on::after{opacity:1}
.bwnav a .i{font-size:13px;line-height:1}
@media(max-width:640px){.bwrail .in{padding:9px 14px}.bwbrand s{display:none}}

/* ---- 对话壳 ---- */
.wrap{max-width:780px;margin:0 auto;padding:22px 20px 28px;
  display:flex;flex-direction:column;min-height:calc(100vh - 52px)}
.hd{display:flex;align-items:baseline;gap:10px;margin-bottom:4px}
.hd h1{margin:0;font-size:19px;font-weight:800;letter-spacing:-.2px}
.hd .st{font-size:11.5px;color:var(--bwmut);margin-left:auto;display:flex;
  align-items:center;gap:6px}
.dot{width:7px;height:7px;border-radius:50%;background:var(--bwdim);display:inline-block}
.dot.on{background:var(--bwok);box-shadow:0 0 0 3px rgba(6,118,71,.15)}
.lead{margin:0 0 14px;font-size:12.5px;color:var(--bwmut)}

.thread{flex:1;background:var(--bwpnl);border:1px solid var(--bwln);
  padding:16px 18px;overflow-y:auto;max-height:60vh;min-height:260px}
.m{display:flex;flex-direction:column;margin-bottom:14px;max-width:76%}
.m:last-child{margin-bottom:2px}
.m.me{margin-left:auto;align-items:flex-end}
.m .bd{padding:9px 12px;font-size:13.5px;line-height:1.6;white-space:pre-wrap;
  word-break:break-word;background:var(--bwsoft);border:1px solid var(--bwln)}
.m.me .bd{background:var(--bwac);border-color:var(--bwac);color:#fff}
.m .ts{font:10.5px var(--bwmono);color:var(--bwdim);margin-top:4px}
.m .who{font-size:10.5px;font-weight:700;color:var(--bwmut);margin-bottom:4px;
  letter-spacing:.6px}
/* 系统提示不给横带:居中小灰字。它每条对话都会出现,做成通告条就是一整页噪音。 */
.m.sys{max-width:100%;align-items:center;margin:10px 0 16px}
.m.sys .bd{background:none;border:none;color:var(--bwdim);font-size:12px;
  text-align:center;padding:0}
/* 附件。缩略图固定高度裁切,否则一张竖屏手机截图能把整条消息顶到几百像素高。 */
.fx{display:flex;flex-wrap:wrap;gap:7px;margin-top:7px}
.fx a{display:block;line-height:0;border:1px solid var(--bwln);overflow:hidden}
.fx img{width:132px;height:92px;object-fit:cover;display:block;background:var(--bwln2)}
.fx video{width:240px;max-height:180px;display:block;background:#000}
.empty{color:var(--bwdim);font-size:12.5px;text-align:center;padding:40px 0}

/* ---- 输入区 ---- */
.comp{background:var(--bwpnl);border:1px solid var(--bwln);border-top:none;
  padding:11px 12px}
.q{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:8px}
.q span{display:inline-flex;align-items:center;gap:6px;font-size:11.5px;
  background:var(--bwsoft);border:1px solid var(--bwln);padding:3px 8px;
  color:var(--bwink2)}
.q span i{font-style:normal;color:var(--bwdim);font-family:var(--bwmono)}
.q span b{cursor:pointer;color:var(--bwdim);font-weight:700}
.q span b:hover{color:var(--bwmal)}
.rw{display:flex;align-items:flex-end;gap:8px}
.clip{flex:none;width:38px;height:38px;display:grid;place-items:center;cursor:pointer;
  border:1px solid var(--bwln);background:var(--bwsoft);font-size:16px;user-select:none}
.clip:hover{border-color:var(--bwac)}
textarea{flex:1;resize:none;min-height:38px;max-height:140px;padding:9px 11px;
  border:1px solid var(--bwln);background:var(--bwbg);color:var(--bwink);
  font:14px/1.5 var(--bwsans);outline:none}
textarea:focus{border-color:var(--bwac);box-shadow:0 0 0 3px rgba(37,99,235,.12)}
button{flex:none;padding:0 18px;height:38px;background:var(--bwac);color:#fff;
  border:none;font:700 13px/1 var(--bwsans);letter-spacing:1px;cursor:pointer}
button:hover{filter:brightness(1.08)}
button:disabled{background:var(--bwdim);cursor:default;filter:none}
.hint{margin-top:8px;font-size:11.5px;color:var(--bwdim)}
.hint.bad{color:var(--bwmal)}
.ft{margin:12px 0 0;font-size:11.5px;color:var(--bwdim)}
</style>
</head>
<body>
<div class="bwrail"><div class="in">
<a class="bwbrand" href="/" title="返回控制台"><span class="mk">&#128737;</span>
<span><b>BULWARK</b><s>THREAT ANALYSIS CONSOLE</s></span></a>
<div class="bwgrow"></div>
<nav class="bwnav">
<a href="/"><span class="i">&#128737;</span>控制台</a>
<a href="/engine"><span class="i">&#129516;</span>攻击链引擎</a>
<a href="/online"><span class="i">&#128225;</span>在线客户端</a>
<a href="/support" class="on"><span class="i">&#127911;</span>在线客服</a>
<a href="/feedback"><span class="i">&#128172;</span>反馈</a>
<a href="/api/docs"><span class="i">&#128268;</span>API 文档</a>
<a href="/about"><span class="i">&#128229;</span>下载</a>
</nav>
</div></div>

<div class="wrap">
  <div class="hd">
    <h1>在线客服</h1>
    <div class="st"><span class="dot" id="dot"></span><span id="stx">连接中</span></div>
  </div>
  <p class="lead" id="lead"></p>
  <div class="thread" id="thread"><div class="empty">正在载入对话…</div></div>
  <div class="comp">
    <div class="q" id="q"></div>
    <div class="rw">
      <label class="clip" for="f" title="发送图片或视频">&#128206;</label>
      <input type="file" id="f" multiple hidden
        accept="image/png,image/jpeg,image/gif,image/webp,video/mp4,video/quicktime,video/webm">
      <textarea id="box" rows="1" placeholder="描述你遇到的问题，回车发送"></textarea>
      <button id="send">发送</button>
    </div>
    <div class="hint" id="hint"></div>
  </div>
  <!-- 客服台入口。放一行小灰字而不是一个按钮:对访客它是噪音,对值守的人它省掉
       记一个 URL。这条链接本身不泄露任何东西 —— /support/admin 需要口令,没配
       口令时它连页面都不出。 -->
  <p class="ft">值守人员入口：<a href="/support/admin">客服台</a></p>
</div>

<script>
const CFG = /*__CFG__*/null;
const $ = id => document.getElementById(id);
let lastId = 0, pending = [], sending = false, polling = false;

/* 北京时间。固定 +08:00,不读访问者时区 —— 服务器时区是 UTC,而用它的人在中国。 */
function hhmm(iso){
  const ms = Date.parse(iso);
  if(!ms) return "";
  const t = new Date(ms + 8*3600*1000), p = n => (n<10?"0":"")+n;
  return p(t.getUTCHours())+":"+p(t.getUTCMinutes());
}
function mb(n){ return (n/1048576).toFixed(n >= 10485760 ? 0 : 1) + " MB"; }

$("lead").textContent = "发送文字、截图或录屏都可以。图片单个上限 "
  + CFG.image_mb + " MB，视频 " + CFG.video_mb + " MB，一次最多 "
  + CFG.max_files + " 个。对话内容与附件会在 " + CFG.retention_days
  + " 天后自动删除。"
  + (CFG.staffed ? "" : "当前客服台尚未配置值守口令，留言会先保存下来。");

/* 三种状态,措辞各自对应一个事实,不含糊:
     有凭证 + 心跳新鲜 -> 客服在线
     有凭证 + 无心跳    -> 留言后会尽快回复
     没有凭证          -> 留言模式（没人能回，就不说会回） */
function statusText(online){
  if(!CFG.staffed) return "留言模式";
  return online ? "客服在线" : "留言后客服会尽快回复";
}

function status(on, text){
  $("dot").className = "dot" + (on ? " on" : "");
  $("stx").textContent = text;
}
function hint(text, bad){
  $("hint").textContent = text || "";
  $("hint").className = "hint" + (bad ? " bad" : "");
}

/* 消息一律用 textContent 落地,不拼 innerHTML。正文是用户和客服两边都能写的自由
   文本,任何一次 innerHTML 拼接都是一条存储型 XSS 的入口。 */
function render(rows){
  const th = $("thread");
  if(th.querySelector(".empty")) th.textContent = "";
  rows.forEach(m => {
    const d = document.createElement("div");
    d.className = "m " + (m.who === "visitor" ? "me" : (m.who === "system" ? "sys" : ""));
    if(m.who === "agent"){
      const w = document.createElement("div");
      w.className = "who"; w.textContent = CFG.agent_name;
      d.appendChild(w);
    }
    if(m.body){
      const b = document.createElement("div");
      b.className = "bd"; b.textContent = m.body;
      d.appendChild(b);
    }
    if(m.files && m.files.length){
      const fx = document.createElement("div");
      fx.className = "fx";
      m.files.forEach(f => {
        const url = "/support/media/" + encodeURIComponent(f.name);
        if(f.kind === "video"){
          const v = document.createElement("video");
          v.src = url; v.controls = true; v.preload = "metadata";
          fx.appendChild(v);
        } else {
          const a = document.createElement("a");
          a.href = url; a.target = "_blank"; a.rel = "noopener noreferrer";
          const i = document.createElement("img");
          i.src = url; i.loading = "lazy"; i.alt = "附件";
          a.appendChild(i); fx.appendChild(a);
        }
      });
      d.appendChild(fx);
    }
    if(m.who !== "system"){
      const t = document.createElement("div");
      t.className = "ts"; t.textContent = hhmm(m.at);
      d.appendChild(t);
    }
    th.appendChild(d);
    if(m.id > lastId) lastId = m.id;
  });
  th.scrollTop = th.scrollHeight;
}

function drawQueue(){
  const q = $("q"); q.textContent = "";
  pending.forEach((p, i) => {
    const s = document.createElement("span");
    s.appendChild(document.createTextNode(p.label));
    const it = document.createElement("i"); it.textContent = mb(p.size);
    const x = document.createElement("b"); x.textContent = "\u00d7";
    x.onclick = () => { pending.splice(i,1); drawQueue(); };
    s.appendChild(it); s.appendChild(x); q.appendChild(s);
  });
}

async function boot(){
  try{
    const r = await fetch("/support/api/session", {credentials:"same-origin"});
    const d = await r.json();
    if(!d.ok){ status(false, "暂不可用"); hint(d.error || "服务未启用", true); return; }
    $("thread").textContent = "";
    if(d.messages && d.messages.length) render(d.messages);
    else {
      render([{id:0, at:"", who:"system", body:CFG.greeting, files:[]}]);
      lastId = 0;
    }
    status(!!d.agent_online, statusText(!!d.agent_online));
    poll();
  }catch(e){ status(false, "连接失败"); hint("网络异常，请刷新重试", true); }
}

/* 长轮询。服务端最多挂 CFG.poll_wait 秒;没有新消息就空手回来,立刻再挂上去。
   出错时退避 3 秒再试,避免服务重启期间前端把自己变成压测工具。 */
async function poll(){
  if(polling) return;
  polling = true;
  for(;;){
    try{
      const r = await fetch("/support/api/poll?after=" + lastId, {credentials:"same-origin"});
      if(r.status === 409){ polling = false; return boot(); }   /* 会话已过期 */
      const d = await r.json();
      if(d.ok && d.messages && d.messages.length) render(d.messages);
      if(d.ok) status(!!d.agent_online, statusText(!!d.agent_online));
    }catch(e){
      status(false, "重连中");
      await new Promise(s => setTimeout(s, 3000));
    }
  }
}

async function upload(file){
  const q = "?name=" + encodeURIComponent(file.name || "file");
  const r = await fetch("/support/api/upload" + q, {
    method:"POST", credentials:"same-origin", body:file,
    headers:{"Content-Type":"application/octet-stream"}});
  const d = await r.json();
  if(!d.ok) throw new Error(d.error || "上传失败");
  return d.name;
}

$("f").onchange = async ev => {
  const files = Array.from(ev.target.files || []);
  ev.target.value = "";
  for(const f of files){
    if(pending.length >= CFG.max_files){ hint("一次最多 " + CFG.max_files + " 个附件", true); break; }
    const isVid = /^video\//.test(f.type || "");
    const cap = (isVid ? CFG.video_mb : CFG.image_mb) * 1048576;
    if(f.size > cap){ hint(f.name + " 超过 " + (isVid?CFG.video_mb:CFG.image_mb) + " MB", true); continue; }
    const slot = {label:f.name.slice(0,28), size:f.size, name:null};
    pending.push(slot); drawQueue(); hint("正在上传 " + slot.label + " …");
    try{
      slot.name = await upload(f);
      hint("");
    }catch(e){
      pending.splice(pending.indexOf(slot), 1); drawQueue();
      hint(e.message, true);
    }
  }
  drawQueue();
};

async function send(){
  if(sending) return;
  const box = $("box");
  const body = box.value.trim();
  const files = pending.filter(p => p.name).map(p => p.name);
  if(!body && !files.length){ hint("请输入内容或选择要发送的文件", true); return; }
  if(body.length > CFG.max_chars){ hint("内容超过 " + CFG.max_chars + " 字", true); return; }
  sending = true; $("send").disabled = true; hint("");
  try{
    const r = await fetch("/support/api/send", {
      method:"POST", credentials:"same-origin",
      headers:{"Content-Type":"application/json"},
      body: JSON.stringify({body:body, files:files})});
    const d = await r.json();
    if(!d.ok){ hint(d.error || "发送失败", true); }
    else{
      box.value = ""; pending = []; drawQueue();
      if(d.messages) render(d.messages);
    }
  }catch(e){ hint("发送失败：" + e.message, true); }
  sending = false; $("send").disabled = false; box.focus();
}

$("send").onclick = send;
$("box").addEventListener("keydown", e => {
  if(e.key === "Enter" && !e.shiftKey){ e.preventDefault(); send(); }
});
$("box").addEventListener("input", e => {
  e.target.style.height = "auto";
  e.target.style.height = Math.min(140, e.target.scrollHeight) + "px";
});
boot();
</script>
</body>
</html>
'''


# ---- /support/admin 客服台 ---------------------------------------------------- #
#
# 两栏:左边会话列表(带未读数),右边一条时间线。和访客页共用同一套气泡样式 ——
# 同一种东西在同一个产品里不该有两种排法。
_SUPPORT_ADMIN_PAGE = r'''<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>客服台 · 磐垒</title>
<style>
:root{
  --bwbg:#edf0f5; --bwpnl:#ffffff; --bwsoft:#f9fafb;
  --bwln:#e4e7ec; --bwln2:#f2f4f7;
  --bwink:#101828; --bwink2:#344054; --bwmut:#667085; --bwdim:#98a2b3;
  --bwac:#2563eb; --bwmal:#d92d20; --bwsus:#b54708; --bwok:#067647;
  --bwmono:"SFMono-Regular","Cascadia Mono",Consolas,Menlo,monospace;
  --bwsans:-apple-system,"Segoe UI",Roboto,"Microsoft YaHei",system-ui,sans-serif;
}
*{box-sizing:border-box}
html,body{margin:0}
body{background:var(--bwbg);color:var(--bwink);font:14px/1.65 var(--bwsans);
  -webkit-font-smoothing:antialiased}
a{color:var(--bwac);text-decoration:none}

.bwrail{position:sticky;top:0;z-index:60;background:rgba(255,255,255,.9);
  backdrop-filter:blur(14px);border-bottom:1px solid var(--bwln)}
.bwrail .in{max-width:1440px;margin:0 auto;display:flex;align-items:center;gap:16px;
  padding:10px 22px}
.bwbrand{display:flex;align-items:center;gap:10px;flex:none}
.bwbrand .mk{width:30px;height:30px;flex:none;display:grid;place-items:center;
  background:var(--bwac);color:#fff;font-size:15px;
  clip-path:polygon(22% 0,100% 0,100% 78%,78% 100%,0 100%,0 22%)}
.bwbrand b{display:block;font-size:13.5px;font-weight:800;letter-spacing:2.2px;
  color:var(--bwink);line-height:1.1}
.bwbrand s{display:block;text-decoration:none;font-size:9px;color:var(--bwmut);
  letter-spacing:1.3px;margin-top:2px}
.bwgrow{flex:1}
.bwnav{display:flex;gap:2px}
.bwnav a{display:inline-flex;align-items:center;gap:7px;padding:9px 13px;
  font-size:12.5px;font-weight:600;color:var(--bwmut);white-space:nowrap}
.bwnav a.on{color:var(--bwac);box-shadow:inset 0 -2px 0 var(--bwac)}
.bwnav a:hover{color:var(--bwink)}
/* 导航图标。缺这一条不会报错也不会渲染失败 —— emoji 只是跟着正文字号走,比其余
   页面的顶栏略小一点,是那种没人会去查的差异。「无规则类」检查就是为这种东西存在的。 */
.bwnav a .i{font-size:13px;line-height:1}

.wrap{max-width:1440px;margin:0 auto;padding:16px 22px 24px}
.bwstats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,200px));
  justify-content:start;gap:12px;margin:0 0 16px}
.bwstat{background:var(--bwpnl);border:1px solid var(--bwln);
  border-top:2px solid var(--bwac);padding:11px 14px}
.bwstat .v{font-family:var(--bwmono);font-size:23px;font-weight:800;line-height:1.05;
  font-variant-numeric:tabular-nums}
.bwstat .k{font-size:10.5px;color:var(--bwmut);margin-top:3px;letter-spacing:1px}
.bwstat.sus{border-top-color:var(--bwsus)}.bwstat.sus .v{color:var(--bwsus)}
.bwstat.ok{border-top-color:var(--bwok)}.bwstat.ok .v{color:var(--bwok)}

.cols{display:grid;grid-template-columns:320px 1fr;gap:14px;align-items:start}
@media(max-width:900px){.cols{grid-template-columns:1fr}}
.list{background:var(--bwpnl);border:1px solid var(--bwln);max-height:74vh;
  overflow-y:auto}
.cv{display:block;width:100%;text-align:left;background:none;border:none;
  border-bottom:1px solid var(--bwln2);padding:11px 13px;cursor:pointer;font:inherit}
.cv:hover{background:rgba(37,99,235,.04)}
.cv.on{background:rgba(37,99,235,.08);box-shadow:inset 2px 0 0 var(--bwac)}
.cv .t{display:flex;align-items:baseline;gap:8px}
.cv .t b{font-size:12.5px;font-weight:700;color:var(--bwink);font-family:var(--bwmono)}
.cv .t i{font-style:normal;font:10.5px var(--bwmono);color:var(--bwdim);margin-left:auto}
.cv .p{font-size:12px;color:var(--bwmut);margin-top:3px;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap}
.cv .n{display:inline-block;min-width:17px;text-align:center;background:var(--bwmal);
  color:#fff;font:700 10px var(--bwmono);padding:1px 5px;border-radius:9px}
.cv.done .t b{color:var(--bwdim)}
.pane{background:var(--bwpnl);border:1px solid var(--bwln);display:flex;
  flex-direction:column;min-height:420px}
.pane .ph{display:flex;align-items:center;gap:10px;padding:11px 15px;
  border-bottom:1px solid var(--bwln)}
.pane .ph b{font:700 12.5px var(--bwmono);color:var(--bwink)}
.pane .ph span{font-size:11.5px;color:var(--bwmut)}
.pane .ph .sp{flex:1}
.pane .ph button{background:none;border:1px solid var(--bwln);color:var(--bwink2);
  padding:5px 11px;font:600 12px var(--bwsans);cursor:pointer}
.pane .ph button:hover{border-color:var(--bwac);color:var(--bwac)}
.thread{flex:1;padding:15px 18px;overflow-y:auto;max-height:56vh;min-height:200px}
.m{display:flex;flex-direction:column;margin-bottom:14px;max-width:76%}
.m.me{margin-left:auto;align-items:flex-end}
.m .bd{padding:9px 12px;font-size:13.5px;line-height:1.6;white-space:pre-wrap;
  word-break:break-word;background:var(--bwsoft);border:1px solid var(--bwln)}
.m.me .bd{background:var(--bwac);border-color:var(--bwac);color:#fff}
.m .ts{font:10.5px var(--bwmono);color:var(--bwdim);margin-top:4px}
.m.sys{max-width:100%;align-items:center;margin:10px 0 16px}
.m.sys .bd{background:none;border:none;color:var(--bwdim);font-size:12px;padding:0}
.fx{display:flex;flex-wrap:wrap;gap:7px;margin-top:7px}
.fx a{display:block;line-height:0;border:1px solid var(--bwln);overflow:hidden}
.fx img{width:132px;height:92px;object-fit:cover;display:block;background:var(--bwln2)}
.fx video{width:240px;max-height:180px;display:block;background:#000}
.empty{color:var(--bwdim);font-size:12.5px;text-align:center;padding:52px 0}
.comp{border-top:1px solid var(--bwln);padding:11px 12px}
.q{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:8px}
.q span{display:inline-flex;align-items:center;gap:6px;font-size:11.5px;
  background:var(--bwsoft);border:1px solid var(--bwln);padding:3px 8px}
.q span b{cursor:pointer;color:var(--bwdim);font-weight:700}
.rw{display:flex;align-items:flex-end;gap:8px}
.clip{flex:none;width:38px;height:38px;display:grid;place-items:center;cursor:pointer;
  border:1px solid var(--bwln);background:var(--bwsoft);font-size:16px}
.clip:hover{border-color:var(--bwac)}
textarea{flex:1;resize:none;min-height:38px;max-height:140px;padding:9px 11px;
  border:1px solid var(--bwln);background:var(--bwbg);color:var(--bwink);
  font:14px/1.5 var(--bwsans);outline:none}
textarea:focus{border-color:var(--bwac);box-shadow:0 0 0 3px rgba(37,99,235,.12)}
button.snd{flex:none;padding:0 18px;height:38px;background:var(--bwac);color:#fff;
  border:none;font:700 13px/1 var(--bwsans);letter-spacing:1px;cursor:pointer}
button.snd:disabled{background:var(--bwdim);cursor:default}
.hint{margin-top:8px;font-size:11.5px;color:var(--bwdim)}
.hint.bad{color:var(--bwmal)}
.note{margin:0 0 14px;font-size:12px;color:var(--bwmut)}
</style>
</head>
<body>
<div class="bwrail"><div class="in">
<a class="bwbrand" href="/"><span class="mk">&#128737;</span>
<span><b>BULWARK</b><s>THREAT ANALYSIS CONSOLE</s></span></a>
<div class="bwgrow"></div>
<nav class="bwnav">
<a href="/"><span class="i">&#128737;</span>控制台</a>
<a href="/support/admin" class="on"><span class="i">&#127911;</span>客服台</a>
<a href="/feedback"><span class="i">&#128172;</span>反馈</a>
<a href="/online"><span class="i">&#128225;</span>在线客户端</a>
</nav>
</div></div>

<div class="wrap">
  <div class="bwstats" id="stats"></div>
  <p class="note" id="note"></p>
  <div class="cols">
    <div class="list" id="list"></div>
    <div class="pane">
      <div class="ph">
        <b id="pt">未选择会话</b><span id="pm"></span><div class="sp"></div>
        <button id="close" hidden>结束会话</button>
      </div>
      <div class="thread" id="thread"><div class="empty">从左侧选择一条会话</div></div>
      <div class="comp">
        <div class="q" id="q"></div>
        <div class="rw">
          <label class="clip" for="f" title="发送图片或视频">&#128206;</label>
          <input type="file" id="f" multiple hidden
            accept="image/png,image/jpeg,image/gif,image/webp,video/mp4,video/quicktime,video/webm">
          <textarea id="box" rows="1" placeholder="回复访客，回车发送"></textarea>
          <button class="snd" id="send" disabled>发送</button>
        </div>
        <div class="hint" id="hint"></div>
      </div>
    </div>
  </div>
</div>

<script>
const CFG = /*__CFG__*/null;
const $ = id => document.getElementById(id);
let cur = null, lastId = 0, cursor = 0, pending = [], convs = [];

function hhmm(iso){
  const ms = Date.parse(iso);
  if(!ms) return "";
  const t = new Date(ms + 8*3600*1000), p = n => (n<10?"0":"")+n;
  return p(t.getUTCHours())+":"+p(t.getUTCMinutes());
}
function rel(iso){
  const ms = Date.parse(iso);
  if(!ms) return "";
  const s = Math.floor((Date.now() - ms) / 1000);
  if(s < 60) return "刚刚";
  if(s < 3600) return Math.floor(s/60) + " 分钟前";
  if(s < 86400) return Math.floor(s/3600) + " 小时前";
  return Math.floor(s/86400) + " 天前";
}
function hint(t, bad){ $("hint").textContent = t || "";
  $("hint").className = "hint" + (bad ? " bad" : ""); }

function drawStats(s){
  const cells = [["待回复", s.waiting, s.waiting ? "sus" : ""],
                 ["进行中", s.open, "ok"], ["会话总数", s.conversations, ""],
                 ["消息总数", s.messages, ""]];
  const box = $("stats"); box.textContent = "";
  cells.forEach(c => {
    const d = document.createElement("div"); d.className = "bwstat " + c[2];
    const v = document.createElement("div"); v.className = "v"; v.textContent = c[1];
    const k = document.createElement("div"); k.className = "k"; k.textContent = c[0];
    d.appendChild(v); d.appendChild(k); box.appendChild(d);
  });
  $("note").textContent = "对话与附件在 " + CFG.retention_days
    + " 天后由定时任务整体删除，包括访客上传的图片和视频。附件目录已用 "
    + s.media_mb + " MB。";
}

function drawList(){
  const box = $("list"); box.textContent = "";
  if(!convs.length){
    const e = document.createElement("div"); e.className = "empty";
    e.textContent = "还没有访客发起会话"; box.appendChild(e); return;
  }
  convs.forEach(c => {
    const b = document.createElement("button");
    b.className = "cv" + (c.token === cur ? " on" : "")
      + (c.status === "closed" ? " done" : "");
    const t = document.createElement("div"); t.className = "t";
    const nm = document.createElement("b"); nm.textContent = c.ip;
    t.appendChild(nm);
    if(c.unread > 0){
      const n = document.createElement("span"); n.className = "n";
      n.textContent = c.unread; t.appendChild(n);
    }
    const ago = document.createElement("i"); ago.textContent = rel(c.last_at);
    t.appendChild(ago);
    const p = document.createElement("div"); p.className = "p";
    p.textContent = c.preview || "（仅附件）";
    b.appendChild(t); b.appendChild(p);
    b.onclick = () => open(c.token);
    box.appendChild(b);
  });
}

function render(rows, reset){
  const th = $("thread");
  if(reset){ th.textContent = ""; lastId = 0; }
  if(th.querySelector(".empty")) th.textContent = "";
  rows.forEach(m => {
    const d = document.createElement("div");
    d.className = "m " + (m.who === "agent" ? "me" : (m.who === "system" ? "sys" : ""));
    if(m.body){
      const b = document.createElement("div");
      b.className = "bd"; b.textContent = m.body; d.appendChild(b);
    }
    if(m.files && m.files.length){
      const fx = document.createElement("div"); fx.className = "fx";
      m.files.forEach(f => {
        const url = "/support/media/" + encodeURIComponent(f.name);
        if(f.kind === "video"){
          const v = document.createElement("video");
          v.src = url; v.controls = true; v.preload = "metadata"; fx.appendChild(v);
        } else {
          const a = document.createElement("a");
          a.href = url; a.target = "_blank"; a.rel = "noopener noreferrer";
          const i = document.createElement("img");
          i.src = url; i.loading = "lazy"; i.alt = "附件";
          a.appendChild(i); fx.appendChild(a);
        }
      });
      d.appendChild(fx);
    }
    if(m.who !== "system"){
      const t = document.createElement("div");
      t.className = "ts"; t.textContent = hhmm(m.at); d.appendChild(t);
    }
    th.appendChild(d);
    if(m.id > lastId) lastId = m.id;
  });
  th.scrollTop = th.scrollHeight;
}

async function open(token){
  cur = token; pending = []; drawQueue(); hint("");
  const c = convs.filter(x => x.token === token)[0] || {};
  $("pt").textContent = c.ip || "会话";
  $("pm").textContent = (c.agent || "") + " · " + (c.page || "") + " · " + (c.msgs || 0) + " 条";
  $("close").hidden = false;
  $("close").textContent = c.status === "closed" ? "重新打开" : "结束会话";
  $("send").disabled = false;
  drawList();
  const r = await fetch("/support/admin/api/thread?token=" + encodeURIComponent(token),
                        {credentials:"same-origin"});
  const d = await r.json();
  if(d.ok) render(d.messages, true);
  refresh();
}

function drawQueue(){
  const q = $("q"); q.textContent = "";
  pending.forEach((p, i) => {
    const s = document.createElement("span");
    s.appendChild(document.createTextNode(p.label));
    const x = document.createElement("b"); x.textContent = "\u00d7";
    x.onclick = () => { pending.splice(i,1); drawQueue(); };
    s.appendChild(x); q.appendChild(s);
  });
}

async function refresh(){
  const r = await fetch("/support/admin/api/list", {credentials:"same-origin"});
  const d = await r.json();
  if(!d.ok) return;
  convs = d.conversations; drawStats(d.stats); drawList();
}

/* 客服台的长轮询挂在「全部会话的最大消息 id」上:任何会话来了新消息都会醒。
   醒来后只刷新列表,当前会话的消息再单独取一次 —— 这样列表的未读数和红点是活的,
   不必为每条会话各挂一个连接。 */
async function poll(){
  for(;;){
    try{
      const r = await fetch("/support/admin/api/poll?after=" + cursor,
                            {credentials:"same-origin"});
      const d = await r.json();
      if(d.ok){
        cursor = d.cursor;
        if(d.hit){
          await refresh();
          if(cur){
            const t = await fetch("/support/admin/api/thread?token="
              + encodeURIComponent(cur) + "&after=" + lastId, {credentials:"same-origin"});
            const td = await t.json();
            if(td.ok && td.messages.length) render(td.messages, false);
          }
        }
      }
    }catch(e){ await new Promise(s => setTimeout(s, 3000)); }
  }
}

async function upload(file){
  const q = "?name=" + encodeURIComponent(file.name || "file")
          + "&token=" + encodeURIComponent(cur);
  const r = await fetch("/support/admin/api/upload" + q, {
    method:"POST", credentials:"same-origin", body:file,
    headers:{"Content-Type":"application/octet-stream"}});
  const d = await r.json();
  if(!d.ok) throw new Error(d.error || "上传失败");
  return d.name;
}

$("f").onchange = async ev => {
  const files = Array.from(ev.target.files || []); ev.target.value = "";
  if(!cur){ hint("先选择一条会话", true); return; }
  for(const f of files){
    if(pending.length >= CFG.max_files){ hint("一次最多 " + CFG.max_files + " 个", true); break; }
    const slot = {label:f.name.slice(0,28), name:null};
    pending.push(slot); drawQueue(); hint("正在上传 " + slot.label + " …");
    try{ slot.name = await upload(f); hint(""); }
    catch(e){ pending.splice(pending.indexOf(slot),1); drawQueue(); hint(e.message, true); }
  }
  drawQueue();
};

async function send(){
  if(!cur) return;
  const box = $("box"), body = box.value.trim();
  const files = pending.filter(p => p.name).map(p => p.name);
  if(!body && !files.length){ hint("请输入内容或选择文件", true); return; }
  $("send").disabled = true;
  try{
    const r = await fetch("/support/admin/api/reply", {
      method:"POST", credentials:"same-origin",
      headers:{"Content-Type":"application/json"},
      body: JSON.stringify({token:cur, body:body, files:files})});
    const d = await r.json();
    if(!d.ok) hint(d.error || "发送失败", true);
    else{ box.value = ""; pending = []; drawQueue(); hint("");
          if(d.messages) render(d.messages, false); refresh(); }
  }catch(e){ hint("发送失败：" + e.message, true); }
  $("send").disabled = false; box.focus();
}

$("send").onclick = send;
$("box").addEventListener("keydown", e => {
  if(e.key === "Enter" && !e.shiftKey){ e.preventDefault(); send(); }
});
$("close").onclick = async () => {
  if(!cur) return;
  const c = convs.filter(x => x.token === cur)[0] || {};
  const want = c.status === "closed" ? "open" : "closed";
  await fetch("/support/admin/api/status", {method:"POST", credentials:"same-origin",
    headers:{"Content-Type":"application/json"},
    body: JSON.stringify({token:cur, status:want})});
  await refresh();
  const c2 = convs.filter(x => x.token === cur)[0] || {};
  $("close").textContent = c2.status === "closed" ? "重新打开" : "结束会话";
};

(async () => { await refresh(); cursor = CFG.cursor; poll(); })();
</script>
</body>
</html>
'''


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
        # 错误提示用状态色而不是字面 red:后者比页面上任何一个红都更刺眼,
        # 和其余页面的「恶意」红也不是同一个色。
        err_html = ('<p class="err">' + error + '</p>') if error else ''
        html = '''<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>磐垒 · 登录</title>
<style>
/* 与其余页面同一套配色:白底、单一强调蓝、加深后的状态色。 */
:root{--bg:#edf0f5;--pnl:#ffffff;--ln:#e4e7ec;--ink:#101828;--mut:#667085;
  --dim:#98a2b3;--acc:#2563eb;--mal:#d92d20;
  --sans:-apple-system,"Segoe UI",Roboto,"Microsoft YaHei",system-ui,sans-serif;
  --mono:"SFMono-Regular","Cascadia Mono",Consolas,Menlo,monospace}
*{box-sizing:border-box}
body{font:14px/1.6 var(--sans);display:flex;justify-content:center;align-items:center;
  min-height:100vh;margin:0;background:var(--bg);color:var(--ink)}
/* 极淡的网格 + 顶部冷光,和控制台是同一个底子 */
body::before{content:"";position:fixed;inset:0;z-index:-2;background:
  repeating-linear-gradient(0deg,transparent 0 47px,rgba(16,24,40,.03) 47px 48px),
  repeating-linear-gradient(90deg,transparent 0 47px,rgba(16,24,40,.03) 47px 48px)}
body::after{content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;
  background:radial-gradient(1000px 460px at 50% -14%,rgba(37,99,235,.08),transparent 70%)}
.box{background:var(--pnl);padding:34px 32px;border:1px solid var(--ln);width:352px;
  box-shadow:0 1px 2px rgba(16,24,40,.05),0 12px 32px rgba(16,24,40,.08)}
.mk{width:36px;height:36px;display:grid;place-items:center;background:var(--acc);
  color:#fff;font-size:18px;margin-bottom:16px;
  clip-path:polygon(22% 0,100% 0,100% 78%,78% 100%,0 100%,0 22%)}
h2{margin:0;font-size:16px;font-weight:800;letter-spacing:1.6px}
.sub{margin:5px 0 22px;color:var(--mut);font-size:11.5px;letter-spacing:.9px;
  font-family:var(--mono)}
label{display:block;font-size:10.5px;font-weight:700;color:var(--mut);
  letter-spacing:1.1px;margin-bottom:7px}
input[type=password]{width:100%;padding:12px 13px;border:1px solid var(--ln);
  border-left:2px solid var(--acc);background:var(--bg);color:var(--ink);
  font:14px var(--mono);letter-spacing:1px;outline:none;transition:.15s}
input[type=password]:focus{border-color:var(--acc);box-shadow:0 0 0 3px rgba(37,99,235,.12)}
input[type=password]::placeholder{color:var(--dim);letter-spacing:normal;
  font-family:var(--sans)}
button{width:100%;padding:12px;background:var(--acc);color:#fff;border:none;
  font:700 13px/1 var(--sans);letter-spacing:1.2px;cursor:pointer;margin-top:14px;
  transition:.13s;clip-path:polygon(8px 0,100% 0,100% calc(100% - 8px),
  calc(100% - 8px) 100%,0 100%,0 8px)}
button:hover{filter:brightness(1.1)}
button:active{transform:translateY(1px)}
.err{margin:0 0 14px;padding:9px 12px;font-size:12.5px;color:var(--mal);
  background:rgba(217,45,32,.07);border-left:2px solid var(--mal)}
.foot{margin-top:18px;font-size:10.5px;color:var(--dim);font-family:var(--mono);
  letter-spacing:.5px}
</style></head><body>
<div class="box">
<div class="mk">&#128737;</div>
<h2>BULWARK</h2>
<div class="sub">THREAT ANALYSIS CONSOLE</div>
''' + err_html + '''
<form method="POST" action="/login">
<label for="pw">访问口令</label>
<input id="pw" type="password" name="password" placeholder="请输入密码" autofocus>
<button type="submit">登录</button>
</form>
<div class="foot">仅授权人员访问</div>
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

    def _serve_feedback(self):
        """管理页:查看用户提交的问题反馈。走网页口令,不对外公开。

        所有用户可控文本(内容/联系方式/UA/页面)都必须转义后再插进 HTML ——
        提交口是公开的,不转义的话一条反馈就是一次存储型 XSS,而看这个页面的
        恰恰是带着 bw_session 的管理员。
        """
        if not self._check_webui_cookie():
            return self._serve_login_page()

        def esc(s):
            return (str(s if s is not None else "").replace("&", "&amp;")
                    .replace("<", "&lt;").replace(">", "&gt;")
                    .replace('"', "&quot;").replace("'", "&#39;"))

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
            # 过一天就给北京时间的绝对时刻。「37 天前」对排查没有用,而看这两页的人
            # 通常是要拿这个时间去跟客户端日志对时的。
            return cst_str(ts, "%m-%d %H:%M")

        KIND = {"bug": "功能异常", "fp": "误报", "fn": "漏报",
                "feature": "功能建议", "other": "其它"}
        items = SERVICE.store.list_feedback(limit=500)
        st = SERVICE.store.feedback_stats()
        img_gated = not self._webui_password()

        rows = []
        for f in items:
            done = f.get("status") == "done"
            kind = KIND.get(f.get("kind", "other"), f.get("kind", "other"))
            contact = f.get("contact") or ""
            # 截图。文件名过一遍白名单正则才拼进 HTML —— 库里的值理论上都是服务端
            # 生成的,但这是给管理员看的页面,不值得为"理论上"省这一道。
            try:
                names = json.loads(f.get("images") or "[]")
            except Exception:
                names = []
            names = [str(n) for n in (names if isinstance(names, list) else [])
                     if IMG_NAME_RE.match(str(n))]
            if names and img_gated:
                # 截图取回口 fail closed(见 _serve_feedback_image)。这里说清楚
                # 图还在、为什么看不到、怎么才能看到 —— 直接放 <img> 只会得到
                # 一排碎图标,没人知道发生了什么。
                shots_html = ('<div class="shots"><span class="dim">已收到 %d 张截图,'
                              '但本服务未设置 webui_password。为避免公网无鉴权读取'
                              '用户上传的内容,截图暂不显示 —— 配置 webui_password '
                              '并重启后即可查看。</span></div>' % len(names))
            elif names:
                shots_html = '<div class="shots">%s</div>' % "".join(
                    '<a class="shot" href="/feedback/img/%s" target="_blank" '
                    'rel="noopener noreferrer"><img src="/feedback/img/%s" '
                    'alt="用户截图" loading="lazy"></a>' % (esc(n), esc(n)) for n in names)
            else:
                shots_html = ""
            msg_html = esc(f.get("message", "")).replace("\n", "<br>")
            if not msg_html and shots_html:
                msg_html = '<span class="dim">(只有截图,没有文字)</span>'
            if f.get("reply"):
                msg_html += ('<div class="rpshow"><b>处理结果</b>%s<span class="dim">%s</span></div>'
                             % (esc(f.get("reply", "")).replace("\n", "<br>"),
                                esc(rel(f.get("replied_at")))))
            if done and not names:
                msg_html += '<div class="dim" style="margin-top:6px">截图已随处理完成自动删除</div>'
            rows.append(
                '<tr class="%s" data-id="%d">'
                '<td class="num">#%d</td>'
                '<td><span class="k">%s</span></td>'
                '<td class="msg">%s</td>'
                '<td class="meta">%s</td>'
                '<td class="meta">%s<br><span class="dim">%s · %s</span></td>'
                '<td class="act">'
                '<input class="rp" placeholder="处理结果(提交者可见)" value="%s">'
                '<button class="b" data-act="%s">%s</button>'
                '<button class="b d" data-act="delete">删除</button>'
                '</td></tr>'
                % ("done" if done else "",
                   int(f["id"]), int(f["id"]), esc(kind),
                   msg_html + shots_html,
                   esc(contact) if contact else '<span class="dim">未留</span>',
                   esc(rel(f.get("at"))), esc(mask_ip(f.get("ip", ""))),
                   esc(f.get("agent", "") or "—"),
                   esc(f.get("reply", "") or ""),
                   "new" if done else "done",
                   "标为未读" if done else "标记已处理"))
        rows_html = "\n".join(rows) if rows else (
            '<tr><td colspan="6" class="empty">还没有收到反馈</td></tr>')

        html = """<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>磐垒 · 问题反馈</title>
<style>
/* ===== 共享控制台外壳(注入 app.py 内嵌的各页面)=====================
   这些页面各自有一套自己的 class 名和版式。这里不去逐页重写,而是统一
   三件决定"是不是同一个产品"的东西:底子(白底+网格)、顶栏、以及标题/
   表格/瓦片这几个到处都在用的组件。
   放在每页样式块的最前面 —— 页面自己的规则在后面,仍可覆盖它。
   ==================================================================== */
:root{
  /* 页面压暗、面板留纯白。原来两者都是 #ffffff，面板只能靠边框描出来，整页过亮。 */
  --bwbg:#edf0f5; --bwpnl:#ffffff; --bwsoft:#f9fafb;
  --bwln:#e4e7ec; --bwln2:#f2f4f7;
  --bwink:#101828; --bwink2:#344054; --bwmut:#667085; --bwdim:#98a2b3;
  --bwac:#2563eb; --bwvi:#7c3aed;
  --bwmal:#d92d20; --bwsus:#b54708; --bwok:#067647;
  --bwmono:"SFMono-Regular","Cascadia Mono",Consolas,Menlo,monospace;
  --bwsans:-apple-system,"Segoe UI",Roboto,"Microsoft YaHei",system-ui,sans-serif;
}
body{background:var(--bwbg);color:var(--bwink);font-family:var(--bwsans);
  -webkit-font-smoothing:antialiased}
/* 白底上的网格必须是深色低透明度,白线等于不存在 */
body::before{content:"";position:fixed;inset:0;z-index:-2;pointer-events:none;background:
  repeating-linear-gradient(0deg,transparent 0 47px,rgba(16,24,40,.03) 47px 48px),
  repeating-linear-gradient(90deg,transparent 0 47px,rgba(16,24,40,.03) 47px 48px)}
body::after{content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;
  background:radial-gradient(1200px 520px at 50% -12%,rgba(37,99,235,.07),transparent 70%)}

/* ---- 顶栏:和 / 上完全一致,导航才不会每页一个样 ---- */
.bwrail{position:sticky;top:0;z-index:60;background:rgba(255,255,255,.9);
  backdrop-filter:blur(14px);border-bottom:1px solid var(--bwln)}
.bwrail .in{max-width:1440px;margin:0 auto;display:flex;align-items:center;gap:16px;
  padding:10px 22px}
.bwbrand{display:flex;align-items:center;gap:10px;text-decoration:none;flex:none}
.bwbrand .mk{width:30px;height:30px;flex:none;display:grid;place-items:center;
  background:var(--bwac);color:#fff;font-size:15px;
  clip-path:polygon(22% 0,100% 0,100% 78%,78% 100%,0 100%,0 22%)}
.bwbrand b{display:block;font-size:13.5px;font-weight:800;letter-spacing:2.2px;
  color:var(--bwink);line-height:1.1}
.bwbrand s{display:block;text-decoration:none;font-size:9px;color:var(--bwmut);
  letter-spacing:1.3px;margin-top:2px}
.bwgrow{flex:1}
.bwnav{display:flex;align-items:stretch;gap:2px;overflow-x:auto;
  scrollbar-width:none;-ms-overflow-style:none}
.bwnav::-webkit-scrollbar{display:none}
.bwnav a{position:relative;display:inline-flex;align-items:center;gap:7px;
  padding:9px 13px;font-size:12.5px;font-weight:600;letter-spacing:.5px;
  color:var(--bwmut);text-decoration:none;white-space:nowrap}
.bwnav a::after{content:"";position:absolute;left:11px;right:11px;bottom:-1px;height:2px;
  background:var(--bwac);opacity:0;transition:opacity .16s}
.bwnav a:hover{color:var(--bwink);text-decoration:none}
.bwnav a:hover::after{opacity:.5}
.bwnav a.on{color:var(--bwac)}
.bwnav a.on::after{opacity:1}
.bwnav a .i{font-size:13px;line-height:1}

/* ---- 到处都在用的组件 ---- */
h1{font-size:21px;font-weight:800;letter-spacing:-.2px;color:var(--bwink)}
h2{font-size:12px!important;font-weight:800;letter-spacing:1.6px;color:var(--bwink);
  display:flex;align-items:center;gap:9px;border-bottom:1px solid var(--bwln2)!important;
  padding-bottom:9px!important}
h2::before{content:"";width:2px;height:13px;background:var(--bwac);flex:none}
a{color:var(--bwac)}
code{font-family:var(--bwmono);background:var(--bwsoft);border:1px solid var(--bwln);
  border-radius:0;color:#1d4ed8}
pre{border-radius:0!important;border:1px solid var(--bwln)}
table th{color:var(--bwdim)!important;font-size:9.5px!important;font-weight:700;
  text-transform:uppercase;letter-spacing:1.2px;background:var(--bwsoft)}
table td{border-bottom:1px solid var(--bwln2)}
table tbody tr:hover td{background:rgba(37,99,235,.04)}
table tbody tr:hover td:first-child{box-shadow:inset 2px 0 0 var(--bwac)}
/* 统计瓦片:顶部 2px 状态色 + 大号等宽数字,和 / 的 .hstat 同一个样式 */
.bwstats{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,240px));justify-content:start;
  gap:12px;margin:0 0 18px}
.bwstat{background:var(--bwpnl);border:1px solid var(--bwln);border-top:2px solid var(--bwac);
  padding:13px 15px;box-shadow:0 1px 2px rgba(16,24,40,.05)}
.bwstat .v{font-family:var(--bwmono);font-size:25px;font-weight:800;line-height:1.05;
  font-variant-numeric:tabular-nums;letter-spacing:-.5px}
/* background/padding/border-radius 是显式清零的，不是多余代码：这些页面各自留着
   给旧标记用的 .k 药丸样式（圆角底色），而 .bwstat .k 只要不写这几个属性，页面级
   的 .k 就会漏进来，标签变成一颗药丸。清零比去每个页面删旧规则安全 —— 那些旧
   规则可能还有别处在用。 */
.bwstat .k{font-size:10.5px;color:var(--bwmut);margin-top:4px;letter-spacing:1.1px;
  background:none;padding:0;border-radius:0;display:block;width:auto}
.bwstat.mal{border-top-color:var(--bwmal)}.bwstat.mal .v{color:var(--bwmal)}
.bwstat.sus{border-top-color:var(--bwsus)}.bwstat.sus .v{color:var(--bwsus)}
.bwstat.ok{border-top-color:var(--bwok)}.bwstat.ok .v{color:var(--bwok)}
@media(max-width:640px){.bwrail .in{padding:9px 14px}.bwbrand s{display:none}}

:root{--bg:#edf0f5;--card:#fff;--soft:#f9fafb;--line:#e4e7ec;--ink:#101828;--muted:#667085;
--dim:#98a2b3;--acc:#2563eb;--ok:#067647;--warn:#b54708}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.6 -apple-system,"Segoe UI",
"Microsoft YaHei",sans-serif;padding:24px}
.wrap{max-width:1180px;margin:0 auto}
h1{font-size:20px;margin:0 0 4px}
.sub{color:var(--muted);font-size:13px;margin-bottom:18px}
.sub a{color:var(--acc);text-decoration:none}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden}
table{width:100%;border-collapse:collapse}
th,td{padding:11px 13px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}
th{background:var(--soft);font-weight:600;font-size:12px;color:var(--muted);
text-transform:uppercase;letter-spacing:.4px;white-space:nowrap}
tr:last-child td{border-bottom:none}
tr.done{background:#fafbfd;color:var(--muted)}
tr.done .msg{text-decoration:line-through;text-decoration-color:var(--dim)}
.num{font-variant-numeric:tabular-nums;color:var(--muted);white-space:nowrap}
.k{display:inline-block;padding:2px 9px;border-radius:99px;background:#eaf0ff;
color:var(--acc);font-size:12px;white-space:nowrap}
.msg{max-width:560px;word-break:break-word;white-space:normal}
/* 用户截图。缩略图固定高度、cover 裁切,否则一张竖屏手机截图会把整行撑到
   几百像素高,一页就只剩两条反馈能看。点开是原图(新标签页)。 */
.shots{display:flex;flex-wrap:wrap;gap:7px;margin-top:8px}
.shot{display:block;line-height:0;border:1px solid var(--line);border-radius:8px;
overflow:hidden;transition:.14s}
.shot:hover{border-color:var(--acc);transform:translateY(-1px);box-shadow:0 4px 12px rgba(0,0,0,.1)}
.shot img{width:110px;height:76px;object-fit:cover;display:block;background:#f2f4f8}
.rp{display:block;width:190px;margin-bottom:6px;padding:5px 8px;border:1px solid var(--line);
border-radius:7px;font:inherit;font-size:12.5px}
.rp:focus{outline:none;border-color:var(--acc)}
.rpshow{margin-top:8px;padding:8px 10px;border-left:3px solid var(--acc);background:#f6f8fd;
border-radius:0 7px 7px 0;font-size:13px}
.rpshow b{display:block;font-size:11.5px;color:var(--acc);margin-bottom:3px}
.meta{font-size:12.5px;color:var(--muted);white-space:nowrap}
.dim{color:var(--dim);font-size:11.5px}
.empty{text-align:center;color:var(--dim);padding:34px}
.act{white-space:nowrap}
.b{border:1px solid var(--line);background:#fff;color:var(--ink);border-radius:7px;
padding:5px 10px;font-size:12px;cursor:pointer;margin-right:5px}
.b:hover{border-color:var(--acc);color:var(--acc)}
.b.d:hover{border-color:#dc2626;color:#dc2626}
.pill{display:inline-block;padding:3px 11px;border-radius:99px;font-size:12px;margin-right:8px}
.p1{background:#fff5e6;color:var(--warn)}
.p2{background:#e9f8ef;color:var(--ok)}
</style></head><body>
<div class="bwrail"><div class="in">
<a class="bwbrand" href="/" title="返回控制台"><span class="mk">🛡️</span>
<span><b>BULWARK</b><s>THREAT ANALYSIS CONSOLE</s></span></a>
<div class="bwgrow"></div>
<nav class="bwnav">
<a href="/"><span class="i">🛡️</span>控制台</a>
<a href="/engine" class=""><span class="i">🧬</span>攻击链引擎</a>
<a href="/online" class=""><span class="i">📡</span>在线客户端</a>
<a href="/support" class=""><span class="i">🎧</span>在线客服</a>
<a href="/feedback" class="on"><span class="i">💬</span>反馈</a>
<a href="/api/docs" class=""><span class="i">&#128268;</span>API 文档</a>
<a href="/about" class=""><span class="i">📥</span>下载</a>
</nav>
<!-- 北京时间读数。这两台机器的系统时区是 UTC,而看页面的人在中国 —— 原来页面上
     没有任何一处告诉你「现在几点」,读时间戳只能靠脑内加 8 小时。
     样式写成内联:顶栏在 4 个页面里是 4 份字面量副本,内联能保证四份永远一致,
     也不用去动那 4 份 CSS 副本、不改变 style 标签计数。 -->
<div style="display:flex;flex-direction:column;align-items:flex-end;line-height:1.2;margin-left:16px">
<b id="bwclk" style="font:600 13px/1.2 ui-monospace,SFMono-Regular,Consolas,monospace;color:var(--ink);font-variant-numeric:tabular-nums">--:--:--</b>
<s id="bwclkd" style="text-decoration:none;font-size:10px;color:var(--mut)">北京时间</s>
</div>
</div></div>
<script>
(function(){
  var b=document.getElementById("bwclk"),d=document.getElementById("bwclkd");
  if(!b)return;
  var DAYS=["\u65e5","\u4e00","\u4e8c","\u4e09","\u56db","\u4e94","\u516d"];
  function p(n){return (n<10?"0":"")+n;}
  function tick(){
    /* Date.now() 是 UTC 毫秒;加 8 小时后再用 getUTC* 读出来,就是北京时间的墙上
       钟面,与浏览器所在时区无关。用固定偏移而不是 toLocaleString("zh-CN") ——
       后者受访问者系统时区影响,在国外打开会显示当地时间。中国无夏令时,
       固定 +08:00 不会错。 */
    var t=new Date(Date.now()+8*3600*1000);
    b.textContent=p(t.getUTCHours())+":"+p(t.getUTCMinutes())+":"+p(t.getUTCSeconds());
    if(d)d.textContent=t.getUTCFullYear()+"-"+p(t.getUTCMonth()+1)+"-"+p(t.getUTCDate())
      +" \u5468"+DAYS[t.getUTCDay()]+" UTC+8";
  }
  tick();setInterval(tick,1000);
})();
</script>
<div class="wrap">
<h1>问题反馈</h1>
<!-- 「未处理」是待办不是统计，所以用可疑色单独立成一块瓦片；返回链接删了 ——
     顶栏已经有全站导航，页内再放一遍只是重复。 -->
<div class="bwstats">
<div class="bwstat sus"><div class="v">__NEW__</div><div class="k">待处理</div></div>
<div class="bwstat"><div class="v">__TOTAL__</div><div class="k">累计提交</div></div>
</div>
<div class="card"><table>
<thead><tr><th>#</th><th>类型</th><th>内容</th><th>联系方式</th><th>时间 / 来源</th><th>处理</th></tr></thead>
<tbody id="tb">
__ROWS__
</tbody></table></div>
</div>
<script>
document.getElementById('tb').addEventListener('click', async (e) => {
  const b = e.target.closest('button[data-act]');
  if (!b) return;
  const tr = b.closest('tr');
  const id = +tr.dataset.id, act = b.dataset.act;
  if (act === 'delete' && !confirm('删除这条反馈?')) return;
  b.disabled = true;
  try {
    // 处理结果跟状态一起提交,省掉一次单独的"保存"动作。留空就不覆盖已有回复
    // (reply 不传 = 不动),否则一次误点就会把之前写好的结论清空。
    const rp = tr.querySelector('input.rp');
    const payload = {id: id, action: act};
    if (rp && rp.value.trim()) payload.reply = rp.value.trim();
    const r = await fetch('/feedback/status', {method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify(payload)});
    const d = await r.json();
    if (!d.ok) { alert('操作失败'); b.disabled = false; return; }
    location.reload();
  } catch (err) { alert('操作失败: ' + err.message); b.disabled = false; }
});
</script></body></html>"""
        html = (html.replace("__ROWS__", rows_html)
                    .replace("__NEW__", str(st["new"]))
                    .replace("__TOTAL__", str(st["total"])))
        self._send_bytes(200, html.encode("utf-8"), "text/html; charset=utf-8")

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
            # 过一天就给北京时间的绝对时刻。「37 天前」对排查没有用,而看这两页的人
            # 通常是要拿这个时间去跟客户端日志对时的。
            return cst_str(ts, "%m-%d %H:%M")

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
/* ===== 共享控制台外壳(注入 app.py 内嵌的各页面)=====================
   这些页面各自有一套自己的 class 名和版式。这里不去逐页重写,而是统一
   三件决定"是不是同一个产品"的东西:底子(白底+网格)、顶栏、以及标题/
   表格/瓦片这几个到处都在用的组件。
   放在每页样式块的最前面 —— 页面自己的规则在后面,仍可覆盖它。
   ==================================================================== */
:root{
  /* 页面压暗、面板留纯白。原来两者都是 #ffffff，面板只能靠边框描出来，整页过亮。 */
  --bwbg:#edf0f5; --bwpnl:#ffffff; --bwsoft:#f9fafb;
  --bwln:#e4e7ec; --bwln2:#f2f4f7;
  --bwink:#101828; --bwink2:#344054; --bwmut:#667085; --bwdim:#98a2b3;
  --bwac:#2563eb; --bwvi:#7c3aed;
  --bwmal:#d92d20; --bwsus:#b54708; --bwok:#067647;
  --bwmono:"SFMono-Regular","Cascadia Mono",Consolas,Menlo,monospace;
  --bwsans:-apple-system,"Segoe UI",Roboto,"Microsoft YaHei",system-ui,sans-serif;
}
body{background:var(--bwbg);color:var(--bwink);font-family:var(--bwsans);
  -webkit-font-smoothing:antialiased}
/* 白底上的网格必须是深色低透明度,白线等于不存在 */
body::before{content:"";position:fixed;inset:0;z-index:-2;pointer-events:none;background:
  repeating-linear-gradient(0deg,transparent 0 47px,rgba(16,24,40,.03) 47px 48px),
  repeating-linear-gradient(90deg,transparent 0 47px,rgba(16,24,40,.03) 47px 48px)}
body::after{content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;
  background:radial-gradient(1200px 520px at 50% -12%,rgba(37,99,235,.07),transparent 70%)}

/* ---- 顶栏:和 / 上完全一致,导航才不会每页一个样 ---- */
.bwrail{position:sticky;top:0;z-index:60;background:rgba(255,255,255,.9);
  backdrop-filter:blur(14px);border-bottom:1px solid var(--bwln)}
.bwrail .in{max-width:1440px;margin:0 auto;display:flex;align-items:center;gap:16px;
  padding:10px 22px}
.bwbrand{display:flex;align-items:center;gap:10px;text-decoration:none;flex:none}
.bwbrand .mk{width:30px;height:30px;flex:none;display:grid;place-items:center;
  background:var(--bwac);color:#fff;font-size:15px;
  clip-path:polygon(22% 0,100% 0,100% 78%,78% 100%,0 100%,0 22%)}
.bwbrand b{display:block;font-size:13.5px;font-weight:800;letter-spacing:2.2px;
  color:var(--bwink);line-height:1.1}
.bwbrand s{display:block;text-decoration:none;font-size:9px;color:var(--bwmut);
  letter-spacing:1.3px;margin-top:2px}
.bwgrow{flex:1}
.bwnav{display:flex;align-items:stretch;gap:2px;overflow-x:auto;
  scrollbar-width:none;-ms-overflow-style:none}
.bwnav::-webkit-scrollbar{display:none}
.bwnav a{position:relative;display:inline-flex;align-items:center;gap:7px;
  padding:9px 13px;font-size:12.5px;font-weight:600;letter-spacing:.5px;
  color:var(--bwmut);text-decoration:none;white-space:nowrap}
.bwnav a::after{content:"";position:absolute;left:11px;right:11px;bottom:-1px;height:2px;
  background:var(--bwac);opacity:0;transition:opacity .16s}
.bwnav a:hover{color:var(--bwink);text-decoration:none}
.bwnav a:hover::after{opacity:.5}
.bwnav a.on{color:var(--bwac)}
.bwnav a.on::after{opacity:1}
.bwnav a .i{font-size:13px;line-height:1}

/* ---- 到处都在用的组件 ---- */
h1{font-size:21px;font-weight:800;letter-spacing:-.2px;color:var(--bwink)}
h2{font-size:12px!important;font-weight:800;letter-spacing:1.6px;color:var(--bwink);
  display:flex;align-items:center;gap:9px;border-bottom:1px solid var(--bwln2)!important;
  padding-bottom:9px!important}
h2::before{content:"";width:2px;height:13px;background:var(--bwac);flex:none}
a{color:var(--bwac)}
code{font-family:var(--bwmono);background:var(--bwsoft);border:1px solid var(--bwln);
  border-radius:0;color:#1d4ed8}
pre{border-radius:0!important;border:1px solid var(--bwln)}
table th{color:var(--bwdim)!important;font-size:9.5px!important;font-weight:700;
  text-transform:uppercase;letter-spacing:1.2px;background:var(--bwsoft)}
table td{border-bottom:1px solid var(--bwln2)}
table tbody tr:hover td{background:rgba(37,99,235,.04)}
table tbody tr:hover td:first-child{box-shadow:inset 2px 0 0 var(--bwac)}
/* 统计瓦片:顶部 2px 状态色 + 大号等宽数字,和 / 的 .hstat 同一个样式 */
.bwstats{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,240px));justify-content:start;
  gap:12px;margin:0 0 18px}
.bwstat{background:var(--bwpnl);border:1px solid var(--bwln);border-top:2px solid var(--bwac);
  padding:13px 15px;box-shadow:0 1px 2px rgba(16,24,40,.05)}
.bwstat .v{font-family:var(--bwmono);font-size:25px;font-weight:800;line-height:1.05;
  font-variant-numeric:tabular-nums;letter-spacing:-.5px}
/* background/padding/border-radius 是显式清零的，不是多余代码：这些页面各自留着
   给旧标记用的 .k 药丸样式（圆角底色），而 .bwstat .k 只要不写这几个属性，页面级
   的 .k 就会漏进来，标签变成一颗药丸。清零比去每个页面删旧规则安全 —— 那些旧
   规则可能还有别处在用。 */
.bwstat .k{font-size:10.5px;color:var(--bwmut);margin-top:4px;letter-spacing:1.1px;
  background:none;padding:0;border-radius:0;display:block;width:auto}
.bwstat.mal{border-top-color:var(--bwmal)}.bwstat.mal .v{color:var(--bwmal)}
.bwstat.sus{border-top-color:var(--bwsus)}.bwstat.sus .v{color:var(--bwsus)}
.bwstat.ok{border-top-color:var(--bwok)}.bwstat.ok .v{color:var(--bwok)}
@media(max-width:640px){.bwrail .in{padding:9px 14px}.bwbrand s{display:none}}

:root{--bg:#edf0f5;--card:#fff;--soft:#f9fafb;--line:#e4e7ec;--ink:#101828;--muted:#667085;
--brand:#2563eb;--brand2:#7c3aed;--on:#067647;--off:#c2c8d2;--mono:"Cascadia Mono",Consolas,monospace;
--sans:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14.5px/1.6 var(--sans)}
/* 760 → 1080：这页有三张 5~6 列的表，760px 下表格被压在页面中间一条窄带里，
   而顶栏是 1440px，视觉上像没对齐。1080 与 /engine(1020)、/feedback(1180) 同量级。 */
.wrap{max-width:1080px;margin:0 auto;padding:34px 20px 70px}
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
.tag.m{background:rgba(37,99,235,.12);color:var(--brand)}.tag.i{background:var(--soft);color:var(--muted)}
td.empty{text-align:center;color:var(--muted);padding:26px}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:7px;vertical-align:middle}
.dot.on{background:var(--on);box-shadow:0 0 0 3px rgba(6,118,71,.15)}.dot.off{background:var(--off)}
h2{font-size:17px;margin:34px 0 4px;display:flex;align-items:center;gap:8px}
h2:first-of-type{margin-top:6px}
h3{font-size:14px;margin:24px 0 10px;color:var(--muted);font-weight:700}
.lead2{color:var(--muted);margin:0 0 16px;font-size:12.5px}
table{margin-bottom:4px}
td.pt{font-family:var(--mono);font-size:12.5px;color:var(--brand)}
.foot{color:var(--muted);font-size:12px;margin-top:16px}
.foot a{color:var(--brand);text-decoration:none}
</style></head><body>
<div class="bwrail"><div class="in">
<a class="bwbrand" href="/" title="返回控制台"><span class="mk">🛡️</span>
<span><b>BULWARK</b><s>THREAT ANALYSIS CONSOLE</s></span></a>
<div class="bwgrow"></div>
<nav class="bwnav">
<a href="/"><span class="i">🛡️</span>控制台</a>
<a href="/engine" class=""><span class="i">🧬</span>攻击链引擎</a>
<a href="/online" class="on"><span class="i">📡</span>在线客户端</a>
<a href="/support" class=""><span class="i">🎧</span>在线客服</a>
<a href="/feedback" class=""><span class="i">💬</span>反馈</a>
<a href="/api/docs" class=""><span class="i">&#128268;</span>API 文档</a>
<a href="/about" class=""><span class="i">📥</span>下载</a>
</nav>
<!-- 北京时间读数。这两台机器的系统时区是 UTC,而看页面的人在中国 —— 原来页面上
     没有任何一处告诉你「现在几点」,读时间戳只能靠脑内加 8 小时。
     样式写成内联:顶栏在 4 个页面里是 4 份字面量副本,内联能保证四份永远一致,
     也不用去动那 4 份 CSS 副本、不改变 style 标签计数。 -->
<div style="display:flex;flex-direction:column;align-items:flex-end;line-height:1.2;margin-left:16px">
<b id="bwclk" style="font:600 13px/1.2 ui-monospace,SFMono-Regular,Consolas,monospace;color:var(--ink);font-variant-numeric:tabular-nums">--:--:--</b>
<s id="bwclkd" style="text-decoration:none;font-size:10px;color:var(--mut)">北京时间</s>
</div>
</div></div>
<script>
(function(){
  var b=document.getElementById("bwclk"),d=document.getElementById("bwclkd");
  if(!b)return;
  var DAYS=["\u65e5","\u4e00","\u4e8c","\u4e09","\u56db","\u4e94","\u516d"];
  function p(n){return (n<10?"0":"")+n;}
  function tick(){
    /* Date.now() 是 UTC 毫秒;加 8 小时后再用 getUTC* 读出来,就是北京时间的墙上
       钟面,与浏览器所在时区无关。用固定偏移而不是 toLocaleString("zh-CN") ——
       后者受访问者系统时区影响,在国外打开会显示当地时间。中国无夏令时,
       固定 +08:00 不会错。 */
    var t=new Date(Date.now()+8*3600*1000);
    b.textContent=p(t.getUTCHours())+":"+p(t.getUTCMinutes())+":"+p(t.getUTCSeconds());
    if(d)d.textContent=t.getUTCFullYear()+"-"+p(t.getUTCMonth()+1)+"-"+p(t.getUTCDate())
      +" \u5468"+DAYS[t.getUTCDay()]+" UTC+8";
  }
  tick();setInterval(tick,1000);
})();
</script>
<div class="wrap">
<h1>🛡️ 连接与访问</h1>
<p class="lead">上半部分是正在使用磐垒、连接到本情报服务器的本地客户端；下半部分是浏览器访客记录。为保护隐私，所有来源 IP 均已打码（仅保留前两段）。</p>
<h2>📡 本地客户端</h2>
<p class="lead2">支持匿名机器 ID 的客户端按机器去重，其余按来源 IP 去重。</p>
<!-- 统计瓦片改用共享的 .bwstat：和控制台首页的 KPI 是同一个样式。
     「当前在线」用安全色 + 复用本页已有的 .dot 在线灯，一眼能看出这个数是活的；
     另外两个是累计量，保持中性色，避免三块都在抢注意力。

     注意 .dot 那个 span 是整段拼好再插进来的，属性值一律不许跨模板拼接边界。
     曾经把 class 的值拆在拼接两侧、漏了收尾引号，结果右尖括号和 span 的闭合标签
     全被吞进属性值：span 不闭合 → .bwstats 一直开着 → 表格和下面整节都变成它的
     grid 子项，整页挤成几条窄柱。py_compile 和标签计数都发现不了（计数是平衡的，
     闭合标签确实存在，只是被属性值吃了），只有 HTML 解析器能看出来。

     这段注释本身也不要再抄那个坏写法的字面量：它位于 Python 三引号模板内部，
     写进去会提前闭合字符串、把示例里的变量名变成真代码。 -->
<div class="bwstats">
<div class="bwstat ok"><div class="v">""" + str(st["online"]) + """</div>
  <div class="k">""" + ('<span class="dot %s"></span>' % ("on" if st["online"] else "off")) + """ 当前在线（近 """ + str(st["window_min"]) + """ 分钟活跃）</div></div>
<div class="bwstat"><div class="v">""" + str(st["total"]) + """</div><div class="k">累计客户端（去重，其中 """ + str(st.get("identified", 0)) + """ 台按机器识别）</div></div>
<div class="bwstat"><div class="v">""" + str(st["total_hits"]) + """</div><div class="k">累计情报查询次数</div></div>
</div>
<table><thead><tr><th>状态</th><th>来源 IP（打码）</th><th>识别方式</th><th>最近活跃</th><th>查询次数</th></tr></thead>
<tbody>
""" + rows_html + """
</tbody></table>

<h2>🌐 网页访客</h2>
<p class="lead2">浏览器访问本站页面的记录（威胁分析台 / 关于 / API 文档 / 下载）。自动刷新与后台轮询不计入。</p>
<div class="bwstats">
<div class="bwstat ok"><div class="v">""" + str(vst["active"]) + """</div>
  <div class="k">""" + ('<span class="dot %s"></span>' % ("on" if vst["active"] else "off")) + """ 当前活跃访客（近 """ + str(vst["window_min"]) + """ 分钟）</div></div>
<div class="bwstat"><div class="v">""" + str(vst["unique"]) + """</div><div class="k">独立访客（按来源 IP 去重）</div></div>
<div class="bwstat"><div class="v">""" + str(vst["today_views"]) + """</div><div class="k">今日访问 / 累计 """ + str(vst["views"]) + """</div></div>
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
        # v20 这一轮带出来的 11 个。补名之前,22 条生效规则里有 10 条的动作链是中英混排,
        # 且这 11 个全部落进「其他」—— 页面看着乱的头号原因是这个,不是配色或间距。
        # 「看得见不会被静默吞掉」这条设计确实成立了,但看得见 ≠ 可以放着不管。
        "base64_encoded_powershell_command_detected": "PowerShell 命令用 Base64 编码",
        # 特征库 1.2 这一轮新挖出来的两个。名字按【实际判据】起,不照抄 Sigma 规则名:
        # 前者的条件就是命令行含 bypass(covers -ep/-exec 等缩写写法),后者是
        # -EncodedCommand。写成「参数缩写异常」之类会让人对不上页面上显示的那行条件。
        "suspicious_powershell_parameter_substring": "PowerShell 命令行带 bypass 参数",
        "suspicious_encoded_powershell_command_line": "PowerShell 用 -EncodedCommand 传参",
        # 特征库 1.3。补齐任务把旧的降级占位行换成完整报告后语料变多,挖掘随之带出新标记
        # —— 这张表要跟着走,不然它们会一起掉进「其他」并显示英文原名。
        "suspicious_powershell_parent_process": "PowerShell 被异常父进程拉起",
        # ⚠ 这一个的判据是「命令行含 truncated」。那不是攻击特征,是 VirusTotal 报告里
        # 命令行过长时留下的截断占位词被当成了字面量。留着中文名只为让页面别显示英文原名,
        # 真正该修的是 engine_build 的条件推导:它应当把报告自身的产物(truncated / …)
        # 列入字面量黑名单。见交接说明。
        "suspicious_mshta_child_process": "mshta 拉起子进程",
        "currentversion_nt_autorun_keys_modification": "改 Windows NT 键下的自启动项",
        "disable_internal_tools_or_feature_in_registry": "改注册表关掉系统功能",
        "path_to_screensaver_binary_modified": "改屏保程序路径",
        "registry_persistence_via_service_in_safe_mode": "让服务连安全模式也启动",
        "remote_access_tool_screenconnect_execution": "跑起远控工具 ScreenConnect",
        "service_startuptype_change_via_sc_exe": "用 sc.exe 改服务启动方式",
        "silenttrinity_stager_msbuild_activity": "SilentTrinity 借 msbuild 外联",
        "suspicious_dns_query_for_ip_lookup_service_apis": "解析查公网 IP 的接口域名",
        "suspicious_msbuild_execution_by_uncommon_parent_process": "msbuild 被异常父进程拉起",
        "suspicious_powershell_in_registry_run_keys": "自启动项里写 PowerShell 命令",
    }

    # ---- 标记的区分力 -------------------------------------------------------- #
    #
    # 【判据的正本在 engine_build.condition_specificity,这里是给页面用的副本】。
    # 为什么容忍这份重复:这一页的用途就是「让人看出客户端到底会怎么判」,而区分力决定
    # 一个标记算不算互证的一份 —— 页面不显示它,就无法回答「这条规则靠得住吗」,而那
    # 恰恰是看这页的人唯一真正想知道的事。app.py 不 import 挖掘器(那是独立的定时任务,
    # 不该成为 HTTP 服务的依赖),故照抄判据并在两处都留下指针。
    # 两边如果跑偏,表现是页面上的区分力与下发表实际生效的不一致 —— 故任何一侧改动
    # 判据时,另一侧必须同步。
    _SPEC_COMMON_BIN = (
        "svchost.exe", "services.exe", "lsass.exe", "explorer.exe", "cmd.exe",
        "conhost.exe", "rundll32.exe", "regsvr32.exe", "msiexec.exe", "dllhost.exe",
        "taskhostw.exe", "wmiprvse.exe", "schtasks.exe", "reg.exe", "sc.exe",
        "powershell.exe", "powershell", "wscript.exe", "cscript.exe", "csc.exe",
        "curl.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe",
    )

    @classmethod
    def _cond_spec(cls, cond):
        """0 = 不构成证据(恒真/只有软信号) 1 = 信息量极低 2 = 可算一份证据。"""
        if not isinstance(cond, dict):
            return 0
        slots = {k: str(cond.get(k) or "").strip()
                 for k in ("actor", "target", "cmdline", "parent",
                           "cmdline_absent", "target_absent", "parent_absent")}
        if not any(slots.values()):
            return 0                      # 无条件,或只有 unsigned -> 软信号
        def lits(p, n=4):
            return [s for s in p.replace("?", "*").split("*") if len(s) >= n]
        sub = 0
        for k in ("target", "cmdline", "parent"):
            if slots[k] and lits(slots[k]):
                sub += 1
        for k in ("cmdline_absent", "target_absent", "parent_absent"):
            if slots[k] and lits(slots[k], 2):
                sub += 1                  # 「不含」条件正是把恒真项变成真判据的那一半
        if slots["actor"]:
            low = slots["actor"].lower()
            if not any(b in low for b in cls._SPEC_COMMON_BIN) and lits(slots["actor"]):
                sub += 1
        return 2 if sub >= 1 else 1

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
        # 「外联下载」原来只说取载荷/回传,装不下远控工具落地与 C2 stager 这两类。
        # 与其为它们单开一个只有两三个标记的分组(分组一多,这一页又回到「乱」),
        # 不如把这一格如实写成「联网这件事的全部去向」。
        ("net",     "外联与远控",     "联网取回载荷、回传,或把机器交给外部控制"),
        ("other",   "其他",           "尚未归类的行为"),
    ]

    MARKER_TACTIC = {
        # 防御规避
        "powershell_defender_exclusion": "evade",
        "windows_defender_exclusions_added_registry": "evade",
        "suspicious_windows_defender_folder_exclusion_added_via_reg_exe": "evade",
        "change_powershell_policies_to_an_insecure_level": "evade",
        "potential_powershell_command_line_obfuscation": "evade",
        "base64_encoded_powershell_command_detected": "evade",
        "disable_internal_tools_or_feature_in_registry": "evade",
        "suspicious_powershell_parameter_substring": "evade",
        "suspicious_encoded_powershell_command_line": "evade",
        "suspicious_powershell_parent_process": "evade",
        # 开机留驻
        "currentversion_autorun_keys_modification": "persist",
        "currentversion_nt_autorun_keys_modification": "persist",
        "new_run_key_pointing_to_suspicious_folder": "persist",
        "suspicious_powershell_in_registry_run_keys": "persist",
        "path_to_screensaver_binary_modified": "persist",
        "registry_persistence_via_service_in_safe_mode": "persist",
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
        "suspicious_msbuild_execution_by_uncommon_parent_process": "exec",
        "suspicious_mshta_child_process": "exec",
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
        "service_startuptype_change_via_sc_exe": "tamper",
        # 外联与远控
        "suspicious_curl_exe_download": "net",
        "suspicious_network_connection_to_ip_lookup_service_apis": "net",
        "suspicious_dns_query_for_ip_lookup_service_apis": "net",
        "office_application_initiated_network_connection_to_non_local_ip": "net",
        "silenttrinity_stager_msbuild_activity": "net",
        "remote_access_tool_screenconnect_execution": "net",
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
                        # 区分力:决定这个标记算不算互证的一份(见 _cond_spec)。
                        "spec": self._cond_spec(cond_of(s)),
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
                "spec": self._cond_spec(cond_of(s)),
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

    # ======================================================================= #
    #  在线客服                                                                #
    # ======================================================================= #
    #
    # 访客侧【必须无鉴权】—— 这是客服的前提,要求用户先登录才能提问就等于没有客服。
    # 代价是这几条路由对公网完全敞开,所以防滥用不是可选项,而且必须是多层的:
    #   · 每 IP 请求滑窗          _throttle_ok()(与反馈提交共用同一套)
    #   · 每 IP 每日新建会话上限  new_conv_per_ip_per_day
    #   · 每会话每日消息上限      messages_per_conv_per_day
    #   · 正文长度上限            max_message_chars
    #   · 附件:张数 / 单个大小 / 类型白名单 / 目录总量闸门
    #   · 长轮询并发上限          max_waiters(见 SUP_WAIT)
    # 少任何一层,单个 IP 都能把磁盘或线程池吃干。

    def _cookie(self, name):
        for part in (self.headers.get("Cookie", "") or "").split(";"):
            kv = part.strip().split("=", 1)
            if len(kv) == 2 and kv[0].strip() == name:
                return kv[1].strip()
        return ""

    @staticmethod
    def _sup_cfg():
        """客服配置。全部有默认值 —— 上线这个功能不需要动 config.json,
        而那个文件是 600 且装着所有 API key,能不碰就不碰。"""
        s = CONFIG.get("support", {}) or {}

        def num(k, d, lo, hi):
            try:
                v = int(s.get(k, d))
            except (TypeError, ValueError):
                v = d
            return max(lo, min(hi, v))

        return {
            "enabled": bool(s.get("enabled", True)),
            "agent_name": (str(s.get("agent_name", "") or "磐垒客服"))[:24],
            "greeting": (str(s.get("greeting", "") or
                             "你好，这里是磐垒在线客服。说明你遇到的问题，"
                             "可以直接发送截图或录屏。"))[:400],
            "retention_days": num("retention_days", 3, 1, 30),
            "max_chars": num("max_message_chars", 2000, 100, SupportStore.MSG_HARD_CAP),
            "max_files": num("max_attachments", 6, 1, SupportStore.MEDIA_HARD_CAP),
            "image_mb": num("max_image_mb", 16, 1, 64),
            "video_mb": num("max_video_mb", 128, 1, 512),
            "dir_max_mb": num("dir_max_mb", 4096, 64, 262144),
            "per_conv_per_day": num("messages_per_conv_per_day", 300, 10, 5000),
            "per_ip_per_day": num("new_conv_per_ip_per_day", 10, 1, 200),
            # 上限 28 秒是【被 socket 超时限住的】,不是随手取的:BulwarkHTTPServer
            # 给每个连接设了 30 秒 conn_timeout,挂得比它久,客户端会先看到连接断开。
            "poll_wait": num("poll_wait_seconds", 25, 1, 28),
            "max_waiters": num("max_waiters", 64, 4, 512),
        }

    def _sup_ready(self, cfg):
        """功能是否可用。SUPPORT 为 None 表示建库失败(磁盘只读等),此时如实说
        不可用,而不是让每个请求各自抛一次 500。"""
        if SUPPORT is None or not cfg["enabled"]:
            self._send(503, {"ok": False, "error": "在线客服未启用"})
            return False
        return True

    def _sup_send(self, code, obj, set_token=None):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if set_token:
            # Path=/support:这个 cookie 只对客服的几条路由有意义,不必跟着每一次
            # 情报查询一起上路。HttpOnly:前端根本不需要读它 —— 令牌由浏览器自动
            # 带上,页面脚本拿不到,一次 XSS 也偷不走会话。
            self.send_header("Set-Cookie",
                             "bw_chat=%s; Path=/support; Max-Age=%d; HttpOnly; SameSite=Lax"
                             % (set_token, 30 * 86400))
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    def _sup_conv(self, cfg):
        """当前访客的会话(带读侧惰性过期)。没有就返回 None。"""
        tok = self._cookie("bw_chat")
        if not tok:
            return None
        return SUPPORT.get_conversation(tok, max_age_days=cfg["retention_days"])

    def _sup_open(self, cfg):
        """按需新建会话。返回 (conv, error)。

        刻意【不在打开页面时就建】:那样每个路过的爬虫都会留下一条空会话,既污染
        客服台的列表,也让「每 IP 每日上限」在真正有人要说话之前就用完了。
        第一次发消息或上传附件时才建。
        """
        ip = self.client_address[0] if self.client_address else ""
        token, mkey, err = SUPPORT.open_conversation(
            ip, ua_short(self.headers.get("User-Agent", "")),
            self.headers.get("Referer", ""), cfg["per_ip_per_day"],
            greeting=cfg["greeting"])
        if err:
            return None, err
        print("[support] new conversation from %s" % mask_ip(ip), flush=True)
        return SUPPORT.get_conversation(token), ""

    def _sup_agent_online(self):
        """客服台在 90 秒内有过心跳就算在线。访客页据此决定说「客服在线」还是
        「留言后会尽快回复」—— 显示一个假的「在线」比不显示更糟。"""
        try:
            seen = parse_iso(SUPPORT.kv_get("agent_seen_at", ""))
        except Exception:
            seen = None
        return bool(seen and seen > now_utc() - timedelta(seconds=90))

    def _serve_support_page(self):
        cfg = self._sup_cfg()
        if SUPPORT is None or not cfg["enabled"]:
            return self._send_bytes(503, "<!doctype html><meta charset=utf-8>"
                                    "<p>在线客服未启用。", "text/html; charset=utf-8")
        blob = json.dumps({
            "agent_name": cfg["agent_name"], "greeting": cfg["greeting"],
            "retention_days": cfg["retention_days"], "max_chars": cfg["max_chars"],
            "max_files": cfg["max_files"], "image_mb": cfg["image_mb"],
            "video_mb": cfg["video_mb"], "poll_wait": cfg["poll_wait"],
            # 没有任何客服凭证时,页面必须说实话:留言会存下来,但现在没人能回。
            # 显示一个假的「客服会尽快回复」比什么都不说更糟。
            "staffed": self._sup_staffed(),
        }, ensure_ascii=False).replace("<", "\\u003c").replace(">", "\\u003e") \
            .replace("&", "\\u0026")
        self._log_visit("/support")
        self._send_bytes(200, _SUPPORT_PAGE.replace("/*__CFG__*/null", blob)
                         .encode("utf-8"), "text/html; charset=utf-8")

    # ---- 客服身份 ----------------------------------------------------------- #
    #
    # 为什么客服台【不能只认 webui_password】:这台机器上根本没配 webui_password,
    # 整个控制台目前是公开可读的。如果客服台只认它,那么要让客服能回话就必须给
    # webui_password 赋值,而那会顺带把 / /engine /online /feedback 全部关到登录
    # 后面 —— 一个「上线客服」的需求不该顺手改掉其余五个页面的访问方式。
    #
    # 所以客服台自己有一把口令 support.agent_password,与 webui_password 并列:
    # 两者任一有效即放行。两者都没配则 fail closed —— 访客对话和访客上传的图片
    # 视频绝不能在公网无鉴权可读,这一点与 _serve_feedback_image 同一条推理。
    @staticmethod
    def _sup_agent_pw():
        return str((CONFIG.get("support", {}) or {}).get("agent_password", "") or "")

    @staticmethod
    def _sup_agent_digest(pw):
        # 与 webui 的推导刻意用不同前缀,这样两把口令即使设成同一个字符串,
        # 两个 cookie 也不通用 —— 一把口令泄露不会顺带成为另一处的凭证。
        return hashlib.sha256(("bwa_" + pw).encode()).hexdigest()[:32]

    def _sup_is_agent(self):
        """当前请求是不是客服。两条凭证任一成立即可。"""
        pw = self._webui_password()
        if pw and self._check_webui_cookie():
            return True
        apw = self._sup_agent_pw()
        if apw:
            got = self._cookie("bw_agent")
            if got and hmac.compare_digest(got, self._sup_agent_digest(apw)):
                return True
        return False

    def _sup_staffed(self):
        """客服台是否有可用凭证。没有就等于没人能回话 —— 访客页要据此说实话,
        而不是继续显示「客服会尽快回复」。"""
        return bool(self._webui_password() or self._sup_agent_pw())

    def _serve_support_login(self, error=""):
        err = ('<p class="err">' + error + '</p>') if error else ''
        html = ('''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>客服台 · 登录</title>
<style>
:root{--bg:#edf0f5;--pnl:#fff;--ln:#e4e7ec;--ink:#101828;--mut:#667085;
  --dim:#98a2b3;--acc:#2563eb;--mal:#d92d20;
  --sans:-apple-system,"Segoe UI",Roboto,"Microsoft YaHei",system-ui,sans-serif;
  --mono:"SFMono-Regular","Cascadia Mono",Consolas,Menlo,monospace}
*{box-sizing:border-box}
body{font:14px/1.6 var(--sans);display:flex;justify-content:center;
  align-items:center;min-height:100vh;margin:0;background:var(--bg);color:var(--ink)}
.box{background:var(--pnl);padding:34px 32px;border:1px solid var(--ln);width:352px;
  box-shadow:0 1px 2px rgba(16,24,40,.05),0 12px 32px rgba(16,24,40,.08)}
.mk{width:36px;height:36px;display:grid;place-items:center;background:var(--acc);
  color:#fff;font-size:18px;margin-bottom:16px;
  clip-path:polygon(22% 0,100% 0,100% 78%,78% 100%,0 100%,0 22%)}
h2{margin:0;font-size:16px;font-weight:800;letter-spacing:1.6px}
.sub{margin:5px 0 22px;color:var(--mut);font-size:11.5px;letter-spacing:.9px;
  font-family:var(--mono)}
label{display:block;font-size:10.5px;font-weight:700;color:var(--mut);
  letter-spacing:1.1px;margin-bottom:7px}
input[type=password]{width:100%;padding:12px 13px;border:1px solid var(--ln);
  border-left:2px solid var(--acc);background:var(--bg);color:var(--ink);
  font:14px var(--mono);letter-spacing:1px;outline:none}
input[type=password]:focus{border-color:var(--acc);
  box-shadow:0 0 0 3px rgba(37,99,235,.12)}
button{width:100%;padding:12px;background:var(--acc);color:#fff;border:none;
  font:700 13px/1 var(--sans);letter-spacing:1.2px;cursor:pointer;margin-top:14px}
button:hover{filter:brightness(1.1)}
.err{margin:0 0 14px;padding:9px 12px;font-size:12.5px;color:var(--mal);
  background:rgba(217,45,32,.07);border-left:2px solid var(--mal)}
.foot{margin-top:18px;font-size:10.5px;color:var(--dim);font-family:var(--mono)}
</style></head><body>
<div class="box">
<div class="mk">&#127911;</div>
<h2>BULWARK</h2>
<div class="sub">SUPPORT DESK</div>
''' + err + '''
<form method="POST" action="/support/admin/login">
<label for="pw">客服口令</label>
<input id="pw" type="password" name="password" placeholder="请输入口令" autofocus>
<button type="submit">进入客服台</button>
</form>
<div class="foot">仅授权人员访问</div>
</div></body></html>''')
        self._send_bytes(200, html.encode("utf-8"), "text/html; charset=utf-8")

    def _sup_admin_login(self):
        """客服台登录。口令是公开可提交的,所以走 per-IP 滑窗限流 —— 否则这就是
        一个不限速的在线爆破入口。"""
        if not self._throttle_ok():
            return
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length > 4096:
            self.close_connection = True
            return self._send(413, {"ok": False, "error": "too large"})
        raw = self.rfile.read(length) if length else b""
        form_pw = ""
        for part in raw.decode("utf-8", "replace").split("&"):
            kv = part.split("=", 1)
            if len(kv) == 2 and kv[0] == "password":
                form_pw = urllib.parse.unquote_plus(kv[1])
        apw = self._sup_agent_pw()
        wpw = self._webui_password()
        if apw and hmac.compare_digest(form_pw, apw):
            digest = self._sup_agent_digest(apw)
            self.send_response(302)
            self.send_header("Set-Cookie",
                             "bw_agent=%s; Path=/support; Max-Age=%d; HttpOnly; SameSite=Lax"
                             % (digest, 12 * 3600))
            self.send_header("Location", "/support/admin")
            self.end_headers()
            print("[support] agent signed in from %s" % mask_ip(
                self.client_address[0] if self.client_address else ""), flush=True)
            return
        if wpw and hmac.compare_digest(form_pw, wpw):
            # 也接受网页总口令,这样已经用它登录控制台的人不必再记第二个。
            self.send_response(302)
            self.send_header("Set-Cookie",
                             "bw_session=%s; Path=/; HttpOnly; SameSite=Strict"
                             % hashlib.sha256(("bw_" + wpw).encode()).hexdigest()[:32])
            self.send_header("Location", "/support/admin")
            self.end_headers()
            return
        return self._serve_support_login(error="口令错误")

    def _sup_admin_ok(self, as_json=True):
        """客服台的闸门,【必须 fail closed】。

        _check_webui_cookie() 在没配 webui_password 时一律放行 —— 那对「服务端自己
        生成的页面」是可接受的取舍,对「客户对话和客户上传的图片视频」不是同一件事。
        8787 是公网口,提交口又是公开的,两头一敞开,任何人都能翻别人的对话。
        """
        if not self._sup_staffed():
            msg = ("客服台未配置口令。请在 /etc/bulwark-intel/config.json 的 "
                   "support 段设置 agent_password（只影响客服台），"
                   "或设置顶层 webui_password（会同时给整个控制台加登录）。"
                   "在此之前，为避免公网无鉴权读取访客对话，客服台不予提供")
            if as_json:
                self._send(403, {"ok": False, "error": msg})
            else:
                self._send_bytes(403, "<!doctype html><meta charset=utf-8>"
                                 "<p>" + msg + "。", "text/html; charset=utf-8")
            return False
        if not self._sup_is_agent():
            if as_json:
                self._send(401, {"ok": False, "error": "unauthorized"})
            else:
                self._serve_support_login()
            return False
        return True

    def _serve_support_admin(self):
        cfg = self._sup_cfg()
        if not self._sup_admin_ok(as_json=False):
            return
        if SUPPORT is None or not cfg["enabled"]:
            return self._send_bytes(503, "<!doctype html><meta charset=utf-8>"
                                    "<p>在线客服未启用。", "text/html; charset=utf-8")
        SUPPORT.kv_set("agent_seen_at", iso(now_utc()))
        blob = json.dumps({
            "retention_days": cfg["retention_days"], "max_files": cfg["max_files"],
            "max_chars": cfg["max_chars"], "poll_wait": cfg["poll_wait"],
            "cursor": SUPPORT.max_message_id(),
        }, ensure_ascii=False)
        self._send_bytes(200, _SUPPORT_ADMIN_PAGE.replace("/*__CFG__*/null", blob)
                         .encode("utf-8"), "text/html; charset=utf-8")

    # ---- 附件 --------------------------------------------------------------- #
    def _sup_take_upload(self, conv, cfg):
        """把请求体流式写进附件目录。返回 (name, kind, error)。

        【不走 base64-in-JSON】,这一点与反馈截图刻意不同:一段 128MB 的视频,
        base64 后是 170MB,整份读进内存再解码,峰值 300MB 出头,而这个 unit 的
        MemoryMax 是 2G —— 几个人同时发就能把服务打成 OOM,而且谁都能发。
        改走 _read_upload 那条已经在样本上传上验证过的流式写盘路径,一次 1MiB,
        内存占用与文件大小无关。

        类型判定只看首部魔术字节。扩展名和 Content-Type 都是上传者说的话,
        在一个公开的口子上不能当依据。
        """
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length <= 0:
            return None, None, "空请求体"
        hard = max(cfg["image_mb"], cfg["video_mb"]) * 1024 * 1024
        if length > hard:
            # 【不读就拒】的时候必须让连接关掉:剩下的请求体还在管道里,复用这个
            # 连接会把视频字节当成下一个请求的起始行。
            self.close_connection = True
            return None, None, "文件过大（上限 %d MB）" % (hard // (1024 * 1024))
        budget = cfg["dir_max_mb"] * 1024 * 1024 - SUPPORT.media_dir_bytes()
        if length > budget:
            self.close_connection = True
            return None, None, "附件空间已满，请稍后再试"
        d = SUPPORT.media_dir
        try:
            os.makedirs(d, exist_ok=True)
        except OSError:
            pass
        tmp = os.path.join(d, ".up-%s.part" % uuid.uuid4().hex)
        head, got = b"", 0
        try:
            with open(tmp, "wb") as f:
                remaining = length
                while remaining > 0:
                    chunk = self.rfile.read(min(1024 * 1024, remaining))
                    if not chunk:
                        break
                    if len(head) < 160:
                        head += chunk[:160 - len(head)]
                    f.write(chunk)
                    remaining -= len(chunk)
                    got += len(chunk)
            if got != length:
                return None, None, "上传中断（收到 %d/%d 字节）" % (got, length)
            ext, _mime, kind = sniff_media(head)
            if not ext:
                return None, None, ("只支持图片（PNG/JPEG/GIF/WebP）"
                                    "与视频（MP4/MOV/WebM）")
            cap = (cfg["video_mb"] if kind == "video" else cfg["image_mb"]) * 1024 * 1024
            if got > cap:
                return None, None, ("%s超过 %d MB"
                                    % ("视频" if kind == "video" else "图片",
                                       cap // (1024 * 1024)))
            name = "sup-%s-%s.%s" % (conv["mkey"], uuid.uuid4().hex[:16], ext)
            dest = os.path.join(d, name)
            os.replace(tmp, dest)
            try:
                os.chmod(dest, 0o640)
            except OSError:
                pass
            return name, kind, ""
        except OSError as e:
            print("[support] upload write failed: %s" % e, flush=True)
            return None, None, "服务端写入失败"
        finally:
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except OSError:
                pass

    def _serve_support_media(self, u):
        """附件取回。【以会话令牌为能力凭证】。

        这里不能照搬 /feedback/img 的「只给 bw_session」:访客要能看见自己和客服
        刚刚交换的图片和视频,而访客手上永远不会有管理员 cookie。所以放行两种身份:
          · 带着本会话 bw_chat 令牌的访客(256 位随机,只能看自己那条对话)
          · 带着 bw_session 的客服

        文件名里带的是 mkey,不是 token 的任何一段 —— 否则每条媒体链接都等于把
        令牌的前 48 位写在地址栏里。
        """
        cfg = self._sup_cfg()
        if SUPPORT is None or not cfg["enabled"]:
            return self._send(404, {"ok": False, "error": "not found"})
        name = urllib.parse.unquote(u.path.rsplit("/", 1)[-1])
        # 白名单正则同时挡掉 .. 和 /:名字必须完全长成我们自己生成的样子。
        if not SUP_NAME_RE.match(name):
            return self._send(404, {"ok": False, "error": "not found"})
        conv = SUPPORT.conversation_by_mkey(name[4:16])
        if not conv:
            return self._send(404, {"ok": False, "error": "not found"})
        # 过期的对话连附件也不给看 —— 承诺是「3 天后没有」,清理任务万一没跑,
        # 读侧也要守住。
        last = parse_iso(conv.get("last_at") or "")
        if not last or last < now_utc() - timedelta(days=cfg["retention_days"]):
            return self._send(404, {"ok": False, "error": "not found"})
        if not (self._sup_is_agent() or self._cookie("bw_chat") == conv["token"]):
            return self._send(403, {"ok": False, "error": "forbidden"})
        path = os.path.join(SUPPORT.media_dir, name)
        try:
            size = os.path.getsize(path)
            fh = open(path, "rb")
        except OSError:
            return self._send(404, {"ok": False, "error": "not found"})
        mime = SUP_EXT_MIME.get(name.rsplit(".", 1)[-1], "application/octet-stream")
        try:
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(size))
            # nosniff + sandbox:即便有人设法存进了别的东西,浏览器也不准改主意
            # 按 HTML 解释它。与 /feedback/img 同一套头。
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Disposition", 'inline; filename="%s"' % name)
            self.send_header("Content-Security-Policy", "default-src 'none'; sandbox")
            self.send_header("Cache-Control", "private, max-age=600")
            self.end_headers()
            shutil.copyfileobj(fh, self.wfile, 256 * 1024)
        except OSError:
            pass
        finally:
            fh.close()

    # ---- 访客侧 API --------------------------------------------------------- #
    def _sup_get(self, u):
        cfg = self._sup_cfg()
        if not self._sup_ready(cfg):
            return
        rest = u.path[len("/support/api/"):]
        if rest == "session":
            conv = self._sup_conv(cfg)
            msgs = SUPPORT.messages(conv["token"]) if conv else []
            return self._sup_send(200, {"ok": True, "has": bool(conv),
                                        "agent_online": self._sup_agent_online(),
                                        "messages": msgs})
        if rest == "poll":
            conv = self._sup_conv(cfg)
            if not conv:
                # 409 而不是 404:前端据此重新初始化(会话过期或被清理了),
                # 而 404 会被当成「这个接口不存在」。
                return self._send(409, {"ok": False, "error": "no session"})
            try:
                after = int((urllib.parse.parse_qs(u.query).get("after") or ["0"])[0])
            except ValueError:
                after = 0
            rows, _ = self._sup_wait(conv["token"], after, cfg, admin=False)
            return self._sup_send(200, {"ok": True, "messages": rows,
                                        "agent_online": self._sup_agent_online()})
        return self._send(404, {"ok": False, "error": "unknown endpoint"})

    def _sup_wait(self, token, after, cfg, admin=False):
        """长轮询的公共入口,带并发闸门。

        ThreadingHTTPServer 一个连接一个线程,没有任何上限;若不限制同时挂着的
        轮询数,几百个连接就能把这台机器的线程和内存吃光 —— 而它还要同时扛信誉
        查询。超出闸门就立刻空手返回,前端会退化成短轮询,功能不坏,只是慢一点。
        """
        if SUP_WAIT is None or not SUP_WAIT.acquire(blocking=False):
            rows = (SUPPORT.admin_messages(after) if admin
                    else SUPPORT.messages(token, after))
            return rows, False
        try:
            return SUPPORT.wait_messages(token, after, cfg["poll_wait"], admin=admin)
        finally:
            SUP_WAIT.release()

    def _sup_post(self, u):
        cfg = self._sup_cfg()
        if not self._sup_ready(cfg):
            return
        if not self._throttle_ok():
            return
        rest = u.path[len("/support/api/"):]

        if rest == "upload":
            conv = self._sup_conv(cfg)
            new_token = None
            if not conv:
                conv, err = self._sup_open(cfg)
                if err:
                    self.close_connection = True
                    return self._send(429, {"ok": False, "error": err})
                new_token = conv["token"]
            name, kind, err = self._sup_take_upload(conv, cfg)
            if err:
                return self._sup_send(400, {"ok": False, "error": err}, new_token)
            print("[support] attachment %s (%s) from %s" % (
                name, kind, mask_ip(self.client_address[0] if self.client_address else "")),
                flush=True)
            return self._sup_send(200, {"ok": True, "name": name, "kind": kind},
                                  new_token)

        if rest == "send":
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length > 64 * 1024:      # 正文而已,附件是另一条路
                self.close_connection = True
                return self._send(413, {"ok": False, "error": "内容过长"})
            raw = self.rfile.read(length) if length else b""
            try:
                body = json.loads(raw.decode("utf-8", "replace")) if raw else {}
            except Exception:
                return self._send(400, {"ok": False, "error": "请求体不是合法 JSON"})
            if not isinstance(body, dict):
                return self._send(400, {"ok": False, "error": "请求体格式不对"})
            conv = self._sup_conv(cfg)
            new_token = None
            if not conv:
                conv, err = self._sup_open(cfg)
                if err:
                    return self._send(429, {"ok": False, "error": err})
                new_token = conv["token"]
            files = body.get("files") or []
            if not isinstance(files, list):
                files = []
            # 只接受【本会话】自己上传出来的文件名。mkey 前缀一核对,别人会话的
            # 附件就没法被引用进这条对话 —— 否则拿到一个文件名就能把它转贴到
            # 任意会话里。
            files = [str(x) for x in files
                     if SUP_NAME_RE.match(str(x)) and str(x)[4:16] == conv["mkey"]]
            mid, err = SUPPORT.add_message(
                conv["token"], "visitor", str(body.get("body", "")),
                media=files[: cfg["max_files"]],
                per_day_cap=cfg["per_conv_per_day"], max_chars=cfg["max_chars"])
            if err:
                return self._sup_send(400, {"ok": False, "error": err}, new_token)
            rows = SUPPORT.messages(conv["token"], mid - 1)
            return self._sup_send(200, {"ok": True, "id": mid, "messages": rows},
                                  new_token)

        return self._send(404, {"ok": False, "error": "unknown endpoint"})

    # ---- 客服侧 API --------------------------------------------------------- #
    def _sup_admin_get(self, u):
        cfg = self._sup_cfg()
        if not self._sup_admin_ok():
            return
        if not self._sup_ready(cfg):
            return
        SUPPORT.kv_set("agent_seen_at", iso(now_utc()))
        rest = u.path[len("/support/admin/api/"):]
        qs = urllib.parse.parse_qs(u.query)

        if rest == "list":
            convs = []
            for c in SUPPORT.list_conversations(limit=200):
                convs.append({"token": c["token"], "ip": mask_ip(c["ip"]),
                              "agent": c.get("agent", ""), "page": c.get("page", ""),
                              "created_at": c["created_at"], "last_at": c["last_at"],
                              "status": c["status"], "unread": c["unread"],
                              "msgs": c["msgs"], "preview": c["preview"]})
            st = SUPPORT.stats()
            st["media_mb"] = round(SUPPORT.media_dir_bytes() / 1048576.0, 1)
            return self._send(200, {"ok": True, "conversations": convs, "stats": st})

        if rest == "thread":
            token = (qs.get("token") or [""])[0]
            conv = SUPPORT.get_conversation(token)
            if not conv:
                return self._send(404, {"ok": False, "error": "会话不存在"})
            try:
                after = int((qs.get("after") or ["0"])[0])
            except ValueError:
                after = 0
            if not after:
                SUPPORT.mark_read(token)
            return self._send(200, {"ok": True, "messages":
                                    SUPPORT.messages(token, after)})

        if rest == "poll":
            try:
                after = int((qs.get("after") or ["0"])[0])
            except ValueError:
                after = 0
            rows, _ = self._sup_wait(None, after, cfg, admin=True)
            cursor = max([r["id"] for r in rows] + [after])
            return self._send(200, {"ok": True, "hit": bool(rows), "cursor": cursor})

        return self._send(404, {"ok": False, "error": "unknown endpoint"})

    def _sup_admin_post(self, u):
        cfg = self._sup_cfg()
        if not self._sup_admin_ok():
            return
        if not self._sup_ready(cfg):
            return
        SUPPORT.kv_set("agent_seen_at", iso(now_utc()))
        rest = u.path[len("/support/admin/api/"):]

        if rest == "upload":
            token = (urllib.parse.parse_qs(u.query).get("token") or [""])[0]
            conv = SUPPORT.get_conversation(token)
            if not conv:
                self.close_connection = True
                return self._send(404, {"ok": False, "error": "会话不存在"})
            name, kind, err = self._sup_take_upload(conv, cfg)
            if err:
                return self._send(400, {"ok": False, "error": err})
            return self._send(200, {"ok": True, "name": name, "kind": kind})

        length = int(self.headers.get("Content-Length", 0) or 0)
        if length > 64 * 1024:
            self.close_connection = True
            return self._send(413, {"ok": False, "error": "内容过长"})
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw.decode("utf-8", "replace")) if raw else {}
        except Exception:
            return self._send(400, {"ok": False, "error": "bad json"})
        if not isinstance(body, dict):
            return self._send(400, {"ok": False, "error": "bad json"})
        token = str(body.get("token", ""))
        conv = SUPPORT.get_conversation(token)
        if not conv:
            return self._send(404, {"ok": False, "error": "会话不存在"})

        if rest == "reply":
            files = body.get("files") or []
            if not isinstance(files, list):
                files = []
            files = [str(x) for x in files
                     if SUP_NAME_RE.match(str(x)) and str(x)[4:16] == conv["mkey"]]
            mid, err = SUPPORT.add_message(token, "agent", str(body.get("body", "")),
                                           media=files[: cfg["max_files"]],
                                           per_day_cap=0, max_chars=cfg["max_chars"])
            if err:
                return self._send(400, {"ok": False, "error": err})
            return self._send(200, {"ok": True, "id": mid,
                                    "messages": SUPPORT.messages(token, mid - 1)})

        if rest == "status":
            want = str(body.get("status", ""))
            ok = SUPPORT.set_status(token, want)
            if ok and want == "closed":
                SUPPORT.add_message(token, "system", "客服已结束本次会话",
                                    per_day_cap=0, max_chars=cfg["max_chars"])
            return self._send(200, {"ok": ok})

        return self._send(404, {"ok": False, "error": "unknown endpoint"})

    def _authed(self):
        token = CONFIG.get("auth_token", "")
        if not token:
            return True  # no token configured -> open (not recommended)
        auth = self.headers.get("Authorization", "")
        return auth == "Bearer " + token

    def _client_ip(self):
        return self.client_address[0] if self.client_address else ""

    @staticmethod
    def _in_whitelist(ip, wl):
        """精确匹配,外加【显式的】前缀写法。

        原来只有 `ip in wl`。家宽出口地址一变,白名单就静默失效 —— 线上实测正是这样:
        白名单里有一条 123.154.x,而实际吃到 429 的是同段的另一个地址。
        前缀必须以 '.' 或 '*' 结尾才算前缀,不做隐式判断:否则写 "1.2.3.4" 会把
        "1.2.3.40" 也放进来,那是把防滥用悄悄放宽,比不支持前缀更糟。
        """
        for e in wl:
            s = str(e or "").strip()
            if not s:
                continue
            if s.endswith("*"):
                if ip.startswith(s[:-1]):
                    return True
            elif s.endswith("."):
                if ip.startswith(s):
                    return True
            elif ip == s:
                return True
        return False

    def _refund_if_cached(self, res):
        """命中缓存的查询不该扣每 IP 名额 —— 它没花任何上游配额。

        为什么是「退」而不是「查完再判」:闸门必须在处理之前拦,否则一个 IP 就能靠
        海量请求把服务器本身拖垮,限流形同虚设。而请求处理完才知道是否命中缓存,所以
        只能先扣后退。

        这条修的是一个具体症状:批量查 35 个文件,前 20 个成功、第 21 个起被锁一小时
        (per_hour=20),而其中相当一部分本来是缓存命中、根本没碰 VT。
        """
        if THROTTLE is None or not isinstance(res, dict) or not res.get("cached"):
            return
        ip = self._client_ip()
        if ip and ip not in ("127.0.0.1", "::1"):
            THROTTLE.refund(ip)

    def _throttle_ok(self):
        ip = self._client_ip()
        _wl = (CONFIG.get("public_rate_limit", {}) or {}).get("whitelist", []) or []
        if THROTTLE is None or ip in ("127.0.0.1", "::1") or self._in_whitelist(ip, _wl):
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

    # ---- 反馈截图 ---------------------------------------------------------- #
    @staticmethod
    def _fb_img_dir():
        return CONFIG.get("feedback_images_dir", "/var/lib/bulwark-intel/feedback_img")

    @staticmethod
    def _fb_limits():
        """截图上限,全部可配。默认给到正常使用碰不到的程度。

        为什么不做成字面上的"无限":这个提交口是【公网 + 无鉴权】的,而请求体是
        整份读进内存再 base64 解码的,峰值内存约等于请求体的两倍。真去掉上限,
        一条请求就能把服务打成 OOM,而且谁都能发。
        所以给的是"宽到不碍事"而不是"没有":要更大就改这几个键。
          feedback.max_images     单条反馈的张数上限
          feedback.max_image_mb   单张上限
          feedback.max_body_mb    整个请求体上限(要容得下 base64 的 4/3 膨胀)
          feedback.dir_max_mb     截图目录总量闸门
        """
        fb = CONFIG.get("feedback", {}) or {}
        return {
            "count": max(1, min(int(fb.get("max_images", 20) or 20),
                                SERVICE.store.FEEDBACK_IMG_HARD_CAP)),
            "each": max(1, int(fb.get("max_image_mb", 32) or 32)) * 1024 * 1024,
            "body": max(1, int(fb.get("max_body_mb", 640) or 640)) * 1024 * 1024,
            "dir": max(1, int(fb.get("dir_max_mb", 4096) or 4096)) * 1024 * 1024,
        }

    def _drop_fb_images(self, names):
        """删掉一批截图文件。名字必须先过白名单正则 —— 这是唯一会 unlink 的地方。"""
        gone = 0
        for n in (names or []):
            if not IMG_NAME_RE.match(str(n)):
                continue
            try:
                os.remove(os.path.join(self._fb_img_dir(), str(n)))
                gone += 1
            except OSError:
                pass
        return gone

    @classmethod
    def _fb_dir_bytes(cls):
        d = cls._fb_img_dir()
        total = 0
        try:
            for n in os.listdir(d):
                try:
                    total += os.path.getsize(os.path.join(d, n))
                except OSError:
                    pass
        except OSError:
            return 0
        return total

    def _store_feedback_images(self, fid, items):
        """把 data-URL / 裸 base64 的截图落盘,返回真正写成功的文件名。

        每一步都是在替客户端说的话找反证:
          · 类型按魔术字节判,不看它给的 MIME,也不看扩展名
          · 文件名整个由服务端生成,用户输入一个字节都不参与 —— 没有拼接就没有
            路径穿越
          · 目录总量到顶就直接不收,不然公开提交口等于一个免费网盘
        """
        out = []
        d = self._fb_img_dir()
        try:
            os.makedirs(d, exist_ok=True)
        except OSError as e:
            print("[feedback] cannot create image dir %s: %s" % (d, e), flush=True)
            return out
        lim = self._fb_limits()
        budget = lim["dir"] - self._fb_dir_bytes()
        for i, raw in enumerate(items[: lim["count"]]):
            s = str(raw or "")
            if s.startswith("data:"):
                comma = s.find(",")
                if comma < 0:
                    continue
                s = s[comma + 1:]
            s = re.sub(r"\s+", "", s)
            try:
                data = base64.b64decode(s, validate=True)
            except Exception:
                continue
            if not data or len(data) > lim["each"]:
                continue
            if len(data) > budget:
                print("[feedback] image dir at capacity -> dropping attachment", flush=True)
                break
            ext, _mime = sniff_image(data)
            if not ext:
                continue          # 不是我们认得的位图容器 -> 丢掉,不落盘
            name = "fb%d-%d-%s.%s" % (int(fid), min(i, 9), uuid.uuid4().hex[:16], ext)
            try:
                with open(os.path.join(d, name), "wb") as f:
                    f.write(data)
                os.chmod(os.path.join(d, name), 0o640)
            except OSError as e:
                print("[feedback] image write failed: %s" % e, flush=True)
                continue
            budget -= len(data)
            out.append(name)
        return out

    def _serve_feedback_image(self, u):
        """截图只给带 bw_session 的管理员看。

        这一点是这个功能的主要遏制手段:上传口是公开的,但取回口不是,所以谁也
        不能拿这台服务器当图床来托管任意内容。"""
        # 【这一条必须 fail closed,不能沿用管理页的约定】。
        # _check_webui_cookie() 在没配 webui_password 时一律放行 —— 那对"服务端
        # 自己生成的 HTML"是可以接受的取舍,但对"任意用户上传的二进制"不是同一
        # 件事:8787 是公网口,上传又是公开无鉴权的,两头一敞开,这台机器就成了
        # 谁都能写、谁都能读的图床,而内容完全不受我们控制。
        # 实测过:不加这一段时,无 cookie 直接 GET 截图返回 200。
        if not self._webui_password():
            return self._send(403, {"ok": False, "error":
                                    "未设置 webui_password;为避免公网无鉴权读取"
                                    "用户上传内容,截图不予提供"})
        if not self._check_webui_cookie():
            return self._send(401, {"ok": False, "error": "unauthorized"})
        name = urllib.parse.unquote(u.path.rsplit("/", 1)[-1])
        # 白名单正则同时挡掉 .. 和 /:名字必须完全长成我们自己生成的样子。
        if not IMG_NAME_RE.match(name):
            return self._send(404, {"ok": False, "error": "not found"})
        path = os.path.join(self._fb_img_dir(), name)
        if not os.path.isfile(path):
            return self._send(404, {"ok": False, "error": "not found"})
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            return self._send(404, {"ok": False, "error": "not found"})
        mime = IMG_EXT_MIME.get(name.rsplit(".", 1)[-1], "application/octet-stream")
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        # nosniff:即便有人设法存进了别的东西,浏览器也不准改主意按 HTML 解释它。
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Disposition", 'inline; filename="%s"' % name)
        self.send_header("Content-Security-Policy", "default-src 'none'; sandbox")
        self.send_header("Cache-Control", "private, max-age=600")
        self.end_headers()
        try:
            self.wfile.write(data)
        except OSError:
            pass

    @staticmethod
    def _secondary_only_payload(h, r):
        """VT has no record but other clouds do. Returns a 200 payload, or None so
        the caller falls through to its normal 404.

        vt_lookup has to keep ok=False on a VT 404 (harvest.py's upload trigger keys
        on it), so without this the API would answer "not found" while holding a
        perfectly good 微步/OTX verdict in its hand."""
        if not r.get("vt_unknown") or int(r.get("sources_ok") or 0) <= 0:
            return None
        rep = r.get("report") or {}
        return {"ok": True, "hash": h, "vt_unknown": True, "degraded": True,
                "verdict": r.get("verdict", "unknown"),
                "malicious": r.get("malicious", 0),
                "total_engines": r.get("total_engines", 0),
                "sources_ok": int(r.get("sources_ok") or 0),
                "sources": rep.get("sources", []),
                "note": "VirusTotal 无此文件记录;结论来自其他威胁情报云"}

    def _api_get(self, u, info):
        rest = u.path[len("/api/v1/"):]
        if rest.startswith("hash/"):
            h = rest[len("hash/"):].strip().lower()
            if not re.match(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$", h):
                return self._send(400, {"ok": False, "error": "invalid hash (md5/sha1/sha256)"})
            r = SERVICE.vt_lookup(h, False)
            if not r.get("ok"):
                alt = self._secondary_only_payload(h, r)
                if alt:
                    return self._send(200, alt)
                return self._send(404, {"ok": False, "error": r.get("error", "not found")})
            return self._send(200, self._api_hash_summary(r))
        if rest.startswith("file/"):
            h = rest[len("file/"):].strip().lower()
            if not re.match(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$", h):
                return self._send(400, {"ok": False, "error": "invalid hash"})
            r = SERVICE.vt_lookup(h, False)
            if not r.get("ok"):
                alt = self._secondary_only_payload(h, r)
                if alt:
                    return self._send(200, alt)
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
                alt = self._secondary_only_payload(h, r)
                if alt:
                    return self._send(200, alt)
                return self._send(404, {"ok": False, "error": r.get("error", "not found")})
            return self._send(200, self._api_hash_summary(r))
        return self._send(404, {"ok": False, "error": "unknown endpoint; see /api/docs"})

    # --------------------------------------------------- 在线更新(公开接口) #
    # 客户端「软件内更新」用的两个接口。两者都刻意放在 _authed() 闸门【之前】:
    # 发布包里 ReputationProxy.BearerToken 是空的,放到闸门之后等于「只有持令牌的
    # 人能检查更新」,而那恰恰是唯一一批不需要这个功能的人。
    #
    # 服务器侧的目录约定(文件由 scripts/make-update-package.ps1 生成后手工投放,
    # 本进程只读不写):
    #     <app 目录>/update/<channel>/manifest.json
    #     <app 目录>/update/<channel>/<载荷文件>
    #
    # 这里【不做签名】,也不需要:签名在文件自身(Authenticode),由客户端按编译期
    # 钉死的证书指纹校验(见 cpp/shared/include/bulwark/UpdateTrust.h)。服务器只是
    # 分发点 —— 这正是「服务器被拿下也决定不了客户端装什么」的原因。清单里的哈希由
    # 服务器现算(带 mtime 缓存),这样「清单说 X、文件是 Y」这一类陈旧不一致压根
    # 不可能出现;它不是安全边界,安全边界是客户端那道指纹校验。
    _UPDATE_CHANNELS = ("stable", "beta")
    _UPDATE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    _update_hash_cache = {}   # path -> (size, mtime_ns, sha256)

    def _update_dir(self, channel):
        if channel not in self._UPDATE_CHANNELS:
            return None
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), "update", channel)

    def _update_file_sha256(self, path, st):
        """SHA-256,按 (size, mtime) 缓存。投放新文件时 mtime 变化即自动失效。"""
        key = path
        cached = self._update_hash_cache.get(key)
        if cached and cached[0] == st.st_size and cached[1] == st.st_mtime_ns:
            return cached[2]
        import hashlib
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                b = f.read(1024 * 1024)
                if not b:
                    break
                h.update(b)
        digest = h.hexdigest()
        self._update_hash_cache[key] = (st.st_size, st.st_mtime_ns, digest)
        return digest

    def _update_manifest_obj(self, channel):
        """读 manifest.json 并用磁盘真实状态收敛 files[]。返回 (obj, error)。"""
        d = self._update_dir(channel)
        if not d:
            return None, "unknown channel"
        try:
            with open(os.path.join(d, "manifest.json"), "rb") as f:
                man = json.loads(f.read().decode("utf-8"))
        except OSError:
            return None, "no release published"
        except (ValueError, UnicodeDecodeError) as e:
            return None, "manifest unreadable: %s" % e
        if not isinstance(man, dict):
            return None, "manifest is not an object"

        files = []
        missing = []
        for item in (man.get("files") or []):
            name = str((item or {}).get("name", "")).strip()
            # 清单是人工投放的文本,这里当不可信输入处理:名字不合规就丢掉,
            # 绝不拼进路径。否则一个 "../../etc/passwd" 就能把任意文件读出去。
            if not self._UPDATE_NAME_RE.match(name):
                continue
            p = os.path.join(d, name)
            try:
                st = os.stat(p)
            except OSError:
                missing.append(name)
                continue
            if not os.path.isfile(p):
                missing.append(name)
                continue
            files.append({"name": name, "size": st.st_size,
                          "sha256": self._update_file_sha256(p, st),
                          "url": "/v1/update/file/%s/%s" % (channel, name)})
        # 少一个文件就不算一次可用的更新:半套载荷装上去,机器上就是一个新 exe
        # 配旧驱动的组合 —— 那种状态比不更新危险得多。宁可整份不发布。
        if missing:
            return None, "incomplete release (missing: %s)" % ",".join(sorted(missing))
        if not files:
            return None, "release lists no usable files"

        out = {
            "ok": True,
            "available": True,
            "channel": channel,
            "version": str(man.get("version", "")).strip(),
            "label": str(man.get("label", "")).strip(),
            "published": str(man.get("published", "")).strip(),
            "notes": str(man.get("notes", "")),
            "files": files,
            "totalBytes": sum(f["size"] for f in files),
        }
        if not out["version"]:
            return None, "manifest has no version"
        return out, None

    def _serve_update_manifest(self, u):
        qs = urllib.parse.parse_qs(u.query or "")
        channel = (qs.get("channel") or ["stable"])[0].strip().lower()
        man, err = self._update_manifest_obj(channel)
        if err:
            # 三种情况必须回三种码,否则客户端只能笼统地说「检查更新失败」:
            #   200 还没发布任何版本 —— 这是正常状态,不是错误。用 404/5xx 表达它,
            #       会与「网络不通 / 端点配错」在客户端侧混成同一个现象。
            #   400 channel 传错 —— 客户端的错。回 5xx 会让它显示成「服务器不可用」,
            #       于是有人去查服务器,而问题在请求里。
            #   503 发布内容自身有问题(清单缺文件/版本号为空)—— 确实是服务端的事,
            #       且是【暂时】的:补齐文件即恢复,所以 503 而不是 500。
            if err == "no release published":
                return self._send(200, {"ok": True, "available": False,
                                        "channel": channel, "reason": err})
            code = 400 if err == "unknown channel" else 503
            return self._send(code, {"ok": False, "available": False,
                                     "channel": channel, "reason": err})
        return self._send(200, man)

    def _serve_update_file(self, u):
        # /v1/update/file/<channel>/<name>
        rest = u.path[len("/v1/update/file/"):]
        parts = [p for p in rest.split("/") if p != ""]
        if len(parts) != 2:
            return self._send(400, {"ok": False, "error": "need /v1/update/file/<channel>/<name>"})
        channel, name = parts[0].strip().lower(), urllib.parse.unquote(parts[1]).strip()
        if channel not in self._UPDATE_CHANNELS or not self._UPDATE_NAME_RE.match(name):
            return self._send(400, {"ok": False, "error": "bad channel or name"})
        # 只允许下载【当前清单里列出的】文件。比单纯的文件名正则更强:即便有人往
        # update/ 目录里放了别的东西,也不会因为这个接口而变成可下载的。
        man, err = self._update_manifest_obj(channel)
        if err:
            return self._send(404, {"ok": False, "error": err})
        entry = next((f for f in man["files"] if f["name"].lower() == name.lower()), None)
        if not entry:
            return self._send(404, {"ok": False, "error": "not part of the published release"})
        path = os.path.join(self._update_dir(channel), entry["name"])
        # realpath 兜底:即使上面的校验被绕过,也不允许把 update/ 之外的文件送出去。
        root = os.path.realpath(self._update_dir(channel))
        real = os.path.realpath(path)
        if not (real == root or real.startswith(root + os.sep)):
            return self._send(400, {"ok": False, "error": "path escapes the update directory"})
        try:
            f = open(real, "rb")
        except OSError:
            return self._send(404, {"ok": False, "error": "file unavailable"})
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(entry["size"]))
            self.send_header("Content-Disposition",
                             'attachment; filename="%s"' % entry["name"])
            # 客户端会自己按清单里的 sha256 校验,缓存只会带来「更新了却拿到旧文件」
            # 这种最难查的故障,直接禁掉。
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Bulwark-Sha256", entry["sha256"])
            self.end_headers()
            shutil.copyfileobj(f, self.wfile)
        except OSError:
            pass
        finally:
            f.close()
        return None

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
        # ---- 在线客服 -----------------------------------------------------
        # 顺序是承重的:更长的前缀必须先判,否则 /support/admin/api/* 会被
        # /support/admin 吃掉、/support/media/* 会被 /support 吃掉。
        # 整组都放在 _authed() 闸门【之前】—— 访客侧不可能带 Bearer token,
        # 放在闸门之后等于这个功能只有管理员能用,那就不叫客服了。
        if u.path.startswith("/support/media/"):
            return self._serve_support_media(u)
        if u.path.startswith("/support/admin/api/"):
            return self._sup_admin_get(u)
        if u.path in ("/support/admin", "/support/admin/"):
            return self._serve_support_admin()
        if u.path.startswith("/support/api/"):
            return self._sup_get(u)
        if u.path in ("/support", "/support/", "/kefu"):
            return self._serve_support_page()
        if u.path in ("/online", "/online/", "/clients"):
            return self._serve_online()
        if u.path in ("/feedback/mine", "/feedback/mine/"):
            # 提交者查看自己提交过什么、处理到哪一步了。公开可访问,但只按调用方
            # 的 IP 返回,且不含 contact/ip/agent —— 详见 list_feedback_by_ip。
            ip_now = self.client_address[0] if self.client_address else ""
            return self._send(200, {"ok": True, "ip": mask_ip(ip_now),
                                    "items": SERVICE.store.list_feedback_by_ip(ip_now)})
        if u.path.startswith("/feedback/img/"):
            # 反馈截图。同样要网页口令 —— 上传公开,取回不公开。
            # 放在 /feedback 判断【之前】,否则会被上面的前缀匹配吃掉。
            return self._serve_feedback_image(u)
        if u.path in ("/feedback", "/feedback/"):
            # 与 /online 同级:页面本身要网页口令,而 POST /feedback(提交)是公开的。
            self._log_visit("/feedback")
            return self._serve_feedback()
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
        # ---- 在线更新(公开:发布包不带令牌,见 _serve_update_manifest 的说明)----
        if u.path in ("/v1/update/manifest", "/v1/update/manifest/"):
            return self._serve_update_manifest(u)
        if u.path.startswith("/v1/update/file/"):
            return self._serve_update_file(u)
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
                                    "feedback": SERVICE.store.feedback_stats(),
                                    "quota_today": {
                                        "VirusTotal": SERVICE.store.quota_used("VirusTotal"),
                                        "ThreatBook": SERVICE.store.quota_used("ThreatBook")}})
        if u.path == "/vt/reports":
            return self._send(200, {"count": SERVICE.store.vt_report_count(),
                                    "reports": SERVICE.list_vt_reports(),
                                    "stats": SERVICE.store.archive_stats(),
                                    "silverfox": SERVICE.store.list_silverfox()})
        if u.path == "/benign/reports":
            # 正常样本区。与 /vt/reports 对称,同样坐在 _authed() 闸门之后。
            # 干净文件刻意不进 vt_reports(否则威胁计数/家族分布全失真,见 LOOKUP_DDL
            # 处说明),而是单独存在 benign_reports,这里单独出一份清单给网页展示。
            bstats = SERVICE.store.benign_stats()
            return self._send(200, {"count": bstats.get("total", 0),
                                    "reports": SERVICE.list_benign_reports(),
                                    "stats": bstats})
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
        # ---- 在线客服 --------------------------------------------------------
        # 同样刻意放在 _authed() 之前,理由与下面的反馈提交一样。
        if u.path == "/support/admin/login":
            return self._sup_admin_login()
        if u.path.startswith("/support/admin/api/"):
            return self._sup_admin_post(u)
        if u.path.startswith("/support/api/"):
            return self._sup_post(u)
        # ---- 用户反馈提交 ----------------------------------------------------
        # 刻意放在 _authed() 之前:提交反馈的是普通用户,浏览器 fetch 不带 Bearer
        # token,放在闸门之后等于这个功能只有管理员能用,反馈就永远收不到。
        # 代价是它对外完全开放,所以 per-IP 滑窗限流 + Store 里的每日条数上限
        # 与长度上限一起构成防滥用,三者缺一不可。
        if u.path in ("/feedback", "/api/feedback"):
            if not self._throttle_ok():
                return
            length = int(self.headers.get("Content-Length", 0) or 0)
            # 截图走 JSON 里的 base64,所以这个上限必须容得下 3 张 2MB 的图再乘
            # base64 的 4/3 膨胀,留点余量 = 9MB。刻意不改成 multipart:多写一个
            # 解析器就是在公开无鉴权的口子上多开一片攻击面,而 base64 的解码路径
            # 是标准库里久经考验的那一条。
            lim = self._fb_limits()
            if length > lim["body"]:
                return self._send(413, {"ok": False, "error":
                                        "内容过长(整份提交上限 %d MB,可调 feedback.max_body_mb)"
                                        % (lim["body"] // (1024 * 1024))})
            raw = self.rfile.read(length) if length else b""
            try:
                body = json.loads(raw.decode("utf-8", "replace")) if raw else {}
            except Exception:
                return self._send(400, {"ok": False, "error": "请求体不是合法 JSON"})
            if not isinstance(body, dict):
                return self._send(400, {"ok": False, "error": "请求体格式不对"})
            imgs_in = body.get("images") or []
            if not isinstance(imgs_in, list):
                imgs_in = []
            ip_now = self.client_address[0] if self.client_address else ""
            # 先建记录拿到 id(文件名要带 id 才能一眼看出属于谁),再落盘,最后把
            # 文件名回填。顺序反过来的话,一条被每日上限拒掉的提交仍然已经把图
            # 写进了盘,而且没有任何记录引用它 —— 那就是永久垃圾。
            fid, err = SERVICE.store.add_feedback(
                ip_now,
                str(body.get("kind", "other")),
                str(body.get("contact", "")),
                str(body.get("message", "")),
                ua_short(self.headers.get("User-Agent", "")),
                str(body.get("page", "")),
                images=["pending"] * min(len(imgs_in), lim["count"]))
            if err:
                return self._send(400, {"ok": False, "error": err})
            names = self._store_feedback_images(fid, imgs_in) if imgs_in else []
            SERVICE.store.set_feedback_images(fid, names)
            SERVICE.store.counter_incr("feedback_received")
            if names:
                SERVICE.store.counter_incr("feedback_images", len(names))
            print("[feedback] #%d from %s (%d img): %s" % (
                fid, mask_ip(ip_now), len(names),
                str(body.get("message", ""))[:80].replace("\n", " ")), flush=True)
            return self._send(200, {"ok": True, "id": fid, "images": len(names),
                                    "images_rejected": max(0, len(imgs_in) - len(names))})
        if u.path == "/feedback/status":
            # 管理动作(标记已处理 / 删除)。走网页口令而不是 Bearer token ——
            # 管理员是在浏览器里点的,身上只有 bw_session cookie。
            if not self._check_webui_cookie():
                return self._send(401, {"ok": False, "error": "unauthorized"})
            length = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(length) if length else b""
            try:
                body = json.loads(raw.decode("utf-8", "replace")) if raw else {}
            except Exception:
                return self._send(400, {"ok": False, "error": "bad json"})
            fid = int(body.get("id", 0) or 0)
            act = str(body.get("action", ""))
            if act == "delete":
                ok, imgs = SERVICE.store.delete_feedback(fid)
                return self._send(200, {"ok": ok, "images_removed": self._drop_fb_images(imgs)})
            if act in ("new", "done"):
                reply = body.get("reply")
                ok, drop = SERVICE.store.set_feedback_status(
                    fid, act, None if reply is None else str(reply))
                # 标为已处理 -> 截图使命结束,立即删盘。数据库里的引用已在 Store
                # 里清空,所以不会留下指向不存在文件的记录。
                return self._send(200, {"ok": ok, "images_removed": self._drop_fb_images(drop)})
            return self._send(400, {"ok": False, "error": "unknown action"})
        if not self._authed():
            return self._send(401, {"error": "unauthorized"})
        # 会真的花掉共享上游配额的两条路照旧先过 per-IP 滑窗。
        # /v1/reputation/hash 【不在这里判】—— 它的闸门推迟到读出 lookupOnly 之后(见下),
        # 因为「只查收录」的查询不限次数。
        if u.path in ("/vt/upload", "/vt/lookup") and not self._throttle_ok():
            return
        length = int(self.headers.get("Content-Length", 0) or 0)
        # Binary sample upload -> read raw bytes (no JSON). Filename via ?name=<urlencoded>.
        if u.path == "/vt/upload":
            st, obj = self._read_upload(u)
            return self._send(st, obj)
        # JSON 体一律限长。这条以前靠「读之前先限流」间接兜着,现在只读收录的查询不再限次数,
        # 就得自己挡住「一个请求声明 4GB 体长」这种最省事的打法。这些 JSON 体最大也就几百字节。
        if length > 64 * 1024:
            return self._send(413, {"error": "payload too large"})
        raw = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(raw or b"{}")
        except Exception:
            return self._send(400, {"error": "invalid json"})
        if u.path == "/v1/reputation/hash":
            sha = str(payload.get("sha256", "")).strip()
            if not SHA256_RE.match(sha):
                return self._send(400, {"error": "invalid sha256"})
            # 只查收录、不要动服务端上游。三种写法任一成立即生效:
            #   lookupOnly(新客户端的常态模式)/ cacheOnly(老客户端配额耗尽时就在发)/
            #   X-Cache-Only 头(纯 header 型调用方)。
            # 认 cacheOnly 是刻意的:那个字段本来就承诺「绝不动用付费上游」,此前服务端不读它
            # 才让承诺落空;现在一并兑现,老客户端无需升级即可停止烧共享配额。
            lookup_only = (bool(payload.get("lookupOnly", False))
                           or bool(payload.get("cacheOnly", False))
                           or str(self.headers.get("X-Cache-Only", "")).strip() == "1")
            # 【只查收录 = 不限次数】。
            #
            # per-IP 滑窗存在的理由只有一个:别让一个 IP 把机队共用的付费上游配额烧光。
            # 而 lookup_only 的请求根本不碰上游 —— 它就是一次 sha256 主键的 SQLite 查询,
            # 命中就答、不命中就回 recorded=false。对这种请求限次数是在拿唯一一条【免费】通路
            # 去省【付费】通路的钱,方向是反的:每挡掉一次「服务器收录了吗」,换来的都是客户端
            # 多烧一次自己的 VirusTotal 免费额度(4/min、500/天),而超限的代价更离谱 ——
            # 回 429 且 retry_after_seconds=3600,整整一小时里云查全部退回纯本地。
            #
            # 仍然守住的部分:会触达上游的查询(lookup_only 为假)、/vt/lookup、/vt/upload
            # 照旧限流,JSON 体限长在上面。
            if not lookup_only and not self._throttle_ok():
                return
            SERVICE.store.touch_client(self.client_address[0] if self.client_address else "",
                                       self._client_id())
            res = SERVICE.reputation_hash(sha, lookup_only)
            if not lookup_only:
                # 只有真的扣过名额才谈退还。lookup_only 压根没扣,这里若照退,弹掉的是【别的
                # 并发请求】刚记下的那个时间戳 —— 等于凭一串只读查询把限流额度洗掉。
                self._refund_if_cached(res)
            return self._send(200, res)
        if u.path == "/vt/lookup":
            h = str(payload.get("hash", "")).strip().lower()
            if not re.match(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$", h):
                return self._send(400, {"ok": False, "error": "invalid hash (need md5/sha1/sha256)"})
            res = SERVICE.vt_lookup(h, bool(payload.get("refresh", False)))
            self._refund_if_cached(res)
            return self._send(200, res)
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

    # 对端提前挂断不是错误,不该印 20 行 traceback。
    #
    # 实测:一个扫描器 GET / 之后在服务端还在写那 131 KB 控制台页时就断开,sendall 抛
    # ConnectionReset,socketserver 默认把整段调用栈打进 journal。一次访问三条 traceback。
    #
    # 这件事本身无害(死的只是那一个线程,服务照常),但它会毁掉一个判据:部署守卫用
    # 「重启以来 traceback 数为 0」当健康门,而这条门此后随时会被一个路过的扫描器按下 ——
    # 那正是本项目最不想要的「假失败」。所以把断连这一类收敛成一行,其余异常【原样保留】
    # 完整调用栈:真的 bug 绝不能被这个开关顺手藏掉。
    _QUIET_ERRORS = (BrokenPipeError, ConnectionResetError, ConnectionAbortedError,
                     TimeoutError, ssl.SSLEOFError, ssl.SSLZeroReturnError)

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, self._QUIET_ERRORS):
            print("%s - client went away mid-response (%s)"
                  % (client_address[0] if client_address else "?",
                     type(exc).__name__), flush=True)
            return
        super().handle_error(request, client_address)


def main():
    global SERVICE, CONFIG, THROTTLE, SUPPORT, SUP_WAIT
    CONFIG = load_config()
    SERVICE = IntelService(CONFIG)
    _prl = CONFIG.get("public_rate_limit", {}) or {}
    THROTTLE = IPThrottle(int(_prl.get("per_minute", 60)), int(_prl.get("per_hour", 600)))

    # ---- 在线客服 ---------------------------------------------------------- #
    # 独立的数据库文件,默认放在 db_path 旁边(那是这个 unit 唯一可写的目录:
    # ProtectSystem=strict + ReadWritePaths=/var/lib/bulwark-intel)。
    # 建库失败【不能让整个服务起不来】—— 情报查询是主业,客服是附加功能,
    # 后者的磁盘问题不该把前者一起拖下线。
    _sup = CONFIG.get("support", {}) or {}
    if _sup.get("enabled", True):
        _state = os.path.dirname(CONFIG["db_path"]) or "/var/lib/bulwark-intel"
        try:
            SUPPORT = SupportStore(
                _sup.get("db_path") or os.path.join(_state, "support.db"),
                _sup.get("media_dir") or os.path.join(_state, "support_media"))
            try:
                _mw = max(4, min(512, int(_sup.get("max_waiters", 64))))
            except (TypeError, ValueError):
                _mw = 64
            SUP_WAIT = threading.BoundedSemaphore(_mw)
            print("support desk ready (db=%s, media=%s, waiters=%d)"
                  % (SUPPORT.path, SUPPORT.media_dir, _mw), flush=True)
        except Exception as e:
            SUPPORT, SUP_WAIT = None, None
            print("support desk DISABLED: %s: %s" % (type(e).__name__, e), flush=True)
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
