"""Bulwark master-side dashboard (node-local, stdlib only).

The receiving end's view. The harvesting node's dashboard shows what IT sent; this
shows what the master actually took in, and from whom:

    /            总览      inventory size, today's intake, quota
    /ingest      入库批次   every push recorded in ingest_log.jsonl
    /nodes       来源节点   per-source-node contribution
    /inventory   库存      growth by day, verdict mix, top families, source quota

Provenance comes from /var/lib/bulwark-intel/ingest_log.jsonl, written by
bulwark-ingest.py. It has to: vt_reports carries no origin column, so without the
ledger the master cannot tell which rows arrived from a satellite and which it
looked up itself. Rows older than the ledger are therefore unattributable, and
this page says so rather than guessing.

Separate service, not new routes in app.py: app.py is byte-identical across nodes
and must never go down for a reporting feature. cache.db is opened read-only.

Auth: a bearer token is REQUIRED. The master holds every hash and every quota
level; there is no unauthenticated mode.
"""
import json
import os
import re
import sqlite3
import subprocess
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONFIG_PATH = os.environ.get("BULWARK_INTEL_CONFIG", "/etc/bulwark-intel/config.json")
DASH_CONFIG = os.environ.get("BULWARK_MDASH_CONFIG", "/etc/bulwark-intel/master_dashboard.json")
LISTEN_HOST = os.environ.get("BULWARK_MDASH_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("BULWARK_MDASH_PORT", "8789"))
STATE_DIR = "/var/lib/bulwark-intel"
INGEST_LOG = os.path.join(STATE_DIR, "ingest_log.jsonl")
SOURCES = ("VirusTotal", "MalwareBazaar", "ThreatBook", "OTX",
           "MetaDefender", "HybridAnalysis")


def now_utc():
    return datetime.now(timezone.utc)


def today():
    return now_utc().strftime("%Y-%m-%d")


def load_json(path, default=None):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default if default is not None else {}


def cfg():
    return load_json(CONFIG_PATH, {})


def dash_token():
    t = os.environ.get("BULWARK_MDASH_TOKEN") or load_json(DASH_CONFIG, {}).get("token", "")
    return str(t or "").strip()


def db_path():
    return cfg().get("db_path", os.path.join(STATE_DIR, "cache.db"))


def db():
    c = sqlite3.connect("file:%s?mode=ro" % db_path(), uri=True, timeout=5)
    c.execute("PRAGMA busy_timeout=4000")
    c.row_factory = sqlite3.Row
    return c


_CACHE = {}


def cached(key, ttl, fn):
    """The browser polls; COUNT(*) over a multi-hundred-MB cache.db and systemctl
    shell-outs should not run on every request. Racing duplicates are harmless."""
    hit = _CACHE.get(key)
    now = time.monotonic()
    if hit and now - hit[0] < ttl:
        return hit[1]
    val = fn()
    _CACHE[key] = (now, val)
    return val


def sysd(args, timeout=10):
    def run():
        try:
            r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
            return (r.stdout or "").strip()
        except Exception:
            return ""
    return cached("sysd:" + " ".join(args), 5.0, run)


def batches(limit=0):
    """ingest_log.jsonl, newest first. One record per push attempt."""
    def run():
        try:
            with open(INGEST_LOG, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except Exception:
            return []
        out = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            out.append({
                "ts": d.get("ts", ""), "peer": d.get("peer", "") or "?",
                "ok": bool(d.get("ok")),
                "received": int(d.get("received", 0) or 0),
                "inserted": int(d.get("inserted", 0) or 0),
                "skipped": int(d.get("skipped", 0) or 0),
                "malformed": int(d.get("malformed", 0) or 0),
                "total": int(d.get("total", 0) or 0),
                "kb": round(float(d.get("kb", 0) or 0), 1),
                "oldest": d.get("oldest", ""), "newest": d.get("newest", ""),
                "new_count": int(d.get("new_count", 0) or 0),
                "new": d.get("new") or [],
                "error": d.get("error", ""),
                "empty": bool(d.get("empty")),
            })
        out.reverse()
        return out
    all_ = cached("ledger", 4.0, run)
    return all_[:limit] if limit else all_


def head_ctx():
    return {
        "now": now_utc().strftime("%Y-%m-%d %H:%M:%S"),
        "node": os.uname().nodename,
        "u": {
            "intel": sysd(["systemctl", "is-active", "bulwark-intel"]),
            "harvest_timer": sysd(["systemctl", "is-active", "bulwark-harvest.timer"]),
            "harvest_enabled": sysd(["systemctl", "is-enabled", "bulwark-harvest.timer"]),
        },
    }


def quota_today():
    q = {}
    with db() as conn:
        for r in conn.execute("SELECT source,count FROM quota WHERE day=?", (today(),)):
            q[r["source"]] = r["count"]
    return q


def caps():
    c = cfg()
    out = {}
    vt = c.get("virustotal", {}) or {}
    nk = max(1, len([k for k in (str(x).split(":")[0].strip()
                                 for x in vt.get("api_keys", []) or []) if len(k) == 64]))
    out["VirusTotal"] = int(vt.get("requests_per_day", 0) or 0) * nk
    out["_vt_keys"] = nk
    for key, name in (("malwarebazaar", "MalwareBazaar"), ("threatbook", "ThreatBook"),
                      ("otx", "OTX"), ("metadefender", "MetaDefender"),
                      ("hybridanalysis", "HybridAnalysis")):
        s = c.get(key) or {}
        out[name] = int(s.get("requests_per_day", 0) or 0) if isinstance(s, dict) else 0
    return out


def attribution():
    """Which hashes the ledger can prove came from a satellite. `new` is capped per
    line by bulwark-ingest.py, so listed < counted on very large batches; both are
    reported instead of pretending the list is complete."""
    def run():
        per = {}
        listed = counted = 0
        seen = set()
        for b in batches():
            p = per.setdefault(b["peer"], {"listed": set(), "counted": 0})
            p["counted"] += b["new_count"]
            for h in b["new"]:
                p["listed"].add(h)
                seen.add(h)
            counted += b["new_count"]
        for p in per.values():
            p["listed"] = len(p["listed"])
        listed = len(seen)
        return {"per": per, "listed": listed, "counted": counted}
    return cached("attr", 6.0, run)


def inventory_stats():
    def run():
        out = {"total": 0, "today": 0, "per_day": [], "verdicts": {}, "families": [],
               "db_bytes": 0, "tables": {}, "err": ""}
        try:
            out["db_bytes"] = os.path.getsize(db_path())
        except OSError:
            pass
        try:
            with db() as conn:
                out["total"] = conn.execute("SELECT COUNT(*) FROM vt_reports").fetchone()[0]
                out["today"] = conn.execute(
                    "SELECT COUNT(*) FROM vt_reports WHERE substr(stored_at,1,10)=?",
                    (today(),)).fetchone()[0]
                for r in conn.execute(
                        "SELECT substr(stored_at,1,10) d, COUNT(*) n FROM vt_reports "
                        "GROUP BY d ORDER BY d DESC LIMIT 30"):
                    out["per_day"].append({"d": r["d"], "n": r["n"]})
                out["per_day"].reverse()
                for r in conn.execute(
                        "SELECT verdict, COUNT(*) n FROM vt_reports "
                        "GROUP BY verdict ORDER BY n DESC"):
                    out["verdicts"][r["verdict"] or "unknown"] = r["n"]
                for r in conn.execute(
                        "SELECT threat_label t, COUNT(*) n FROM vt_reports "
                        "WHERE threat_label IS NOT NULL AND threat_label<>'' "
                        "GROUP BY t ORDER BY n DESC LIMIT 25"):
                    out["families"].append({"t": r["t"], "n": r["n"]})
                for t in ("vt_reports", "hash_cache", "behaviour_reports",
                          "benign_reports", "clients", "visit_log"):
                    try:
                        out["tables"][t] = conn.execute(
                            "SELECT COUNT(*) FROM %s" % t).fetchone()[0]
                    except sqlite3.Error:
                        out["tables"][t] = None
        except Exception as e:
            out["err"] = "%s: %s" % (type(e).__name__, str(e)[:140])
        return out
    return cached("inv", 20.0, run)


# ---------------------------------------------------------------- views

def v_summary():
    t = today()
    inv = inventory_stats()
    bl = batches()
    bt = [b for b in bl if str(b["ts"])[:10] == t]
    ok = [b for b in bt if b["ok"]]
    q, cp = quota_today(), caps()
    attr = attribution()
    peers = sorted(set(b["peer"] for b in bl))
    days = [x["n"] for x in inv["per_day"][-7:]]
    d = head_ctx()
    d.update({
        "db_error": inv["err"],
        "inv": {"total": inv["total"], "today": inv["today"],
                "avg7": round(sum(days) / len(days), 1) if days else 0,
                "db_mb": round(inv["db_bytes"] / 1048576.0, 1),
                "per_day": inv["per_day"][-14:], "verdicts": inv["verdicts"]},
        "ing": {
            "batches_today": len(bt), "ok_today": len(ok),
            "fail_today": len([b for b in bt if not b["ok"]]),
            "received_today": sum(b["received"] for b in ok),
            "inserted_today": sum(b["inserted"] for b in ok),
            "skipped_today": sum(b["skipped"] for b in ok),
            "kb_today": round(sum(b["kb"] for b in ok), 1),
            "batches_all": len(bl),
            "peers": peers, "peer_count": len(peers),
            "last": bl[0]["ts"] if bl else "",
            "since": bl[-1]["ts"] if bl else "",
            "attr_listed": attr["listed"], "attr_counted": attr["counted"],
            "unattributed": max(0, inv["total"] - attr["counted"]),
        },
        "quota": [{"s": s, "used": q.get(s, 0), "cap": cp.get(s, 0)} for s in SOURCES],
        "vt_keys": cp.get("_vt_keys", 1),
    })
    return d


def v_ingest():
    t = today()
    bl = batches()
    bt = [b for b in bl if str(b["ts"])[:10] == t]
    rows = []
    for b in bl[:200]:
        r = dict(b)
        r["new_shown"] = b["new"][:8]
        r["new_listed"] = len(b["new"])
        del r["new"]
        rows.append(r)
    d = head_ctx()
    d.update({
        "db_error": "",
        "ing": {
            "rows": rows, "shown": len(rows), "all": len(bl),
            "today": len(bt),
            "received_today": sum(b["received"] for b in bt if b["ok"]),
            "inserted_today": sum(b["inserted"] for b in bt if b["ok"]),
            "skipped_today": sum(b["skipped"] for b in bt if b["ok"]),
            "malformed_today": sum(b["malformed"] for b in bt),
            "fail_today": len([b for b in bt if not b["ok"]]),
            "kb_today": round(sum(b["kb"] for b in bt if b["ok"]), 1),
            "since": bl[-1]["ts"] if bl else "",
            "log_path": INGEST_LOG,
        },
    })
    return d


def v_nodes():
    bl = batches()
    attr = attribution()
    inv = inventory_stats()
    per = {}
    for b in bl:
        p = per.setdefault(b["peer"], {
            "peer": b["peer"], "batches": 0, "ok": 0, "fail": 0,
            "received": 0, "inserted": 0, "skipped": 0, "malformed": 0,
            "kb": 0.0, "first": "", "last": "", "master_total": 0})
        p["batches"] += 1
        if b["ok"]:
            p["ok"] += 1
            p["received"] += b["received"]
            p["inserted"] += b["inserted"]
            p["skipped"] += b["skipped"]
            p["kb"] += b["kb"]
            p["master_total"] = max(p["master_total"], b["total"])
        else:
            p["fail"] += 1
        p["malformed"] += b["malformed"]
        if not p["last"] or b["ts"] > p["last"]:
            p["last"] = b["ts"]
        if not p["first"] or b["ts"] < p["first"]:
            p["first"] = b["ts"]
    rows = []
    for k, p in per.items():
        p["kb"] = round(p["kb"], 1)
        a = attr["per"].get(k) or {}
        p["attr_listed"] = a.get("listed", 0)
        p["attr_counted"] = a.get("counted", 0)
        rows.append(p)
    rows.sort(key=lambda x: x["inserted"], reverse=True)
    d = head_ctx()
    d.update({
        "db_error": inv["err"],
        "n": {
            "rows": rows,
            "inv_total": inv["total"],
            "attr_counted": attr["counted"],
            "unattributed": max(0, inv["total"] - attr["counted"]),
            "since": bl[-1]["ts"] if bl else "",
        },
    })
    return d


def v_inventory():
    inv = inventory_stats()
    q, cp = quota_today(), caps()
    d = head_ctx()
    d.update({
        "db_error": inv["err"],
        "inv": {
            "total": inv["total"], "today": inv["today"],
            "db_mb": round(inv["db_bytes"] / 1048576.0, 1),
            "per_day": inv["per_day"], "verdicts": inv["verdicts"],
            "families": inv["families"], "tables": inv["tables"],
        },
        "quota": [{"s": s, "used": q.get(s, 0), "cap": cp.get(s, 0)} for s in SOURCES],
        "vt_keys": cp.get("_vt_keys", 1),
    })
    return d


PAGE = r"""<!DOCTYPE html>
<html lang="zh-CN"><head>
<meta charset="utf-8">
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Bulwark 主服务器</title>
<style>
/* Same palette as the node dashboard on purpose -- one operator switches between
   the two. Page is a soft grey and surfaces are white: an all-white page let the
   cards vanish into the background and glared on a large monitor. */
:root{
 --bg:#eceff4; --surface:#fff; --line:#dadfe6; --line2:#edf0f4;
 --soft:#f4f6f9; --chip:#e7ebf1; --track:#e5eaf0;
 --ink:#2c333d; --muted:#6a7480; --dim:#98a1ac;
 --blue:#2c6cd6; --green:#1f7a3d; --amber:#b57f07; --red:#c9313c;
 --shadow:0 1px 2px rgba(28,38,54,.05),0 2px 5px rgba(28,38,54,.04);
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--ink);font:15px/1.65 "Microsoft YaHei","PingFang SC",
 -apple-system,"Segoe UI",Roboto,sans-serif;padding:0 0 48px}
.top{background:var(--surface);border-bottom:1px solid var(--line);padding:12px 26px 0;
 position:sticky;top:0;z-index:9;box-shadow:0 1px 3px rgba(28,38,54,.06)}
.top .line1{display:flex;flex-wrap:wrap;gap:18px;align-items:center;margin-bottom:10px}
.top h1{font-size:17px;font-weight:700}
.top .meta{font-size:13px;color:var(--muted)}
.top .meta b{color:var(--ink);font-variant-numeric:tabular-nums}
.nav{display:flex;gap:2px;flex-wrap:wrap}
.nav a{display:block;padding:8px 16px;font-size:14px;font-weight:600;color:var(--muted);
 text-decoration:none;border-bottom:2px solid transparent;border-radius:6px 6px 0 0}
.nav a:hover{color:var(--ink);background:var(--soft)}
.nav a.on{color:var(--ink);border-bottom-color:#e8834f}
.nav a .c{display:inline-block;margin-left:6px;padding:0 7px;border-radius:10px;
 background:var(--chip);color:var(--muted);font-size:12px;font-variant-numeric:tabular-nums}
.tag{display:inline-block;padding:2px 10px;border-radius:20px;font-size:12px;font-weight:600;
 border:1px solid transparent}
.tag.on{background:#e4f6e9;color:#146c30;border-color:#c2e5cb}
.tag.off{background:#fceced;color:#a5252f;border-color:#f4ccd0}
.tag.mid{background:#fdf4d6;color:#7a5300;border-color:#eddfaa}
.tag.gray{background:var(--soft);color:var(--muted);border-color:var(--line)}
.wrap{padding:22px 26px;max-width:1560px;margin:0 auto}
h2.pg{font-size:20px;font-weight:700;margin-bottom:4px}
p.lead{font-size:13px;color:var(--muted);margin-bottom:18px}
.kpi{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;margin-bottom:18px}
.k{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:16px 18px;
 border-top:3px solid var(--blue);box-shadow:var(--shadow)}
.k.g{border-top-color:var(--green)} .k.y{border-top-color:var(--amber)}
.k.r{border-top-color:var(--red)}
.k .lab{font-size:13px;color:var(--muted);margin-bottom:6px;font-weight:600}
.k .num{font-size:32px;font-weight:700;line-height:1.15;letter-spacing:-.5px;
 font-variant-numeric:tabular-nums}
.k .sub{font-size:13px;color:var(--muted);margin-top:6px}
.sec{font-size:16px;font-weight:700;margin:26px 0 12px;display:flex;align-items:center;gap:10px}
.sec:after{content:"";flex:1;height:1px;background:var(--line)}
.cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:14px}
.box{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:16px 18px;
 box-shadow:var(--shadow)}
.box h3{font-size:14px;color:var(--muted);margin-bottom:12px;font-weight:700}
.row{display:flex;justify-content:space-between;align-items:baseline;gap:12px;
 padding:7px 0;border-bottom:1px solid var(--line2);font-size:14px}
.row:last-child{border-bottom:none}
.row span{color:var(--muted)}
.row b{font-size:16px;font-weight:700;font-variant-numeric:tabular-nums}
.bar{height:8px;background:var(--track);border-radius:5px;overflow:hidden;margin:8px 0 4px}
.bar i{display:block;height:100%;background:var(--green);transition:width .5s}
.bar.y i{background:var(--amber)} .bar.r i{background:var(--red)}
.pct{font-size:12px;color:var(--muted);text-align:right;font-variant-numeric:tabular-nums}
.note{font-size:12px;color:var(--muted);margin-top:10px;line-height:1.5}
table{width:100%;border-collapse:collapse;font-size:13px}
th{background:var(--soft);color:var(--muted);font-size:12px;font-weight:700;
 padding:9px 11px;text-align:right;border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:8px 11px;text-align:right;border-bottom:1px solid var(--line2);
 font-variant-numeric:tabular-nums;white-space:nowrap}
th:first-child,td:first-child{text-align:left}
tbody tr:hover td{background:var(--soft)}
.mono{font-family:Consolas,"SF Mono",Menlo,monospace;font-size:12px;color:#215fbf}
.z{color:var(--dim)}
.bad{color:var(--red);font-weight:700}
.scroll{overflow-x:auto;background:var(--surface);border:1px solid var(--line);
 border-radius:10px;box-shadow:var(--shadow)}
.days{display:flex;align-items:flex-end;gap:4px;height:92px;margin:12px 0 4px}
.days i{flex:1;background:#7fb2ef;border-radius:2px 2px 0 0;min-height:2px}
.days i:hover{background:var(--blue)}
.err{background:#fceced;border:1px solid #f4ccd0;color:#a5252f;
 padding:12px 16px;border-radius:10px;margin-bottom:16px;font-size:14px}
.warn{background:#fdf4d6;border:1px solid #eddfaa;color:#7a5300;
 padding:11px 15px;border-radius:10px;margin-bottom:16px;font-size:13px}
</style></head><body>
<div class="top">
  <div class="line1">
    <h1>Bulwark 主服务器</h1>
    <span class="meta" id="node"></span>
    <span class="meta" id="now"></span>
    <span class="meta">刷新 <b id="tick">5</b>s</span>
    <span id="units"></span>
  </div>
  <div class="nav" id="nav"></div>
</div>
<div class="wrap">
  <div id="err"></div>
  <div id="body"></div>
</div>
<script>
var $=function(s){return document.querySelector(s)};
var VIEWS=[
  {p:'/',          k:'home',  t:'总览',     api:'/api/summary',
   lead:'主服务器作为汇聚端的整体状况：库存规模、今日接收量、各情报源配额。'},
  {p:'/ingest',    k:'ingest',t:'入库批次', api:'/api/ingest',
   lead:'每一次卫星节点推送的完整记录 —— 来源、行数、真正新入库的哈希。'},
  {p:'/nodes',     k:'nodes', t:'来源节点', api:'/api/nodes',
   lead:'按来源节点统计贡献量。vt_reports 没有来源列，归属完全来自入库账本。'},
  {p:'/inventory', k:'inv',   t:'库存',     api:'/api/inventory',
   lead:'库存增长、判定分布、家族排行、各情报源今日配额消耗。'}
];
var PATH=location.pathname.replace(/\/index\.html$/,'/');
var CUR=VIEWS[0];
for(var vi=0;vi<VIEWS.length;vi++) if(VIEWS[vi].p===PATH) CUR=VIEWS[vi];

function n(v){return v==null?'-':Number(v).toLocaleString('en-US')}
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
function bar(u,c){
  var p = c ? Math.min(100, 100*u/c) : 0;
  var k = p>=95 ? 'bar r' : p>=75 ? 'bar y' : 'bar';
  return '<div class="'+k+'"><i style="width:'+p+'%"></i></div>'+
         '<div class="pct">'+n(u)+' / '+n(c)+'  ('+p.toFixed(1)+'%)</div>';
}
function kcard(cls,lab,num,sub){
  return '<div class="k '+cls+'"><div class="lab">'+lab+'</div>'+
         '<div class="num">'+num+'</div><div class="sub">'+sub+'</div></div>';
}
function row(l,v){return '<div class="row"><span>'+l+'</span><b>'+v+'</b></div>'}
function box(t,i){return '<div class="box"><h3>'+t+'</h3>'+i+'</div>'}
function tag(v){return '<span class="tag '+(v==='active'?'on':'off')+'">'+esc(v||'?')+'</span>'}
function table(head,rows,empty,cols){
  return '<div class="scroll"><table><thead><tr>'+head+'</tr></thead><tbody>'+
    (rows || '<tr><td colspan="'+(cols||9)+'" class="z">'+empty+'</td></tr>')+
    '</tbody></table></div>';
}
function days(a){
  if(!a||!a.length) return '<div class="z">暂无数据</div>';
  var mx=1,i;
  for(i=0;i<a.length;i++) if(a[i].n>mx) mx=a[i].n;
  var h='<div class="days">';
  for(i=0;i<a.length;i++)
    h+='<i style="height:'+Math.max(2,92*a[i].n/mx)+'px" title="'+esc(a[i].d)+'  '+a[i].n+' 条"></i>';
  return h+'</div><div class="pct">'+esc(a[0].d)+' → '+esc(a[a.length-1].d)+
         '（峰值 '+mx+' 条/天）</div>';
}
function verdTag(v){
  if(v==='malicious') return '<span class="tag off">恶意</span>';
  if(v==='suspicious') return '<span class="tag mid">可疑</span>';
  if(v==='clean') return '<span class="tag on">干净</span>';
  return '<span class="z">'+esc(v)+'</span>';
}
function quotaBox(q,keys){
  var h='';
  for(var i=0;i<q.length;i++){
    var x=q[i], p=x.cap?100*x.used/x.cap:0;
    var over = x.cap && x.used>x.cap;
    h+='<div style="margin-bottom:10px"><div class="row" style="border:none;padding:2px 0">'+
       '<span>'+esc(x.s)+(x.s==='VirusTotal'?' ('+keys+' key)':'')+'</span>'+
       '<b>'+n(x.used)+' / '+n(x.cap)+(over?' <span class="tag off">超限</span>':'')+'</b></div>'+
       '<div class="'+(p>=95?'bar r':p>=75?'bar y':'bar')+'">'+
       '<i style="width:'+Math.min(100,p)+'%"></i></div></div>';
  }
  return h;
}
function nav(counts){
  var h='';
  for(var i=0;i<VIEWS.length;i++){
    var v=VIEWS[i], c=counts&&counts[v.k];
    h+='<a href="'+v.p+'"'+(v.k===CUR.k?' class="on"':'')+'>'+v.t+
       (c!=null?'<span class="c">'+n(c)+'</span>':'')+'</a>';
  }
  $('#nav').innerHTML=h;
}
function head(d){
  $('#node').textContent=d.node||'';
  $('#now').textContent=(d.now||'')+' UTC';
  var u=d.u||{};
  $('#units').innerHTML='情报服务 '+tag(u.intel)+
    ' <span class="tag gray">本机采集 '+esc(u.harvest_enabled||'?')+'</span>';
  $('#err').innerHTML = d.db_error ? '<div class="err">数据库读取异常：'+esc(d.db_error)+'</div>' : '';
}
function title(){return '<h2 class="pg">'+CUR.t+'</h2><p class="lead">'+CUR.lead+'</p>'}
function attrNote(unattr,total,since){
  if(!since) return '<div class="warn">入库账本还没有记录。账本是 bulwark-ingest.py '+
    '写的，只能记录它启用之后的推送；之前入库的行无法追溯来源。</div>';
  return '<div class="warn">账本起始于 '+esc(since)+'。在那之前入库的 '+n(unattr)+
    ' 行（共 '+n(total)+' 行）没有来源记录 —— vt_reports 没有来源列，'+
    '这部分既可能来自卫星节点，也可能是主服务器自己查的，无法追溯。</div>';
}

/* ---------- 总览 ---------- */
function rHome(d){
  var inv=d.inv, ing=d.ing;
  nav({ingest:ing.batches_today, nodes:ing.peer_count});
  var html=title()+'<div class="kpi">'+
    kcard('','库存总量',n(inv.total),'今日 +'+n(inv.today)+' · 近 7 天均 '+n(inv.avg7))+
    kcard('g','今日接收',n(ing.received_today),
      '入库 '+n(ing.inserted_today)+' · 重复 '+n(ing.skipped_today))+
    kcard(ing.fail_today?'r':'g','今日批次',n(ing.batches_today),
      ing.fail_today?(n(ing.fail_today)+' 批失败'):'全部成功 · '+n(ing.kb_today)+' KB')+
    kcard('','来源节点',n(ing.peer_count),
      ing.peers.length?esc(ing.peers.join(' ')):'账本暂无记录')+
    '</div>';
  html+='<div class="cols">'+
    box('接收汇总',
      row('今日批次',n(ing.batches_today)+' 批')+
      row('今日接收行数',n(ing.received_today))+
      row('其中真正入库',n(ing.inserted_today))+
      row('重复跳过',n(ing.skipped_today))+
      row('传输量',n(ing.kb_today)+' KB')+
      row('最后一次接收',esc(ing.last)||'-'))+
    box('库存',
      row('vt_reports 总行数',n(inv.total))+
      row('今日新增','+'+n(inv.today))+
      row('近 7 天日均',n(inv.avg7))+
      row('数据库大小',n(inv.db_mb)+' MB')+
      days(inv.per_day))+
    box('情报源配额（今日）',quotaBox(d.quota,d.vt_keys))+
    box('判定分布（全部库存）',
      (Object.keys(inv.verdicts||{}).length
        ? Object.keys(inv.verdicts).map(function(k){
            return row(verdTag(k),n(inv.verdicts[k]))}).join('')
        : '<div class="z">暂无</div>'))+
    '</div>';
  html+=attrNote(ing.unattributed,inv.total,ing.since);
  $('#body').innerHTML=html;
}

/* ---------- 入库批次 ---------- */
function rIngest(d){
  var g=d.ing;
  nav({ingest:g.today});
  var html=title()+'<div class="kpi">'+
    kcard('','今日批次',n(g.today),n(g.kb_today)+' KB')+
    kcard('g','今日接收行数',n(g.received_today),'入库 '+n(g.inserted_today))+
    kcard(g.skipped_today?'y':'g','重复跳过',n(g.skipped_today),
      '主库已有，INSERT OR IGNORE 保留原值')+
    kcard(g.fail_today||g.malformed_today?'r':'g','失败 / 畸形',
      n(g.fail_today)+' / '+n(g.malformed_today),
      g.fail_today?'检查来源节点':'无异常')+
    '</div>';
  html+='<div class="cols" style="margin-bottom:14px">'+
    box('账本',
      row('总记录数',n(g.all)+' 批')+
      row('本页显示',n(g.shown)+' 批')+
      row('起始时间',esc(g.since)||'-')+
      '<div class="note">文件 '+esc(g.log_path)+'，每次推送追加一行，'+
      '超过 2 MB 自动裁到最近 2000 行。</div>')+
    box('接收链路',
      row('鉴权方式','authorized_keys 强制命令')+
      row('运行身份','runuser -u bulwarkintel')+
      row('合并策略','INSERT OR IGNORE')+
      '<div class="note">推送用的那把 key 被 restrict + command= 锁死，只能执行入库脚本，'+
      '拿不到 shell。卫星节点只能补主库缺的哈希，不能覆盖主库已有的。</div>')+
    '</div>';
  html+='<div class="sec">批次明细</div>'+table(
    '<th>时间 (UTC)</th><th>来源</th><th>接收</th><th>入库</th><th>重复</th>'+
    '<th>畸形</th><th>大小</th><th>批次数据时间段</th><th>入库后主库总数</th>'+
    '<th>结果</th><th>新增哈希</th>',
    (g.rows||[]).map(function(b){
      var res = b.ok ? (b.empty?'<span class="tag gray">空批次</span>'
                               :'<span class="tag on">成功</span>')
                     : '<span class="tag off" title="'+esc(b.error)+'">失败</span>';
      var span = (b.oldest&&b.newest)
        ? esc(b.oldest.slice(11,19))+' → '+esc(b.newest.slice(11,19)) : '<span class="z">-</span>';
      var hs = (b.new_shown||[]).map(function(h){return esc(h.slice(0,10))}).join(' ');
      if(b.new_count>(b.new_shown||[]).length) hs+=' <span class="z">…共 '+n(b.new_count)+'</span>';
      return '<tr><td>'+esc(b.ts.replace('T',' ').replace('Z',''))+'</td>'+
        '<td class="mono">'+esc(b.peer)+'</td>'+
        '<td>'+n(b.received)+'</td><td><b>'+n(b.inserted)+'</b></td>'+
        '<td>'+n(b.skipped)+'</td>'+
        '<td>'+(b.malformed?'<span class="bad">'+n(b.malformed)+'</span>':'0')+'</td>'+
        '<td>'+n(b.kb)+' KB</td><td class="z">'+span+'</td>'+
        '<td>'+n(b.total)+'</td><td>'+res+'</td>'+
        '<td class="mono">'+(hs||'<span class="z">-</span>')+'</td></tr>';
    }).join(''),'账本暂无记录（启用后第一次推送就会出现）',11);
  $('#body').innerHTML=html;
}

/* ---------- 来源节点 ---------- */
function rNodes(d){
  var s=d.n;
  nav({nodes:(s.rows||[]).length});
  var tot=0, ins=0, i;
  for(i=0;i<(s.rows||[]).length;i++){ tot+=s.rows[i].received; ins+=s.rows[i].inserted; }
  var html=title()+'<div class="kpi">'+
    kcard('','来源节点数',n((s.rows||[]).length),'账本内出现过的对端 IP')+
    kcard('g','累计接收行数',n(tot),'真正入库 '+n(ins))+
    kcard('','可归属行数',n(s.attr_counted),'占库存 '+
      (s.inv_total?(100*s.attr_counted/s.inv_total).toFixed(1):'0')+'%')+
    kcard('y','无法归属',n(s.unattributed),'账本启用前入库')+
    '</div>';
  html+=attrNote(s.unattributed,s.inv_total,s.since);
  html+='<div class="sec">按来源节点</div>'+table(
    '<th>来源 IP</th><th>批次</th><th>成功</th><th>失败</th><th>接收行数</th>'+
    '<th>真正入库</th><th>重复</th><th>畸形</th><th>传输量</th>'+
    '<th>首次</th><th>最近</th>',
    (s.rows||[]).map(function(p){
      return '<tr><td class="mono">'+esc(p.peer)+'</td>'+
        '<td>'+n(p.batches)+'</td>'+
        '<td>'+n(p.ok)+'</td>'+
        '<td>'+(p.fail?'<span class="tag off">'+n(p.fail)+'</span>':'0')+'</td>'+
        '<td>'+n(p.received)+'</td><td><b>'+n(p.inserted)+'</b></td>'+
        '<td>'+n(p.skipped)+'</td>'+
        '<td>'+(p.malformed?'<span class="bad">'+n(p.malformed)+'</span>':'0')+'</td>'+
        '<td>'+n(p.kb)+' KB</td>'+
        '<td class="z">'+esc(String(p.first).replace('T',' ').replace('Z',''))+'</td>'+
        '<td class="z">'+esc(String(p.last).replace('T',' ').replace('Z',''))+'</td></tr>';
    }).join(''),'账本暂无记录',11);
  html+='<div class="note">「真正入库」是该节点补进主库的净增量；「重复」是主库已经有的哈希，'+
    '按 INSERT OR IGNORE 保留主库原值 —— 主库自己查过的报告通常比卫星节点的更全'+
    '（多 behaviour、yara 等），所以不覆盖是有意的。</div>';
  $('#body').innerHTML=html;
}

/* ---------- 库存 ---------- */
function rInv(d){
  var inv=d.inv;
  nav(null);
  var html=title()+'<div class="kpi">'+
    kcard('','vt_reports',n(inv.total),'今日 +'+n(inv.today))+
    kcard('','数据库大小',n(inv.db_mb)+' MB','cache.db')+
    kcard('','恶意',n((inv.verdicts||{}).malicious||0),
      '可疑 '+n((inv.verdicts||{}).suspicious||0))+
    kcard('','家族种类',n((inv.families||[]).length)+'+','取前 25 名')+
    '</div>';
  html+='<div class="cols" style="margin-bottom:14px">'+
    box('库存增长（近 30 天）',days(inv.per_day))+
    box('情报源配额（今日）',quotaBox(d.quota,d.vt_keys))+
    box('判定分布',
      (Object.keys(inv.verdicts||{}).length
        ? Object.keys(inv.verdicts).map(function(k){
            return row(verdTag(k),n(inv.verdicts[k]))}).join('')
        : '<div class="z">暂无</div>'))+
    box('数据表行数',
      Object.keys(inv.tables||{}).map(function(k){
        return row('<span class="mono">'+esc(k)+'</span>',
          inv.tables[k]==null?'<span class="z">-</span>':n(inv.tables[k]))}).join(''))+
    '</div>';
  html+='<div class="sec">家族排行</div>'+table(
    '<th>威胁家族</th><th>数量</th><th>占恶意样本比例</th>',
    (inv.families||[]).map(function(f){
      var mal=(inv.verdicts||{}).malicious||0;
      return '<tr><td>'+esc(f.t)+'</td><td>'+n(f.n)+'</td>'+
        '<td>'+(mal?(100*f.n/mal).toFixed(2):'0')+'%</td></tr>';
    }).join(''),'暂无数据',3);
  $('#body').innerHTML=html;
}

var RENDER={home:rHome,ingest:rIngest,nodes:rNodes,inv:rInv};
function load(){
  fetch(CUR.api,{cache:'no-store'}).then(function(r){
    if(!r.ok) throw new Error('HTTP '+r.status); return r.json();
  }).then(function(d){ head(d); RENDER[CUR.k](d); }).catch(function(e){
    $('#err').innerHTML='<div class="err">读取失败：'+esc(e.message)+'</div>';
  });
}
nav(null);
var t=5;
setInterval(function(){ t--; if(t<=0){t=5;load();} $('#tick').textContent=t; },1000);
load();
</script></body></html>
"""

HTML_ROUTES = ("/", "/index.html", "/ingest", "/nodes", "/inventory")
API_ROUTES = {
    "/api/summary": v_summary,
    "/api/ingest": v_ingest,
    "/api/nodes": v_nodes,
    "/api/inventory": v_inventory,
}


class Handler(BaseHTTPRequestHandler):
    server_version = "bulwark-master-dash"

    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _authed(self):
        want = dash_token()
        if not want:
            return False
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer ") and auth[7:].strip() == want:
            return True
        for part in (self.headers.get("Cookie", "") or "").split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                if k.strip() == "bw_mdash" and v.strip() == want:
                    return True
        return False

    def do_GET(self):
        path, _, query = self.path.partition("?")
        qs = dict(p.split("=", 1) for p in query.split("&") if "=" in p)
        if path == "/health":
            return self._send(200, {"status": "ok", "service": "bulwark-master-dash"})
        want = dash_token()
        if not want:
            return self._send(503, "dashboard token not configured; refusing to serve",
                              "text/plain; charset=utf-8")
        if qs.get("token") == want:
            dest = path if path in HTML_ROUTES else "/"
            return self._send(302, b"", "text/plain", extra=[
                ("Set-Cookie",
                 "bw_mdash=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800" % want),
                ("Location", dest)])
        if not self._authed():
            return self._send(401, "unauthorized -- open /?token=YOURTOKEN once",
                              "text/plain; charset=utf-8")
        fn = API_ROUTES.get(path)
        if fn:
            try:
                return self._send(200, fn())
            except Exception as e:
                return self._send(500, {"error": "%s: %s" % (type(e).__name__, str(e)[:200])})
        if path in HTML_ROUTES:
            return self._send(200, PAGE, "text/html; charset=utf-8")
        return self._send(404, {"error": "not found"})

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args), flush=True)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def get_request(self):
        s, a = self.socket.accept()
        s.settimeout(20)
        return s, a


def main():
    if not dash_token():
        print("WARNING: no token in %s -- all requests refused" % DASH_CONFIG, flush=True)
    print("bulwark-master-dash listening on http://%s:%d" % (LISTEN_HOST, LISTEN_PORT), flush=True)
    Server((LISTEN_HOST, LISTEN_PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
