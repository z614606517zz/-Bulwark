#!/usr/bin/env python3
"""Push this node's new vt_reports rows to the master node.
Watermark is INCLUSIVE (stored_at >= mark): stored_at is 1-second resolution, so
'>' would drop rows sharing the boundary second; re-sending is free because the
master uses INSERT OR IGNORE. Watermark only advances after the master says OK.

The master address is deliberately NOT defaulted to a literal host: this file is
public, and a baked-in fallback is both an infrastructure disclosure and a way to
silently push to the wrong place if the unit file forgets the variable. Set
BULWARK_MASTER (e.g. root@master.example) in the systemd unit."""
import gzip, json, os, sqlite3, subprocess, sys, tempfile
from datetime import datetime, timezone
DB=os.environ.get("BULWARK_DB","/var/lib/bulwark-intel/cache.db")
MARK=os.environ.get("BULWARK_SYNC_MARK","/var/lib/bulwark-intel/sync_watermark.txt")
LEDGER=os.environ.get("BULWARK_SYNC_LOG","/var/lib/bulwark-intel/sync_log.jsonl")
# The master's own view of our pushes, pulled back after each one so the dashboard
# can reconcile the two sides without doing network IO while rendering a page.
MASTER_LOG=os.environ.get("BULWARK_MASTER_LOG","/var/lib/bulwark-intel/master_ingest.jsonl")
MASTER=os.environ.get("BULWARK_MASTER","")
KEY=os.environ.get("BULWARK_SYNC_KEY","/root/.ssh/id_sync23")
LIMIT=int(os.environ.get("BULWARK_SYNC_LIMIT","5000"))
EPOCH="1970-01-01T00:00:00Z"
COLS=("sha256","md5","sha1","name","verdict","malicious","total_engines","stored_at","report","threat_label","category","silverfox")
def log(*a): print("[sync %s]"%datetime.now(timezone.utc).strftime("%H:%M:%S"),*a,flush=True)
def read_mark():
    try:
        v=open(MARK).read().strip(); return v or EPOCH
    except OSError: return EPOCH
def write_mark(v):
    tmp=MARK+".tmp"; open(tmp,"w").write(v); os.replace(tmp,MARK)
def _i(v):
    try: return int(v)
    except (TypeError,ValueError): return 0
def ledger(rec):
    """Append-only record of every push attempt, mode 644 on purpose: this runs as
    root (it needs root's SSH key) while the dashboard runs as bulwarkintel, which
    therefore cannot see these runs in the journal at all. Trimmed, not rotated."""
    rec["ts"]=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        with open(LEDGER,"a",encoding="utf-8") as f: f.write(json.dumps(rec,ensure_ascii=False)+"\n")
        os.chmod(LEDGER,0o644)
        if os.path.getsize(LEDGER)>524288:
            with open(LEDGER,encoding="utf-8") as f: keep=f.readlines()[-1000:]
            tmp=LEDGER+".tmp"
            with open(tmp,"w",encoding="utf-8") as f: f.writelines(keep)
            os.replace(tmp,LEDGER); os.chmod(LEDGER,0o644)
    except OSError as e: log("ledger write failed: %s"%e)
def require_master():
    """Fail loudly rather than run ssh with an empty destination.

    There is no baked-in fallback host on purpose (see module docstring), so a unit
    file that forgets BULWARK_MASTER would otherwise produce an obscure ssh usage
    error on every timer tick. Checked once, before any database work."""
    if not MASTER.strip():
        log("BULWARK_MASTER is not set -- refusing to sync. "
            "Set it in the systemd unit, e.g. Environment=BULWARK_MASTER=root@master.example")
        sys.exit(2)
def ssh_args(cmd=None):
    a=["ssh","-T","-i",KEY,"-o","IdentitiesOnly=yes","-o","BatchMode=yes",
       "-o","ConnectTimeout=20","-o","StrictHostKeyChecking=accept-new",MASTER]
    return a+([cmd] if cmd else [])
def pull_master_ledger():
    """Fetch the master's record of OUR pushes (it filters by our source address).
    Best-effort: a failure here must never fail the sync -- the data is already
    delivered by this point, this is only reconciliation material."""
    try:
        p=subprocess.run(ssh_args("export-ledger"),capture_output=True,timeout=120)
    except Exception as e:
        log("master ledger pull failed: %s %s"%(type(e).__name__,str(e)[:100])); return
    if p.returncode!=0:
        log("master ledger pull rc=%d err=%r"
            %(p.returncode,(p.stderr or b"").decode("utf-8","replace")[:150])); return
    text=(p.stdout or b"").decode("utf-8","replace")
    good=[]
    for line in text.splitlines():
        line=line.strip()
        if not line: continue
        try: json.loads(line)
        except Exception: continue
        good.append(line)
    if not good:
        log("master ledger pull: nothing recorded for us yet"); return
    try:
        tmp=MASTER_LOG+".tmp"
        with open(tmp,"w",encoding="utf-8") as f: f.write("\n".join(good)+"\n")
        os.replace(tmp,MASTER_LOG); os.chmod(MASTER_LOG,0o644)
        log("master ledger pulled: %d records"%len(good))
    except OSError as e:
        log("master ledger write failed: %s"%e)
def main():
    require_master()
    mark=read_mark()
    db=sqlite3.connect(DB,timeout=30); db.execute("PRAGMA busy_timeout=30000")
    rows=db.execute("SELECT %s FROM vt_reports WHERE stored_at>=? ORDER BY stored_at LIMIT ?"%",".join(COLS),(mark,LIMIT)).fetchall()
    total=db.execute("SELECT COUNT(*) FROM vt_reports").fetchone()[0]; db.close()
    log("watermark=%s local_total=%d candidates=%d"%(mark,total,len(rows)))
    if not rows: log("nothing to push"); return 0
    newest=max(r[COLS.index("stored_at")] or EPOCH for r in rows)
    fd,path=tempfile.mkstemp(prefix="bwsync-",suffix=".jsonl.gz",dir="/var/lib/bulwark-intel"); os.close(fd)
    kb=0.0
    try:
        with gzip.open(path,"wt",encoding="utf-8",compresslevel=6) as gz:
            for r in rows: gz.write(json.dumps(dict(zip(COLS,r)),ensure_ascii=False)+"\n")
        kb=os.path.getsize(path)/1024.0
        log("payload %d rows, %.1f KB gzipped, newest=%s"%(len(rows),kb,newest))
        with open(path,"rb") as f:
            p=subprocess.run(ssh_args(),stdin=f,capture_output=True,timeout=900)
        out=(p.stdout or b"").decode("utf-8","replace").strip()
        if p.returncode!=0 or not out.startswith("OK"):
            log("push FAILED rc=%d out=%r err=%r"%(p.returncode,out[:200],(p.stderr or b"").decode("utf-8","replace")[:200]))
            ledger({"ok":False,"rows":len(rows),"kb":round(kb,1),"received":0,"inserted":0,
                    "skipped":0,"malformed":0,"master_total":0,"newest":newest,"master":MASTER,
                    "error":(out[:120] or "rc=%d"%p.returncode)})
            log("watermark left at %s so this range retries next run"%mark); return 1
        log("master says: %s"%out)
        st=dict(kv.split("=",1) for kv in out.split()[1:] if "=" in kv)
        ledger({"ok":True,"rows":len(rows),"kb":round(kb,1),"received":_i(st.get("received")),
                "inserted":_i(st.get("inserted")),"skipped":_i(st.get("skipped")),
                "malformed":_i(st.get("malformed")),"master_total":_i(st.get("total")),
                "newest":newest,"master":MASTER})
    finally:
        try: os.unlink(path)
        except OSError: pass
    write_mark(newest); log("watermark advanced to %s"%newest)
    pull_master_ledger()
    return 0
if __name__=="__main__":
    try: sys.exit(main())
    except Exception as e: log("FATAL",type(e).__name__,str(e)[:200]); sys.exit(1)
