#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 vt_reports 里的「降级占位行」重新查回真报告。

【为什么需要它】
VirusTotal 的日配额一到,app.py 的 _degraded_lookup 会转而问其余五个情报源。这条兜底
是对的 —— 但它只能拿到「哪个源说这是恶意的」,拿不到 VT 的引擎明细、文件类型和沙箱行为。
于是它存进 vt_reports 的是一行占位:file={}、behaviour={}、没有文件名。

实测线上 8160 行里有 3450 行(42.3%)是这种占位,其中 3301 行的原因就是
`VirusTotal HTTP 429`。这些行对攻击链挖掘完全无用:engine_build 要 file.type_tag
判平台、要 behaviour.sigma_analysis_results 提标记,占位行两样都没有。也就是说威胁
归档里四成是空壳,而「挖掘语料不够」正有这一份原因。

app.py 里已经写好了自愈机制:save_vt_report 是 upsert,占位行超过
degraded_retry_seconds 后被当作未命中,下一次成功查询就会原地覆盖成完整报告。缺的
只是【有人再去查它们一次】—— 在线查询只会碰用户正好查的那些哈希,不会主动回头。
这个脚本就是那个「有人」。

【为什么走本地服务而不是直连 VT】
  1. 密钥池、每把 key 的冷却、日配额记账全在 app.py 手里。绕过它等于两个记账方各算
     一套,谁也不知道真实余量 —— 而余量算错的后果是把在线查询的配额吃掉。
  2. save_vt_report 的 upsert 语义、behaviour_summary 的第二次取回、干净样本进
     benign_reports 当正常语料,这些副作用都是要的,自己实现一遍等于复制三份逻辑。
  3. /vt/lookup 对 127.0.0.1 免限流(_throttle_ok 显式豁免回环),不会挤占公网名额。

【安全边界】
  · 只读 vt_reports 选行,自己【不写任何表】—— 写库这件事全部交给 app.py。
  · 绝不 DELETE。重查失败就把那行留在原地,下次再来。
  · 花 VT 配额,所以有硬预算:留出 reserve 给在线查询,用完就停。
  · 连续多次仍拿到降级结果 = VT 又 429 了,立刻收工,不把整轮时间浪费在必然失败上。
"""
import argparse
import json
import os
import sqlite3
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

CONFIG_PATH = os.environ.get("BULWARK_INTEL_CONFIG", "/etc/bulwark-intel/config.json")
STATE_DIR = "/var/lib/bulwark-intel"
LEDGER = os.path.join(STATE_DIR, "backfill_log.jsonl")

# 回环上是自签证书,校验必然失败。这里刻意不校验:对端是 127.0.0.1 上的本机进程,
# 中间人无处插入,而开启校验只会让这个任务永远跑不起来。
_CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


def now_utc():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg):
    sys.stdout.write("[backfill] %s\n" % msg)
    sys.stdout.flush()


def load_cfg():
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        log("读不到配置 %s: %s" % (CONFIG_PATH, e))
        return {}


def db_ro(path):
    c = sqlite3.connect("file:%s?mode=ro" % path, uri=True, timeout=30)
    c.execute("PRAGMA busy_timeout=8000")
    c.row_factory = sqlite3.Row
    return c


def vt_budget(cfg, db_path):
    """今天还能花多少次 VT。返回 (剩余可用, 已用, 名义上限)。

    名义上限 = requests_per_day × key 数。与 app.py 的 RateLimiter 同一算法,故两边
    对「还剩多少」的判断一致 —— 不一致的话,这个任务会以为有余量而实际每次都撞 429。
    """
    vt = cfg.get("virustotal", {}) or {}
    raw = vt.get("api_keys") or ([vt.get("api_key")] if vt.get("api_key") else [])
    keys = [str(x).split(":")[0].strip() for x in raw]
    keys = [k for k in keys if len(k) == 64]
    cap = int(vt.get("requests_per_day", 500) or 500) * max(1, len(keys))
    used = 0
    try:
        c = db_ro(db_path)
        row = c.execute("SELECT count FROM quota WHERE source=? AND day=?",
                        ("VirusTotal", now_utc().strftime("%Y-%m-%d"))).fetchone()
        used = row["count"] if row else 0
        c.close()
    except Exception as e:
        log("读配额失败(按已用满处理,宁可不跑也不超支): %s" % e)
        return 0, 0, cap
    return max(0, cap - used), used, cap


def scan(db_path, limit, min_age_seconds):
    """一次扫库同时得到三样东西:要补的行、占位行总数、总行数。

    刻意合成一次:数据库 446 MB、vt_reports 八千多行,每行的 report 都要 json.loads
    才能可靠判断 degraded —— report 是 TEXT,SQL 里没有 JSON 谓词,而
    LIKE '%degraded%' 会把 degraded_reason 只在别处出现的行也捞进来。分成「先统计、
    再挑行」两趟就是把这份代价付两遍,而这个任务每小时都跑,还要和在线查询抢同一个库。

    min_age_seconds 是刻意的:刚写下的占位行还在 degraded_retry_seconds 的节流窗口里,
    app.py 会照原样返回而不去问 VT —— 这时候来查等于白跑一趟,还把 VT 名额花在一个
    注定返回缓存的请求上。
    """
    cut = iso(now_utc() - timedelta(seconds=max(0, int(min_age_seconds))))
    picked, n_deg, n_tot = [], 0, 0
    c = db_ro(db_path)
    try:
        # 按时间正序:最旧的占位行优先补。同一趟里既统计也挑行,所以【不能】提前 break。
        for r in c.execute("SELECT sha256, stored_at, verdict, report FROM vt_reports "
                           "ORDER BY stored_at ASC"):
            n_tot += 1
            try:
                d = json.loads(r["report"] or "{}")
            except Exception:
                continue
            if not d.get("degraded"):
                continue
            n_deg += 1
            if (not limit or len(picked) < limit) and (r["stored_at"] or "") <= cut:
                picked.append({"sha256": r["sha256"], "stored_at": r["stored_at"],
                               "verdict": r["verdict"],
                               "why": str(d.get("degraded_reason") or "")})
    finally:
        c.close()
    return picked, n_deg, n_tot


def count_degraded(db_path):
    """占位行总数与总行数。用于报进度,也是判断这个任务有没有效果的唯一凭据。"""
    n = tot = 0
    try:
        c = db_ro(db_path)
        for (rep,) in c.execute("SELECT report FROM vt_reports"):
            tot += 1
            try:
                if json.loads(rep or "{}").get("degraded"):
                    n += 1
            except Exception:
                pass
        c.close()
    except Exception as e:
        log("统计占位行失败: %s" % e)
    return n, tot


def svc_lookup(base, sha, timeout=180):
    body = json.dumps({"hash": sha, "refresh": True}).encode("utf-8")
    req = urllib.request.Request(base + "/vt/lookup", data=body,
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_CTX) as r:
            return r.status, json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8", "replace"))
        except Exception:
            return e.code, {}
    except Exception as e:
        return 0, {"error": repr(e)}


def append_ledger(rec, limit_bytes=1048576, keep_lines=2000):
    rec["ts"] = iso(now_utc())
    try:
        with open(LEDGER, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        try:
            os.chmod(LEDGER, 0o644)
        except OSError:
            pass
        if os.path.getsize(LEDGER) > limit_bytes:
            with open(LEDGER, encoding="utf-8") as f:
                tail = f.readlines()[-keep_lines:]
            tmp = LEDGER + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.writelines(tail)
            os.replace(tmp, LEDGER)
    except OSError as e:
        log("台账写入失败: %s" % e)


def main():
    ap = argparse.ArgumentParser(
        description="重查 vt_reports 里的降级占位行,把它们补成完整报告")
    ap.add_argument("--max-per-run", type=int, default=None,
                    help="本轮最多补多少行(缺省读配置 backfill.max_per_run,再缺省 60)")
    ap.add_argument("--reserve", type=int, default=None,
                    help="给在线查询留出的 VT 次数(缺省 150)")
    ap.add_argument("--min-age-hours", type=float, default=None,
                    help="占位行至少这么旧才重查(缺省 2 小时)")
    ap.add_argument("--sleep", type=float, default=None,
                    help="每行之间的间隔秒数(缺省 16 —— VT 免费档 4 次/分,一行两次调用)")
    ap.add_argument("--dry-run", action="store_true",
                    help="只选行、只报数,不发任何请求")
    args = ap.parse_args()

    cfg = load_cfg()
    bf = cfg.get("backfill", {}) or {}
    if not bf.get("enabled", True):
        log("配置里 backfill.enabled=false,不跑")
        return 0

    db_path = cfg.get("db_path", os.path.join(STATE_DIR, "cache.db"))
    base = (cfg.get("harvest", {}) or {}).get("service_url") or "https://127.0.0.1:8787"
    base = base.rstrip("/")
    cap_run = int(args.max_per_run if args.max_per_run is not None
                  else bf.get("max_per_run", 60) or 60)
    reserve = int(args.reserve if args.reserve is not None
                  else bf.get("vt_reserve", 150) or 150)
    min_age = float(args.min_age_hours if args.min_age_hours is not None
                    else bf.get("min_age_hours", 2) or 2) * 3600.0
    gap = float(args.sleep if args.sleep is not None else bf.get("sleep_seconds", 16) or 16)

    left, used, cap = vt_budget(cfg, db_path)
    log("VT 今日 %d / %d,剩 %d;本轮预留 %d 给在线查询" % (used, cap, left, reserve))

    # 一行要花两次 VT(文件报告 + 沙箱行为),所以能补的行数是余量的一半。
    affordable = max(0, (left - reserve) // 2)
    budget = min(cap_run, affordable)

    rows, n_deg, n_tot = scan(db_path, budget, min_age)
    log("占位行 %d / %d 行 (%.1f%%)" % (n_deg, n_tot, 100.0 * n_deg / max(1, n_tot)))
    if budget <= 0:
        log("VT 余量不够(可补 %d 行),本轮不动。留给在线查询。" % affordable)
        append_ledger({"ok": True, "skipped": "no_budget", "degraded": n_deg,
                       "total": n_tot, "vt_used": used, "vt_cap": cap})
        return 0
    log("挑出 %d 行(上限 %d;只取 %.1f 小时以前写下的)"
        % (len(rows), budget, min_age / 3600.0))
    if not rows:
        log("没有够旧的占位行,收工")
        append_ledger({"ok": True, "skipped": "nothing_due", "degraded": n_deg,
                       "total": n_tot})
        return 0

    if args.dry_run:
        for r in rows[:12]:
            log("  [dry] %s  %s  %s" % (r["sha256"][:16], r["stored_at"], r["why"][:44]))
        log("dry-run:不发任何请求。以上 %d 行会被重查。" % len(rows))
        return 0

    healed = still = failed = 0
    consecutive_degraded = 0
    t0 = time.time()
    for i, r in enumerate(rows, 1):
        st, resp = svc_lookup(base, r["sha256"])
        rep = (resp or {}).get("report") or {}
        if st != 200:
            failed += 1
            log("%d/%d %s -> HTTP %s %s" % (i, len(rows), r["sha256"][:16], st,
                                            str(resp.get("error"))[:60]))
        elif rep.get("degraded"):
            still += 1
            consecutive_degraded += 1
            log("%d/%d %s -> 仍是降级 (%s)"
                % (i, len(rows), r["sha256"][:16],
                   str(rep.get("degraded_reason"))[:40]))
            # VT 又不可用了。继续跑下去每行都会是同一个结果,而且每行还白花一次
            # 取 key 的记账 —— 立刻收工比跑完更省。
            if consecutive_degraded >= 3:
                log("连续 3 行仍降级 -> VT 现在不可用,提前收工")
                break
        else:
            healed += 1
            consecutive_degraded = 0
            f = rep.get("file") or {}
            log("%d/%d %s -> 已补齐  类型=%s  行为=%s  %s"
                % (i, len(rows), r["sha256"][:16], f.get("type_tag") or "-",
                   "有" if rep.get("behaviour_available") else "无",
                   (f.get("meaningful_name") or "")[:36]))
        if i < len(rows) and gap > 0:
            time.sleep(gap)

    left2, used2, _ = vt_budget(cfg, db_path)
    # 收尾这一趟【要】真扫,不用 n_deg - healed 顶替:在线查询也会顺手治好占位行
    # (upsert 是同一条路径),算术只能反映本任务干了多少,反映不了库里现在还剩多少。
    # 两个数都记进台账,差值就是别人治好的那部分。
    n_deg2, n_tot2 = count_degraded(db_path)
    log("done 补齐=%d 仍降级=%d 失败=%d  耗时 %.0fs" % (healed, still, failed,
                                                       time.time() - t0))
    log("占位行 %d -> %d;VT 今日 %d -> %d" % (n_deg, n_deg2, used, used2))
    append_ledger({"ok": True, "healed": healed, "still_degraded": still,
                   "failed": failed, "attempted": healed + still + failed,
                   "degraded_before": n_deg, "degraded_after": n_deg2,
                   "total_rows": n_tot2, "vt_used_before": used,
                   "vt_used_after": used2, "vt_cap": cap,
                   "seconds": round(time.time() - t0, 1)})
    return 0


try:
    sys.exit(main())
except KeyboardInterrupt:
    sys.exit(130)
except Exception as exc:                                  # noqa: BLE001
    import traceback
    log("EXCEPTION %r" % exc)
    traceback.print_exc()
    try:
        append_ledger({"ok": False, "error": repr(exc)[:300]})
    except Exception:
        pass
    sys.exit(1)
