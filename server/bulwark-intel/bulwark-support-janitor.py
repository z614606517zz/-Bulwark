#!/usr/bin/env python3
"""Bulwark 在线客服清理器。每 3 天把对话内容整体清空 —— 消息、附件、会话本身。

「清理对话内容的所有东西」这句话里,最容易漏掉的是【附件文件】和【会话行】。
只删消息表会留下一地无人引用的图片和视频,以及一份完整的「谁在什么时候找过客服、
从哪个页面来、说了多少条」的元数据 —— 那也是对话内容。所以这个脚本按四步走,
缺一步都不算清完:

  1. 过期会话的附件文件      -> 从磁盘删
  2. 过期会话的消息行        -> 从库里删
  3. 过期会话本身            -> 从库里删(元数据一起走)
  4. 没有任何消息引用的孤儿附件 -> 从磁盘删

第 4 步是必需的,不是保险:上传是先落盘、再由前端把文件名附到消息上的两步动作,
用户选了文件又不按发送,盘上就留下一个永远不会被引用的文件。给它一小时宽限期
(可能正在上传中),超过就删。

【它只碰 support.db,永远不碰 cache.db】。这不是靠约定保证的,是靠 assert_not_intel_db()
在开跑前拿两个路径比一次 —— 情报库有一份 vt_reports 全量校验凭据要在每次部署前后
比对,任何"顺手"删到它的可能性都必须在代码里被排除,而不是在文档里被提醒。

留存期默认 3 天,取 support.retention_days。与 app.py 读侧的惰性过期用【同一个键】:
两边不一致的话,会出现"页面上看不到但盘上还在"或者反过来,而后者是把承诺说空了。

用法:
    bulwark-support-janitor.py                 # 按留存期清理
    bulwark-support-janitor.py --dry-run       # 只报告,什么都不动
    bulwark-support-janitor.py --all           # 无视留存期,全部清空
"""
import argparse
import json
import os
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone

CONFIG_PATH = os.environ.get("BULWARK_INTEL_CONFIG", "/etc/bulwark-intel/config.json")
# 可覆盖,这样这条删除路径能拿一份丢弃的副本演练。演练不了的删除路径等于没测过。
STATE_DIR = os.environ.get("BULWARK_STATE_DIR", "/var/lib/bulwark-intel")
LEDGER = os.path.join(STATE_DIR, "support_janitor_log.jsonl")
TS_FMT = "%Y-%m-%dT%H:%M:%SZ"
# 上传落盘与"消息引用它"之间有一个短窗口,宽限期要盖住最慢的一次上传。
ORPHAN_GRACE_SECONDS = 3600


def log(*a):
    print("[support-janitor %s]" % datetime.now(timezone.utc).strftime("%H:%M:%S"),
          *a, flush=True)


def now_utc():
    return datetime.now(timezone.utc)


def iso_now():
    return now_utc().strftime(TS_FMT)


def load_cfg():
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        log("cannot read config: %s" % e)
        return {}


def ledger(rec):
    """删了东西而不留记录是不能接受的,所以每次运行都写一行,哪怕什么都没删。"""
    rec["ts"] = iso_now()
    try:
        with open(LEDGER, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        os.chmod(LEDGER, 0o644)
        if os.path.getsize(LEDGER) > 262144:
            with open(LEDGER, encoding="utf-8") as f:
                keep = f.readlines()[-800:]
            tmp = LEDGER + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.writelines(keep)
            os.replace(tmp, LEDGER)
            os.chmod(LEDGER, 0o644)
    except OSError as e:
        log("ledger write failed: %s" % e)


def num(d, key, default):
    """带默认值的数字配置,且【显式写的 0 不会被默认值吃掉】。

    常见写法 `d.get(k, default) or default` 会把配置里的 0 悄悄变成默认值,
    因为 0 是假值。这里 0 是有意义的取值,不能被放大成 3 天。
    """
    v = d.get(key)
    if v is None or v == "":
        return default
    try:
        return float(v)
    except (TypeError, ValueError):
        log("config %s=%r is not a number, using %r" % (key, v, default))
        return default


def resolve_paths(cfg):
    sup = cfg.get("support", {}) or {}
    intel_db = cfg.get("db_path") or os.path.join(STATE_DIR, "cache.db")
    db = sup.get("db_path") or os.path.join(os.path.dirname(intel_db) or STATE_DIR,
                                            "support.db")
    media = sup.get("media_dir") or os.path.join(os.path.dirname(intel_db) or STATE_DIR,
                                                 "support_media")
    return intel_db, db, media


def assert_not_intel_db(intel_db, sup_db):
    """机械保证:客服清理器绝不可能指向情报库。

    比的是 realpath,不是字符串 —— 符号链接、相对路径、多余的斜杠都能让两个看起来
    不同的路径指向同一个文件。
    """
    try:
        a = os.path.realpath(intel_db)
        b = os.path.realpath(sup_db)
    except OSError:
        a, b = intel_db, sup_db
    if a == b:
        log("ABORT: support db resolves to the intel database (%s). Refusing to run." % a)
        ledger({"job": "support", "ok": False, "abort": "support db == intel db",
                "path": a})
        return False
    return True


def media_names_in_db(conn, tokens=None):
    """库里现存的附件文件名集合。tokens 给定时只看这些会话。"""
    sql = "SELECT media FROM messages WHERE media<>''"
    args = []
    if tokens is not None:
        if not tokens:
            return set()
        sql += " AND token IN (%s)" % ",".join("?" * len(tokens))
        args = list(tokens)
    out = set()
    for (raw,) in conn.execute(sql, args):
        try:
            v = json.loads(raw or "[]")
        except Exception:
            continue
        if isinstance(v, list):
            out.update(str(x) for x in v)
    return out


def unlink_all(media_dir, names, dry):
    removed, freed = 0, 0
    for n in sorted(names):
        # 只删长得像我们自己生成的名字。这是唯一会 unlink 的地方,不值得为
        # "理论上库里只有服务端生成的名字"省掉这一道。
        if not n.startswith("sup-") or "/" in n or "\\" in n or ".." in n:
            log("  refusing to remove suspicious name: %r" % n)
            continue
        p = os.path.join(media_dir, n)
        try:
            sz = os.path.getsize(p)
        except OSError:
            continue
        if dry:
            removed += 1
            freed += sz
            continue
        try:
            os.remove(p)
            removed += 1
            freed += sz
        except OSError as e:
            log("  could not remove %s: %s" % (n, e))
    return removed, freed


def run(cfg, dry, wipe_all):
    intel_db, db_path, media_dir = resolve_paths(cfg)
    if not assert_not_intel_db(intel_db, db_path):
        return 1

    sup = cfg.get("support", {}) or {}
    days = num(sup, "retention_days", 3.0)
    cutoff = (now_utc() - timedelta(days=days)).strftime(TS_FMT)

    if not os.path.exists(db_path):
        log("no support database at %s -- nothing to clean" % db_path)
        ledger({"job": "support", "ok": True, "dry": dry, "note": "no database",
                "conversations": 0, "messages": 0, "files": 0})
        return 0

    log("db=%s media=%s" % (db_path, media_dir))
    log("mode=%s retention=%.1fd cutoff=%s"
        % ("WIPE ALL" if wipe_all else "expire", days, cutoff))

    conn = sqlite3.connect(db_path, timeout=60)
    conn.execute("PRAGMA busy_timeout=60000")
    try:
        have = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        if "conversations" not in have or "messages" not in have:
            log("schema not initialised yet -- nothing to clean")
            ledger({"job": "support", "ok": True, "dry": dry, "note": "no schema"})
            return 0

        conv_before = conn.execute("SELECT COUNT(*) FROM conversations").fetchone()[0]
        msg_before = conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]

        if wipe_all:
            doomed = [r[0] for r in conn.execute("SELECT token FROM conversations")]
        else:
            # last_at 而不是 created_at:一条昨天还在聊的会话不该因为三天前开的就被删。
            doomed = [r[0] for r in conn.execute(
                "SELECT token FROM conversations WHERE last_at < ?", (cutoff,))]
        log("conversations=%d messages=%d  ->  expiring %d conversation(s)"
            % (conv_before, msg_before, len(doomed)))

        # --- 1) 过期会话的附件先删盘 -------------------------------------- #
        # 顺序是刻意的:【先删文件,再删库里的引用】。反过来的话,删完引用后如果
        # 进程挂了,盘上的文件就再没有任何东西指向它 —— 只能靠孤儿清理去兜,
        # 而那一步有一小时宽限期。先删文件最坏情况只是留下一条指向不存在文件的
        # 记录,而它下一秒就要被删掉了。
        doomed_media = media_names_in_db(conn, doomed)
        files_removed, bytes_freed = unlink_all(media_dir, doomed_media, dry)
        log("  attachments of expiring conversations: %d removed, %.1f KB"
            % (files_removed, bytes_freed / 1024.0))

        msgs_deleted = convs_deleted = 0
        if doomed and not dry:
            with conn:
                for i in range(0, len(doomed), 400):     # 分批,别让 IN(...) 无上限地长
                    batch = doomed[i:i + 400]
                    q = ",".join("?" * len(batch))
                    msgs_deleted += conn.execute(
                        "DELETE FROM messages WHERE token IN (%s)" % q, batch).rowcount or 0
                    convs_deleted += conn.execute(
                        "DELETE FROM conversations WHERE token IN (%s)" % q,
                        batch).rowcount or 0
        elif doomed:
            msgs_deleted = conn.execute(
                "SELECT COUNT(*) FROM messages WHERE token IN (%s)"
                % ",".join("?" * min(len(doomed), 400)),
                doomed[:400]).fetchone()[0]
            convs_deleted = len(doomed)
            log("  DRY RUN: would delete %d message(s) and %d conversation(s)"
                % (msgs_deleted, convs_deleted))

        # --- 4) 孤儿附件 ---------------------------------------------------- #
        #
        # 宽限期只在【按留存期清理】时成立:那时目的是「过期的都走」,而一个刚落盘
        # 还没被消息引用的文件可能正在上传中,删了就是把用户正在发的东西抽掉。
        # --all 是运维明确下的「全清」指令,宽限期在那里是错的 —— 说了清空却留下
        # 四个视频在盘上,等于这条命令没做到它说的事。
        alive = media_names_in_db(conn)
        orphans = set()
        try:
            entries = os.listdir(media_dir)
        except OSError:
            entries = []
        now = time.time()
        for n in entries:
            if n in alive:
                continue
            p = os.path.join(media_dir, n)
            try:
                if not os.path.isfile(p):
                    continue
                age = now - os.path.getmtime(p)
            except OSError:
                continue
            if wipe_all:
                orphans.add(n)
                continue
            # 未完成的上传是 .up-<hex>.part,与已入库的 sup-* 分开处理:两者都
            # 该走,但半成品不需要等一小时那么久 —— 它本来就是崩溃残留。
            if n.startswith(".up-") and n.endswith(".part"):
                if age > 600:
                    orphans.add(n)
            elif age > ORPHAN_GRACE_SECONDS:
                orphans.add(n)
        orph_removed, orph_bytes = 0, 0
        for n in sorted(orphans):
            p = os.path.join(media_dir, n)
            try:
                sz = os.path.getsize(p)
            except OSError:
                continue
            if dry:
                orph_removed += 1
                orph_bytes += sz
                continue
            try:
                os.remove(p)
                orph_removed += 1
                orph_bytes += sz
            except OSError as e:
                log("  could not remove orphan %s: %s" % (n, e))
        log("  orphaned attachments: %d removed, %.1f KB"
            % (orph_removed, orph_bytes / 1024.0))

        conv_after = conn.execute("SELECT COUNT(*) FROM conversations").fetchone()[0]
        msg_after = conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
    finally:
        conn.close()

    # VACUUM 在这里【是要做的】,与情报库那边刻意跳过恰好相反,因为前提不同:
    # cache.db 有 386MB 且服务一直在读它,独占锁拿不到;support.db 小,而且每 3 天
    # 就被清空一次 —— 不回收的话空闲页会一直占着盘,而里面本来存的是客户数据,
    # 留着已删数据的页面也不是好事。拿不到锁就跳过,不当失败。
    vacuumed = False
    if not dry and (msg_before != msg_after or conv_before != conv_after):
        try:
            c2 = sqlite3.connect(db_path, timeout=15)
            c2.execute("PRAGMA busy_timeout=15000")
            c2.execute("VACUUM")
            c2.close()
            vacuumed = True
        except Exception as e:
            log("VACUUM skipped (%s) -- SQLite will reuse the freed pages" % e)

    try:
        db_bytes = os.path.getsize(db_path)
    except OSError:
        db_bytes = 0
    media_bytes = 0
    try:
        for n in os.listdir(media_dir):
            try:
                media_bytes += os.path.getsize(os.path.join(media_dir, n))
            except OSError:
                pass
    except OSError:
        pass

    log("conversations %d -> %d   messages %d -> %d"
        % (conv_before, conv_after, msg_before, msg_after))
    log("db=%.0f KB   attachments on disk=%.1f MB   vacuum=%s   dry=%s"
        % (db_bytes / 1024.0, media_bytes / 1048576.0, vacuumed, dry))

    ledger({"job": "support", "ok": True, "dry": dry, "wipe_all": wipe_all,
            "retention_days": days, "cutoff": cutoff,
            "conversations_before": conv_before, "conversations_after": conv_after,
            "messages_before": msg_before, "messages_after": msg_after,
            "conversations_deleted": convs_deleted, "messages_deleted": msgs_deleted,
            "files_removed": files_removed, "files_bytes": bytes_freed,
            "orphans_removed": orph_removed, "orphans_bytes": orph_bytes,
            "db_bytes": db_bytes, "media_bytes": media_bytes, "vacuum": vacuumed})
    return 0


def main():
    ap = argparse.ArgumentParser(description="Bulwark support-desk janitor")
    ap.add_argument("--dry-run", action="store_true", help="report, change nothing")
    ap.add_argument("--all", action="store_true", dest="wipe_all",
                    help="ignore the retention window and remove every conversation")
    a = ap.parse_args()
    return run(load_cfg(), a.dry_run, a.wipe_all)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        log("FATAL", type(e).__name__, str(e)[:200])
        try:
            ledger({"job": "support", "ok": False,
                    "error": "%s: %s" % (type(e).__name__, str(e)[:200])})
        except Exception:
            pass
        sys.exit(1)
