#!/usr/bin/env python3
"""Apply VT API key requests dropped by the dashboard, as root.

Why a separate root-side script instead of letting the dashboard edit
config.json directly: config.json is 640 root:bulwarkintel, and the dashboard
runs as bulwarkintel precisely so a reporting bug cannot write to harvester
state. Giving it write access to the config -- which holds every API key and
the whole harvest policy -- would throw that away for one feature. Instead the
dashboard writes a small request file into a spool directory it owns, and this
script (root, timer-driven) validates and applies it.

It will only ever touch virustotal.api_keys. Nothing else in config.json is
read back out or rewritten from the request, so a malformed/hostile request
cannot reach any other setting.

app.py has no config reload path: load_config() runs once at import. Adding a
key therefore requires restarting bulwark-intel.service, which is cheap -- it is
a stateless caching proxy whose data lives in SQLite, so a restart loses nothing
in flight beyond any single in-progress lookup, which the caller retries.

Three actions, all arriving as spool files:
  add     put a key into the pool (the original behaviour; a request with no
          "action" field is treated as add, so older requests still work)
  probe   ask VirusTotal what it thinks of each configured key and write the
          answer to vtkey_status.json for the dashboard to render
  remove  drop one key, identified by FINGERPRINT rather than by the key itself

Why probing lives here and not in the dashboard: rendering a page must never make
a network call to VirusTotal. The page polls every few seconds, so a per-render
probe would spend the entire daily quota on drawing the UI, and one slow upstream
would hang the page. So root probes on a schedule (and on demand), writes a state
file, and the dashboard only reads that file.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

CONFIG = os.environ.get("BULWARK_INTEL_CONFIG", "/etc/bulwark-intel/config.json")
SPOOL = os.environ.get("BULWARK_VTKEY_SPOOL", "/var/lib/bulwark-intel/vtkey-spool")
LEDGER = os.environ.get("BULWARK_VTKEY_LOG", "/var/lib/bulwark-intel/vtkey_log.jsonl")
# Probe results, read by the dashboard. 644 on purpose: it holds no secrets, only
# fingerprints and statuses.
STATUS = os.environ.get("BULWARK_VTKEY_STATUS",
                        "/var/lib/bulwark-intel/vtkey_status.json")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
# A file that VirusTotal certainly has (EICAR). Using a known-present hash means a
# 404 can only be a key problem, never "that sample does not exist".
PROBE_SHA = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
# VT's own error codes. 429 covers BOTH "out of quota" and "too fast", so the HTTP
# status alone cannot tell a dead account from a busy one -- only error.code can.
BANNED_CODES = ("UserNotActiveError",)
INVALID_CODES = ("WrongCredentialsError",)


def fp_of(key):
    """Non-reversible fingerprint. MUST match dashboard.py's vtkey_fp() or the UI
    and this helper would disagree about which key a request refers to.

    Deliberately sha256-based rather than the first 6 characters of the key: the
    ledger is world-readable, and a prefix of a secret is still part of a secret.
    """
    return hashlib.sha256(key.encode()).hexdigest()[:6]


def log(*a):
    print("[vtkey %s]" % datetime.now(timezone.utc).strftime("%H:%M:%S"), *a, flush=True)


def ledger(rec):
    """Append-only audit trail, 644 so the dashboard (bulwarkintel) can read it
    back and show what happened without needing journal access."""
    rec["ts"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        with open(LEDGER, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        os.chmod(LEDGER, 0o644)
    except OSError as e:
        log("ledger write failed: %s" % e)


def normalise(raw):
    """Accept what VirusTotalClient accepts: bare KEY, or KEY:perday:permin.
    Returns the lowercased 64-hex key, or None if it is not a VT key at all."""
    k = str(raw).split(":")[0].strip().lower()
    return k if HEX64.match(k) else None


def config_keys(cfg):
    """The pool as (raw entry, normalised key) pairs, preserving order."""
    vt = cfg.get("virustotal", {}) or {}
    raw = vt.get("api_keys")
    if not isinstance(raw, list):
        raw = [vt.get("api_key")] if vt.get("api_key") else []
    return [(entry, normalise(entry)) for entry in raw]


def _strip_keys(d):
    """A copy with the key pool removed, for comparing 'everything else'."""
    c = json.loads(json.dumps(d))
    v = c.get("virustotal") or {}
    v.pop("api_keys", None)
    v.pop("api_key", None)
    return json.dumps(c, sort_keys=True)


def write_config(new_keys, clear_singular_if_gone=True):
    """Persist a new api_keys list and NOTHING else.

    Note there is deliberately no `cfg` parameter: the new file is rebuilt from the
    config currently ON DISK, with only api_keys replaced. A caller therefore cannot
    smuggle another change through this function even by accident -- the guarantee is
    structural rather than something a comparison has to catch. (An earlier version
    did take the caller's dict and compare; the comparison could never fail, which
    made it dead code pretending to be a safety check.)

    What IS checked, because it can genuinely go wrong: the file is re-read after the
    replace and compared against what was intended. A truncated or interrupted write
    would otherwise leave config.json broken with no key pool -- taking down every VT
    lookup on the node -- and nobody would find out until the next restart. If the
    verification fails the backup is put straight back.

    Add and remove share this one path so a future change cannot tighten one and
    forget the other.
    """
    old = json.load(open(CONFIG, encoding="utf-8"))
    new = json.loads(json.dumps(old))
    vt = new.setdefault("virustotal", {})
    vt["api_keys"] = list(new_keys)
    if clear_singular_if_gone and "api_key" in vt:
        ak = normalise(vt.get("api_key") or "")
        if ak and ak not in {normalise(k) for k in new_keys}:
            # Otherwise the singular field would resurrect a key we just removed.
            vt["api_key"] = ""

    st = os.stat(CONFIG)

    def like_original(path):
        """Copy the original ownership and mode rather than assuming them.

        config.json is 640 root:bulwarkintel and the bulwarkintel-run services must
        keep being able to read it -- getting this wrong takes the whole node down,
        not just this feature.

        The hasattr guard is only so this write path can be rehearsed off-Linux:
        os.chown does not exist on Windows, and a delete/rewrite path that cannot be
        run in a test is a path nobody has actually tested. On Linux hasattr is True,
        so production behaviour is exactly as before.
        """
        if hasattr(os, "chown"):
            os.chown(path, st.st_uid, st.st_gid)
        os.chmod(path, st.st_mode & 0o7777)

    bak = "%s.bak-%s" % (CONFIG, datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"))
    with open(bak, "w", encoding="utf-8") as f:
        json.dump(old, f, indent=2, ensure_ascii=False)
    like_original(bak)

    tmp = CONFIG + ".vtkey.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(new, f, indent=2, ensure_ascii=False)
    like_original(tmp)
    os.replace(tmp, CONFIG)

    # 写后校验。这一步不是形式:config.json 里没有可用的 api_keys 就等于把整个节点的
    # VT 查询关掉,而一次被打断的写入不会有任何人告诉你 —— 下一次重启才发作。
    try:
        back = json.load(open(CONFIG, encoding="utf-8"))
        assert list((back.get("virustotal") or {}).get("api_keys") or []) \
            == list(new_keys), "key pool did not land as intended"
        assert _strip_keys(back) == _strip_keys(new), "something else changed on disk"
    except Exception as e:
        shutil.copyfile(bak, CONFIG)
        like_original(CONFIG)
        raise RuntimeError("write verification failed (%s); config restored from %s"
                           % (e, os.path.basename(bak)))
    return os.path.basename(bak)


def probe_key(key, timeout=25):
    """Ask VirusTotal about one key. Returns (http_status, error_code, quota).

    Costs one API request against that key when the key is healthy. A banned or
    invalid key answers 401 without consuming anything, which is why re-checking
    dead keys is free and re-checking live ones is not.
    """
    def get(url):
        req = urllib.request.Request(
            url, headers={"x-apikey": key, "accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            try:
                return e.code, e.read().decode("utf-8", "replace")
            except Exception:
                return e.code, ""
        except Exception as e:
            return 0, "%s: %s" % (type(e).__name__, str(e)[:120])

    st, body = get("https://www.virustotal.com/api/v3/files/" + PROBE_SHA)
    try:
        code = ((json.loads(body) or {}).get("error") or {}).get("code") or ""
    except Exception:
        code = ""
    quota = None
    # Only worth asking for numbers when the key still works; a dead key would just
    # return the same error again.
    if st == 200:
        st2, body2 = get("https://www.virustotal.com/api/v3/users/%s/overall_quotas"
                         % key)
        if st2 == 200:
            try:
                q = (json.loads(body2).get("data") or {})
                daily = ((q.get("api_requests_daily") or {}).get("user") or {})
                quota = {"used": daily.get("used"), "allowed": daily.get("allowed")}
            except Exception:
                quota = None
    return st, code, quota


def classify(st, code):
    """One place decides what a probe result means, so the UI, the delete guard and
    the ledger can never disagree."""
    if code in BANNED_CODES:
        return "banned", "账号被停用/封禁"
    if code in INVALID_CODES:
        return "invalid", "密钥无效"
    if st == 200:
        return "ok", "正常可用"
    if code == "QuotaExceededError":
        return "quota", "配额已用完"
    if code == "TooManyRequestsError" or st == 429:
        return "rate", "被频率限制"
    if st == 403:
        return "forbidden", "被拒(403)"
    if st == 0:
        return "unknown", "探测失败(网络)"
    return "unknown", "无法判定 (HTTP %s)" % st


def do_probe():
    """Probe every configured key and write vtkey_status.json."""
    cfg = json.load(open(CONFIG, encoding="utf-8"))
    entries = []
    for raw, key in config_keys(cfg):
        if not key:
            entries.append({"fp": "??????", "state": "malformed",
                            "label": "不是 64 位十六进制密钥", "http": None,
                            "code": "", "quota": None, "removable": True})
            continue
        st, code, quota = probe_key(key)
        state, label = classify(st, code)
        entries.append({"fp": fp_of(key), "state": state, "label": label,
                        "http": st, "code": code, "quota": quota,
                        # 只有确定坏掉的才允许删。配额用完/被限速是暂时的,
                        # 让它可删等于把一把还能用的密钥交给一次手滑。
                        "removable": state in ("banned", "invalid", "malformed")})
        log("probe fp=%s http=%s code=%s -> %s" % (entries[-1]["fp"], st,
                                                   code or "-", state))
    out = {"checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "keys": entries}
    tmp = STATUS + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    os.replace(tmp, STATUS)
    os.chmod(STATUS, 0o644)
    bad = [e for e in entries if e["removable"]]
    log("probe done: %d 把密钥,其中 %d 把已坏" % (len(entries), len(bad)))
    ledger({"ok": True, "status": "probed", "detail":
            "%d key(s), %d unusable" % (len(entries), len(bad))})
    return 0


def apply_remove(fp):
    """Remove the key whose fingerprint is `fp`. Returns (status, detail).

    Re-probes the key first: the decision to delete must be made from a fresh
    answer, not from whatever the status file said minutes ago. Removing a key that
    has since recovered would trade real quota for a stale reading.
    """
    cfg = json.load(open(CONFIG, encoding="utf-8"))
    pairs = config_keys(cfg)
    target = [(raw, k) for raw, k in pairs if k and fp_of(k) == fp]
    if not target:
        # A malformed entry has no usable fingerprint; allow removing it by the
        # placeholder the status file shows.
        if fp == "??????":
            target = [(raw, k) for raw, k in pairs if not k]
        if not target:
            return "notfound", "配置里没有指纹为 %s 的密钥" % fp
    raw, key = target[0]

    if key:
        st, code, _ = probe_key(key)
        state, label = classify(st, code)
        if state not in ("banned", "invalid"):
            # 这是最重要的一条守卫:UI 可能是几分钟前的快照。
            return "refused", ("现场重新探测的结果是「%s」(HTTP %s %s),不是封禁/无效 "
                               "—— 拒绝删除" % (label, st, code or "-"))
    keep = [r for r, k in pairs if not (k == key and r == raw)]
    # 只删一个:同一把密钥若被重复配置,留给下一次请求处理,避免一次点击删掉多条。
    if len(keep) == len(pairs):
        return "notfound", "没有匹配到要删除的条目"
    if not [k for _, k in [(r, normalise(r)) for r in keep] if k]:
        return "refused", "这是最后一把可用密钥 —— 拒绝把 VirusTotal 清空"

    bak = write_config(keep)
    return "removed", "已删除,备份 %s,剩余 %d 把" % (bak, len(keep))


def apply_add(key):
    """Add one key to virustotal.api_keys. Returns (status, detail).

    Reads and rewrites config.json in full, but only mutates that one list, so
    every other setting round-trips untouched.
    """
    with open(CONFIG, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    vt = cfg.setdefault("virustotal", {})
    keys = vt.get("api_keys")
    if not isinstance(keys, list):
        keys = []

    # Compare on the normalised key so "KEY" and "KEY:500:4" are not both stored.
    existing = {normalise(k) for k in keys}
    existing.discard(None)
    if key in existing:
        return "duplicate", "already configured (%d key(s) total)" % len(keys)

    keys.append(key)
    # Goes through the shared writer so add and remove are held to the same
    # guarantee: api_keys is the only thing that may change, and the previous
    # config is always backed up first. A single write path is why one of the two
    # cannot quietly become laxer than the other.
    # clear_singular_if_gone=False here: adding a key is no reason to touch a
    # deliberately-set api_key field.
    bak = write_config(keys, clear_singular_if_gone=False)
    return "added", "pool is now %d key(s), backup %s" % (len(keys), bak)


def restart_intel():
    """app.py reads config once at startup, so a new key only takes effect after
    a restart. Never fatal: the key is already persisted at this point, so a
    failed restart just means it activates at the next natural restart."""
    try:
        p = subprocess.run(["systemctl", "restart", "bulwark-intel.service"],
                           capture_output=True, text=True, timeout=90)
        if p.returncode == 0:
            log("bulwark-intel restarted, new key is live")
            return True, ""
        err = (p.stderr or "").strip()[:200]
        log("restart failed rc=%d %s" % (p.returncode, err))
        return False, err
    except Exception as e:
        log("restart error %s %s" % (type(e).__name__, str(e)[:150]))
        return False, "%s: %s" % (type(e).__name__, str(e)[:150])


def process(path):
    name = os.path.basename(path)
    try:
        with open(path, "r", encoding="utf-8") as f:
            req = json.load(f)
    except Exception as e:
        log("bad request %s (%s) -> discard" % (name, e))
        ledger({"ok": False, "file": name, "status": "malformed",
                "detail": "%s: %s" % (type(e).__name__, str(e)[:120])})
        return

    # No "action" means a legacy add request. Keeping that default is what lets an
    # older dashboard build keep working across this change.
    action = str(req.get("action") or "add").strip().lower()

    if action == "probe":
        log("probe requested by %s" % name)
        try:
            do_probe()
        except Exception as e:
            log("probe failed: %s" % e)
            ledger({"ok": False, "file": name, "status": "probe_error",
                    "detail": "%s: %s" % (type(e).__name__, str(e)[:150])})
        return

    if action == "remove":
        fp = str(req.get("fp") or "").strip().lower()
        if not re.match(r"^[0-9a-f]{6}$|^\?{6}$", fp):
            log("rejected %s: bad fingerprint" % name)
            ledger({"ok": False, "file": name, "status": "invalid",
                    "detail": "fingerprint must be 6 hex characters"})
            return
        try:
            status, detail = apply_remove(fp)
        except Exception as e:
            log("remove failed for %s: %s" % (fp, e))
            ledger({"ok": False, "file": name, "status": "error", "fp": fp,
                    "detail": "%s: %s" % (type(e).__name__, str(e)[:150])})
            return
        if status != "removed":
            log("remove %s: %s (%s)" % (fp, status, detail))
            ledger({"ok": status != "error", "file": name, "status": status,
                    "fp": fp, "detail": detail, "restarted": False})
            return
        log("key fp=%s removed: %s" % (fp, detail))
        ok, err = restart_intel()
        ledger({"ok": True, "file": name, "status": "removed", "fp": fp,
                "detail": detail, "restarted": ok,
                "restart_error": err if not ok else ""})
        # The pool changed, so the cached statuses are stale by definition.
        try:
            do_probe()
        except Exception as e:
            log("post-remove probe failed: %s" % e)
        return

    if action != "add":
        log("rejected %s: unknown action %r" % (name, action))
        ledger({"ok": False, "file": name, "status": "invalid",
                "detail": "unknown action %r" % action[:32]})
        return

    key = normalise(req.get("key", ""))
    if not key:
        # Deliberately does not echo the rejected value: it is a secret even when
        # it is malformed, and it may just be a typo of a real key.
        log("rejected %s: not a 64-hex VirusTotal key" % name)
        ledger({"ok": False, "file": name, "status": "invalid",
                "detail": "not a 64-character hex key"})
        return

    fp = fp_of(key)
    try:
        status, detail = apply_add(key)
    except Exception as e:
        log("apply failed for %s: %s" % (fp, e))
        ledger({"ok": False, "file": name, "status": "error", "fp": fp,
                "detail": "%s: %s" % (type(e).__name__, str(e)[:150])})
        return

    if status == "duplicate":
        log("key %s %s" % (fp, detail))
        ledger({"ok": True, "file": name, "status": "duplicate", "fp": fp,
                "detail": detail, "restarted": False})
        return

    log("key %s added: %s" % (fp, detail))
    ok, err = restart_intel()
    ledger({"ok": True, "file": name, "status": "added", "fp": fp,
            "detail": detail, "restarted": ok,
            "restart_error": err if not ok else ""})
    # 新密钥的状态未知,顺手探一次,免得页面上挂着一个「未探测」。
    try:
        do_probe()
    except Exception as e:
        log("post-add probe failed: %s" % e)


def main():
    ap = argparse.ArgumentParser(description="Bulwark VT key helper")
    ap.add_argument("--probe", action="store_true",
                    help="只探测所有密钥的状态并写 vtkey_status.json,不处理 spool")
    a = ap.parse_args()
    if a.probe:
        return do_probe()

    if not os.path.isdir(SPOOL):
        return 0  # nothing to do; the spool is created by the installer

    try:
        names = sorted(n for n in os.listdir(SPOOL) if n.endswith(".json"))
    except OSError as e:
        log("cannot list spool: %s" % e)
        return 1

    if not names:
        return 0

    log("%d request(s) pending" % len(names))
    for n in names:
        path = os.path.join(SPOOL, n)
        # Claim the request before acting on it: renaming first means a crash
        # mid-restart cannot leave a request that gets applied twice.
        claimed = path + ".processing"
        try:
            os.replace(path, claimed)
        except OSError as e:
            log("cannot claim %s: %s" % (n, e))
            continue
        try:
            process(claimed)
        finally:
            try:
                os.unlink(claimed)
            except OSError:
                pass
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        log("FATAL", type(e).__name__, str(e)[:200])
        sys.exit(1)
