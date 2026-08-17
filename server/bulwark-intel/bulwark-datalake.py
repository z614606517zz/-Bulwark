#!/usr/bin/env python3
"""Bulwark datalake collector -- pull samples straight from the abuse.ch daily
archives instead of the MalwareBazaar API.

Runs alongside (not inside) harvest.py: app.py and harvest.py are byte-identical
across nodes on purpose, so this is a separate tool rather than a patch to them.
It reuses the SAME local service endpoints harvest.py uses (/vt/lookup and
/vt/upload), so the shared cache, the permanent vt_reports archive, the quota
meter and the sync-to-master path all keep working untouched.

HOURLY, NOT DAILY
-----------------
abuse.ch publishes the same samples twice: /daily/YYYY-MM-DD.zip and
/hourly/YYYY-MM-DD-HH.zip. This collector defaults to the hourly feed because the
daily one is structurally stale -- day D's archive only appears on D+1 at roughly
20:10 UTC, so today's samples are simply not in it. The hourly archive for hour HH
appears at HH+1:00, which puts the freshest slot at most about an hour behind.

The trade is retention. The hourly directory keeps about 8 days (192 slots;
measured 2026-08-07, oldest 2026-07-30-16, newest 2026-08-07-15), while daily goes
back to 2020-02-24. So hourly is the live feed and daily is the only way to reach
further back: set mode="daily" in config for that, everything else is identical.

WHY RANGE REQUESTS INSTEAD OF DOWNLOADING WHOLE ARCHIVES
--------------------------------------------------------
Measured on 2026-08-07 against datalake.abuse.ch:

  * archives are too big to pull whole. Hourly is usually 1-100 MB but spiked to
    9.9 GB (2026-08-01-22), and the daily equivalents run 500 MB - 18 GB. Node 245
    has 36 GB free, so a whole-archive fetch is wasteful at best and fatal at
    worst -- and extracting it would need the same space again.
  * every entry is named "<sha256>.<ext>", and the sha256 of the extracted bytes
    matches that name exactly (verified on real entries). So the archive's own
    file list IS the hash list -- no metadata feed needed.
  * the server sends "Accept-Ranges: bytes" and answers ranged GETs with 206.
  * the zip central directory for an 800 MB / 472-entry day is only 52 KiB.

So enumerating an entire day costs ~180 KiB of traffic (tail slice + central
directory) instead of 800 MB, and binaries are then fetched one at a time and
only for the hashes VirusTotal does not already know -- which is the same
"only fetch what we actually need" rule harvest.py follows. Peak disk use is one
sample, never a whole day, so the 18 GB day is a non-event.

Two consequences worth knowing:

  * slots go MISSING, not just unpublished: 2026-08-02-21 is absent between -20
    and -22. So a 404 is routine, never fatal -- it is logged and the collector
    moves to the next slot. The current hour is also 404 until HH+1:00.
  * the entries are ZipCrypto-encrypted (password 'infected'), NOT AES. That is
    the opposite of the per-sample zips the get_file API returns, and it is good
    news: stdlib zipfile can decrypt ZipCrypto, so no external 7z is needed and
    decryption happens on a stream we are already range-reading.

No sample binary is kept. Each one is written to a temp file, hashed, uploaded,
and deleted in the same iteration's finally block.
"""

import fcntl
import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timezone

CONFIG_PATH = os.environ.get("BULWARK_INTEL_CONFIG", "/etc/bulwark-intel/config.json")
BASE = {"hourly": "https://datalake.abuse.ch/malware-bazaar/hourly",
        "daily": "https://datalake.abuse.ch/malware-bazaar/daily"}
DAILY_BASE = BASE["daily"]          # kept for callers/tests that reference it
ZIP_PW = b"infected"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
# A "slot" is one archive: an hour (2026-08-07-15) or a day (2026-08-05). Both are
# zero-padded, so plain reverse string sort gives newest-first ordering.
SLOT_RE = {"hourly": re.compile(r"(\d{4}-\d{2}-\d{2}-\d{2})\.zip"),
           "daily": re.compile(r"(\d{4}-\d{2}-\d{2})\.zip")}
SLOT_FMT = {"hourly": "%Y-%m-%d-%H", "daily": "%Y-%m-%d"}
SLOT_HOURS = {"hourly": 1, "daily": 24}


def log(msg):
    sys.stdout.write("[datalake] %s\n" % msg)
    sys.stdout.flush()


def iso_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_day():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def load_cfg():
    with open(CONFIG_PATH) as f:
        return json.load(f)


# --------------------------------------------------------------------------- #
# pacing / quota -- same semantics as harvest.py so the two cannot disagree
# --------------------------------------------------------------------------- #

class VtRate:
    """Sliding-window limiter over everything that reaches VirusTotal.

    Counts lookups AND uploads: a VT-unknown sample costs two upstream calls
    back to back, and pacing only the lookups would let the upload that
    immediately follows slip past the per-minute limit.
    """

    def __init__(self, per_min, window=60.0):
        self.n = max(1, int(per_min))
        self.window = float(window)
        self.hits = []
        self.total = 0

    def acquire(self, what="", on_wait=None):
        """on_wait(seconds_left, what) is called about once a second while this
        blocks. The limiter is where most of a run's wall time goes, so without
        that hook a progress display would sit frozen on stale numbers for
        30-plus seconds and look like a hung process."""
        while True:
            now = time.monotonic()
            self.hits = [t for t in self.hits if now - t < self.window]
            if len(self.hits) < self.n:
                self.hits.append(now)
                self.total += 1
                return
            wait = self.window - (now - self.hits[0]) + 0.05
            log("vt rate %d/%.0fs reached, waiting %.1fs%s"
                % (self.n, self.window, wait, (" for " + what) if what else ""))
            wait = max(0.1, wait)
            if on_wait is None:
                time.sleep(wait)
                continue
            # Sleep in slices so the countdown stays live.
            end = time.monotonic() + wait
            while True:
                left = end - time.monotonic()
                if left <= 0:
                    break
                try:
                    on_wait(left, what)
                except Exception:
                    pass
                time.sleep(min(1.0, left))


def vt_remaining(cfg, reserve):
    """(remaining, cap, used) for today's shared VT allowance, or (None, ..) when
    it cannot be determined. Read-only against the service's DB: the intel service
    is what actually meters this, so its counter is the authority, not ours."""
    vt = cfg.get("virustotal", {}) or {}
    keys = [k for k in (str(x).split(":")[0].strip() for x in (vt.get("api_keys") or []))
            if len(k) == 64]
    cap = int(vt.get("requests_per_day", 0) or 0) * max(1, len(keys))
    if cap <= 0:
        return None, 0, 0
    try:
        p = cfg.get("db_path", "/var/lib/bulwark-intel/cache.db")
        c = sqlite3.connect("file:%s?mode=ro" % p, uri=True, timeout=10)
        c.execute("PRAGMA busy_timeout=8000")
        row = c.execute("SELECT count FROM quota WHERE day=? AND source='VirusTotal'",
                        (utc_day(),)).fetchone()
        c.close()
        used = int(row[0]) if row and row[0] is not None else 0
    except Exception as e:
        log("could not read the VT quota counter (%s) -> not sizing the run by it" % e)
        return None, cap, 0
    return max(0, cap - used - max(0, reserve)), cap, used


# --------------------------------------------------------------------------- #
# seekable HTTP range reader -- this is what makes the whole approach possible
# --------------------------------------------------------------------------- #

class HttpRangeFile(io.RawIOBase):
    """Read-only seekable file over HTTP byte ranges.

    zipfile drives this object: it seeks to the end looking for the end-of-
    central-directory record, reads the central directory, then seeks to
    individual entries. Those are many small reads (it walks 46-byte headers one
    at a time), so everything is served out of an aligned chunk cache -- without
    it, opening one archive would be thousands of HTTP requests.

    Chunk size is deliberately switchable: 64 KiB while zipfile parses the
    directory (small, scattered reads), several MiB while an entry is being
    streamed out (one long sequential read). Changing it drops the cache because
    the cache keys are chunk-aligned offsets.
    """

    def __init__(self, url, timeout=180, chunk=65536, max_chunks=6, retries=3):
        self.url = url
        self.timeout = timeout
        self.chunk = int(chunk)
        self.max_chunks = int(max_chunks)
        self.retries = int(retries)
        self.pos = 0
        self.requests = 0
        self.bytes_fetched = 0
        self._cache = {}
        self._order = []
        self.size = self._probe()

    # -- setup ------------------------------------------------------------- #

    def _probe(self):
        req = urllib.request.Request(self.url, method="HEAD")
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            size = int(r.headers.get("Content-Length") or 0)
            ranges = (r.headers.get("Accept-Ranges") or "").lower()
        if size <= 0:
            raise IOError("no Content-Length for %s" % self.url)
        if "bytes" not in ranges:
            # Refuse to continue rather than silently falling back to a full GET:
            # a full GET here could be an 18 GB download onto a 36 GB disk.
            raise IOError("server does not advertise byte ranges for %s "
                          "(Accept-Ranges=%r) -- refusing to fall back to a full "
                          "download" % (self.url, ranges))
        return size

    def set_chunk(self, chunk):
        chunk = int(chunk)
        if chunk != self.chunk:
            self.chunk = chunk
            self._cache.clear()
            del self._order[:]

    # -- plumbing ----------------------------------------------------------- #

    def _fetch(self, start, length):
        last = None
        for attempt in range(1, self.retries + 1):
            try:
                req = urllib.request.Request(
                    self.url, headers={"Range": "bytes=%d-%d" % (start, start + length - 1)})
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    if r.status not in (200, 206):
                        raise IOError("unexpected status %s for range request" % r.status)
                    data = r.read()
                self.requests += 1
                self.bytes_fetched += len(data)
                return data
            except Exception as e:            # transient network / 5xx
                last = e
                if attempt < self.retries:
                    nap = min(30.0, 2.0 ** attempt)
                    log("range %d+%d failed (%s: %s), retry %d/%d in %.0fs"
                        % (start, length, type(e).__name__, str(e)[:80],
                           attempt, self.retries, nap))
                    time.sleep(nap)
        raise IOError("range %d+%d failed after %d attempts: %s"
                      % (start, length, self.retries, last))

    def _block(self, start):
        blk = self._cache.get(start)
        if blk is None:
            blk = self._fetch(start, min(self.chunk, self.size - start))
            self._cache[start] = blk
            self._order.append(start)
            while len(self._order) > self.max_chunks:
                self._cache.pop(self._order.pop(0), None)
        return blk

    def _read_at(self, off, n):
        out = bytearray()
        while n > 0 and off < self.size:
            start = (off // self.chunk) * self.chunk
            blk = self._block(start)
            k = off - start
            take = min(n, len(blk) - k)
            if take <= 0:
                break
            out += blk[k:k + take]
            off += take
            n -= take
        return bytes(out)

    # -- file protocol ------------------------------------------------------ #

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.pos

    def seek(self, off, whence=io.SEEK_SET):
        if whence == io.SEEK_SET:
            p = off
        elif whence == io.SEEK_CUR:
            p = self.pos + off
        elif whence == io.SEEK_END:
            p = self.size + off
        else:
            raise ValueError("bad whence %r" % whence)
        self.pos = max(0, min(int(p), self.size))
        return self.pos

    def readinto(self, buf):
        want = min(len(buf), self.size - self.pos)
        if want <= 0:
            return 0
        data = self._read_at(self.pos, want)
        buf[:len(data)] = data
        self.pos += len(data)
        return len(data)


# --------------------------------------------------------------------------- #
# the daily index
# --------------------------------------------------------------------------- #

def list_slots(base, mode, timeout=90):
    """Every archive slot in the directory listing, newest first."""
    with urllib.request.urlopen(base + "/", timeout=timeout) as r:
        html = r.read().decode("utf-8", "replace")
    return sorted(set(SLOT_RE[mode].findall(html)), reverse=True)


def slot_age_hours(slot, mode, ref=None):
    """How many hours old a slot is. Hours (not days) because the hourly feed
    needs sub-day resolution to tell 'this hour' from 'yesterday'."""
    try:
        t = datetime.strptime(slot, SLOT_FMT[mode]).replace(tzinfo=timezone.utc)
        ref = ref or datetime.now(timezone.utc)
        return max(0.0, (ref - t).total_seconds() / 3600.0)
    except Exception:
        return None


def slot_day(slot):
    return slot[:10]


def slot_hour(slot, mode):
    return slot[11:13] if mode == "hourly" and len(slot) >= 13 else ""


# Backwards-compatible aliases: the daily-era names are still what the ad-hoc
# verification scripts import.
def list_days(base, timeout=90):
    return list_slots(base, "daily", timeout=timeout)


# --------------------------------------------------------------------------- #
# local service calls -- identical contract to harvest.py
# --------------------------------------------------------------------------- #

def svc_lookup(base, sha, timeout=180):
    body = json.dumps({"hash": sha}).encode("utf-8")
    req = urllib.request.Request(base + "/vt/lookup", data=body,
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def svc_upload(base, path, sha, timeout=300):
    with open(path, "rb") as f:
        data = f.read()
    url = base + "/vt/upload?name=" + urllib.parse.quote(sha + ".bin")
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/octet-stream"},
                                 method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def is_vt_unknown(resp):
    if resp.get("ok"):
        return False
    err = str(resp.get("error", ""))
    return "404" in err or "\u65e0\u6b64\u6587\u4ef6" in err   # "no such file"


# --------------------------------------------------------------------------- #
# small persistent bits
# --------------------------------------------------------------------------- #

def load_seen(path):
    try:
        with open(path) as f:
            return set(x.strip() for x in f if x.strip())
    except OSError:
        return set()


def save_seen(path, seen, cap=200000):
    items = list(seen)[-cap:]
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write("\n".join(items))
    os.replace(tmp, path)


def _chmod_readable(path):
    try:
        os.chmod(path, 0o644)
    except OSError:
        pass


def append_file_log(path, rec, limit_bytes=2097152, keep_lines=4000):
    """Same append-only ledger harvest.py writes, so the dashboard's downloads
    page shows datalake activity with no dashboard change. src='datalake'
    distinguishes the rows.

    The cap was 512 KB / 1000 lines, inherited from harvest.py which only ever ran
    hourly. This collector writes a line per sample LOOKED AT, and node 245 does
    ~1200 lookups a day at ~490 bytes each -- so the ledger could not even hold one
    day, and by mid-afternoon every download record from that same morning had been
    evicted. The dashboard then had nothing to show for 324 downloads, which is what
    "downloaded but no data" looked like from the outside.

    4000 lines / 2 MB holds roughly three days at the current rate. Deliberately not
    unbounded: the dashboard parses the whole file per request, so this file's size
    is a cost paid on every poll.
    """
    rec["ts"] = iso_now()
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        _chmod_readable(path)
        if os.path.getsize(path) > limit_bytes:
            with open(path, encoding="utf-8") as f:
                tail = f.readlines()[-keep_lines:]
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.writelines(tail)
            os.replace(tmp, path)
            _chmod_readable(path)
    except OSError as e:
        log("could not persist file log: %s" % e)


def load_upload_budget(path):
    today = utc_day()
    try:
        with open(path) as f:
            d = json.load(f)
        if d.get("day") == today:
            return today, max(0, int(d.get("used", 0)))
    except Exception:
        pass
    return today, 0


def save_upload_budget(path, day, used):
    tmp = path + ".tmp"
    try:
        with open(tmp, "w") as f:
            json.dump({"day": day, "used": used}, f)
        os.replace(tmp, path)
    except OSError as e:
        log("could not persist upload budget: %s" % e)


def save_run_state(path, state):
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False)
        os.replace(tmp, path)
        _chmod_readable(path)
    except OSError as e:
        log("could not persist run state: %s" % e)


class Progress:
    """Live run progress, written for the dashboard to poll.

    Separate from save_run_state, which only fires once in the closing finally
    and therefore says nothing while a run is actually in flight.

    Speed is computed HERE, not in the dashboard, and that is deliberate. The
    dashboard polls once a second while a single sample often transfers in far
    less than that, so differencing two dashboard polls would mostly measure the
    poll interval, not the network. Only this process sees byte-level timing.

    It reports an instantaneous rate over a short sliding window rather than a
    run average, because a run average here is meaningless: at the default two
    VT calls per minute the collector spends most of its wall time asleep in the
    rate limiter, which would dilute any real transfer rate to near zero.

    Writes are throttled and failures are swallowed -- progress reporting must
    never slow down or break the actual collection.
    """

    MIN_INTERVAL = 0.4          # seconds between ordinary disk writes
    SPEED_WINDOW = 6.0          # sliding window used for the instantaneous rate

    def __init__(self, path, cap, slot_count, wire_fn):
        self.path = path
        self.cap = int(cap or 0)
        self.slot_count = int(slot_count or 0)
        self.wire_fn = wire_fn           # -> cumulative bytes off the wire
        self.start = time.monotonic()
        self.samples = []                # (monotonic, cumulative wire bytes)
        self.last_write = 0.0
        # Seconds per completed sample, refreshed only when a sample finishes.
        # Deriving the ETA from live elapsed/done instead would make the estimate
        # climb throughout every rate-limit wait, which reads as the remaining
        # time going backwards.
        self.per_sample = 0.0
        self.d = {
            "phase": "starting", "phase_detail": "",
            "slot": "", "slot_index": 0, "slot_done": 0, "slot_total": 0,
            "done": 0, "current_file": "", "current_size": 0, "file_bytes": 0,
        }

    # -- state setters; each one just records, then asks for a write ------------

    def phase(self, name, detail="", force=False):
        self.d["phase"] = name
        self.d["phase_detail"] = detail
        self.write(force=force)

    def slot(self, name, index, total_entries=0):
        self.d.update({"slot": name, "slot_index": index,
                       "slot_total": total_entries, "slot_done": 0})
        self.write(force=True)

    def sample(self, done, slot_done, filename, size):
        # Called as sample N starts, so the time elapsed so far is the time it
        # took to finish the previous N-1 -- exactly the average worth projecting.
        if done > 1:
            self.per_sample = (time.monotonic() - self.start) / (done - 1)
        self.d.update({"done": done, "slot_done": slot_done,
                       "current_file": filename, "current_size": int(size or 0),
                       "file_bytes": 0})
        self.write(force=True)

    def file_bytes(self, written):
        """Bytes of the current entry extracted so far.

        Reported alongside the wire total because the two move very differently:
        wire bytes advance in multi-megabyte steps, one per range request, so on a
        large sample the rate figure only refreshes every several seconds. This
        counter advances every megabyte read, which gives the page something that
        visibly moves while a download is in flight. It measures decompressed
        output, so it is a progress signal, not a network rate."""
        self.d["file_bytes"] = int(written or 0)
        self.write()

    # -- speed ----------------------------------------------------------------

    def _speed(self, now, wire):
        """Bytes/sec over the trailing SPEED_WINDOW. Returns 0.0 when there is
        not yet a second sample to difference against."""
        self.samples.append((now, wire))
        cutoff = now - self.SPEED_WINDOW
        # Keep one sample older than the cutoff so a slow trickle still has a
        # baseline to difference against.
        while len(self.samples) > 2 and self.samples[1][0] < cutoff:
            self.samples.pop(0)
        t0, b0 = self.samples[0]
        span = now - t0
        if span <= 0.05 or wire <= b0:
            return 0.0
        return (wire - b0) / span

    def write(self, force=False):
        now = time.monotonic()
        if not force and (now - self.last_write) < self.MIN_INTERVAL:
            return
        self.last_write = now
        try:
            wire = int(self.wire_fn() or 0)
        except Exception:
            wire = 0
        elapsed = now - self.start
        inst = self._speed(now, wire)
        done = int(self.d.get("done") or 0)
        # ETA is derived from wall time per completed sample, not from bytes:
        # rate limiting, not bandwidth, is what sets the pace. Scoped to the
        # current archive so the number means something concrete.
        left = max(0, int(self.d.get("slot_total") or 0) - int(self.d.get("slot_done") or 0))
        if self.cap > 0:
            left = min(left, max(0, self.cap - done))
        eta = round(self.per_sample * left, 0) if (self.per_sample > 0 and left > 0) else None

        out = dict(self.d)
        out.update({
            "running": True,
            "pid": os.getpid(),
            "ts": iso_now(),
            "cap": self.cap,
            "slot_count": self.slot_count,
            "bytes": wire,
            "speed_bps": round(inst, 1),
            "avg_bps": round(wire / elapsed, 1) if elapsed > 0 else 0.0,
            "elapsed_sec": round(elapsed, 1),
            "eta_sec": eta,
        })
        tmp = self.path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(out, f, ensure_ascii=False)
            os.replace(tmp, self.path)
            _chmod_readable(self.path)
        except OSError:
            pass        # never let progress reporting break a run

    def clear(self):
        """Drop the file so the dashboard reads 'idle'. Best effort: a run killed
        by SIGKILL never reaches this, which is why the dashboard also ages the
        file out instead of trusting the running flag."""
        for p in (self.path + ".tmp", self.path):
            try:
                if os.path.exists(p):
                    os.remove(p)
            except OSError:
                pass


def take_lock(path):
    """The rate limit is per-process, so two overlapping runs would double the
    real VT call rate. Exit quietly (0) when another run owns the lock."""
    fd = open(path, "a+")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fd.seek(0)
        other = fd.read().strip()
        log("another datalake run holds the lock (%s) -> exit"
            % (("pid " + other) if other else "pid unknown"))
        return None
    fd.seek(0)
    fd.truncate()
    fd.write(str(os.getpid()))
    fd.flush()
    return fd


# --------------------------------------------------------------------------- #
# extraction
# --------------------------------------------------------------------------- #

def extract_entry(zf, rf, name, dst, big_chunk, size_hint=0, on_chunk=None):
    """Stream one entry out of the remote archive into dst, returning its real
    sha256. The range chunk is enlarged first because this is one long sequential
    read, unlike the scattered little reads of directory parsing -- but only as
    far as the entry actually needs: sizing every extraction at big_chunk made a
    162-byte sample cost a 4 MiB fetch.

    on_chunk(bytes_written_so_far) is invoked as the data streams, which is the
    only point where a live transfer rate can be observed at all."""
    want = max(65536, min(int(big_chunk), int(size_hint or 0) + 65536))
    rf.set_chunk(want)
    h = hashlib.sha256()
    n = 0
    with zf.open(name, "r", pwd=ZIP_PW) as src, open(dst, "wb") as out:
        while True:
            buf = src.read(1024 * 1024)
            if not buf:
                break
            h.update(buf)
            out.write(buf)
            n += len(buf)
            if on_chunk is not None:
                try:
                    on_chunk(n)
                except Exception:
                    pass        # a progress hook must never abort an extraction
    return h.hexdigest(), n


# --------------------------------------------------------------------------- #

def main():
    cfg = load_cfg()
    d = cfg.get("datalake", {}) or {}
    if not bool(d.get("enabled", True)):
        log("datalake collector disabled in config -> nothing to do")
        return 0

    mode = str(os.environ.get("DATALAKE_MODE") or d.get("mode", "hourly")).lower()
    if mode not in BASE:
        log("unknown mode %r -> falling back to hourly" % mode)
        mode = "hourly"
    cfg_base = str(d.get("base_url") or "").rstrip("/")
    # Refuse a base_url left over from the other mode. Reading the daily
    # directory with hourly filename rules matches nothing, and the run would
    # look like a cheerful "no new samples" instead of a misconfiguration.
    base_url = cfg_base if cfg_base.endswith("/" + mode) else BASE[mode]
    if cfg_base and base_url != cfg_base:
        log("config base_url %r does not match mode %r -> using %s"
            % (cfg_base, mode, base_url))
    # Fall back to the harvest section for the service URL: on this node harvest
    # already carries the right value (plain http on loopback, no cert).
    svc = str(d.get("service_url")
              or (cfg.get("harvest", {}) or {}).get("service_url")
              or "http://127.0.0.1:8787").rstrip("/")

    state_file = d.get("state_file", "/var/lib/bulwark-intel/datalake_seen.txt")
    files_path = d.get("file_log", "/var/lib/bulwark-intel/harvest_files.jsonl")
    run_state = d.get("run_state", "/var/lib/bulwark-intel/datalake_state.json")
    progress_path = d.get("progress_file", "/var/lib/bulwark-intel/datalake_progress.json")
    work = d.get("work_dir", "/var/lib/bulwark-intel/datalake_work")
    lock_path = d.get("lock_file", "/var/lib/bulwark-intel/datalake.lock")
    budget_path = d.get("upload_budget_state",
                        "/var/lib/bulwark-intel/harvest_upload_budget.json")

    max_run = int(os.environ.get("DATALAKE_MAX") or d.get("max_per_run", 50))
    max_seconds = int(os.environ.get("DATALAKE_SECONDS") or d.get("max_run_seconds", 1500))
    # Window in hours. 192h (~8 days) is the observed hourly retention -- asking
    # for more than the directory keeps just wastes index parsing.
    max_age_h = int(os.environ.get("DATALAKE_HOURS")
                    or d.get("max_age_hours", 192 if mode == "hourly" else 720))
    if os.environ.get("DATALAKE_DAYS"):
        max_age_h = int(os.environ["DATALAKE_DAYS"]) * 24
    qpm = int(os.environ.get("DATALAKE_QPM") or d.get("queries_per_minute", 2))
    max_sample = int(d.get("max_sample_mb", 32)) * 1024 * 1024
    upload_unknown = bool(d.get("upload_unknown", True))
    budget_cap = int(d.get("upload_budget_per_day", 0))     # 0 == unlimited
    unlimited = budget_cap <= 0
    reserve = int(d.get("vt_reserve", 20))
    small_chunk = int(d.get("dir_chunk_bytes", 65536))
    big_chunk = int(d.get("data_chunk_bytes", 4 * 1024 * 1024))
    enum_only = bool(os.environ.get("DATALAKE_ENUM_ONLY"))
    forced_slot = (os.environ.get("DATALAKE_SLOT")
                   or os.environ.get("DATALAKE_DAY") or "").strip()

    lock = take_lock(lock_path)
    if lock is None:
        return 0

    # We hold the lock, so no other run exists, so any progress file still lying
    # around is a leftover -- from a run killed hard enough to skip its finally,
    # or from an early return below. Drop it now rather than let the dashboard
    # advertise a run that is not happening.
    for _stale in (progress_path + ".tmp", progress_path):
        try:
            if os.path.exists(_stale):
                os.remove(_stale)
        except OSError:
            pass

    os.makedirs(work, exist_ok=True)
    rate = VtRate(qpm)
    seen = load_seen(state_file)
    bday, used_today = load_upload_budget(budget_path)
    today = utc_day()
    deadline = time.monotonic() + max_seconds if max_seconds > 0 else None

    st = {"slots_seen": 0, "missing": 0, "enumerated": 0, "candidates": 0, "looked": 0,
          "stored": 0, "unknown": 0, "extracted": 0, "uploaded": 0,
          "hash_mismatch": 0, "too_big": 0, "skipped_budget": 0, "errors": 0}
    stop = "done"
    http_requests = 0
    http_bytes = 0

    try:
        slots = [forced_slot] if forced_slot else list_slots(base_url, mode)
    except Exception as e:
        log("could not read the %s index (%s: %s) -> abort"
            % (mode, type(e).__name__, str(e)[:120]))
        return 1
    if not slots:
        log("%s index had no archives -> abort" % mode)
        return 1

    fresh = [s for s in slots if (slot_age_hours(s, mode) or 0.0) <= max_age_h]
    log("%s index: %d archives, newest %s (%.1fh old); %d inside the %dh window; "
        "pacing %d/min, cap %d items / %ds"
        % (mode, len(slots), slots[0], slot_age_hours(slots[0], mode) or 0.0,
           len(fresh), max_age_h, qpm, max_run, max_seconds))

    remaining, cap, used = vt_remaining(cfg, reserve)
    if remaining is not None:
        log("vt allowance today: %d used of %d, %d usable after a %d reserve"
            % (used, cap, remaining, reserve))
        if remaining <= 0:
            log("no VT allowance left today -> exit before spending anything")
            save_run_state(run_state, {"ts": iso_now(), "stopped_by": "vt_quota",
                                       "stats": st})
            return 0

    processed = 0
    # Wire-byte accounting for the progress display. http_bytes only grows once a
    # slot is fully done, so the live total has to add the current reader's
    # running count on top of it -- reading http_bytes alone would report a stale
    # figure for the entire duration of a slot, which is exactly the window the
    # user is watching.
    wire = {"committed": 0, "rf": None}
    progress = Progress(progress_path, max_run, len(fresh),
                        lambda: wire["committed"] +
                        (wire["rf"].bytes_fetched if wire["rf"] is not None else 0))
    if not enum_only:
        progress.phase("starting", "读取归档索引", force=True)

    def paced(what):
        """rate.acquire wrapper that keeps the progress countdown alive."""
        rate.acquire(what, on_wait=None if enum_only else
                     (lambda left, w: progress.phase(
                         "rate_wait", "限速等待 %.0fs" % left)))

    try:
        for slot in fresh:
            if processed >= max_run or (deadline and time.monotonic() >= deadline):
                break
            url = "%s/%s.zip" % (base_url, slot)
            if not enum_only:
                progress.d["slot"] = slot
                progress.phase("enumerating", "解析 %s 索引" % slot, force=True)
            try:
                rf = HttpRangeFile(url, chunk=small_chunk)
                wire["rf"] = rf
                zf = zipfile.ZipFile(rf)
                infos = zf.infolist()
            except urllib.error.HTTPError as e:
                # Routine: the current hour is not published until HH+1:00, and
                # individual slots do go missing entirely (e.g. 2026-08-02-21).
                st["missing"] += 1
                # Keep the live byte total monotonic: whatever a failed reader
                # already pulled still crossed the wire, and a total that went
                # backwards would read as zero throughput.
                wire["committed"] += wire["rf"].bytes_fetched if wire["rf"] else 0
                wire["rf"] = None
                log("%s.zip -> HTTP %s%s" % (slot, e.code,
                    " (not published yet or missing)" if e.code == 404 else ""))
                continue
            except Exception as e:
                st["errors"] += 1
                wire["committed"] += wire["rf"].bytes_fetched if wire["rf"] else 0
                wire["rf"] = None
                log("%s.zip open failed: %s: %s" % (slot, type(e).__name__, str(e)[:120]))
                continue

            st["slots_seen"] += 1
            age_h = slot_age_hours(slot, mode) or 0.0
            log("%s.zip: %.1f MiB, %d entries, %.1fh old, directory cost %d KiB "
                "in %d requests" % (slot, rf.size / 1048576.0, len(infos), age_h,
                                    rf.bytes_fetched // 1024, rf.requests))

            todo = []
            for info in infos:
                stem = os.path.basename(info.filename)
                sha = stem.split(".")[0].lower()
                st["enumerated"] += 1
                if not SHA256_RE.match(sha) or sha in seen:
                    continue
                todo.append((sha, info))
            st["candidates"] += len(todo)
            if not todo:
                log("%s: nothing new (all %d entries already processed)" % (slot, len(infos)))
                continue
            if not enum_only:
                # slot_total is the candidate count, not the entry count: the
                # progress bar has to measure the work actually queued.
                progress.slot(slot, st["slots_seen"], len(todo))

            for slot_done, (sha, info) in enumerate(todo, start=1):
                if processed >= max_run:
                    stop = "max_per_run"
                    break
                if deadline and time.monotonic() >= deadline:
                    stop = "time_budget"
                    break
                if remaining is not None and remaining <= 0:
                    stop = "vt_quota"
                    break

                processed += 1
                if not enum_only:
                    progress.sample(processed, slot_done,
                                    os.path.basename(info.filename), info.file_size)
                ext = os.path.splitext(info.filename)[1].lstrip(".").lower()
                fl = {"src": "datalake", "mode": mode, "sha256": sha,
                      "name": os.path.basename(info.filename), "type": ext,
                      "size": int(info.file_size), "sig": "",
                      "slot": slot, "day": slot_day(slot), "hour": slot_hour(slot, mode),
                      "age_hours": round(age_h, 2), "age_days": int(age_h // 24),
                      "in_window": True, "window_hours": max_age_h,
                      "vt_unknown": False, "downloaded": False, "uploaded": False,
                      "skipped_budget": False}
                dst = os.path.join(work, sha[:16] + ".bin")
                try:
                    if enum_only:
                        log("enum-only: would look up %s (%s, %d B)"
                            % (sha[:12], ext or "?", info.file_size))
                        continue

                    paced("lookup " + sha[:12])
                    progress.phase("looking_up", "查询 %s" % sha[:12], force=True)
                    resp = svc_lookup(svc, sha)
                    st["looked"] += 1
                    if remaining is not None and not resp.get("cached"):
                        remaining -= 1        # a real upstream call happened
                    if resp.get("ok") and resp.get("stored"):
                        st["stored"] += 1
                    unknown = is_vt_unknown(resp)
                    fl["vt_unknown"] = unknown
                    if unknown:
                        st["unknown"] += 1

                    can_upload = upload_unknown and (unlimited or used_today < budget_cap)
                    if unknown and upload_unknown and not can_upload:
                        st["skipped_budget"] += 1
                        fl["skipped_budget"] = True
                    elif unknown and info.file_size > max_sample:
                        # VirusTotal's public file endpoint tops out around 32 MB;
                        # sending more just wastes a paced slot and the bandwidth.
                        st["too_big"] += 1
                        fl["too_big"] = True
                        log("unknown but %.1f MiB > %d MiB cap -> lookup only %s"
                            % (info.file_size / 1048576.0, max_sample // 1048576, sha[:12]))
                    elif unknown:
                        # compress_size, not file_size: the compressed bytes are
                        # what actually crosses the wire.
                        progress.phase("downloading", "下载 %s" % sha[:12], force=True)
                        real, n = extract_entry(zf, rf, info.filename, dst,
                                                big_chunk, info.compress_size,
                                                on_chunk=progress.file_bytes)
                        rf.set_chunk(small_chunk)
                        st["extracted"] += 1
                        fl["downloaded"] = True
                        fl["bytes"] = n
                        if real != sha:
                            # The archive names entries by hash, so a mismatch means
                            # corruption -- never hand that to VT as if it were sha.
                            st["hash_mismatch"] += 1
                            fl["hash_mismatch"] = True
                            log("sha mismatch: entry %s extracted to %s -> skip upload"
                                % (sha[:12], real[:12]))
                        else:
                            paced("upload " + sha[:12])
                            progress.phase("uploading",
                                           "上传 %s (%.0f KiB)" % (sha[:12], n / 1024.0),
                                           force=True)
                            up = svc_upload(svc, dst, sha)
                            st["uploaded"] += 1
                            used_today += 1
                            if remaining is not None:
                                remaining -= 1
                            fl["uploaded"] = True
                            fl["upload_ok"] = bool(up.get("ok"))
                            save_upload_budget(budget_path, bday, used_today)
                            log("uploaded unknown %s (%.1f KiB) ok=%s (%d today, ceiling %s)"
                                % (sha[:12], n / 1024.0, up.get("ok"), used_today,
                                   "none" if unlimited else budget_cap))
                    seen.add(sha)
                except Exception as e:
                    st["errors"] += 1
                    fl["error"] = "%s: %s" % (type(e).__name__, str(e)[:100])
                    log("error %s %s %s" % (sha[:12], type(e).__name__, str(e)[:120]))
                finally:
                    try:
                        if os.path.exists(dst):
                            os.remove(dst)      # no sample binary is ever kept
                    except OSError:
                        pass
                    if not enum_only:
                        append_file_log(files_path, fl)
                        save_seen(state_file, seen)
                        progress.write(force=True)

            http_requests += rf.requests
            http_bytes += rf.bytes_fetched
            # Hand the finished reader's bytes to the committed total, in that
            # order, so the live figure never dips between slots.
            wire["committed"] = http_bytes
            wire["rf"] = None
            try:
                zf.close()
            except Exception:
                pass
            if stop in ("max_per_run", "time_budget", "vt_quota"):
                break
    finally:
        progress.clear()
        shutil.rmtree(work, ignore_errors=True)
        save_seen(state_file, seen)
        summary = {"ts": iso_now(), "mode": mode, "stopped_by": stop, "stats": st,
                   "http_requests": http_requests, "http_bytes": http_bytes,
                   "vt_calls_paced": rate.total, "uploads_today": used_today,
                   "vt_remaining": remaining, "window_hours": max_age_h,
                   "newest_slot": slots[0] if slots else "",
                   "newest_slot_age_hours": round(slot_age_hours(slots[0], mode) or 0.0, 2)
                   if slots else None}
        save_run_state(run_state, summary)
        log("done stopped_by=%s %s" % (stop, json.dumps(st)))
        log("traffic: %d range requests, %.1f MiB fetched (a whole-archive download "
            "would have been far larger)" % (http_requests, http_bytes / 1048576.0))
        if lock is not None:
            try:
                fcntl.flock(lock, fcntl.LOCK_UN)
                lock.close()
            except OSError:
                pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
