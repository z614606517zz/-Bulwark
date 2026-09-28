#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
流式采集良性(白)PE 语料：下载一个容器 -> 解包 -> 抽出内部真 PE -> 入库去重
-> 立刻删掉下载物和解包临时目录 -> 到目标量即停。

设计要点
--------
1) 磁盘常量占用。任意时刻只有【1 个下载物 + 1 个解包目录】在盘上，处理完立即删。
   语料库里只留去重后的 PE 本体，安装包本身不留。30GB 的安装包能压成几 GB 的语料。

2) 绝不执行样本。解包全部走 7z / Python zipfile，只读不跑。这条是硬约束：
   白样本采集器一旦执行样本，采集机自己就成了受害者。

3) 厂商多样性优先于数量。负样本(白样本)如果全是微软签名，模型会学成
   "微软签名 => 干净"，一遇第三方软件就狂误报。所以主力来源是 PyPI wheel /
   NuGet 包 / GitHub release —— 它们横跨几百个厂商、几十种编译器工具链。

4) PyPI wheel 里的 .pyd/.dll 绝大多数【没有签名】。这是特意要的：
   语料里必须有"无签名但良性"的样本，否则模型会把"无签名"当成恶意特征，
   而按本项目的设计原则，无签名只是软信号、绝不单独定罪。

5) 语料落盘布局与 extract_features.py 的预期一致：
      <out>/benign/<sha256前2位>/<sha256>
      <out>/manifests/benign_manifest.jsonl
   所以采完可以直接跑 extract_features.py，不需要搬文件。

6) 可断点续跑。启动时把已有 manifest 的 sha256 读进内存做去重集，
   重复运行只会补新样本，不会重复下载已入库的包。

用法
----
  python harvest_benign.py --out "C:\\path\\corpus" --target 20000 \
      --sevenzip "C:\\path\\7z.exe"
  python harvest_benign.py --out ... --target 20000 --sources pypi,nuget,github
  python harvest_benign.py --out ... --ingest-dir "C:\\path\\installers"   # 处理已下载的
"""

import argparse
import hashlib
import json
import os
import random
import shutil
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

UA = "Mozilla/5.0 bulwark-benign-harvester"

# 解包后认这些为"可能是 PE"的候选扩展名；仍要读头确认，扩展名只是初筛
PE_EXT = {".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr", ".drv", ".efi",
          ".pyd", ".node", ".ax", ".acm", ".ime", ".rll", ".mun", ".winmd"}
# Python zipfile 能直接开的容器(不需要 7z)
ZIP_EXT = {".zip", ".whl", ".nupkg", ".vsix", ".jar", ".crx", ".egg", ".apk"}
# 交给 7z 的容器
ARC_EXT = {".exe", ".msi", ".msix", ".msixbundle", ".appx", ".7z", ".rar",
           ".cab", ".msu", ".tar", ".gz", ".xz", ".bz2", ".iso", ".dmg"}

MIN_PE = 1024
MAX_PE = 64 * 1024 * 1024


# ---------------------------------------------------------------- PE 识别
def pe_info(path):
    """确认是真 PE 并返回 (arch, is_dll, timedatestamp)；不是 PE 返回 None。

    只读头部，不解析全文件 —— 解包出来的垃圾文件多，这一步必须快。
    """
    try:
        with open(path, "rb") as f:
            head = f.read(0x400)
    except OSError:
        return None
    if len(head) < 0x40 or head[:2] != b"MZ":
        return None
    try:
        e = struct.unpack_from("<I", head, 0x3C)[0]
        if e <= 0 or e + 26 > len(head) or head[e:e + 4] != b"PE\0\0":
            return None
        machine, _nsec, tds = struct.unpack_from("<HHI", head, e + 4)
        chars = struct.unpack_from("<H", head, e + 22)[0]
    except (struct.error, IndexError):
        return None
    arch = {0x8664: "x64", 0x014c: "x86", 0xAA64: "arm64", 0x01c0: "arm",
            0x01c4: "armnt", 0x0200: "ia64"}.get(machine, "0x%x" % machine)
    return arch, bool(chars & 0x2000), tds


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


# ---------------------------------------------------------------- 语料库
class Corpus:
    def __init__(self, root, target):
        self.root = root
        self.bdir = os.path.join(root, "benign")
        self.mdir = os.path.join(root, "manifests")
        os.makedirs(self.bdir, exist_ok=True)
        os.makedirs(self.mdir, exist_ok=True)
        self.manifest = os.path.join(self.mdir, "benign_manifest.jsonl")
        self.target = target
        self.seen = set()
        self.pkgs = set()
        self._load()
        self.mf = open(self.manifest, "a", encoding="utf-8")

    def _load(self):
        if not os.path.isfile(self.manifest):
            return
        with open(self.manifest, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    o = json.loads(line)
                except ValueError:
                    continue
                s = str(o.get("sha256", "")).lower()
                if len(s) == 64:
                    self.seen.add(s)
                p = o.get("pkg")
                if p:
                    self.pkgs.add(p)
        print(f"[resume] 已有 {len(self.seen)} 个白样本 / {len(self.pkgs)} 个来源包",
              flush=True)

    @property
    def n(self):
        return len(self.seen)

    def full(self):
        return self.n >= self.target

    def add(self, path, src, pkg):
        """把一个已确认的 PE 收进语料库；返回 True 表示是新样本。"""
        try:
            size = os.path.getsize(path)
        except OSError:
            return False
        if size < MIN_PE or size > MAX_PE:
            return False
        info = pe_info(path)
        if info is None:
            return False
        try:
            sha = sha256_file(path)
        except OSError:
            return False
        if sha in self.seen:
            return False

        sub = os.path.join(self.bdir, sha[:2])
        os.makedirs(sub, exist_ok=True)
        dst = os.path.join(sub, sha)
        if not os.path.exists(dst):
            try:
                shutil.copyfile(path, dst)
            except OSError:
                return False

        arch, is_dll, tds = info
        self.seen.add(sha)
        self.pkgs.add(pkg)
        self.mf.write(json.dumps({
            "sha256": sha, "label": "benign", "size": size,
            "ext": os.path.splitext(path)[1].lower(), "arch": arch,
            "pe_type": "dll" if is_dll else "exe", "tds": tds,
            "src": src, "pkg": pkg,
            "inner": os.path.basename(path),
            "collected": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }, ensure_ascii=False) + "\n")
        return True

    def flush(self):
        self.mf.flush()

    def close(self):
        try:
            self.mf.close()
        except Exception:
            pass


# ---------------------------------------------------------------- 解包
def unpack_zip(src, dst):
    """用 Python zipfile 解 zip 家族。逐条解，坏条目跳过不影响整体。"""
    n = 0
    try:
        with zipfile.ZipFile(src) as z:
            for info in z.infolist():
                if info.is_dir() or info.file_size > MAX_PE:
                    continue
                name = info.filename.replace("\\", "/")
                # 防目录穿越
                parts = [p for p in name.split("/")
                         if p not in ("", ".", "..") and ":" not in p]
                if not parts:
                    continue
                out = os.path.join(dst, *parts)
                os.makedirs(os.path.dirname(out), exist_ok=True)
                try:
                    with z.open(info) as fi, open(out, "wb") as fo:
                        shutil.copyfileobj(fi, fo, 1 << 20)
                    n += 1
                except Exception:
                    continue
    except Exception:
        return n
    return n


def unpack_7z(src, dst, sevenzip, timeout=300):
    """7z x -y：能吃 NSIS / InnoSetup / MSI / CAB / SFX / 7z / rar。"""
    if not sevenzip:
        return -1
    try:
        p = subprocess.run(
            [sevenzip, "x", "-y", "-bd", "-bso0", "-bse0",
             "-o" + dst, src],
            timeout=timeout, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return p.returncode
    except subprocess.TimeoutExpired:
        return -2
    except Exception:
        return -3


def harvest_container(path, corpus, src, pkg, work, sevenzip, depth=0):
    """解一个容器，把里面的 PE 全收进语料库。返回新增数量。

    depth<=1 时对解出来的内层容器再解一层 —— 安装包套安装包(带 vcredist 的)很常见，
    但不做无限递归，避免压缩炸弹。
    """
    ext = os.path.splitext(path)[1].lower()
    tmp = os.path.join(work, "x%d_%d" % (depth, random.randrange(1 << 30)))
    os.makedirs(tmp, exist_ok=True)
    added = 0
    try:
        if ext in ZIP_EXT:
            unpack_zip(path, tmp)
        elif ext in ARC_EXT:
            rc = unpack_7z(path, tmp, sevenzip)
            if rc != 0:
                # NSIS/Inno 常报非 0 但仍解出东西；有内容就继续用
                pass
        else:
            return 0

        inner_arcs = []
        for root, _dirs, files in os.walk(tmp):
            for fn in files:
                fp = os.path.join(root, fn)
                fext = os.path.splitext(fn)[1].lower()
                if fext in PE_EXT or fext == "":
                    if corpus.add(fp, src, pkg):
                        added += 1
                        if corpus.full():
                            return added
                if depth < 1 and fext in (ZIP_EXT | ARC_EXT) and fext != ".exe":
                    inner_arcs.append(fp)

        for ia in inner_arcs[:40]:
            if corpus.full():
                break
            added += harvest_container(ia, corpus, src, pkg, work,
                                       sevenzip, depth + 1)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return added


# ---------------------------------------------------------------- 下载
def http_get(url, timeout=30):
    headers = {"User-Agent": UA, "Accept": "application/json"}
    # 有 token 就带上：GitHub 未认证 60 次/小时，带 token 是 5000 次/小时。
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if tok and "api.github.com" in url:
        headers["Authorization"] = f"Bearer {tok}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def http_json(url, timeout=30):
    return json.loads(http_get(url, timeout).decode("utf-8", "ignore"))


def download(url, dst, timeout=300):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r, open(dst, "wb") as f:
        shutil.copyfileobj(r, f, 1 << 20)
    return os.path.getsize(dst)


# ---------------------------------------------------------------- 来源
CURATED_PYPI = """
numpy scipy pandas pillow lxml cryptography cffi pyyaml psutil pyzmq
greenlet sqlalchemy msgpack regex aiohttp frozenlist yarl multidict
charset-normalizer markupsafe wrapt kiwisolver matplotlib contourpy
fonttools scikit-learn scikit-image opencv-python opencv-python-headless
h5py numba llvmlite pyarrow grpcio protobuf tornado ujson orjson
bcrypt pynacl pycryptodome pycryptodomex zope-interface twisted
pywin32 pywinpty pyinstaller pefile capstone keystone-engine unicorn
lief yara-python python-snappy zstandard brotli lz4 blosc2 bitarray
xxhash cityhash mmh3 rapidfuzz levenshtein jellyfish
netifaces psycopg2-binary mysqlclient pymssql cx-oracle
gevent uvloop httptools websockets watchdog rpds-py pydantic-core
tokenizers safetensors sentencepiece onnxruntime
soundfile av imageio-ffmpeg simplejson ruamel-yaml-clib
coverage cython pybind11 setuptools wheel pip debugpy
shapely rasterio fiona pyproj gdal netcdf4 cftime
statsmodels xgboost lightgbm catboost
duckdb polars pyodbc thrift
"""

# 第二批：专挑发【便携压缩包】的项目。便携包解出来的 EXE 比安装包多得多，
# 而白样本里 EXE 正是最稀缺的一类（系统目录和 wheel/nupkg 九成以上都是 DLL）。
# 未认证 GitHub API 只有 60 次/小时，所以这批刻意控制在一小时预算内。
CURATED_GITHUB_EXE = """
sharkdp/bat sharkdp/hyperfine sharkdp/hexyl BurntSushi/ripgrep
jqlang/jq mikefarah/yq eza-community/eza junegunn/fzf
ajeetdsouza/zoxide starship/starship dandavison/delta
ClementTsang/bottom Byron/gitoxide extrawurst/gitui
XAMPPRocky/tokei rust-lang/mdBook casey/just watchexec/watchexec
sxyazi/yazi Wilfred/difftastic dalance/procs bootandy/dust
orf/gping imsnif/bandwhich nushell/nushell PowerShell/PowerShell
neovim/neovim helix-editor/helix lapce/lapce
FFmpeg/FFmpeg shinchiro/mpv-winbuild-cmake
curl/curl-for-win openssl/openssl stunnel/stunnel
rclone/rclone restic/restic syncthing/syncthing
containerd/containerd docker/cli lima-vm/lima
kubernetes/minikube derailed/k9s
mesonbuild/meson ninja-build/ninja ccache/ccache
git-for-windows/git gitextensions/gitextensions
sqlitebrowser/sqlitebrowser duckdb/duckdb
WinMerge/winmerge greenshot/greenshot flameshot-org/flameshot
AutoHotkey/AutoHotkey winsiderss/systeminformer
Genymobile/scrcpy ImageMagick/ImageMagick
espanso/espanso LGUG2Z/komorebi glzr-io/glazewm
Flow-Launcher/Flow.Launcher zhongyang219/TrafficMonitor
kingToolbox/WindTerm ZGGSONG/STranslate
"""

CURATED_GITHUB = """
notepad-plus-plus/notepad-plus-plus microsoft/PowerToys ShareX/ShareX
git-for-windows/git PowerShell/PowerShell keepassxreboot/keepassxc
files-community/Files audacity/audacity obsproject/obs-studio
flameshot-org/flameshot Eugeny/tabby HandBrake/HandBrake
WinMerge/winmerge jgraph/drawio-desktop Zettlr/Zettlr
logseq/logseq dbeaver/dbeaver beekeeper-studio/beekeeper-studio
greenshot/greenshot AutoHotkey/AutoHotkey gitextensions/gitextensions
ankitects/anki microsoft/winget-cli qbittorrent/qBittorrent
rustdesk/rustdesk Molunerfinn/PicGo agalwood/Motrix
kingToolbox/WindTerm zhongyang219/TrafficMonitor
xiaoyifang/goldendict-ng pot-app/pot-desktop localsend/localsend
ZGGSONG/STranslate marktext/marktext Kong/insomnia
th-ch/youtube-music peazip/PeaZip laurent22/joplin
mpv-player/mpv sharkdp/fd BurntSushi/ripgrep jqlang/jq
neovim/neovim vim/vim-win32-installer curl/curl-for-win
StefanKert/BuildVision microsoft/terminal microsoft/vscode
espanso/espanso lapce/lapce helix-editor/helix
Genymobile/scrcpy stashapp/stash ImageMagick/ImageMagick
FFmpeg/FFmpeg openssl/openssl python/cpython golang/go
oven-sh/bun nodejs/node denoland/deno rust-lang/rust
"""


def src_pypi(limit, offset=0):
    """PyPI：只挑带 win_amd64 平台标签的 wheel —— 那些才含编译好的 .pyd/.dll。

    offset 用于并行：跑第二个实例时给个偏移，两边取榜单的不同区段，
    否则两个进程会把同一批包重复下一遍。
    """
    names = CURATED_PYPI.split()
    # 有网就用真实下载量榜，扩到几千个包；拿不到就用上面的精选表
    try:
        data = http_json("https://hugovk.github.io/top-pypi-packages/"
                         "top-pypi-packages.min.json", timeout=40)
        rows = data.get("rows") or data.get("data") or []
        top = [r.get("project") for r in rows if r.get("project")]
        if top:
            seen = set(names)
            names = names + [t for t in top if t not in seen]
            print(f"[pypi] 取到下载量榜 {len(top)} 个包", flush=True)
    except Exception as e:
        print(f"[pypi] 榜单拿不到({type(e).__name__})，用精选表 {len(names)} 个",
              flush=True)

    if offset:
        names = names[offset:]
        print(f"[pypi] 跳过前 {offset} 个包，从第 {offset+1} 个开始", flush=True)
    for name in names[:limit]:
        try:
            j = http_json(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json",
                          timeout=25)
        except Exception:
            continue
        urls = j.get("urls") or []
        picked = []
        for u in urls:
            fn = (u.get("filename") or "").lower()
            if not fn.endswith(".whl"):
                continue
            if "win_amd64" not in fn and "win32" not in fn:
                continue
            if u.get("size", 0) < 20000:
                continue
            picked.append(u)
        # 每个包最多取 2 个 wheel(不同 Python ABI)，避免同一份 .pyd 反复下
        picked.sort(key=lambda u: u.get("size", 0), reverse=True)
        for u in picked[:2]:
            yield ("pypi", name, u["filename"], u["url"])


def src_nuget(limit, offset=0):
    """NuGet：按下载量翻页，.nupkg 是纯 zip，里面常带 native dll。"""
    try:
        svc = http_json("https://api.nuget.org/v3/index.json", timeout=25)
        base = None
        for r in svc.get("resources", []):
            if r.get("@type", "").startswith("SearchQueryService"):
                base = r["@id"]
                break
        if not base:
            return
    except Exception as e:
        print(f"[nuget] 索引拿不到: {type(e).__name__}", flush=True)
        return

    got = 0
    for skip in range(offset, offset + 8000, 100):
        if got >= limit:
            return
        try:
            j = http_json(f"{base}?q=&skip={skip}&take=100&prerelease=false"
                          f"&semVerLevel=2.0.0", timeout=30)
        except Exception:
            return
        data = j.get("data") or []
        if not data:
            return
        for pkg in data:
            pid = pkg.get("id")
            ver = pkg.get("version")
            if not pid or not ver:
                continue
            lo = pid.lower()
            url = (f"https://api.nuget.org/v3-flatcontainer/{lo}/{ver}/"
                   f"{lo}.{ver}.nupkg")
            yield ("nuget", pid, f"{lo}.{ver}.nupkg", url)
            got += 1
            if got >= limit:
                return


GITHUB_REPO_FILE = ""      # 由 --github-file 设置
GITHUB_EXE_FIRST = False   # 由 --github-exe-list 设置：用偏 EXE 的第二批仓库


def src_github(limit):
    """GitHub Releases：装机量大的开源项目，签名者分布广。

    zip/7z 形态的 portable 包是全部来源里单包出货量最高的（一个 OBS/PowerShell
    压缩包能出几百个 PE），所以优先给它们加分。

    【限流】未认证的 GitHub API 只有 60 次/小时，每个仓库要花 1 次查 latest release。
    也就是说这一路每小时最多只能覆盖 60 个仓库，超了就静默失败(异常被吞掉)。
    要靠 --github-file 扩到几百个仓库，必须先设 GITHUB_TOKEN(5000 次/小时)。
    """
    repos = (CURATED_GITHUB_EXE.split() if GITHUB_EXE_FIRST
             else CURATED_GITHUB.split())
    if GITHUB_REPO_FILE and os.path.isfile(GITHUB_REPO_FILE):
        extra = []
        with open(GITHUB_REPO_FILE, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "/" in line:
                    extra.append(line)
        seen = set(repos)
        repos = repos + [r for r in extra if r not in seen]
        print(f"[github] 仓库列表扩到 {len(repos)} 个", flush=True)
    for repo in repos[:limit]:
        try:
            rel = http_json(
                f"https://api.github.com/repos/{repo}/releases/latest", timeout=25)
        except Exception:
            continue
        best = None
        for a in rel.get("assets", []):
            n = (a.get("name") or "").lower()
            if not n.endswith((".exe", ".msi", ".zip", ".7z", ".msixbundle")):
                continue
            if any(b in n for b in (".sig", ".sha256", ".sha512", "blockmap",
                                    ".pdb", "symbols", "debug", "source")):
                continue
            if "arm" in n or "aarch" in n or "linux" in n or "mac" in n or "osx" in n:
                continue
            sz = int(a.get("size") or 0)
            score = 0
            if any(k in n for k in ("x64", "amd64", "win64", "64-bit", "64bit")):
                score += 3
            if "win" in n:
                score += 2
            if n.endswith((".zip", ".7z")):
                score += 1   # 压缩包解出来的 PE 通常比安装包多
            if best is None or (score, sz) > (best[0], best[1]):
                best = (score, sz, a.get("name"), a.get("browser_download_url"))
        if best and best[3]:
            yield ("github", repo, best[2], best[3])


SOURCES = {"pypi": src_pypi, "nuget": src_nuget, "github": src_github}


# ---------------------------------------------------------------- 主流程
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, help="语料库根目录")
    ap.add_argument("--target", type=int, default=20000, help="到多少个唯一 PE 就停")
    ap.add_argument("--sources", default="pypi,nuget,github")
    ap.add_argument("--sevenzip", default="", help="7z.exe 路径(解 exe/msi 必需)")
    ap.add_argument("--work", default="", help="临时工作目录")
    ap.add_argument("--ingest-dir", default="", help="先把这个目录里已下载的容器处理掉")
    ap.add_argument("--keep-ingest", action="store_true",
                    help="处理 --ingest-dir 时不删原文件")
    ap.add_argument("--pypi-limit", type=int, default=4000)
    ap.add_argument("--nuget-limit", type=int, default=3000)
    ap.add_argument("--github-limit", type=int, default=200)
    ap.add_argument("--github-file", default="",
                    help="额外的 GitHub 仓库列表文件，每行 owner/repo")
    ap.add_argument("--pypi-offset", type=int, default=0,
                    help="跳过下载量榜前 N 个包(并行跑多实例时错开区段用)")
    ap.add_argument("--nuget-offset", type=int, default=0,
                    help="NuGet 翻页起始 skip(并行跑多实例时错开区段用)")
    ap.add_argument("--github-exe-list", action="store_true",
                    help="用偏便携压缩包的第二批仓库，专门补稀缺的白样本 EXE")
    args = ap.parse_args()

    global GITHUB_REPO_FILE, GITHUB_EXE_FIRST
    GITHUB_REPO_FILE = args.github_file
    GITHUB_EXE_FIRST = args.github_exe_list

    sevenzip = args.sevenzip
    if sevenzip and not os.path.isfile(sevenzip):
        print(f"[warn] 找不到 7z: {sevenzip} -> exe/msi 容器会被跳过", flush=True)
        sevenzip = ""
    if not sevenzip:
        print("[warn] 未提供 7z.exe，只能处理 zip 家族(whl/nupkg/vsix/zip)", flush=True)

    work = args.work or os.path.join(args.out, "_work")
    os.makedirs(work, exist_ok=True)
    dl_dir = os.path.join(work, "dl")
    os.makedirs(dl_dir, exist_ok=True)

    corpus = Corpus(args.out, args.target)
    t0 = time.time()
    stats = {"containers": 0, "dl_bytes": 0, "dl_fail": 0}

    def report(tag, pkg, fn, added, size):
        el = time.time() - t0
        rate = corpus.n / el * 60 if el > 1 else 0
        print(f"[{corpus.n}/{args.target}] {tag}:{pkg} {fn} "
              f"{size/1e6:.1f}MB +{added}  pkgs={len(corpus.pkgs)} "
              f"{rate:.0f}/min", flush=True)

    # ---- 先消化已经下载好的目录(不浪费之前下的安装包) ----
    if args.ingest_dir and os.path.isdir(args.ingest_dir):
        print(f"==== 消化已下载目录: {args.ingest_dir} ====", flush=True)
        for root, _d, files in os.walk(args.ingest_dir):
            for fn in sorted(files):
                if corpus.full():
                    break
                fp = os.path.join(root, fn)
                ext = os.path.splitext(fn)[1].lower()
                if ext not in (ZIP_EXT | ARC_EXT):
                    continue
                try:
                    size = os.path.getsize(fp)
                except OSError:
                    continue
                if size < 50000:
                    continue
                added = harvest_container(fp, corpus, "local", fn, work, sevenzip)
                stats["containers"] += 1
                corpus.flush()
                report("local", fn, "", added, size)
                if not args.keep_ingest:
                    try:
                        os.remove(fp)          # 抽完就删，磁盘不堆积
                    except OSError:
                        pass
            if corpus.full():
                break

    # ---- 边下边抽 ----
    limits = {"pypi": args.pypi_limit, "nuget": args.nuget_limit,
              "github": args.github_limit}
    offsets = {"pypi": args.pypi_offset, "nuget": args.nuget_offset,
               "github": 0}
    gens = []
    for s in [x.strip() for x in args.sources.split(",") if x.strip()]:
        if s not in SOURCES:
            print(f"[warn] 未知来源: {s}", flush=True)
            continue
        off = offsets.get(s, 0)
        gens.append((s, SOURCES[s](limits.get(s, 1000), off) if off
                     else SOURCES[s](limits.get(s, 1000))))

    # 轮转各来源，别把 4000 个 wheel 抽完才开始 nuget —— 多样性要尽早铺开
    alive = list(gens)
    while alive and not corpus.full():
        for i, (name, gen) in enumerate(list(alive)):
            if corpus.full():
                break
            try:
                tag, pkg, fn, url = next(gen)
            except StopIteration:
                alive = [a for a in alive if a[0] != name]
                print(f"[{name}] 来源耗尽", flush=True)
                continue
            except Exception as e:
                print(f"[{name}] 生成器异常 {type(e).__name__}: {e}", flush=True)
                alive = [a for a in alive if a[0] != name]
                continue

            safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in fn)
            dst = os.path.join(dl_dir, safe or "item.bin")
            try:
                size = download(url, dst)
            except Exception as e:
                stats["dl_fail"] += 1
                print(f"    [dl-fail] {tag}:{pkg} {type(e).__name__}", flush=True)
                if os.path.exists(dst):
                    os.remove(dst)
                continue

            stats["dl_bytes"] += size
            stats["containers"] += 1
            added = harvest_container(dst, corpus, tag, pkg, work, sevenzip)
            try:
                os.remove(dst)                 # 抽完立刻删下载物
            except OSError:
                pass
            corpus.flush()
            report(tag, pkg, fn, added, size)

    corpus.flush()
    corpus.close()
    shutil.rmtree(work, ignore_errors=True)

    el = time.time() - t0
    print("\n================ 采集结束 ================", flush=True)
    print(f"唯一白样本 : {corpus.n}  (目标 {args.target})")
    print(f"来源包数量 : {len(corpus.pkgs)}")
    print(f"处理容器数 : {stats['containers']}  下载失败 {stats['dl_fail']}")
    print(f"累计下载   : {stats['dl_bytes']/1e9:.2f} GB (已全部删除，不占盘)")
    print(f"耗时       : {el/60:.1f} 分钟")
    print(f"语料库     : {corpus.bdir}")
    print(f"manifest   : {corpus.manifest}")
    if corpus.n < args.target:
        print("\n[!] 未达目标。加大 --pypi-limit/--nuget-limit 或补 --sources 再跑一遍"
              "(可断点续跑)。")


if __name__ == "__main__":
    sys.exit(main())
