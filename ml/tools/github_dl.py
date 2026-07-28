#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Download latest Windows installer assets from GitHub Releases (reliable, version-agnostic).
Bypasses CN vendors' JS/dynamic-URL problem: the GitHub API returns the exact current
download URL. Covers Chinese-origin open-source apps + international open-source.
Only unambiguously-benign software (no proxy/VPN/game-cheat that AV flags as PUP).
Downloads only, never executes. stdlib urllib only.
"""
import json, os, urllib.request, urllib.error

DL = r"C:\Users\61460\Desktop\新建文件夹\github"
os.makedirs(DL, exist_ok=True)
LOG = os.path.join(DL, "_github_dl.log")

REPOS = [
    # --- Chinese-origin open-source ---
    "rustdesk/rustdesk",                      # RustDesk 远程桌面
    "Molunerfinn/PicGo",                      # PicGo 图床
    "agalwood/Motrix",                        # Motrix 下载器
    "kingToolbox/WindTerm",                   # WindTerm 终端
    "zhongyang219/TrafficMonitor",            # 流量监控(popular CN)
    "xiaoyifang/goldendict-ng",               # GoldenDict 词典
    "pot-app/pot-desktop",                    # Pot 翻译
    "Kilento/...placeholder",                 # (ignored if fails)
    # --- International open-source (clean, mostly signed) ---
    "notepad-plus-plus/notepad-plus-plus",
    "microsoft/PowerToys",
    "ShareX/ShareX",
    "git-for-windows/git",
    "PowerShell/PowerShell",
    "laurent22/joplin",
    "localsend/localsend",
    "keepassxreboot/keepassxc",
    "files-community/Files",
    "audacity/audacity",
    "obsproject/obs-studio",
    "peazip/PeaZip",
    "flameshot-org/flameshot",
    "Eugeny/tabby",
    # --- batch 2: more clean open-source (win x64 installers) ---
    "ZGGSONG/STranslate",
    "HandBrake/HandBrake",
    "WinMerge/winmerge",
    "jgraph/drawio-desktop",
    "Zettlr/Zettlr",
    "marktext/marktext",
    "logseq/logseq",
    "dbeaver/dbeaver",
    "beekeeper-studio/beekeeper-studio",
    "Kong/insomnia",
    "greenshot/greenshot",
    "AutoHotkey/AutoHotkey",
    "gitextensions/gitextensions",
    "ankitects/anki",
    "th-ch/youtube-music",
    "microsoft/winget-cli",
    "notepad4-editor/notepad4",
    "qbittorrent/qBittorrent",
]

UA = "Mozilla/5.0 bulwark-benign-collector"


def api(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=25) as r:
        return json.loads(r.read().decode("utf-8", "ignore"))


def pick_asset(assets):
    cands = []
    for a in assets:
        n = a.get("name", "") or ""
        nl = n.lower()
        if not nl.endswith((".exe", ".msi", ".msixbundle")):
            continue
        if any(b in nl for b in (".sig", ".sha256", ".sha512", "blockmap", ".sym", ".pdb", "debug", "symbols")):
            continue
        if "arm" in nl or "aarch" in nl:
            continue
        is64 = any(k in nl for k in ("x64", "x86_64", "amd64", "win64", "64-bit", "64bit"))
        is32only = (("x86" in nl and "x86_64" not in nl) or "win32" in nl or "ia32" in nl or "32-bit" in nl) and not is64
        if is32only:
            continue
        score = 0
        if is64:
            score += 3
        if "setup" in nl or "install" in nl:
            score += 2
        if nl.endswith(".msi"):
            score += 1
        if "portable" in nl:
            score -= 2
        cands.append((score, int(a.get("size", 0) or 0), n, a.get("browser_download_url")))
    if not cands:
        return None
    cands.sort(key=lambda c: (c[0], c[1]), reverse=True)
    return cands[0]


def download(url, dst):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=180) as r, open(dst, "wb") as f:
        while True:
            b = r.read(1 << 20)
            if not b:
                break
            f.write(b)


def main():
    ok = fail = 0
    lf = open(LOG, "a", encoding="utf-8")
    for repo in REPOS:
        if "placeholder" in repo:
            continue
        try:
            rel = api(f"https://api.github.com/repos/{repo}/releases/latest")
            a = pick_asset(rel.get("assets", []))
            if not a:
                msg = f"[skip] {repo}: no win x64 installer asset"
                print(msg, flush=True); lf.write(msg + "\n"); fail += 1; continue
            score, size, name, url = a
            dst = os.path.join(DL, name)
            if os.path.exists(dst) and os.path.getsize(dst) > 50000:
                print(f"[have] {repo}: {name}", flush=True); ok += 1; continue
            print(f"[get ] {repo}: {name} ({size/1e6:.1f}MB)", flush=True)
            download(url, dst)
            msg = f"[ok  ] {repo}: {name} {os.path.getsize(dst)} bytes"
            lf.write(msg + "\n"); lf.flush(); ok += 1
        except urllib.error.HTTPError as e:
            msg = f"[fail] {repo}: HTTP {e.code}"
            print(msg, flush=True); lf.write(msg + "\n"); fail += 1
        except Exception as e:
            msg = f"[fail] {repo}: {type(e).__name__} {e}"
            print(msg, flush=True); lf.write(msg + "\n"); fail += 1
    lf.close()
    print(f"\nGitHub releases done: ok={ok} fail={fail} -> {DL}", flush=True)


if __name__ == "__main__":
    main()
