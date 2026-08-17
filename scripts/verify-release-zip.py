# -*- coding: utf-8 -*-
"""独立校验 pack-release.py 产出的加密 zip。

为什么不复用 pack-release.py 自带的自校验:
  那是「自己验自己」—— 同一份代码写、同一份代码读,写错了也对得上。这里改用标准库
  zipfile 反向解密。标准库用的是与 Windows 资源管理器同一套 PKWARE 传统加密算法,
  它能解开才真正说明【用户双击能打开】。这是发布前唯一能证明这件事的检查。

检查项:
  · 顶层目录唯一(否则用户解压出来散在桌面上)
  · 每个条目都置了加密标志(否则等于没设密码)
  · testzip 逐条解密 + CRC(密码错会抛,数据坏会报条目名)
  · 每个文件 SHA-256 与源目录逐一比对
  · 关键载荷齐全(服务/界面/驱动/配置/MSVC 运行库/Qt TLS 后端)
  · .bat 纯 ASCII —— CJK 会触发 cmd.exe 的 UTF-8 字节偏移错位,
    表现是把注释行的尾巴当命令执行
  · bulwark.ps1 带 UTF-8 BOM —— 缺了 PS 5.1 在 zh-CN 上按 GBK 读,中文全乱
  · 配置里没有明文端点、没有密钥(发布包最后一道闸)

报告写进 <zip 同目录>/_verify.txt(显式 UTF-8);stdout 只打 ASCII ——
在 zh-CN 控制台 print 中文遇到 cp936/重定向会抛 UnicodeEncodeError,
实测能把整个调用方会话带崩,结果一行都拿不到。

用法:
    python scripts/verify-release-zip.py --zip <zip> --src <便携包目录> [--password 123]
退出码 0 = 全部通过。
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
import zipfile

MUST_HAVE = [
    "bulwark_service.exe", "bulwark_ui.exe", "Bulwark.sys", "appsettings.json",
    "bulwark.ps1", "msvcp140.dll", "msvcp140_1.dll", "msvcp140_2.dll",
    "vcruntime140.dll", "vcruntime140_1.dll",
    "platforms/qwindows.dll", "tls/qschannelbackend.dll",
]
# 这些串一旦出现在发布包里就是泄漏。
#
# 明文清单不写在这里:本文件是公开的,把「我们的端点、令牌、兜底 IP」原样列出来,
# 等于用一个防泄漏检查去泄漏它要防的东西。唯一真源是 packaging/redaction-needles.txt
# (不入库、不进任何发布包),与 verify_portable.ps1 和 bulwark.ps1 共用同一份。
#
# 缺文件时【不降级为通过】:一个什么都没检查却打印绿灯的扫描,比没有扫描更糟 ——
# 它会被信任。自建者若不需要这项检查,按需要传 --skip-leak-scan。
NEEDLE_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "packaging", "redaction-needles.txt")


def load_leak_probes(path=NEEDLE_FILE):
    """读取明文特征串清单。返回小写去重列表;文件缺失或为空则抛 FileNotFoundError。"""
    with open(path, encoding="utf-8") as f:
        probes = []
        for line in f:
            s = line.strip()
            if s and not s.startswith("#"):
                probes.append(s.lower())
    if not probes:
        raise FileNotFoundError("%s 里没有任何特征串" % path)
    return sorted(set(probes))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--zip", required=True)
    ap.add_argument("--src", required=True)
    ap.add_argument("--password", default="123")
    ap.add_argument("--top", default="Bulwark")
    ap.add_argument("--skip-leak-scan", action="store_true",
                    help="跳过敏感串扫描(没有 packaging/redaction-needles.txt 时使用)")
    args = ap.parse_args()

    zip_path, src, pw, top = args.zip, args.src, args.password.encode(), args.top
    report = os.path.join(os.path.dirname(os.path.abspath(zip_path)), "_verify.txt")
    out: list[str] = []
    fail: list[str] = []

    try:
        zf = zipfile.ZipFile(zip_path)
        zf.setpassword(pw)
        names = [n for n in zf.namelist() if not n.endswith("/")]
        out.append("zip 条目          : %d 个文件" % len(names))

        tops = sorted({n.split("/")[0] for n in zf.namelist()})
        out.append("顶层目录          : %s" % tops)
        if tops != [top]:
            fail.append("顶层目录不是单一的 %r,实际 %s" % (top, tops))

        unenc = [n for n in names if not (zf.getinfo(n).flag_bits & 0x1)]
        if unenc:
            fail.append("未加密条目 %d 个,例如 %s" % (len(unenc), unenc[:3]))
        else:
            out.append("加密标志          : 全部条目已加密")

        bad = zf.testzip()
        if bad:
            fail.append("CRC 校验失败: %s" % bad)
        else:
            out.append("CRC / 密码        : 通过(密码 %s 能解开,资源管理器同算法)"
                       % args.password)

        src_files = {}
        for root, _, fs in os.walk(src):
            for f in fs:
                p = os.path.join(root, f)
                src_files[os.path.relpath(p, src).replace("\\", "/")] = p
        out.append("源目录            : %d 个文件" % len(src_files))

        zip_rel = {n[len(top) + 1:]: n for n in names}
        for label, diff in (("zip 里缺少", sorted(set(src_files) - set(zip_rel))),
                            ("zip 里多出", sorted(set(zip_rel) - set(src_files)))):
            if diff:
                fail.append("%s: %s" % (label, diff))

        mismatch = []
        for rel, p in sorted(src_files.items()):
            if rel not in zip_rel:
                continue
            with open(p, "rb") as f:
                h = hashlib.sha256(f.read()).hexdigest()
            if h != hashlib.sha256(zf.read(zip_rel[rel])).hexdigest():
                mismatch.append(rel)
        if mismatch:
            fail.append("内容与源目录不一致: %s" % mismatch)
        else:
            out.append("内容比对          : %d 个文件 SHA-256 与源目录逐一相同"
                       % len(src_files))

        miss = [m for m in MUST_HAVE if m not in zip_rel]
        if miss:
            fail.append("关键载荷缺失: %s" % miss)
        else:
            out.append("关键载荷          : 齐全(含 MSVC 运行库 + Qt TLS 后端)")

        bats = [n for n in zip_rel if n.lower().endswith(".bat")]
        bad_bat = []
        for b in bats:
            n_non = sum(1 for x in zf.read(zip_rel[b]) if x > 127)
            if n_non:
                bad_bat.append("%s(%d 字节)" % (b, n_non))
        if bad_bat:
            fail.append(".bat 含非 ASCII,会触发 cmd 字节偏移错位: %s" % bad_bat)
        else:
            out.append(".bat 编码         : %d 个全为纯 ASCII" % len(bats))

        ps1s = [n for n in zip_rel if n.lower().endswith(".ps1")]
        no_bom = [p for p in ps1s if zf.read(zip_rel[p])[:3] != b"\xef\xbb\xbf"]
        if no_bom:
            fail.append(".ps1 缺 UTF-8 BOM(PS 5.1 会按 GBK 读,中文全乱): %s" % no_bom)
        else:
            out.append(".ps1 编码         : %d 个均带 UTF-8 BOM" % len(ps1s))

        # 发布包最后一道闸:任何文本文件里都不许出现端点/密钥
        if args.skip_leak_scan:
            out.append("脱敏检查          : 已按 --skip-leak-scan 跳过")
        else:
            try:
                probes = load_leak_probes()
            except (OSError, FileNotFoundError) as e:
                # 报错而不是跳过。见 NEEDLE_FILE 处的说明:静默通过会被当成「检查过了」。
                fail.append("敏感串清单不可用(%s)。补上 packaging/redaction-needles.txt,"
                            "或显式加 --skip-leak-scan。" % e)
                probes = None
            if probes:
                hits = []
                for rel, zn in sorted(zip_rel.items()):
                    if not rel.lower().endswith((".json", ".txt", ".bat", ".ps1", ".html")):
                        continue
                    try:
                        text = zf.read(zn).decode("utf-8", "ignore")
                    except Exception:
                        continue
                    low = text.lower()          # 清单已小写,两边同时降级才不会漏大小写变体
                    for probe in probes:
                        if probe in low:
                            hits.append("%s -> %s" % (rel, probe))
                if hits:
                    fail.append("发布包里出现敏感串: %s" % hits)
                else:
                    out.append("脱敏检查          : 无明文端点、无密钥(%d 条特征串)"
                               % len(probes))

        zf.close()

        sz = os.path.getsize(zip_path)
        tot = sum(os.path.getsize(p) for p in src_files.values())
        out.append("大小              : %s B -> %s B (压缩后 %.0f%%)"
                   % (format(tot, ","), format(sz, ","), sz * 100.0 / max(1, tot)))
        with open(zip_path, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        out.append("SHA-256           : %s" % digest)
    except Exception as e:
        fail.append("校验过程异常: %r" % (e,))
        digest = ""

    lines = ["== 发布 zip 校验 =="] + ["  " + s for s in out]
    lines += ([""] + ["失败:"] + ["  X " + f for f in fail]) if fail else ["", "全部校验通过"]
    with open(report, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print("verify: %d ok, %d fail -> %s" % (len(out), len(fail), report))
    if digest and not fail:
        print("sha256: %s" % digest)
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
