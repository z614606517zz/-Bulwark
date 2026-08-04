#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""打包发布用的加密 zip(ZipCrypto),并自解校验。

为什么不用 AES:
  服务器上现役的 Bulwark-Release.zip 用的是传统 ZipCrypto。Windows 资源管理器
  【不支持】AES 加密的 zip —— 换成 AES 会让没装 7-Zip/WinRAR 的普通用户直接解不开,
  等于把公开下载弄坏。密码本来就是 "123"(只为避免网盘/杀软自动扫描,不承担保密职责),
  AES 在这里换不来实际安全收益,却牺牲兼容性。故沿用 ZipCrypto。

为什么自己实现加密:
  Python 标准库 zipfile 只能【读】ZipCrypto、不能写;pyzipper 只支持 AES;
  本机没有 7-Zip/WinRAR。PKWARE 传统加密算法本身很简单且有完整公开规范,
  而且写完可以用标准库反向解密逐字节比对来证明正确性(资源管理器用的是同一套算法),
  所以自实现 + 强校验比引入新依赖更稳。

用法:
    python scripts/pack-release.py --src "C:\\Users\\1\\Desktop\\新建文件夹" \
        --out "C:\\Users\\1\\Desktop\\Bulwark-Release.zip" --password 123 --top Bulwark
"""
from __future__ import annotations

import argparse
import hashlib
import os
import secrets
import struct
import sys
import time
import zipfile
import zlib
from pathlib import Path

# ── PKWARE traditional encryption (ZipCrypto) ────────────────────────────────
_CRC_TAB = [0] * 256
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (0xEDB88320 ^ (_c >> 1)) if (_c & 1) else (_c >> 1)
    _CRC_TAB[_i] = _c


class ZipCrypto:
    """流式加密器。注意 update_keys 用的是【明文】字节。"""

    def __init__(self, password: bytes):
        self.k0, self.k1, self.k2 = 305419896, 591751049, 878082192
        for b in password:
            self._update(b)

    @staticmethod
    def _crc32(crc: int, b: int) -> int:
        return (crc >> 8) ^ _CRC_TAB[(crc ^ b) & 0xFF]

    def _update(self, b: int) -> None:
        self.k0 = self._crc32(self.k0, b)
        self.k1 = (self.k1 + (self.k0 & 0xFF)) & 0xFFFFFFFF
        self.k1 = (self.k1 * 134775813 + 1) & 0xFFFFFFFF
        self.k2 = self._crc32(self.k2, (self.k1 >> 24) & 0xFF)

    def _stream_byte(self) -> int:
        t = (self.k2 | 2) & 0xFFFF
        return ((t * (t ^ 1)) >> 8) & 0xFF

    def encrypt(self, data: bytes) -> bytes:
        out = bytearray(len(data))
        for i, p in enumerate(data):
            out[i] = p ^ self._stream_byte()
            self._update(p)
        return bytes(out)


def dos_datetime(ts: float):
    t = time.localtime(ts)
    year = max(1980, t.tm_year)
    date = ((year - 1980) << 9) | (t.tm_mon << 5) | t.tm_mday
    tm = (t.tm_hour << 11) | (t.tm_min << 5) | (t.tm_sec // 2)
    return tm, date


FLAG_ENCRYPTED = 0x0001
FLAG_UTF8 = 0x0800          # 让「使用说明.txt / 启动Bulwark.bat」这类中文名正确还原


def build_zip(src: Path, out: Path, password: bytes, top: str, level: int = 6) -> dict:
    files, dirs = [], []
    for p in sorted(src.rglob("*"), key=lambda x: str(x).lower()):
        rel = p.relative_to(src)
        arc = (top + "/" + str(rel).replace("\\", "/")) if top else str(rel).replace("\\", "/")
        (dirs if p.is_dir() else files).append((p, arc))
    # 目录条目(含顶层),明文存储、不加密 —— 与现役包一致
    dir_arcs = ([top + "/"] if top else []) + [a + "/" for _, a in dirs]

    central = []
    blob = bytearray()

    def add_dir(arc: str):
        name = arc.encode("utf-8")
        tm, dt = dos_datetime(time.time())
        off = len(blob)
        blob.extend(struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, FLAG_UTF8, 0,
                                tm, dt, 0, 0, 0, len(name), 0))
        blob.extend(name)
        central.append(struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, FLAG_UTF8, 0,
                                   tm, dt, 0, 0, 0, len(name), 0, 0, 0, 0,
                                   0x10, off) + name)   # 0x10 = FILE_ATTRIBUTE_DIRECTORY

    def add_file(path: Path, arc: str):
        data = path.read_bytes()
        crc = zlib.crc32(data) & 0xFFFFFFFF
        co = zlib.compressobj(level, zlib.DEFLATED, -15)
        comp = co.compress(data) + co.flush()
        # 12 字节加密头:11 随机 + 1 校验字节(明文 CRC 的高位字节)
        hdr = secrets.token_bytes(11) + bytes([(crc >> 24) & 0xFF])
        enc = ZipCrypto(password).encrypt(hdr + comp)
        name = arc.encode("utf-8")
        tm, dt = dos_datetime(path.stat().st_mtime)
        flags = FLAG_ENCRYPTED | FLAG_UTF8
        off = len(blob)
        blob.extend(struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, flags, 8,
                                tm, dt, crc, len(enc), len(data), len(name), 0))
        blob.extend(name)
        blob.extend(enc)
        central.append(struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, flags, 8,
                                   tm, dt, crc, len(enc), len(data), len(name), 0, 0, 0, 0,
                                   0x20, off) + name)   # 0x20 = ARCHIVE
        return len(data)

    for a in dir_arcs:
        add_dir(a)
    raw_total = 0
    for p, a in files:
        raw_total += add_file(p, a)

    cd_off = len(blob)
    cd = b"".join(central)
    blob.extend(cd)
    blob.extend(struct.pack("<IHHHHIIH", 0x06054B50, 0, 0,
                            len(central), len(central), len(cd), cd_off, 0))

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(bytes(blob))
    return {"files": len(files), "dirs": len(dir_arcs), "raw": raw_total,
            "zip": out.stat().st_size}


def verify(out: Path, src: Path, password: bytes, top: str) -> list[str]:
    """用标准库(与资源管理器同一套 ZipCrypto 实现)反向解密逐字节比对。"""
    errs = []
    with zipfile.ZipFile(out) as z:
        z.setpassword(password)          # 必须先设密码,否则 testzip 会因加密条目直接抛错
        bad = z.testzip()
        if bad:
            errs.append("testzip 报错于: %s" % bad)
        names = set(z.namelist())
        for p in sorted(src.rglob("*")):
            if not p.is_dir():
                arc = (top + "/" + str(p.relative_to(src)).replace("\\", "/")) if top \
                      else str(p.relative_to(src)).replace("\\", "/")
                if arc not in names:
                    errs.append("缺条目: %s" % arc)
                    continue
                try:
                    got = z.read(arc)
                except Exception as e:
                    errs.append("解密失败 %s: %s" % (arc, e))
                    continue
                if got != p.read_bytes():
                    errs.append("内容不一致: %s" % arc)
        # 必须确实加密了
        for i in z.infolist():
            if not i.filename.endswith("/") and not (i.flag_bits & FLAG_ENCRYPTED):
                errs.append("未加密条目: %s" % i.filename)
        # 错密码必须失败
        z.setpassword(b"wrong-password")
        f = next(i.filename for i in z.infolist() if not i.filename.endswith("/"))
        try:
            z.read(f)
            errs.append("错密码竟然解开了(加密无效)")
        except Exception:
            pass
    return errs


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--password", default="123")
    ap.add_argument("--top", default="Bulwark", help="压缩包内顶层目录名(空字符串=放根)")
    args = ap.parse_args()

    if not args.src.is_dir():
        print("[错误] 源目录不存在: %s" % args.src)
        return 2
    pw = args.password.encode()

    print("源目录 : %s" % args.src)
    print("输出   : %s" % args.out)
    print("顶层   : %s/" % args.top)
    print("加密   : ZipCrypto(兼容 Windows 资源管理器)  密码长度=%d" % len(pw))
    print()

    st = build_zip(args.src, args.out, pw, args.top)
    print("已打包 : %d 文件 + %d 目录条目" % (st["files"], st["dirs"]))
    print("原始   : %d 字节 (%.1f MB)" % (st["raw"], st["raw"] / 1048576))
    print("压缩后 : %d 字节 (%.1f MB,压缩率 %.1f%%)"
          % (st["zip"], st["zip"] / 1048576, 100.0 * st["zip"] / max(1, st["raw"])))

    errs = verify(args.out, args.src, pw, args.top)
    sha = hashlib.sha256(args.out.read_bytes()).hexdigest()
    print("sha256 : %s" % sha)
    print()
    if errs:
        print("校验未通过:")
        for e in errs[:20]:
            print("   - " + e)
        return 3
    print("校验通过:全部文件可用密码解出且逐字节一致;错密码被拒绝。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
