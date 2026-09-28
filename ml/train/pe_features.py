#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
静态 PE 特征提取器 —— extract_features.py / infer_probe.py 依赖的 PEFeatureExtractor。

对外接口只有一个（与原设计保持一致，调用方不需要改）：
    PEFeatureExtractor().feature_vector(bytez) -> np.ndarray(float32, 固定维度)

为什么用 pefile 而不是 LIEF
--------------------------
仓库里 server/bulwark-broker/ember_pkg/features.py 是一份完整的 EMBER v2 实现，
但它写的是 LIEF 0.9 时代的 API（lief.bad_format / lief.pe_error /
lief.PE.parse(list(bytez))），现代 LIEF 全部移除了这些符号，钉回老版本在
Python 3.12/3.13 上又没有轮子。而 ml/train/requirements.txt 本来列的就是 pefile。
所以这里按 EMBER 的特征分块思路用 pefile 重写，维度固定、不依赖 LIEF。

刻意排除的东西（每一条都是会导致模型学歪的陷阱）
--------------------------------------------
1) 文件名 / 路径：负样本大量来自 C:\\Windows 与 PyPI wheel，路径一进特征，
   模型直接靠路径分类，线上换个目录就废。
2) 签名者名字：银狐等大量借用【真实或被盗签名】，签名者名字既不可靠又会
   让模型记住具体厂商字符串。
3) has_signature（有无嵌入签名）：计算了但【不进向量】。这是本项目实测过的
   标签泄漏方向 —— 系统文件走 .cat 目录签名，嵌入证书为空；恶意侧反而大量
   自带被盗的嵌入证书。放进去模型会学成"有嵌入签名 ⇒ 恶意"，方向是反的。
   本语料里更糟：PyPI 的 .pyd 基本无签名、GitHub 包部分签名，会进一步放大偏差。
4) TimeDateStamp 原值：恶意侧常被清零或伪造，且随采集年份漂移，属于
   "采集时代的痕迹"而不是行为特征。

维度绑定 SCHEMA_VERSION。任何增删特征都必须 +1 并重训，否则线上模型和
离线特征会静默错位。
"""

import hashlib
import math
import re
import struct

import numpy as np

try:
    import pefile
except ImportError:  # 给出可执行的修复指令，而不是一个裸 ImportError
    raise SystemExit(
        "缺少 pefile。装依赖：\n"
        "  python -m pip install -r ml/train/requirements.txt")

from sklearn.feature_extraction import FeatureHasher

SCHEMA_VERSION = 1

# ------------------------------------------------------------------ 各分块维度
DIM_BYTE_HIST = 256
DIM_BYTE_ENTROPY = 256
DIM_GENERAL = 9
DIM_HEADER = 62
DIM_SECTION = 255
DIM_IMPORTS = 1280
DIM_EXPORTS = 128
DIM_STRINGS = 104
DIM_DATADIRS = 30

FEATURE_DIM = (DIM_BYTE_HIST + DIM_BYTE_ENTROPY + DIM_GENERAL + DIM_HEADER
               + DIM_SECTION + DIM_IMPORTS + DIM_EXPORTS + DIM_STRINGS
               + DIM_DATADIRS)          # = 2380


def _hasher(n):
    return FeatureHasher(n_features=n, input_type="string")


def _hasher_pair(n):
    return FeatureHasher(n_features=n, input_type="pair")


def _entropy(counts, total):
    if total <= 0:
        return 0.0
    p = counts[counts > 0] / total
    return float(-np.sum(p * np.log2(p)))


# ------------------------------------------------------------------ 字节级特征
def byte_histogram(data):
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    total = counts.sum()
    if total == 0:
        return np.zeros(256, dtype=np.float32)
    return (counts / total).astype(np.float32)


def byte_entropy_histogram(data, step=1024, window=2048):
    """EMBER 的二维(窗口熵 x 字节值)联合直方图，16x16=256 维。

    刻画"文件里高熵区域用的是哪些字节"，对加壳/加密段很敏感。
    """
    out = np.zeros((16, 16), dtype=np.float32)
    arr = np.frombuffer(data, dtype=np.uint8)
    if arr.size < window:
        if arr.size == 0:
            return out.flatten()
        window = arr.size
        step = arr.size
    for start in range(0, arr.size - window + 1, step):
        block = arr[start:start + window]
        # 熵用全 256 个字节值算才准；但联合直方图的字节轴只保留高 4 位(16 桶)，
        # 否则 16x256 会把这一块撑到 4096 维，且过于稀疏。
        h = _entropy(np.bincount(block, minlength=256).astype(np.float64), window)
        row = min(int(h * 2), 15)          # 熵 0..8 -> 16 个桶
        out[row] += np.bincount(block >> 4, minlength=16)
    s = out.sum()
    if s > 0:
        out /= s
    return out.flatten()


# ------------------------------------------------------------------ 字符串特征
_RE_STRING = re.compile(rb"[\x20-\x7f]{5,}")
_RE_PATH = re.compile(rb"[Cc]:\\\\|[Cc]:/")
_RE_URL = re.compile(rb"https?://", re.IGNORECASE)
_RE_REG = re.compile(rb"HKEY_|HKLM|HKCU", re.IGNORECASE)
_RE_MZ = re.compile(rb"MZ")


def string_features(data):
    """可打印字符串的统计画像。只统计分布，不把字符串内容本身放进向量。"""
    v = np.zeros(DIM_STRINGS, dtype=np.float32)
    strs = _RE_STRING.findall(data)
    if strs:
        lengths = np.array([len(s) for s in strs], dtype=np.float64)
        v[0] = len(strs)
        v[1] = lengths.mean()
        # 可打印字符直方图(0x20..0x7f 共 96 个)
        allc = b"".join(strs)
        c = np.bincount(np.frombuffer(allc, dtype=np.uint8) - 0x20,
                        minlength=96)[:96]
        tot = c.sum()
        if tot > 0:
            v[2:98] = (c / tot).astype(np.float32)
            v[98] = _entropy(c.astype(np.float64), tot)
    v[99] = len(_RE_PATH.findall(data))
    v[100] = len(_RE_URL.findall(data))
    v[101] = len(_RE_REG.findall(data))
    v[102] = len(_RE_MZ.findall(data))
    v[103] = len(data)
    return v


# ------------------------------------------------------------------ 结构化特征
def _safe(fn, default=0):
    try:
        r = fn()
        return default if r is None else r
    except Exception:
        return default


def general_features(pe, data):
    """整体规模与"有没有某类结构"。has_signature 特意不在这里。"""
    v = np.zeros(DIM_GENERAL, dtype=np.float32)
    v[0] = len(data)
    v[1] = _safe(lambda: pe.OPTIONAL_HEADER.SizeOfImage)
    v[2] = 1.0 if hasattr(pe, "DIRECTORY_ENTRY_DEBUG") else 0.0
    v[3] = 1.0 if hasattr(pe, "DIRECTORY_ENTRY_BASERELOC") else 0.0
    v[4] = 1.0 if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE") else 0.0
    v[5] = 1.0 if hasattr(pe, "DIRECTORY_ENTRY_TLS") else 0.0
    n_imp = n_dll = 0
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for e in pe.DIRECTORY_ENTRY_IMPORT:
            n_dll += 1
            n_imp += len(e.imports or [])
    v[6] = n_imp
    v[7] = n_dll
    v[8] = _safe(lambda: len(pe.DIRECTORY_ENTRY_EXPORT.symbols))
    return v


def header_features(pe):
    """COFF + OptionalHeader。machine/subsystem/characteristics 走 hash，
    避免把枚举值当成有序数值喂给树模型。"""
    parts = []
    fh = pe.FILE_HEADER
    oh = pe.OPTIONAL_HEADER

    h10 = _hasher(10)
    parts.append(h10.transform([[str(_safe(lambda: fh.Machine))]]).toarray()[0])
    chars = []
    for name, mask in (("RELOC_STRIPPED", 0x0001), ("EXECUTABLE_IMAGE", 0x0002),
                       ("LARGE_ADDRESS_AWARE", 0x0020), ("32BIT_MACHINE", 0x0100),
                       ("DEBUG_STRIPPED", 0x0200), ("DLL", 0x2000),
                       ("SYSTEM", 0x1000), ("UP_SYSTEM_ONLY", 0x4000)):
        if _safe(lambda m=mask: fh.Characteristics) & mask:
            chars.append(name)
    parts.append(_hasher(10).transform([chars]).toarray()[0])
    parts.append(_hasher(10).transform(
        [[str(_safe(lambda: oh.Subsystem))]]).toarray()[0])
    dll_chars = []
    for name, mask in (("DYNAMIC_BASE", 0x0040), ("FORCE_INTEGRITY", 0x0080),
                       ("NX_COMPAT", 0x0100), ("NO_ISOLATION", 0x0200),
                       ("NO_SEH", 0x0400), ("NO_BIND", 0x0800),
                       ("APPCONTAINER", 0x1000), ("WDM_DRIVER", 0x2000),
                       ("GUARD_CF", 0x4000), ("TERMINAL_SERVER_AWARE", 0x8000)):
        if _safe(lambda: oh.DllCharacteristics) & mask:
            dll_chars.append(name)
    parts.append(_hasher(10).transform([dll_chars]).toarray()[0])
    parts.append(_hasher(10).transform([[str(_safe(lambda: oh.Magic))]]).toarray()[0])

    nums = np.array([
        _safe(lambda: oh.MajorImageVersion), _safe(lambda: oh.MinorImageVersion),
        _safe(lambda: oh.MajorLinkerVersion), _safe(lambda: oh.MinorLinkerVersion),
        _safe(lambda: oh.MajorSubsystemVersion), _safe(lambda: oh.MinorSubsystemVersion),
        _safe(lambda: oh.MajorOperatingSystemVersion),
        _safe(lambda: oh.MinorOperatingSystemVersion),
        _safe(lambda: oh.SizeOfCode), _safe(lambda: oh.SizeOfHeaders),
        _safe(lambda: oh.SizeOfInitializedData),
        _safe(lambda: oh.SizeOfUninitializedData),
    ], dtype=np.float32)
    parts.append(nums)
    return np.hstack(parts).astype(np.float32)[:DIM_HEADER]


def section_features(pe):
    """节表：数量/异常计数 + 名称、大小、熵、虚拟大小、属性各自 hash 成 50 维。

    n_wx（可写且可执行）和 rawsize=0 但 vsize 很大是典型的加壳/自解压迹象。
    """
    secs = list(getattr(pe, "sections", []) or [])
    names, sizes, entropies, vsizes, chars = [], [], [], [], []
    n_zero = n_wx = n_rx = n_noname = 0
    for s in secs:
        try:
            nm = s.Name.rstrip(b"\x00").decode("utf-8", "ignore")
        except Exception:
            nm = ""
        if not nm:
            n_noname += 1
        raw = _safe(lambda: s.SizeOfRawData)
        vs = _safe(lambda: s.Misc_VirtualSize)
        c = _safe(lambda: s.Characteristics)
        if raw == 0:
            n_zero += 1
        if (c & 0x20000000) and (c & 0x80000000):
            n_wx += 1
        if (c & 0x20000000) and (c & 0x40000000):
            n_rx += 1
        names.append(nm)
        sizes.append((nm, float(raw)))
        vsizes.append((nm, float(vs)))
        try:
            entropies.append((nm, float(s.get_entropy())))
        except Exception:
            entropies.append((nm, 0.0))
        for bit, label in ((0x20000000, "EXEC"), (0x80000000, "WRITE"),
                           (0x40000000, "READ"), (0x02000000, "DISCARDABLE"),
                           (0x00000020, "CODE"), (0x00000040, "INITDATA"),
                           (0x00000080, "UNINITDATA")):
            if c & bit:
                chars.append(label)

    head = np.array([len(secs), n_zero, n_noname, n_rx, n_wx], dtype=np.float32)
    parts = [head,
             _hasher(50).transform([names]).toarray()[0],
             _hasher_pair(50).transform([sizes]).toarray()[0],
             _hasher_pair(50).transform([entropies]).toarray()[0],
             _hasher_pair(50).transform([vsizes]).toarray()[0],
             _hasher(50).transform([chars]).toarray()[0]]
    return np.hstack(parts).astype(np.float32)[:DIM_SECTION]


def import_features(pe):
    """导入表：DLL 名 hash 256 维 + 'dll:函数' 对 hash 1024 维。

    导入什么 API 是最强的行为代理特征（CreateRemoteThread / CryptEncrypt /
    RegSetValue 之类），比任何头部字段都值钱。
    """
    dlls, pairs = [], []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for e in pe.DIRECTORY_ENTRY_IMPORT:
            try:
                dll = (e.dll or b"").decode("utf-8", "ignore").lower()
            except Exception:
                dll = ""
            if dll:
                dlls.append(dll)
            for imp in (e.imports or []):
                if imp.name:
                    try:
                        fn = imp.name.decode("utf-8", "ignore")
                    except Exception:
                        continue
                    pairs.append(f"{dll}:{fn}")
                elif imp.ordinal is not None:
                    pairs.append(f"{dll}:ord{imp.ordinal}")
    a = _hasher(256).transform([dlls]).toarray()[0]
    b = _hasher(1024).transform([pairs]).toarray()[0]
    return np.hstack([a, b]).astype(np.float32)


def export_features(pe):
    names = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for s in (pe.DIRECTORY_ENTRY_EXPORT.symbols or []):
            if s.name:
                try:
                    names.append(s.name.decode("utf-8", "ignore"))
                except Exception:
                    pass
    return _hasher(DIM_EXPORTS).transform([names]).toarray()[0].astype(np.float32)


def datadir_features(pe):
    """15 个数据目录的 (size, vaddr)。安全目录(证书)只取长度，不取内容。"""
    v = np.zeros(DIM_DATADIRS, dtype=np.float32)
    dirs = getattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY", []) or []
    for i, d in enumerate(dirs[:15]):
        v[i * 2] = _safe(lambda: d.Size)
        v[i * 2 + 1] = _safe(lambda: d.VirtualAddress)
    return v


# ------------------------------------------------------------------ 对外类
class PEFeatureExtractor(object):
    """把 PE 字节流变成固定长度向量。

    解析失败不抛异常，也不返回全零 —— 全零会被模型当成一个真实的"空样本"类别。
    这里的约定是：字节级特征永远可算（不依赖 PE 解析成功），结构化部分算不出来
    就留 0，并通过 parse_ok 让调用方能把彻底解析失败的样本剔掉。
    """

    def __init__(self, feature_version=SCHEMA_VERSION, print_feature_warning=False):
        if feature_version != SCHEMA_VERSION:
            raise ValueError(
                f"本实现只提供 SCHEMA_VERSION={SCHEMA_VERSION}，收到 {feature_version}")
        self.dim = FEATURE_DIM
        self.schema_version = SCHEMA_VERSION

    # -- 供调用方判断样本可用性 -------------------------------------------
    @staticmethod
    def is_pe(data):
        if len(data) < 0x40 or data[:2] != b"MZ":
            return False
        try:
            e = struct.unpack_from("<I", data, 0x3C)[0]
            return 0 < e < len(data) - 4 and data[e:e + 4] == b"PE\0\0"
        except struct.error:
            return False

    def raw_features(self, bytez):
        return {"sha256": hashlib.sha256(bytez).hexdigest(),
                "size": len(bytez),
                "parse_ok": self.is_pe(bytez)}

    def feature_vector(self, bytez):
        # 字节级：不依赖 PE 解析，任何输入都能算
        blocks = [byte_histogram(bytez),
                  byte_entropy_histogram(bytez),
                  string_features(bytez)]

        pe = None
        if self.is_pe(bytez):
            try:
                # fast_load 只读头，再按需补目录，避免 pefile 全量解析的开销
                pe = pefile.PE(data=bytez, fast_load=True)
                pe.parse_data_directories(directories=[
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"],
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"],
                ])
            except Exception:
                pe = None

        if pe is None:
            blocks += [np.zeros(DIM_GENERAL, dtype=np.float32),
                       np.zeros(DIM_HEADER, dtype=np.float32),
                       np.zeros(DIM_SECTION, dtype=np.float32),
                       np.zeros(DIM_IMPORTS, dtype=np.float32),
                       np.zeros(DIM_EXPORTS, dtype=np.float32),
                       np.zeros(DIM_DATADIRS, dtype=np.float32)]
        else:
            try:
                blocks += [general_features(pe, bytez),
                           header_features(pe),
                           section_features(pe),
                           import_features(pe),
                           export_features(pe),
                           datadir_features(pe)]
            finally:
                try:
                    pe.close()
                except Exception:
                    pass

        vec = np.hstack(blocks).astype(np.float32)
        if vec.shape[0] != FEATURE_DIM:
            # 维度必须恒定，宁可显式报错也不要静默补零/截断导致列错位
            raise RuntimeError(
                f"特征维度异常: {vec.shape[0]} != {FEATURE_DIM}")
        np.nan_to_num(vec, copy=False, nan=0.0, posinf=0.0, neginf=0.0)
        return vec


def feature_names():
    """给 train.py 的 feature_names 用；hash 出来的维度只能给出块名+序号。"""
    names = []
    names += [f"bytehist_{i}" for i in range(DIM_BYTE_HIST)]
    names += [f"byteent_{i}" for i in range(DIM_BYTE_ENTROPY)]
    names += ["str_count", "str_avglen"]
    names += [f"str_char_{i}" for i in range(96)]
    names += ["str_entropy", "str_paths", "str_urls", "str_registry",
              "str_mz", "str_filesize"]
    names += ["gen_size", "gen_vsize", "gen_has_debug", "gen_has_reloc",
              "gen_has_resource", "gen_has_tls", "gen_n_imports",
              "gen_n_dlls", "gen_n_exports"]
    names += [f"hdr_{i}" for i in range(DIM_HEADER)]
    names += ["sec_count", "sec_zero_rawsize", "sec_noname", "sec_rx", "sec_wx"]
    names += [f"sec_{i}" for i in range(DIM_SECTION - 5)]
    names += [f"imp_dll_{i}" for i in range(256)]
    names += [f"imp_fn_{i}" for i in range(1024)]
    names += [f"exp_{i}" for i in range(DIM_EXPORTS)]
    names += [f"datadir_{i}" for i in range(DIM_DATADIRS)]
    assert len(names) == FEATURE_DIM, (len(names), FEATURE_DIM)
    return names


if __name__ == "__main__":
    import sys
    ex = PEFeatureExtractor()
    print(f"SCHEMA_VERSION={SCHEMA_VERSION}  FEATURE_DIM={ex.dim}")
    for p in sys.argv[1:]:
        with open(p, "rb") as f:
            d = f.read()
        v = ex.feature_vector(d)
        print(f"{p}: dim={v.shape[0]} nonzero={int((v != 0).sum())} "
              f"parse_ok={ex.is_pe(d)}")
