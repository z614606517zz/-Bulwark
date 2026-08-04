#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把行为规则包与代码内置规则(DefaultRules.cpp)对齐,产出精简包。

为什么必须做这一步:
  DefaultRules.cpp 已内置 310 条规则,直接把挖出来的规则全量导入会有两个问题 ——
  1) 大量重复:同一手法两条规则,规则列表虚胖、UI 里命中两条,排查时误以为是两个问题;
  2) 【静默改变产品行为】:内置规则对 certutil 下载 / bitsadmin / -enc / DownloadString
     等手法刻意判 Ask(这些手法确有合法运维用途),而生成的规则判 Block + hardOverride。
     hardOverride 会排到流水线最前,把「弹窗询问」变成「静默拦截」,直接违背
     「尽量不打扰、只对真正危险的行为动手」的设计原则,可能拦掉正常管理操作。

处理策略:
  * 内置已覆盖且裁决相同  -> 丢弃(纯冗余)
  * 内置刻意判 Ask 而本包判 Block -> 降级为 Ask 并去掉 hardOverride,尊重内置意图
  * 内置未覆盖            -> 保留(这才是真正补上的检测盲区)
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RULES = ROOT / "cpp" / "shared" / "src" / "engine" / "DefaultRules.cpp"
ACT_STR = {0: "Allow", 1: "Block", 2: "Ask"}
BLOCK, ASK = 1, 2
RANK = {1: 2, 2: 1, 0: 0}   # Block 最强


def parse_builtin(src: str):
    """抽取 helper(list, "pattern", VerdictAction::X, "note") 形式的内置规则。"""
    out = {}
    for m in re.finditer(r'\b\w+\s*\(\s*list\s*,\s*"((?:[^"\\]|\\.)*)"\s*,\s*VerdictAction::(\w+)', src):
        pat = m.group(1).replace("\\\\", "\\").lower()
        act = {"Allow": 0, "Block": 1, "Ask": 2}.get(m.group(2))
        if act is None:
            continue
        # 同一 pattern 可能出现多次,取最强裁决
        if pat not in out or RANK[act] > RANK[out[pat]]:
            out[pat] = act
    return out


def tokens(pat: str):
    return [t for t in re.split(r"\*+", (pat or "").replace("\\\\", "\\").lower()) if t]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pack", type=Path,
                    default=ROOT / "packaging" / "bulwark-rules-behavior.json")
    ap.add_argument("--out", type=Path,
                    default=ROOT / "packaging" / "bulwark-rules-behavior-refined.json")
    args = ap.parse_args()

    builtin = parse_builtin(DEFAULT_RULES.read_text(encoding="utf-8", errors="replace"))
    pack = json.loads(args.pack.read_text(encoding="utf-8"))
    print("内置规则: %d 条   输入包: %d 条" % (len(builtin), len(pack)))

    kept, dropped, downgraded = [], [], []
    for r in pack:
        mine = (r["commandLinePattern"] or r["targetPattern"] or r["actorPattern"] or "").lower()
        mt = tokens(mine)
        # 找出「与本条描述同一活动」的内置规则:内置 pattern 的 token 全部出现在我的 pattern 里
        # (即内置更宽或等价)。反向包含不算 —— 那只是我的规则更宽,不构成覆盖。
        covering = None
        for bp, ba in builtin.items():
            bt = tokens(bp)
            if bt and all(t in mine for t in bt):
                if covering is None or RANK[ba] > RANK[covering[1]]:
                    covering = (bp, ba)

        if covering is None:
            kept.append(r)
            continue

        bp, ba = covering
        if ba == r["action"]:
            dropped.append((r, bp, ba))                     # 完全冗余
        elif r["action"] == BLOCK and ba == ASK:
            # 内置刻意只询问 -> 不允许本包偷偷升格为拦截
            r = dict(r)
            r["action"] = ASK
            r["hardOverride"] = False
            r["note"] = r["note"] + " · 已按内置规则意图对齐为询问(内置: Ask)"
            downgraded.append((r, bp))
            kept.append(r)
        else:
            kept.append(r)                                   # 我更保守,无害

    print()
    print("丢弃(与内置重复) : %d" % len(dropped))
    print("降级(尊重内置意图) : %d" % len(downgraded))
    print("保留             : %d" % len(kept))

    if downgraded:
        print()
        print("已降级为 Ask 的规则:")
        for r, bp in downgraded:
            print("   - %s" % r["note"][:96])
            print("     (内置 %s 判 Ask)" % bp[:60])

    args.out.write_text(json.dumps(kept, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    b = sum(1 for r in kept if r["action"] == BLOCK)
    a = sum(1 for r in kept if r["action"] == ASK)
    h = sum(1 for r in kept if r["hardOverride"])
    print()
    print("输出: %s" % args.out)
    print("精简包: %d 条 (Block=%d Ask=%d hardOverride=%d)" % (len(kept), b, a, h))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
