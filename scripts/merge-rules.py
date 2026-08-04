#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把生成的防护规则包安全并入本机规则库 %ProgramData%\\Bulwark\\rules.json。

为什么需要专门的合并脚本(而不是直接覆盖):
  规则库里混有【用户的信任白名单】(note 以 "[信任]" 开头)以及用户在弹窗里选择
  「记住」而落盘的裁决。直接覆盖会把这些全部弄丢 —— 服务端 RuleStore::save() 特意
  用原子写来防止这类事故,合并侧同样不能偷懒。

安全设计:
  * 默认 DRY-RUN,只报告不落盘;确认无误后再加 --apply
  * 写入前必备份(rules.json.bak-<时间戳>)
  * 只做「增量追加」,绝不删除/修改任何已存在的规则
  * 按匹配条件去重 => 可反复执行,不会越跑越多(幂等)
  * 原子落盘(临时文件 + os.replace),中途断电不会留下半个文件
  * 冲突体检:若规则包里的 Block 与用户已有的 Allow 条件相同,明确列出来让人裁决

用法:
    python scripts/merge-rules.py                          # 预演,看报告
    python scripts/merge-rules.py --apply                  # 真正写入
    python scripts/merge-rules.py --pack <file> --apply
    python scripts/merge-rules.py --rules-path <file>      # 指定规则库位置
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

TRUST_TAG = "[信任]"          # DefenseRule::trustNoteTag()
ACTION_NAME = {0: "Allow", 1: "Block", 2: "Ask"}
EVENT_NAME = {
    0: "ProcessCreate", 1: "ProcessTerminate", 2: "RemoteThread", 3: "ImageLoad",
    4: "FileWrite", 5: "FileDelete", 6: "RegistryWrite", 7: "NetworkConnect",
    8: "SelfProtect", 9: "DnsQuery", None: "(任意)",
}
REQUIRED = {
    "id", "actorPath", "actorPattern", "type", "targetPattern", "commandLinePattern",
    "parentPattern", "requireUnsigned", "exemptTrustedOsComponent", "hardOverride",
    "actorHashes", "action", "note", "createdUtc", "expiresUtc", "sessionOnly", "enabled",
}


def default_rules_path() -> Path:
    base = os.environ.get("ProgramData") or r"C:\ProgramData"
    return Path(base) / "Bulwark" / "rules.json"


def default_pack_path() -> Path:
    return Path(__file__).resolve().parent.parent / "packaging" / "bulwark-rules-behavior.json"


def load_array(p: Path, what: str) -> list:
    """读取一个 JSON 数组;RuleStore::load() 要求顶层必须是数组。"""
    raw = p.read_text(encoding="utf-8-sig")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise SystemExit("[错误] %s 不是合法 JSON: %s" % (what, e))
    if not isinstance(data, list):
        raise SystemExit("[错误] %s 顶层必须是 JSON 数组(RuleStore 只接受数组)" % what)
    return data


def validate(rules: list, what: str) -> list[str]:
    problems = []
    for i, r in enumerate(rules):
        if not isinstance(r, dict):
            problems.append("%s[%d] 不是对象" % (what, i))
            continue
        missing = REQUIRED - set(r)
        if missing:
            problems.append("%s[%d] 缺字段: %s" % (what, i, ", ".join(sorted(missing))))
        if r.get("action") not in (0, 1, 2):
            problems.append("%s[%d] action 非法: %r" % (what, i, r.get("action")))
        has_criteria = any([
            r.get("actorPath"), r.get("actorPattern"), r.get("targetPattern"),
            r.get("commandLinePattern"), r.get("parentPattern"), r.get("actorHashes"),
        ])
        if not has_criteria:
            problems.append("%s[%d] 无任何匹配条件(会命中一切,危险): %s"
                            % (what, i, str(r.get("note"))[:50]))
    return problems


def signature(r: dict) -> tuple:
    """规则「身份」= 它的匹配条件 + 动作。用于幂等去重。

    刻意不含 id / note / createdUtc:同一条规则重新生成时这些会变,
    但它在语义上仍是同一条,不该被重复插入。
    """
    def norm(s) -> str:
        return (s or "").strip().lower()
    return (
        r.get("type"),
        norm(r.get("actorPath")),
        norm(r.get("actorPattern")),
        norm(r.get("targetPattern")),
        norm(r.get("commandLinePattern")),
        norm(r.get("parentPattern")),
        bool(r.get("requireUnsigned")),
        tuple(sorted(h.upper() for h in (r.get("actorHashes") or []))),
        r.get("action"),
    )


def criteria_only(r: dict) -> tuple:
    """只看匹配条件,不看动作 —— 用于发现「同条件不同裁决」的冲突。"""
    return signature(r)[:-1]


def describe(r: dict) -> str:
    bits = []
    if r.get("actorPath"):          bits.append("actor=" + r["actorPath"])
    if r.get("actorPattern"):       bits.append("actor~" + r["actorPattern"])
    if r.get("parentPattern"):      bits.append("parent~" + r["parentPattern"])
    if r.get("commandLinePattern"): bits.append("cmd~" + r["commandLinePattern"])
    if r.get("targetPattern"):      bits.append("target~" + r["targetPattern"])
    if r.get("actorHashes"):        bits.append("hash×%d" % len(r["actorHashes"]))
    if r.get("requireUnsigned"):    bits.append("仅未签名")
    if r.get("hardOverride"):       bits.append("硬拦截")
    return "%-6s %-15s %s" % (ACTION_NAME.get(r.get("action"), "?"),
                              EVENT_NAME.get(r.get("type"), "?"), " ".join(bits))


def write_atomically(path: Path, payload: str) -> None:
    """临时文件 + 原子替换。规则库里有用户加白项,不能容忍写坏。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".rules-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)          # 同盘原子替换
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def main() -> int:
    ap = argparse.ArgumentParser(description="安全合并 Bulwark 防护规则包")
    ap.add_argument("--pack", type=Path, default=default_pack_path(), help="要并入的规则包")
    ap.add_argument("--rules-path", type=Path, default=default_rules_path(), help="本机规则库路径")
    ap.add_argument("--apply", action="store_true", help="真正写入(缺省仅预演)")
    ap.add_argument("--verbose", action="store_true", help="逐条列出将新增的规则")
    ap.add_argument("--replace-tag", metavar="TAG",
                    help="先移除 note 以 TAG 开头的旧规则再导入(用于更新规则包,"
                         "例如 --replace-tag \"[行为]\")。绝不会碰 [信任] 及用户规则。")
    args = ap.parse_args()
    if args.replace_tag and args.replace_tag.startswith(TRUST_TAG):
        print("[拒绝] --replace-tag 不允许指向信任条目(%s),那是用户数据。" % TRUST_TAG)
        return 2

    print("规则包   : %s" % args.pack)
    print("规则库   : %s" % args.rules_path)
    print("模式     : %s" % ("写入 (--apply)" if args.apply else "预演 (未加 --apply,不会改动任何文件)"))
    print()

    if not args.pack.is_file():
        print("[错误] 规则包不存在: %s" % args.pack)
        return 2
    pack = load_array(args.pack, "规则包")
    probs = validate(pack, "规则包")
    if probs:
        print("[错误] 规则包校验未通过:")
        for p in probs[:20]:
            print("   - " + p)
        return 2
    print("规则包校验通过: %d 条" % len(pack))

    existing: list = []
    if args.rules_path.is_file():
        existing = load_array(args.rules_path, "规则库")
        probs = validate(existing, "规则库")
        if probs:
            # 已有库里的异常只告警 —— 那是用户数据,不由我们判死刑
            print("[告警] 现有规则库有 %d 处异常(将原样保留,不作修改):" % len(probs))
            for p in probs[:5]:
                print("   - " + p)
        print("现有规则库: %d 条" % len(existing))
    else:
        print("现有规则库: 不存在 —— 将新建(首次安装场景)")

    trust_cnt = sum(1 for r in existing
                    if isinstance(r, dict) and str(r.get("note", "")).startswith(TRUST_TAG))
    print("其中信任条目(必须保住): %d 条" % trust_cnt)

    # --replace-tag:更新规则包时,先摘掉同标签的旧版本,避免新旧混存互相打架。
    removed = 0
    if args.replace_tag:
        before = len(existing)
        existing = [r for r in existing
                    if not str(r.get("note", "")).startswith(args.replace_tag)]
        removed = before - len(existing)
        print("按标签移除旧规则 %r: %d 条 (剩余 %d 条)" % (args.replace_tag, removed, len(existing)))
        still_trust = sum(1 for r in existing
                          if isinstance(r, dict) and str(r.get("note", "")).startswith(TRUST_TAG))
        if still_trust != trust_cnt:
            print("[中止] 移除操作影响到了信任条目(%d -> %d),这不应发生。"
                  % (trust_cnt, still_trust))
            return 4
    print()

    have = {signature(r) for r in existing if isinstance(r, dict)}
    crit_map: dict[tuple, list] = {}
    for r in existing:
        if isinstance(r, dict):
            crit_map.setdefault(criteria_only(r), []).append(r)

    to_add, dup, conflicts = [], 0, []
    for r in pack:
        if signature(r) in have:
            dup += 1
            continue
        for old in crit_map.get(criteria_only(r), []):
            if old.get("action") != r.get("action"):
                conflicts.append((old, r))
        to_add.append(r)

    print("拟新增   : %d 条" % len(to_add))
    print("已存在跳过: %d 条 (幂等,可反复执行)" % dup)

    if conflicts:
        print()
        print("[需你裁决] 以下 %d 处「匹配条件相同但裁决不同」——" % len(conflicts))
        print("           你已有的规则会被保留,规则包的那条也会加入;")
        print("           引擎按『动作强度』排序,Block 会盖过 Allow。若那是你故意加的白名单,")
        print("           请在 UI 里删掉新加的对应规则,或改用更具体的信任条目。")
        for old, new in conflicts[:10]:
            print("   你的 : %s | %s" % (describe(old), str(old.get("note"))[:40]))
            print("   包的 : %s | %s" % (describe(new), str(new.get("note"))[:40]))
            print()

    if args.verbose and to_add:
        print()
        print("将新增的规则:")
        for r in to_add:
            print("   " + describe(r))
            print("        " + str(r.get("note", ""))[:100])

    if not to_add and not removed:
        print()
        print("无需改动:规则包内容已全部存在。")
        return 0

    merged = existing + to_add          # 追加式合并:已有规则一条都不动
    payload = json.dumps(merged, ensure_ascii=False, indent=2) + "\n"

    print()
    if removed:
        print("合并后总计: %d 条 (保留 %d + 新增 %d,已移除同标签旧规则 %d)"
              % (len(merged), len(existing), len(to_add), removed))
    else:
        print("合并后总计: %d 条 (原 %d + 新 %d)" % (len(merged), len(existing), len(to_add)))

    if not args.apply:
        print()
        print("预演结束,未写入任何文件。确认无误后重新执行并加上 --apply:")
        print("    python scripts/merge-rules.py --apply")
        return 0

    # ---- 落盘 ----
    if args.rules_path.is_file():
        stamp = time.strftime("%Y%m%d-%H%M%S")
        backup = args.rules_path.with_name(args.rules_path.name + ".bak-" + stamp)
        shutil.copy2(args.rules_path, backup)
        print("已备份   : %s" % backup)

    try:
        write_atomically(args.rules_path, payload)
    except PermissionError:
        print()
        print("[错误] 无写入权限。%s 位于 ProgramData,需以【管理员】身份运行。" % args.rules_path.name)
        print("       另外:若 Bulwark 服务正在运行,它可能在停止时用内存里的规则回写覆盖本次改动。")
        print("       建议先停服务 →  sc stop BulwarkService  ,合并完再启动。")
        return 3

    # 回读验证:确认写出去的东西能被原样解析回来,且条数一致
    check = load_array(args.rules_path, "写入后的规则库")
    ok = (len(check) == len(merged))
    print("已写入   : %s" % args.rules_path)
    print("回读验证 : %d 条 (%s)" % (len(check), "一致" if ok else "不一致,请用备份还原!"))
    kept_trust = sum(1 for r in check
                     if isinstance(r, dict) and str(r.get("note", "")).startswith(TRUST_TAG))
    print("信任条目 : %d 条 (合并前 %d 条,%s)"
          % (kept_trust, trust_cnt, "已完整保留" if kept_trust == trust_cnt else "丢失,请还原备份!"))
    if not ok or kept_trust != trust_cnt:
        return 4

    print()
    print("完成。重启 Bulwark 服务后生效:  sc stop BulwarkService && sc start BulwarkService")
    return 0


if __name__ == "__main__":
    sys.exit(main())
