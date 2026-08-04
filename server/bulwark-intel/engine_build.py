#!/usr/bin/env python3
"""Bulwark 攻击链组合引擎 —— 服务器端特征构建器。

思路(无模型、无训练,纯计数):
  归档里每份 VT 报告都自带沙箱行为记录 —— 该样本在虚拟机里跑起来后做过什么。
  单个动作说明不了问题(正常安装程序也写 Run 键、也落 exe),但【若干动作凑在一起】
  就足以定性。本构建器就是从真实样本里把这些「攻击链组合」数出来。

  样本越多组合越准;每天增量重算即可,不需要任何重新训练。

实测踩到的三个坑,本文件逐一处理:
  1. 沙箱记录里【环境噪音压倒性多数】。直接按频次排序,冠军是 services.exe /
     svchost.exe / lsass.exe / /bin/gzip / /var/log/*.gz —— 全是虚拟机自己的正常活动,
     跟样本无关。故【不用】raw 字段(processes_created / files_written / registry_keys_set),
     只用 VT 已经标注过严重度的 sigma_analysis_results(社区 Sigma 规则命中)与精选
     MITRE 手法 —— 判断由社区规则给出,不自己从噪音里猜。
  2. 归档里 42% 是 Linux/ELF 样本(mirai 家族霸榜),对 Windows 端点无用,先按类型剔除。
  3. 存在【同义标记】与【蕴含标记】,不处理会让组合虚高:
     · 同义: "Powershell Defender Exclusion" 与 "Windows Defender Exclusions Added -
       PowerShell" 实测共现 44 次,本是同一动作,算成两个等于凭一个动作就凑够一组;
     · 蕴含: "New RUN Key Pointing to Suspicious Folder" 必然同时命中
       "CurrentVersion Autorun Keys Modification"(前者是后者的特例),两者同现不构成互证。
     同义靠人工表归一;蕴含靠数据自动识别(条件概率 > IMPLY_RATIO 即判定为蕴含并折叠),
     这样新出现的蕴含关系不必等人去发现。

输出三张表:engine_markers(标记字典) / engine_patterns(组合) / engine_versions(版本)。
"""

import argparse
import collections
import hashlib
import itertools
import json
import os
import re
import sqlite3
import sys
from datetime import datetime, timezone

CONFIG_PATH = os.environ.get("BULWARK_INTEL_CONFIG", "/etc/bulwark-intel/config.json")

# ---- 调参(全部是阈值,不是学习出来的参数) ------------------------------------- #

# 只挖 Windows 端点用得上的样本类型。归档里 ELF 占 42%,对 Windows 客户端毫无价值。
WIN_TYPES = {"peexe", "pedll", "msi", "vba", "javascript", "lnk", "hta", "wsf",
             "doc", "docx", "xls", "xlsx", "rtf", "ppt", "pptx", "chm"}

# Sigma 规则严重度门槛:low 级噪音太大(如"非交互式 PowerShell 启动"正常运维也会有)。
SIGMA_LEVELS = {"medium", "high", "critical"}

# 是否把 MITRE 手法也当行为标记。默认关闭 —— 实测这是个陷阱:
# mitre_attack_techniques 的 signature_description 是【静态特征描述】而非攻击行为,
# 诸如「读取自身二进制镜像」「PE 文件含 overlay」「查询注册表挂载点」正常打包程序全都命中。
# 开启后标记词表从数十个膨胀到 1330 个,挖出 29649 条组合且榜首尽是这类噪音。
# Sigma 规则才是真正带严重度的检测规则(判断已由社区做好),故只用它。
USE_MITRE = False

# 出现率超过此比例的标记视为「通用行为」而非攻击特征,直接丢弃。
GENERIC_DF_RATIO = 0.45

# 条件概率 P(B|A) 超过此值 -> 判定 A 蕴含 B,折叠掉 B(不计为独立互证)。
IMPLY_RATIO = 0.90
# 支持度不足的标记不参与蕴含判定。取 12:实测取 5 时在稀疏数据上判出 3835 条蕴含关系,
# 绝大多数是低计数下的偶然共现,把真实互证也一起折叠掉了。
IMPLY_MIN_SUPPORT = 12

# 冗余组合折叠:子集组合的支持度若与某个超集组合接近(比值 >= 此值),说明它没有提供
# 额外信息(那些样本几乎总是把超集里的动作全做齐),只保留信息量更大的超集。
# 这一步是把「组合爆炸」压回可用规模的关键。
REDUNDANT_RATIO = 0.80

# 一条组合至少要被这么多样本共同命中才收录(避免单样本偶然)。
MIN_SUPPORT = 5
# 组合最多几个标记(再大意义不高且组合数爆炸)。
MAX_ITEMSET = 4

# 分级所需的最低支持度。动作数与严重度只说明「这组合看起来多严重」,支持度才说明
# 「有多少真实样本为它作证」。实测只按动作数分级时,1729 条仅 5~13 个样本支撑的组合
# 全被判成「可直接拦」—— 证据这么薄就敢直接阻断即是过拟合,故按动作强度分别设门槛:
# 越是要「不问就拦」,越要更多样本作证。
SUPPORT_FOR_HARD = 10    # 直接阻断
SUPPORT_FOR_STRONG = 8   # 阻断或强提示
SUPPORT_FOR_ASK = 5      # 弹窗询问

# ---- 区分度(正常样本语料) ----------------------------------------------------- #
#
# 上面所有阈值都只看【恶意样本】,答的是「多少病毒有这个组合」。真正决定误报的是另一个问题:
# 「多少正常软件也有」。缺了后者,一条组合是真特征还是普遍现象根本区分不出来。
#
# GENERIC_DF_RATIO 看似在做这件事,其实不是 —— 它算的是恶意样本【内部】的出现率。
# 一个标记完全可以只出现在 5% 的病毒里、却出现在 90% 的正常软件里,照样过得了那道门槛。
# 实测就撞上了:某条组合两个标记的条件都退化成「未签名的进程创建」,支持度 13、严重度 high,
# 顺利进档,命中的却是 ripgrep 和本产品自己的 UI。
#
# 正常语料来自 app.py 的 benign_reports 表:信誉查询本来就为每个 hash 抓了沙箱行为,
# 以前干净文件抓完即弃,现在留下来当分母。
#
# 语料规模不足时【完全不参与定级】—— 3 个正常样本得出的结论比没有更危险。
BENIGN_MIN_CORPUS = 50

# 正常软件里出现率超过此比例的标记,不是攻击特征。这是真正的区分度过滤。
BENIGN_GENERIC_RATIO = 0.30

# 组合在正常软件中的出现率 -> 定级上限。宁可少拦不可误伤,故只降不升:
#   命中 >=1 个正常样本            -> 不得「不问就拦」(hard 降 strong)
#   出现率 > BENIGN_ASK_RATIO      -> 只能弹窗询问
#   出现率 > BENIGN_DROP_RATIO     -> 整条丢弃
BENIGN_ASK_RATIO = 0.02
BENIGN_DROP_RATIO = 0.10

# ---- 标记 -> 磐垒可观测事件的映射 -------------------------------------------- #
#
# 组合挖出来只是「知道哪几个动作凑一起是病毒」,客户端还得知道「这个动作在我这儿长什么样」。
# 这张表就干这件事:把 Sigma 规则标题翻译成磐垒的事件类型 + 匹配条件。
#
# 字段刻意做成与 DefenseRule 完全一致的形状(actor/target/cmdline/parent/unsigned),
# 这样客户端【直接复用现成的 DefenseRule::matches()】,不必为本引擎新写一套匹配逻辑。
# 通配符沿用 DefenseRule::wildcardMatch 的约定('*' 任意长度,大小写不敏感)。
#
# 【重要】这些条件是 Sigma 原规则的宽松近似,不是等价实现 —— 故意宽:
# 单个标记【永远不会】单独触发处置,只有凑齐组合才算。宽一点只会让标记更容易置位,
# 真正的定性门槛在「组合 + 支持度 + 严重度」那三道上,所以这里宁可宽不可漏。
#
# event 取值对应 bulwark::EventType 的成员名(见 cpp/shared/include/bulwark/models/Enums.h)。
MARKER_RULES = {
    # ---- 注册表持久化 / 篡改 ----
    "new_run_key_pointing_to_suspicious_folder": {
        "event": "RegistryWrite", "target": "*\\CurrentVersion\\Run*"},
    "currentversion_autorun_keys_modification": {
        "event": "RegistryWrite", "target": "*\\CurrentVersion\\Run*"},
    "new_root_or_ca_or_authroot_certificate_to_store": {
        "event": "RegistryWrite", "target": "*\\SystemCertificates\\*"},
    "windows_defender_exclusions_added_registry": {
        "event": "RegistryWrite", "target": "*\\Windows Defender\\Exclusions*"},
    "registry_tampering_by_potentially_suspicious_processes": {
        "event": "RegistryWrite", "unsigned": True},
    "service_binary_in_suspicious_folder": {
        "event": "RegistryWrite", "target": "*\\Services\\*"},
    "cmstp_execution_registry_event": {
        "event": "RegistryWrite", "target": "*\\CMMGR32.EXE*"},

    # ---- 启动目录 / 公共目录落文件 ----
    "startup_folder_file_write": {
        "event": "FileWrite", "target": "*\\Start Menu\\Programs\\Startup\\*"},
    "suspicious_startup_folder_persistence": {
        "event": "FileWrite", "target": "*\\Start Menu\\Programs\\Startup\\*"},
    "suspicious_binaries_and_scripts_in_public_folder": {
        "event": "FileWrite", "target": "*\\Users\\Public\\*"},
    "windows_shell_scripting_application_file_write_to_suspicious_folder": {
        "event": "FileWrite", "target": "*\\Temp\\*"},
    "file_with_uncommon_extension_created_by_an_office_application": {
        "event": "FileWrite", "parent": "*\\WIN*.EXE"},

    # ---- 模块加载 / 侧载 ----
    #
    # 下面两条的原意都是「被加载的【模块】未签名」,而客户端的 unsigned 判的是
    # 【主体进程】的签名(DefenseRule::requireUnsigned -> !e.actorSigned),两者不是一回事。
    # 客户端目前没有"被加载模块的签名"这个字段,所以这两条无法忠实表达,先标为不可观测。
    # 硬映射的后果实测过,两种都很糟:
    #   * lsass 那条写成 target="*\\lsass.exe":ImageLoad 的 target 是【被加载模块路径】,
    #     模块不会叫 lsass.exe,于是永不匹配 —— 而它出现在 9 条组合里(含支持度最高的
    #     那条 strong),等于让 9 条规则常年是死的,而统计上还显示"已生效"。
    #   * windows_utility 那条只有 unsigned 一项:反而变成【几乎无条件匹配】任何主体未签名的
    #     模块加载。实机上路径解析失败时 actorSigned 恒为 false,于是它照样命中 —— 唯一那次
    #     真实命中就是它,主体记的是占位串 "PID 8120"。
    # 要恢复这两条,需要客户端补「模块签名」维度(给 ImageLoad 事件校验 target 文件的签名),
    # 那是独立的一次改动,不在此处凑合。
    "unsigned_image_loaded_into_lsass_process": {
        "event": "ImageLoad", "unobservable": True,
        "why": "语义是被加载模块未签名;客户端只有主体进程签名,表达不了"},
    "unsigned_dll_loaded_by_windows_utility": {
        "event": "ImageLoad", "unobservable": True,
        "why": "同上;若只按主体未签名匹配会变成近乎无条件命中的误报源"},
    "potential_vcruntime140_dll_sideloading": {
        "event": "ImageLoad", "target": "*\\vcruntime140.dll"},

    # ---- Defender 关防 ----
    "powershell_defender_exclusion": {
        "event": "ProcessCreate", "cmdline": "*Add-MpPreference*Exclusion*"},
    "suspicious_windows_defender_folder_exclusion_added_via_reg_exe": {
        "event": "ProcessCreate", "cmdline": "*Windows Defender\\Exclusions*"},

    # ---- PowerShell / 脚本宿主滥用 ----
    "potentially_suspicious_powershell_script_execution_from_temp_folder": {
        "event": "ProcessCreate", "cmdline": "*\\Temp\\*", "actor": "*\\powershell*.exe"},
    "change_powershell_policies_to_an_insecure_level": {
        "event": "ProcessCreate", "cmdline": "*Set-ExecutionPolicy*"},
    "potential_powershell_command_line_obfuscation": {
        "event": "ProcessCreate", "cmdline": "*-e*ncodedcommand*"},
    "suspicious_powershell_invocation_from_script_engines": {
        "event": "ProcessCreate", "actor": "*\\powershell*.exe",
        "parent": "*\\w*script.exe"},
    "script_interpreter_execution_from_suspicious_folder": {
        "event": "ProcessCreate", "actor": "*\\Temp\\*"},
    "potential_lethalhta_technique_execution": {
        "event": "ProcessCreate", "actor": "*\\mshta.exe"},

    # ---- 计划任务持久化 ----
    "schedule_task_creation_from_env_variable_or_potentially_suspicious_path_via_schtasks_exe": {
        "event": "ProcessCreate", "actor": "*\\schtasks.exe"},
    "scheduled_temp_file_as_task_from_temp_location": {
        "event": "ProcessCreate", "actor": "*\\schtasks.exe", "cmdline": "*\\Temp\\*"},
    "suspicious_scheduled_task_creation_via_masqueraded_xml_file": {
        "event": "ProcessCreate", "actor": "*\\schtasks.exe", "cmdline": "*/xml*"},
    "schedule_system_process": {
        "event": "ProcessCreate", "actor": "*\\schtasks.exe"},

    # ---- 系统进程伪装 / svchost 异常 ----
    "uncommon_svchost_command_line_parameter": {
        "event": "ProcessCreate", "actor": "*\\svchost.exe"},
    "uncommon_svchost_parent_process": {
        "event": "ProcessCreate", "actor": "*\\svchost.exe"},
    "files_with_system_process_name_in_unsuspected_locations": {
        "event": "ProcessCreate", "unsigned": True},
    "system_file_execution_location_anomaly": {
        "event": "ProcessCreate", "unsigned": True},

    # ---- LOLBin / 其它 ----
    "reg_add_suspicious_paths": {
        "event": "ProcessCreate", "actor": "*\\reg.exe", "cmdline": "*add*"},
    "bypass_uac_via_cmstp": {
        "event": "ProcessCreate", "actor": "*\\cmstp.exe"},
    "suspicious_curl_exe_download": {
        "event": "ProcessCreate", "actor": "*\\curl.exe", "cmdline": "*-o*"},
    "dynamic_net_compilation_via_csc_exe": {
        "event": "ProcessCreate", "actor": "*\\csc.exe"},
    "dot_net_compiler_compiles_file_from_suspicious_location": {
        "event": "ProcessCreate", "actor": "*\\csc.exe", "cmdline": "*\\Temp\\*"},
    "suspicious_windows_service_tampering": {
        "event": "ProcessCreate", "actor": "*\\sc.exe"},

    # ---- 网络 ----
    "suspicious_network_connection_to_ip_lookup_service_apis": {
        "event": "NetworkConnect"},
    "office_application_initiated_network_connection_to_non_local_ip": {
        "event": "NetworkConnect", "actor": "*\\WIN*.EXE"},
}

# 未在上表登记的新标记走关键词兜底猜测(仅决定事件类型,不给匹配条件)。
# 目的是让【新出现的 Sigma 规则】不至于直接变成不可观测项,同时在网页上仍标出「待人工确认」。
KEYWORD_EVENT_HINTS = [
    (("registry", "regedit", "reg.exe", "autorun", "hive"), "RegistryWrite"),
    (("dll", "image load", "sideload", "loaded into"), "ImageLoad"),
    (("file creation", "file write", "created by", "dropped"), "FileWrite"),
    (("network", "connection", "http", "dns", "smtp", "c2"), "NetworkConnect"),
    (("delete", "wiped", "shadow copy"), "FileDelete"),
]

# 人工同义表:键与值归一到同一个标记。只放【确认是同一动作】的,宁少勿多。
SYNONYMS = {
    "windows defender exclusions added - powershell": "powershell defender exclusion",
    "windows defender exclusions added": "powershell defender exclusion",
    "suspicious powershell script execution from temp folder":
        "potentially suspicious powershell script execution from temp folder",
}


# 展示版本号的步长与起点。给人看的编号从 0.1 开始,每次【内容真的变了】就 +0.1。
# 与内部的整数 version 分开:后者是「客户端要不要重新下载」的判据,必须单调递增的整数
#(客户端按 manifest.version > 本地版本 拉取,AUTOINCREMENT 保证;换成浮点会踩比较精度的坑)。
LABEL_STEP = 0.1


def next_label(prev_label):
    """算下一个展示版本号。prev_label 为空(首次启用本机制)时返回 "0.1"。

    刻意用整数计数再乘步长,而不是 prev + 0.1 累加:浮点累加 10 次会得到 0.9999999999999999,
    格式化成一位小数虽然看不出来,但比较与去重就开始出错。
    """
    try:
        n = int(round(float(prev_label) / LABEL_STEP)) if prev_label else 0
    except ValueError:
        n = 0
    return "%.1f" % ((n + 1) * LABEL_STEP)


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_db_path():
    try:
        with open(CONFIG_PATH) as f:
            return json.load(f).get("db_path", "/var/lib/bulwark-intel/cache.db")
    except Exception:
        return "/var/lib/bulwark-intel/cache.db"


def slug(text):
    """可读标题 -> 稳定的标记 ID(小写下划线,截断)。"""
    s = re.sub(r"[^a-z0-9]+", "_", (text or "").strip().lower()).strip("_")
    return s[:70] or "unknown"


# ---- 从一份报告里提取行为标记 ------------------------------------------------ #

def extract_markers(rep):
    """返回 {marker_id: (title, level, source)}。只取已被标注严重度的高信号字段。"""
    out = {}
    b = rep.get("behaviour") or {}
    if not isinstance(b, dict):
        return out

    # 1) Sigma 社区规则命中 —— 主力信号。自带 rule_level,判断已由社区做好。
    for x in (b.get("sigma_analysis_results") or []):
        if not isinstance(x, dict):
            continue
        title = (x.get("rule_title") or "").strip()
        level = (x.get("rule_level") or "").strip().lower()
        if not title or level not in SIGMA_LEVELS:
            continue
        key = SYNONYMS.get(title.lower(), title.lower())
        out[slug(key)] = (title, level, "sigma")

    # 2) MITRE 手法 —— 默认不用(见 USE_MITRE 处的说明:那是静态特征描述,不是攻击行为)。
    if USE_MITRE:
        for x in (b.get("mitre_attack_techniques") or []):
            if not isinstance(x, dict):
                continue
            tid = (x.get("id") or "").strip()
            desc = (x.get("signature_description") or "").strip()
            if not tid or not desc:
                continue
            title = "%s %s" % (tid, desc[:80])
            out[slug(title)] = (title, "medium", "mitre")

    return out


def sample_family(rep):
    f = rep.get("file") or {}
    ptc = f.get("popular_threat_classification") or {}
    if isinstance(ptc, dict):
        return (ptc.get("suggested_threat_label") or "").strip()
    return ""


# ---- 主流程 ------------------------------------------------------------------ #

def collect(con):
    """扫【恶意】归档 -> [(marker_set, family)],同时累积标记字典。

    vt_reports 按设计只收威胁(app.py 的留存策略:malicious/suspicious 才落库),
    所以这里不必再按 verdict 过滤。正常样本走另一张表,见 collect_benign()。
    加一道 verdict 保险:万一以后有人放开 vt_reports 的留存策略,干净样本混进来
    会被当成恶意证据统计,比没有正常语料更糟。
    """
    samples = []
    catalog = {}          # marker_id -> (title, level, source)
    skipped_platform = 0
    skipped_nobehav = 0
    total = 0

    skipped_clean = 0
    for row in con.execute("SELECT verdict, report FROM vt_reports"):
        try:
            rep = json.loads(row[1] or "{}")
        except Exception:
            continue
        total += 1
        f = rep.get("file") or {}
        if (f.get("type_tag") or "").lower() not in WIN_TYPES:
            skipped_platform += 1
            continue
        if not _is_threat(row[0], f):
            skipped_clean += 1      # 不是威胁 -> 不能当恶意证据(正常语料走 benign_reports)
            continue
        marks = extract_markers(rep)
        if not marks:
            skipped_nobehav += 1
            continue
        for mid, meta in marks.items():
            # 同一标记可能来自多份报告;保留更高的严重度。
            prev = catalog.get(mid)
            if prev is None or _level_rank(meta[1]) > _level_rank(prev[1]):
                catalog[mid] = meta
        samples.append((set(marks.keys()), sample_family(rep)))

    return samples, catalog, {
        "total_reports": total,
        "skipped_other_platform": skipped_platform,
        "skipped_not_threat": skipped_clean,
        "skipped_no_behaviour": skipped_nobehav,
        "usable_samples": len(samples),
    }


def _is_threat(verdict, file_attr):
    """这份报告算不算威胁。以 verdict 列为准,空值时回退到引擎计数。"""
    v = (verdict or "").strip().lower()
    if v in ("malicious", "suspicious"):
        return True
    if v == "clean":
        return False
    st = file_attr.get("last_analysis_stats") or {}
    return (int(st.get("malicious") or 0) + int(st.get("suspicious") or 0)) > 0


def collect_benign(con, catalog):
    """扫【正常样本】语料 -> [marker_set, ...]。数据来自 app.py 的 benign_reports 表。

    两条容易搞错的规矩:
      * 只统计【真在沙箱里跑过】的样本。没跑过就不知道它会做什么,计入分母会把出现率
        算低,等于放过通用行为 —— 比不做还糟。app.py 只在 behaviour_available 时入库,
        这里再按同一口径核一遍。
      * 【没有任何 sigma 命中的正常样本也要计入】。它不是"无用样本",而是「这个行为
        并不普遍」的正面证据,是分母不可缺的一部分。只把有命中的算进来会系统性高估出现率。
    """
    have = con.execute("""SELECT COUNT(*) FROM sqlite_master
                          WHERE type='table' AND name='benign_reports'""").fetchone()[0]
    if not have:
        return [], {"benign_reports": 0, "benign_usable": 0}

    known = set(catalog.keys())
    out = []
    total = 0
    skipped_platform = 0
    for (rep_s,) in con.execute("SELECT report FROM benign_reports"):
        try:
            rep = json.loads(rep_s or "{}")
        except Exception:
            continue
        total += 1
        f = rep.get("file") or {}
        if (f.get("type_tag") or "").lower() not in WIN_TYPES:
            skipped_platform += 1
            continue
        if not rep.get("behaviour_available"):
            continue
        # 只保留恶意侧也见过的标记:正常软件独有的标记不影响任何组合的区分度。
        out.append(set(extract_markers(rep).keys()) & known)
    return out, {"benign_reports": total,
                 "benign_other_platform": skipped_platform,
                 "benign_usable": len(out)}


class BenignCorpus:
    """正常样本语料 —— 组合的区分度由它决定。

    语料规模不足 BENIGN_MIN_CORPUS 时 usable=False:此时仍然统计并展示出现次数,
    但【不参与定级】。几个样本得出的"出现率"噪声比信号大,拿它去砍规则会砍错。
    """

    def __init__(self, samples):
        self.samples = [s for s in samples]
        self.n = len(self.samples)
        self.df = collections.Counter()
        for marks in self.samples:
            for m in marks:
                self.df[m] += 1
        # 至少出现过一次的标记。用于剪枝:组合里只要有一个标记在正常软件里从未出现,
        # 整条组合的正常侧支持度必然为 0,不必逐样本比对。
        self.seen = {m for m, c in self.df.items() if c > 0}

    @property
    def usable(self):
        return self.n >= BENIGN_MIN_CORPUS

    @property
    def grading_n(self):
        """参与定级时用的分母。语料不足时为 0 —— 让所有区分度逻辑自动失效。

        刻意做成一个属性而不是在各调用点各写一遍 `if usable`:漏写一处就会让
        3 个样本的语料去砍真规则,而这种错在结果里看不出来。
        """
        return self.n if self.usable else 0

    def supports(self, patterns):
        """一次算出所有组合的正常侧支持度 {frozenset: 命中的正常样本数}。"""
        out = {p: 0 for p in patterns}
        live = [p for p in patterns if p <= self.seen]
        if not live:
            return out
        for marks in self.samples:
            if not marks:
                continue
            for p in live:
                if p <= marks:
                    out[p] += 1
        return out

    def rate(self, hits):
        return (hits / self.n) if self.n else 0.0


def _level_rank(lv):
    return {"critical": 3, "high": 2, "medium": 1}.get((lv or "").lower(), 0)


def _normalized_marker_rules():
    """把 MARKER_RULES 的键过一遍 slug(),保证与标记 ID 的生成方式完全一致。

    否则长标题会对不上 —— slug() 截断到 70 字符,而上表里是手写的全长键。
    实测「Schedule Task Creation From Env Variable Or Potentially Suspicious Path Via
    Schtasks.EXE」就因此漏配。经此归一后,上表可以照抄完整标题、不必自己数字符。
    """
    return {slug(k): v for k, v in MARKER_RULES.items()}


_MARKER_RULES_N = None


def resolve_mapping(marker_id, title):
    """标记 -> (是否可观测, 事件类型, 匹配条件 JSON)。

    三级:登记表命中 -> 关键词兜底(只给事件类型,标为待确认) -> 不可观测。
    不可观测的标记仍然入库、仍参与组合统计,只是客户端拿不到匹配条件,无法自行置位。
    """
    global _MARKER_RULES_N
    if _MARKER_RULES_N is None:
        _MARKER_RULES_N = _normalized_marker_rules()
    rule = _MARKER_RULES_N.get(marker_id)
    if rule:
        # 显式标注「客户端表达不出这个条件」的标记:仍留在表里(便于下一个人看到理由,
        # 而不是以为漏配),但不下发条件 -> 客户端不会置位它,含它的组合会被整条剔除。
        # 之所以需要这个开关:有些 Sigma 规则的语义落在客户端没有的字段上,硬映射成近似条件
        # 反而更糟 —— 要么永不匹配(死规则),要么过宽(误报源)。两种都实际发生过,见下方各条注释。
        if rule.get("unobservable"):
            return 0, rule.get("event", ""), ""
        cond = {k: v for k, v in rule.items()
                if k not in ("event", "unobservable", "why")}
        return 1, rule["event"], json.dumps(cond, ensure_ascii=False)

    low = (title or "").lower()
    for words, ev in KEYWORD_EVENT_HINTS:
        if any(w in low for w in words):
            # 只猜事件类型、不给条件:observable=0 表示「还需人工补条件」,网页上可筛出来。
            return 0, ev, ""
    return 0, "", ""


def observable_ids(catalog):
    """客户端能自行置位的标记集合(resolve_mapping 给出 observable=1 的那些)。

    用途:覆盖选择时只考虑「全部标记都可观测」的组合。一个标记若没有可下发的匹配条件,
    客户端永远不会给它置位,含它的组合就永远凑不齐 —— 是纯粹的死规则。
    实测 v11 的 35 条组合里有 15 条含这种标记,客户端只装载了 18 条,而服务器侧的支持度、
    覆盖率、分级统计把那 15 条全算在内:数字好看,实际不干活。

    【为什么不在挖掘前就把这些标记从样本里删掉】——试过,更糟:265 个标记会被删掉 230 个,
    共现结构被打残,挖出的组合从 1763 条掉到 130 条,hard 与 strong 两档全军覆没(只剩 27 条
    全是 ask),覆盖率从 40% 掉到 29%。挖掘阶段仍需要完整的共现信息,过滤只该发生在
    「决定下发哪些」这一步。
    """
    out = set()
    for mid, (title, _lv, _src) in catalog.items():
        obs, _ev, _cond = resolve_mapping(mid, title)
        if obs:
            out.add(mid)
    return out


def drop_generic(samples, catalog, ratio):
    """剔除出现率过高的通用行为(不是攻击特征,留着只会稀释组合)。"""
    n = len(samples)
    if n == 0:
        return set()
    df = collections.Counter()
    for marks, _ in samples:
        for m in marks:
            df[m] += 1
    generic = {m for m, c in df.items() if c > n * ratio}
    for marks, _ in samples:
        marks -= generic
    return generic


def drop_benign_generic(samples, benign, ratio):
    """剔除【正常软件也普遍具备】的标记 —— 真正的区分度过滤,与 drop_generic 互补。

    drop_generic 算的是恶意样本内部的出现率,答不了「正常软件是不是也这样」。
    一个标记只出现在 5% 的病毒里(轻松过 GENERIC_DF_RATIO)、却出现在 90% 的正常软件里,
    留着它就是纯误报源。这里把这类标记在挖掘【之前】拿掉,组合里就不会再出现。

    语料不足时直接返回空集:不做判断,而不是做个不可靠的判断。
    """
    if not benign.usable:
        return set()
    generic = {m for m, c in benign.df.items() if c > benign.n * ratio}
    if not generic:
        return set()
    for marks, _ in samples:
        marks -= generic
    return generic


def find_implications(samples):
    """自动识别蕴含关系:P(B|A) > IMPLY_RATIO 即 A 蕴含 B。

    返回 {A: {被 A 蕴含的 B...}}。用于折叠 —— A 在场时 B 不再计为独立互证,
    否则「Run 键指向可疑目录」+「修改了 Run 键」会被当成两条证据,而它们其实是一件事。
    """
    df = collections.Counter()
    co = collections.Counter()
    for marks, _ in samples:
        ms = sorted(marks)
        for m in ms:
            df[m] += 1
        for a, b in itertools.combinations(ms, 2):
            co[(a, b)] += 1

    implies = collections.defaultdict(set)
    for (a, b), c in co.items():
        if df[a] >= IMPLY_MIN_SUPPORT and c / df[a] > IMPLY_RATIO:
            implies[a].add(b)      # A 几乎总是伴随 B -> A 蕴含 B
        if df[b] >= IMPLY_MIN_SUPPORT and c / df[b] > IMPLY_RATIO:
            implies[b].add(a)
    return implies


def reduce_markers(marks, implies):
    """折叠蕴含:若集合里同时有 A 和被 A 蕴含的 B,去掉 B(保留信息量更大的 A)。

    必须按 sorted 遍历:存在互相蕴含(A->B 且 B->A)的情形,此时谁被保留取决于遍历顺序。
    而 Python 的字符串哈希每进程随机化,直接遍历 set 会让同一份数据每次算出不同结果。
    """
    out = set(marks)
    for a in sorted(marks):
        if a in implies:
            out -= (implies[a] & out) - {a}
    return out


def mine(samples, min_support, max_size):
    """Apriori 式频繁项集挖掘:只扩展达到支持度的项集,避免组合爆炸。

    纯计数,没有任何模型。返回 {frozenset: (support, [family...])}。
    """
    sets = [(s, fam) for s, fam in samples if len(s) >= 2]
    result = {}

    # 1 元起步
    level = collections.Counter()
    for s, _ in sets:
        for m in s:
            level[m] += 1
    current = {frozenset([m]) for m, c in level.items() if c >= min_support}

    size = 1
    while current and size < max_size:
        size += 1
        cand = collections.Counter()
        fams = collections.defaultdict(collections.Counter)
        # 用「已达标项集」两两并成候选,天然满足 Apriori 剪枝的必要条件
        cur_list = sorted(current, key=lambda x: sorted(x))
        for i in range(len(cur_list)):
            for j in range(i + 1, len(cur_list)):
                u = cur_list[i] | cur_list[j]
                if len(u) != size:
                    continue
                cand[u] += 0     # 先登记候选
        if not cand:
            break
        for s, fam in sets:
            if len(s) < size:
                continue
            for u in cand:
                if u <= s:
                    cand[u] += 1
                    if fam:
                        fams[u][fam] += 1
        current = {u for u, c in cand.items() if c >= min_support}
        # 按 sorted 写入 result:dict 的插入顺序会被下游 drop_redundant / select_cover 的
        # 同分决胜所继承,而 frozenset 的哈希每进程随机化 —— 不定序则整条流程不可复现。
        for u in sorted(current, key=lambda x: sorted(x)):
            # most_common 对同计数项按插入序返回,同样不稳定 -> 显式按 (计数降序, 名称) 定序。
            top = [f for f, _ in sorted(fams[u].items(), key=lambda kv: (-kv[1], kv[0]))[:3]]
            result[u] = (cand[u], top)
    return result


def drop_redundant(patterns, ratio=REDUNDANT_RATIO):
    """折叠冗余组合:若某组合是另一个组合的子集、且支持度接近,则它没提供额外信息。

    例:{落exe, 改Run键} 支持度 42,而 {落exe, 改Run键, 装根证书} 支持度 40 ——
    说明命中前者的样本几乎都把第三个动作也做了,单独保留前者只是让规则库变大、
    并且更容易误伤(要求的动作更少)。故只保留信息量更大的超集。

    这一步把实测的 29649 条压到几百条,是能否落地的关键。
    """
    # 末位以标记名兜底,使排序成为【全序】—— 否则同长同支持度的组合之间由输入 dict 顺序决定,
    # 而那个顺序受 frozenset 哈希随机化影响,不可复现。
    keys = sorted(patterns.keys(), key=lambda s: (-len(s), -patterns[s][0], sorted(s)))
    kept = []
    for p in keys:
        sup = patterns[p][0]
        redundant = False
        for q in kept:
            if p < q and sup <= patterns[q][0] / ratio:
                redundant = True
                break
        if not redundant:
            kept.append(p)
    return {p: patterns[p] for p in kept}


def select_cover(samples, patterns, catalog, min_gain=1, bsup=None, btotal=0, obs=None):
    """贪心集合覆盖:挑出「能解释最多样本」的最小组合子集。

    为什么需要这一步:去冗余之后仍有 1936 条组合,却只覆盖 174 个样本 —— 平均 11 条规则
    压在同一批样本上。这些组合彼此高度重叠(一个命中 8 个标记的样本能派生出 56 个三元组),
    留着它们既不增加检出、又白白放大误报面与规则库体积。

    做法:每轮选出「能新覆盖最多样本」的那条,直到没有组合还能新增覆盖。
    同分时优先 动作多(链条更完整) -> 支持度高 -> 等级强,使结果稳定可复现。
    """
    order = {"hard": 3, "strong": 2, "ask": 1, "weak": 0}
    bsup = bsup or {}
    cands = []
    for p, (sup, fams) in patterns.items():
        # 可达性:组合里任一标记客户端置不了位,整条就永远凑不齐。这种组合绝不能占用覆盖额度 ——
        # 它会把本来能补位的可用组合挤掉,然后自己在客户端装载时被剔除,等于白丢检出。
        # (实测未加此过滤时,35 条下发里 15 条如此,客户端只装载了 18 条。)
        if obs is not None and not (set(p) <= obs):
            continue
        # 定级要带上正常侧:被正常语料判死的组合不该进覆盖选择,否则它会占掉覆盖额度,
        # 把本来能补位的组合挤掉,最后又在 persist 里被丢弃 —— 白白丢检出。
        g = grade(p, catalog, sup, bsup.get(p, 0), btotal)
        if g == "weak":
            continue
        hits = frozenset(i for i, (marks, _f) in enumerate(samples) if p <= marks)
        if hits:
            cands.append((p, sup, fams, g, hits))
    # 候选先定序:下面每轮挑选在同分时取「先遇到的那个」,输入顺序不定则结果不可复现。
    cands.sort(key=lambda it: sorted(it[0]))

    uncovered = set(range(len(samples)))
    chosen = []
    while cands:
        best = None
        best_key = None
        for item in cands:
            gain = len(item[4] & uncovered)
            if gain < min_gain:
                continue
            # 末位以标记名兜底,使决胜成为【全序】(同覆盖增益/同动作数/同支持度/同等级时也唯一)。
            key = (gain, len(item[0]), item[1], order[item[3]], sorted(item[0]))
            if best_key is None or key > best_key:
                best, best_key = item, key
        if best is None:
            break
        chosen.append(best)
        uncovered -= best[4]
        cands.remove(best)

    return {p: (sup, fams) for p, sup, fams, _g, _h in chosen}


_GRADE_ORDER = ["weak", "ask", "strong", "hard"]


def grade(markers, catalog, support, benign_hits=0, benign_total=0):
    """组合的定性强度 —— 决定「能不能不问就拦」的唯一依据,宁保守勿激进。

    第一段(恶意侧):动作数(链条多长) × 最高严重度 × 支持度(多少真实样本作证),三者都要够。

    hard  : >=3 动作 + 含 high/critical + >=SUPPORT_FOR_HARD 样本   -> 可直接阻断
    strong: >=3 动作 + >=SUPPORT_FOR_STRONG 样本                    -> 阻断或强提示
    ask   : >=2 动作 + 含 high/critical + >=SUPPORT_FOR_ASK 样本     -> 弹窗询问
    weak  : 其余 -> 丢弃。两个 medium 动作绝不下判断:实测正常安装程序确实会
            「写 Run 键 + 落 exe」,凭这个就拦必然误伤。

    第二段(正常侧):按正常软件里的出现率【封顶】。只降不升 —— 恶意侧证据再多,
    也不能抵消「正常软件也这么干」这个事实,那是误报的直接预测量。
    benign_total=0(没有正常语料)时第二段完全不生效,行为与加此段之前一致。
    """
    lv = max((_level_rank(catalog.get(m, ("", "", ""))[1]) for m in markers), default=0)
    n = len(markers)
    if n >= 3 and lv >= 2 and support >= SUPPORT_FOR_HARD:
        g = "hard"
    elif n >= 3 and support >= SUPPORT_FOR_STRONG:
        g = "strong"
    elif n >= 2 and lv >= 2 and support >= SUPPORT_FOR_ASK:
        g = "ask"
    else:
        return "weak"
    return _cap_by_benign(g, benign_hits, benign_total)


def _cap_by_benign(g, hits, total):
    """按正常软件出现率给定级封顶。total<=0 表示无语料 -> 不封顶。"""
    if total <= 0 or hits <= 0:
        return g
    rate = hits / total
    if rate > BENIGN_DROP_RATIO:
        return "weak"                                   # 正常软件里太常见,整条丢弃
    cap = "ask" if rate > BENIGN_ASK_RATIO else "strong"  # 命中过就不许「不问就拦」
    return g if _GRADE_ORDER.index(g) <= _GRADE_ORDER.index(cap) else cap


# ---- 落库 -------------------------------------------------------------------- #

DDL = [
    """CREATE TABLE IF NOT EXISTS engine_markers(
        id TEXT PRIMARY KEY, title TEXT, level TEXT, source TEXT,
        samples INTEGER DEFAULT 0, implies TEXT DEFAULT '',
        observable INTEGER DEFAULT 0, bulwark_event TEXT DEFAULT '')""",
    """CREATE TABLE IF NOT EXISTS engine_patterns(
        markers TEXT PRIMARY KEY, n INTEGER, support INTEGER, grade TEXT,
        max_level TEXT, families TEXT, first_seen TEXT, last_seen TEXT)""",
    # version:内部整数,单调递增,是客户端「要不要重新下载」的唯一判据,不可改成小数。
    # label  :给人看的版本号(0.1 起,每次内容变化 +0.1),只用于展示。见 next_label()。
    """CREATE TABLE IF NOT EXISTS engine_versions(
        version INTEGER PRIMARY KEY AUTOINCREMENT, built_at TEXT,
        samples INTEGER, markers INTEGER, patterns INTEGER, stats TEXT,
        digest TEXT DEFAULT '', label TEXT DEFAULT '')""",
    "CREATE INDEX IF NOT EXISTS idx_engine_pat_grade ON engine_patterns(grade, support)",
]


def persist(con, catalog, df, implies, patterns, stats, benign=None, bsup=None):
    for sql in DDL:
        con.execute(sql)
    # 幂等迁移:老库缺这些列。
    for col, decl in (("match_json", "TEXT DEFAULT ''"),
                      ("benign_samples", "INTEGER DEFAULT 0")):
        try:
            con.execute("ALTER TABLE engine_markers ADD COLUMN %s %s" % (col, decl))
        except sqlite3.OperationalError:
            pass                              # 列已存在
    for col, decl in (("benign_support", "INTEGER DEFAULT 0"),):
        try:
            con.execute("ALTER TABLE engine_patterns ADD COLUMN %s %s" % (col, decl))
        except sqlite3.OperationalError:
            pass
    for col, decl in (("digest", "TEXT DEFAULT ''"),
                      ("label", "TEXT DEFAULT ''")):
        try:
            con.execute("ALTER TABLE engine_versions ADD COLUMN %s %s" % (col, decl))
        except sqlite3.OperationalError:
            pass
    now = now_iso()
    bsup = bsup or {}
    btotal = benign.grading_n if benign else 0      # 语料不足 -> 0 -> 区分度不参与定级
    bdf = benign.df if benign else {}

    # ---- 先把「本轮应有的完整状态」在内存里算出来,再一次性对齐数据库 ----
    marker_rows = {}
    mapped = 0
    for mid, (title, level, source) in catalog.items():
        obs, ev, cond = resolve_mapping(mid, title)
        mapped += obs
        # benign_samples 追加在【末尾】—— 下面的指纹按位置取字段,插在中间会静默错位。
        marker_rows[mid] = (title, level, source, df.get(mid, 0),
                            ",".join(sorted(implies.get(mid, ()))), obs, ev, cond,
                            int(bdf.get(mid, 0)))

    pattern_rows = {}
    pattern_benign = {}
    capped = 0
    dropped_by_benign = 0
    for markers, (support, fams) in patterns.items():
        bh = bsup.get(markers, 0)
        g = grade(markers, catalog, support, bh, btotal)
        if g == "weak":
            # 分不清是恶意侧本来就不够,还是被正常侧判死的 —— 只在后者时计数。
            if grade(markers, catalog, support) != "weak":
                dropped_by_benign += 1
            continue
        if btotal > 0 and g != grade(markers, catalog, support):
            capped += 1
        key = "|".join(sorted(markers))
        lv = max((_level_rank(catalog.get(m, ("", "", ""))[1]) for m in markers), default=0)
        lvname = {3: "critical", 2: "high", 1: "medium"}.get(lv, "medium")
        pattern_rows[key] = (len(markers), support, g, lvname, ", ".join(fams))
        # 【不进 pattern_rows】:正常侧支持度随语料增长天天变,进了指纹就等于每天升版本、
        # 客户端每天白下载一遍。它对客户端匹配没有影响(影响的是 grade,那个已在指纹里)。
        pattern_benign[key] = bh

    stats = dict(stats)
    stats["markers_mapped"] = mapped
    stats["patterns_kept"] = len(pattern_rows)
    stats["benign_capped"] = capped
    stats["benign_dropped"] = dropped_by_benign

    # ---- 内容指纹:只覆盖【客户端真正消费的东西】 ----
    #
    # 为什么需要:原实现每次构建都插一条新版本记录,于是即便某天挖出的组合与前一天【完全一样】,
    # 版本号也照涨,客户端便会白下载一遍全量表 —— ?since= 的省流量机制跨天直接失效。
    # (实测调试期连跑 4 次,样本数与组合数一模一样,版本却从 v1 涨到 v4。)
    #
    # 刻意【不含】marker 的 samples 计数:它随采集持续变动,但客户端并不消费它(C++ 侧只读
    # title/level/event/match/observable),把它算进指纹会让版本天天变,等于没修。
    # 代价仅是网页上某个标记的"出现样本数"可能滞后到下次真实变更 —— 纯展示,不影响判定。
    h = hashlib.sha256()
    for key in sorted(pattern_rows):
        h.update(("P|" + key + "|" + "|".join(str(x) for x in pattern_rows[key]) + "\n").encode())
    used = {m for key in pattern_rows for m in key.split("|")}
    for mid in sorted(used):
        r = marker_rows.get(mid)
        if r:
            # title/level/observable/event/match_json —— 变了客户端行为或证据文案就会变
            h.update(("M|" + mid + "|" + str(r[0]) + "|" + str(r[1]) + "|"
                      + str(r[5]) + "|" + str(r[6]) + "|" + str(r[7]) + "\n").encode())
    digest = h.hexdigest()

    prev = con.execute("""SELECT version, digest, label FROM engine_versions
                          ORDER BY version DESC LIMIT 1""").fetchone()
    prev_version = prev[0] if prev else 0
    prev_label = (prev[2] if prev else "") or ""
    unchanged = bool(prev and prev[1] == digest)

    # 首次启用展示版本号时,当前已发布的那一版还没有 label。就地补成 0.1,【不动内部版本号】——
    # 否则得等到下一次内容变化才有展示号,界面在那之前只能回退显示整数版本号。
    # 写成自愈式(每次都检查)而不是一次性迁移脚本:换机、恢复旧库、手工建库都能自动补上。
    if prev and not prev_label:
        prev_label = next_label("")
        con.execute("UPDATE engine_versions SET label=? WHERE version=?",
                    (prev_label, prev_version))

    # ---- 清理不再存在的行 ----
    # 原实现只 INSERT/UPDATE、从不删除:某条组合一旦不再被挖出来,它会永久留在表里继续下发,
    # 于是下发的表只增不减,还夹带早已失效的规则。这里按本轮结果对齐。
    cur_pat = {r[0] for r in con.execute("SELECT markers FROM engine_patterns")}
    stale_pat = cur_pat - set(pattern_rows)
    for key in stale_pat:
        con.execute("DELETE FROM engine_patterns WHERE markers=?", (key,))
    cur_mk = {r[0] for r in con.execute("SELECT id FROM engine_markers")}
    stale_mk = cur_mk - set(marker_rows)
    for mid in stale_mk:
        con.execute("DELETE FROM engine_markers WHERE id=?", (mid,))
    stats["stale_patterns_removed"] = len(stale_pat)
    stats["stale_markers_removed"] = len(stale_mk)

    # ---- 落库 ----
    for mid, r in marker_rows.items():
        con.execute(
            """INSERT INTO engine_markers(id, title, level, source, samples, implies,
                                          observable, bulwark_event, match_json, benign_samples)
               VALUES(?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET title=excluded.title, level=excluded.level,
                   source=excluded.source, samples=excluded.samples, implies=excluded.implies,
                   observable=excluded.observable, bulwark_event=excluded.bulwark_event,
                   match_json=excluded.match_json, benign_samples=excluded.benign_samples""",
            (mid,) + r)
    for key, r in pattern_rows.items():
        con.execute(
            """INSERT INTO engine_patterns(markers, n, support, grade, max_level,
                                           families, first_seen, last_seen, benign_support)
               VALUES(?,?,?,?,?,?,?,?,?)
               ON CONFLICT(markers) DO UPDATE SET support=excluded.support,
                   grade=excluded.grade, max_level=excluded.max_level,
                   families=excluded.families, last_seen=excluded.last_seen,
                   benign_support=excluded.benign_support""",
            (key,) + r + (now, now, pattern_benign.get(key, 0)))

    if unchanged:
        # 内容没变 -> 不升版本号,客户端下次带 since= 来问时服务器直接回 unchanged,不下发规则体。
        # 仍然刷新 last_seen(上面的 upsert 已做),便于看出「这条组合今天仍被挖到」。
        # label 同理不动 —— 展示版本号只跟【内容】走,不跟构建次数走,否则每天空跑一次都涨 0.1。
        con.commit()
        return len(pattern_rows), prev_version, True

    label = next_label(prev_label)
    con.execute(
        """INSERT INTO engine_versions(built_at, samples, markers, patterns, stats, digest, label)
           VALUES(?,?,?,?,?,?,?)""",
        (now, stats.get("usable_samples", 0), len(catalog), len(pattern_rows),
         json.dumps(stats, ensure_ascii=False), digest, label))
    new_version = con.execute("SELECT MAX(version) FROM engine_versions").fetchone()[0]
    con.commit()
    return len(pattern_rows), new_version, False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="只打印结果,不写库")
    ap.add_argument("--min-support", type=int, default=MIN_SUPPORT)
    ap.add_argument("--top", type=int, default=15, help="打印前 N 条组合")
    args = ap.parse_args()

    db = load_db_path()
    con = sqlite3.connect(db, timeout=30)

    samples, catalog, stats = collect(con)
    if not samples:
        print("没有可用样本(归档里没有带沙箱行为的 Windows 报告)。")
        return 1

    # 正常语料。没有也能跑 —— 全部区分度逻辑在 n=0 时自动退化为「不生效」,
    # 结果与加入本机制之前完全一致,不会因为语料还没攒起来就把规则库砍空。
    benign_sets, bstats = collect_benign(con, catalog)
    stats.update(bstats)
    benign = BenignCorpus(benign_sets)

    generic = drop_generic(samples, catalog, GENERIC_DF_RATIO)
    ben_generic = drop_benign_generic(samples, benign, BENIGN_GENERIC_RATIO)
    implies = find_implications(samples)
    for marks, _ in samples:
        marks &= set(catalog.keys())
        red = reduce_markers(marks, implies)
        marks.clear()
        marks |= red

    # 正常样本必须过【同一套】归约:组合是从归约后的恶意集合里挖出来的,
    # 拿未归约的正常集合去做子集比对,分母侧的集合更大,出现率会系统性偏高。
    benign = BenignCorpus([reduce_markers(s - ben_generic, implies) for s in benign_sets])

    mined_raw = mine(samples, args.min_support, MAX_ITEMSET)
    deduped = drop_redundant(mined_raw)
    # 支持度【始终】统计(便于网页展示"这条在正常软件里见过几次"),但定级只在
    # 语料够大时才受它影响 —— 由 grading_n 统一把关。
    bsup_dedup = benign.supports(list(deduped.keys()))
    obs_ids = observable_ids(catalog)
    patterns = select_cover(samples, deduped, catalog,
                            bsup=bsup_dedup, btotal=benign.grading_n, obs=obs_ids)
    bsup = {p: bsup_dedup.get(p, 0) for p in patterns}

    df = collections.Counter()
    for marks, _ in samples:
        for m in marks:
            df[m] += 1

    stats["markers_observable"] = len(obs_ids)
    stats["generic_dropped"] = len(generic)
    stats["benign_generic_dropped"] = len(ben_generic)
    stats["benign_grading_active"] = 1 if benign.usable else 0
    stats["implications"] = sum(len(v) for v in implies.values())
    stats["markers_effective"] = len(df)
    stats["patterns_mined"] = len(mined_raw)
    stats["patterns_after_dedup"] = len(deduped)
    stats["patterns_after_cover"] = len(patterns)

    def g_of(p, sup):
        return grade(p, catalog, sup, bsup.get(p, 0), benign.grading_n)

    graded = collections.Counter()
    for markers, (support, _f) in patterns.items():
        graded[g_of(markers, support)] += 1

    print("=" * 66)
    print("Bulwark 攻击链组合引擎 · 构建结果")
    print("=" * 66)
    for k, v in stats.items():
        print("  %-26s %s" % (k, v))
    print("  分级:", dict(graded))
    if not benign.usable:
        print("  ⚠ 正常样本语料 %d 个,不足 %d —— 区分度【未参与】定级。"
              "组合只由恶意侧证据定档,无法判断是否误伤正常软件。"
              % (benign.n, BENIGN_MIN_CORPUS))

    effective = [p for p, (sup, _f) in patterns.items() if g_of(p, sup) != "weak"]
    covered = sum(1 for marks, _ in samples if any(p <= marks for p in effective))
    print("  有效组合覆盖样本         %d/%d (%.0f%%)"
          % (covered, len(samples), 100.0 * covered / len(samples)))

    print("\n---- 支持度最高的组合(排除 weak) ----")
    shown = 0
    for markers, (support, fams) in sorted(patterns.items(),
                                          key=lambda x: (-x[1][0], len(x[0]))):
        g = g_of(markers, support)
        if g == "weak":
            continue
        shown += 1
        if shown > args.top:
            break
        bh = bsup.get(markers, 0)
        bnote = ""
        if bh:
            bnote = "  ⚠ 正常软件也见过 %d/%d (%.1f%%)" % (bh, benign.n, 100.0 * bh / benign.n)
        print("\n[%s] %d 个样本同时具备 (%d 个动作)%s%s"
              % (g.upper(), support, len(markers),
                 ("  家族: " + ", ".join(fams)) if fams else "", bnote))
        for m in sorted(markers):
            title, level, source = catalog.get(m, (m, "?", "?"))
            print("      · [%-8s] %s" % (level, title))

    if args.dry_run:
        print("\n(dry-run:未写库)")
        return 0

    kept, ver, unchanged = persist(con, catalog, df, implies, patterns, stats,
                                   benign=benign, bsup=bsup)
    if unchanged:
        print("\n已写库:内容与上一版完全相同,版本保持 v%s(不升版本 -> 客户端无需重复下载)。"
              "收录组合 %d 条,标记 %d 个。" % (ver, kept, len(catalog)))
    else:
        print("\n已写库:版本 v%s,收录组合 %d 条,标记 %d 个。" % (ver, kept, len(catalog)))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print("FATAL %s: %s" % (type(e).__name__, e))
        sys.exit(1)
