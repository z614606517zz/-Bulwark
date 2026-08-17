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

# ---- 区分力闸门(condition specificity) --------------------------------------- #
#
# 这一段修的是本引擎最严重的一处结构性缺陷,实测数据:v19 下发 32 条组合,其中 9 条
# (28%)含一个【零区分力】标记,而 26 条装载组合里有 12 条依赖同一个这样的标记。
#
#   System File Execution Location Anomaly          -> {"unsigned": true}
#   Files With System Process Name In Unsuspected... -> {"unsigned": true}
#   Suspicious Network Connection to IP Lookup APIs  -> {}          (匹配每一条外联)
#   Uncommon Svchost Command Line Parameter          -> {"actor":"*\\svchost.exe"}
#
# 前两条按本产品自己的底线就是【软信号】——「软信号单独出现绝不该触发拦截或弹窗,
# 必须由硬指标互证」。第三条连信号都不是。第四条匹配 Windows 上每一次 svchost 启动。
# 于是「N 个动作互相作证」在这些组合上退化成「一个动作 + 一个恒真项」,而客户端的
# applyHitToEvent 在强制模式下会把命中登记为【硬指标】—— 等于把软信号提拔成处置依据。
#
# 客户端已有一道「证据重复」护栏(指纹去重),但它只能发现【两个标记条件完全相同】,
# 发现不了「其中一个条件恒真」。故必须在服务端按区分力把这类标记挡在证据之外。
#
# 评分只需要区分「这是一个真实产物」还是「这在任何机器上都成立」,故刻意做得粗:
MARKER_SPEC_NONE = 0      # 无条件 / 只有 unsigned -> 不构成证据
MARKER_SPEC_WEAK = 1      # 只有一个常驻系统程序作主体 -> 信息量极低
MARKER_SPEC_OK = 2        # 有指向性,可以算一份证据
# 一条组合至少要有这么多份【真证据】才允许下发。低于此数即丢弃 ——
# 这是本引擎「必须互证」前提的机械保证,而不是靠人去看表。
MIN_EVIDENCE_MARKERS = 2

# ---- 「不含」条件的下发开关 --------------------------------------------------- #
#
# 【这是一个版本耦合闸门,不是调优项。改它之前先读完这段。】
#
# cmdline_absent / target_absent / parent_absent 由客户端的
# ChainMarker::matchesEvent 消费。老客户端【不认识这几个键,会静默忽略】,于是:
#   · 客户端看到的仍是 actor=*\svchost.exe —— 在 Windows 上恒真;
#   · 而服务端因为条件里有 _absent,给它算了「实质条件」-> 当成一份真证据。
# 两边一叠加,结果比不加这个功能更糟:一个恒真项被正式承认为互证的一半,
# 而组合命中在强制模式下是按【硬指标】登记的。
#
# 所以顺序是硬的:【先让认识这些键的客户端铺开,再打开这个开关】。
# 打开时要一并确认:endpoint 的 bulwark_service.exe 已包含 ChainMarker::matchesEvent
# (grep 二进制里的 cmdline_absent 即可验证),而不是只确认代码进了仓库。
ABSENT_CONDITIONS_ENABLED = False


def _strip_absent(cond):
    """按开关剥掉「不含」条件。关闭时连带把它对区分力的贡献一起去掉 ——
    只剥键不剥评分,才是最危险的那种半开状态。"""
    if ABSENT_CONDITIONS_ENABLED or not isinstance(cond, dict):
        return cond
    return {k: v for k, v in cond.items()
            if k not in ("cmdline_absent", "target_absent", "parent_absent")}

# 在健康的 Windows 上不停启动的程序。「主体是它」这件事本身几乎不携带信息,
# 所以只有它一项时算 WEAK,必须再有 target/cmdline 之类的实质条件才算证据。
COMMON_HOST_BINARIES = (
    "svchost.exe", "services.exe", "lsass.exe", "explorer.exe", "cmd.exe",
    "conhost.exe", "rundll32.exe", "regsvr32.exe", "msiexec.exe", "dllhost.exe",
    "taskhostw.exe", "wmiprvse.exe", "schtasks.exe", "reg.exe", "sc.exe",
    "powershell.exe", "powershell", "wscript.exe", "cscript.exe", "csc.exe",
    "curl.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe",
)


def condition_specificity(cond):
    """一条匹配条件能提供多少区分力。返回 (分档, 可读理由)。

    判据顺序即重要性顺序:先看有没有实质条件(target/cmdline/parent 的字面片段),
    再看主体是不是常驻程序,最后才考虑 unsigned —— unsigned 永远只是加成,
    单独出现不构成证据。
    """
    if not isinstance(cond, dict):
        return MARKER_SPEC_NONE, "条件缺失"
    slots = {k: str(cond.get(k) or "").strip()
             for k in ("actor", "target", "cmdline", "parent",
                       "cmdline_absent", "target_absent", "parent_absent")}
    uns = bool(cond.get("unsigned"))
    if not any(slots.values()):
        return (MARKER_SPEC_NONE,
                "只有 unsigned -> 软信号,不能算互证的一份" if uns
                else "无任何条件 -> 匹配该类型的每一条事件")

    def literals(pat):
        # 通配式里剩下的连续常量串。少于 4 个字符的碎片(如 "\\"、".exe")不算指向性。
        return [s for s in pat.replace("?", "*").split("*") if len(s) >= 4]

    why = []
    substantive = 0
    for k in ("target", "cmdline", "parent"):
        if slots[k] and literals(slots[k]):
            substantive += 1
            why.append("%s 有字面片段" % k)
    # 「不含」条件同样算实质条件 —— 它恰恰是把恒真项变成真判据的那一半。
    # 门槛比肯定条件低(2 个字符即可):"-k " 这种开关本身就短,而它的区分力很高
    # (带 -k 的 svchost 是绝大多数,排除掉之后剩下的才是异常)。
    for k in ("cmdline_absent", "target_absent", "parent_absent"):
        if slots[k] and any(len(s) >= 2 for s in slots[k].replace("?", "*").split("*")):
            substantive += 1
            why.append("%s=%s(排除常态)" % (k, slots[k]))
    if slots["actor"]:
        low = slots["actor"].lower()
        common = any(b in low for b in COMMON_HOST_BINARIES)
        why.append("actor=%s%s" % (slots["actor"], "(常驻程序,信息量低)" if common else ""))
        if not common and literals(slots["actor"]):
            substantive += 1
    if uns:
        why.append("+unsigned(仅加成)")
    if substantive >= 1:
        return MARKER_SPEC_OK, "; ".join(why)
    # 走到这里 = 只有一个常驻程序主体,或者只有纯通配的槽位。
    return MARKER_SPEC_WEAK, "; ".join(why) + " -> 无实质条件,不能算互证的一份"


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
    #
    # 这两条的信号都是【缺少某个东西】,而不是含有什么:
    #   · 真正的 svchost 永远带 `-k <组名>` 启动,该规则命中的是【没有 -k】的那种;
    #   · 真正的 svchost 永远由 services.exe 拉起,该规则命中的是【父进程不是它】的那种。
    # 此前只能下发肯定的那一半(actor=*\svchost.exe),而那一半在 Windows 上恒真 ——
    # 实测 v19 的 26 条装载组合里 12 条依赖它,等于让一个恒真项冒充互证的一半。
    # 客户端现已支持 *_absent(见 ChainMarker::matchesEvent),故补上否定的那一半。
    # context 佐证:该标记 226 个样本的 CommandLine 全是裸的 svchost 路径,无任何参数。
    "uncommon_svchost_command_line_parameter": {
        "event": "ProcessCreate", "actor": "*\\svchost.exe",
        "cmdline_absent": "*-k *"},
    "uncommon_svchost_parent_process": {
        "event": "ProcessCreate", "actor": "*\\svchost.exe",
        "parent_absent": "*\\services.exe"},
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


# ---- 「这是不是 Windows 端点用得上的样本」 ------------------------------------- #
#
# 原判据是单一的 `type_tag in WIN_TYPES`,而 VT 并不总给 type_tag。实测:
#   · benign_reports 63 份里 39 份(62%)type_tag 为空 -> 全被判成非本平台
#     -> 可用语料只剩 13 份,低于 BENIGN_MIN_CORPUS(50),区分度环节整体空转;
#   · vt_reports 4621 行里 2877 行被判「非本平台」,其中有多少是同一个原因,
#     在改成多字段判据之前无从知道。
# 一个可选字段缺失就让整份样本被丢弃,这是判据本身太脆,不是数据的问题。
#
# 判据做成【有明确证据就用它,没有才逐级退让】,每一级都写清为什么可信:
WIN_EXTS = {
    "exe", "dll", "sys", "msi", "msp", "scr", "cpl", "ocx", "com", "drv",
    "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta",
    "lnk", "chm", "doc", "docx", "xls", "xlsx", "xlsm", "ppt", "pptx", "rtf",
    "docm", "pub", "vsd", "one",
}
# type_description / magic 里出现即可判定为 Windows 的字样。
WIN_TEXT_HINTS = (
    "win32", "win64", "pe32", "pe32+", "ms windows", "windows executable",
    "windows setup", "microsoft installer", "msi installer", "dos executable",
    "html application", "windows shortcut", "compiled html", "rich text format",
    "microsoft word", "microsoft excel", "microsoft powerpoint", "office open xml",
    "composite document file",
)
# 明确不是 Windows 的字样。放在肯定判据【之前】判 —— "shell script" 里也含 "script",
# 单靠肯定词表会把 ELF 与脚本捞进来,而归档里 ELF 占了很大一块。
NON_WIN_TEXT_HINTS = (
    "elf ", "elf,", "elf 32", "elf 64", "mach-o", "shell script", "bourne-again",
    "python script", "perl script", "ruby script", "php script",
    "java archive", "java class", "android", "dalvik", "apk", "debian binary",
    "rpm ", "iso 9660", "macintosh",
)


def _ext_of(name):
    n = (name or "").strip().lower().rstrip(".")
    if "." not in n:
        return ""
    return n.rsplit(".", 1)[-1][:8]


def is_windows_sample(attr):
    """这份报告是不是 Windows 端点用得上的样本。

    逐级退让,前一级有结论就不再往下:
      1. type_tag —— VT 自己的归类,最可信;
      2. type_extension —— 同样来自 VT 的解析结果;
      3. type_description / magic 的字样 —— 先排除明确的非 Windows,再看肯定词;
      4. meaningful_name 的扩展名 —— 最弱的一级,但对【已经存下来的老语料】是唯一
         还剩的线索(slim_benign_report 当初只留了 type_tag 和 meaningful_name)。
    四级都没结论 -> 判否。宁可少一份语料,不可把 ELF 当成 Windows 正常软件的分母。
    """
    if not isinstance(attr, dict):
        return False
    tag = (attr.get("type_tag") or "").strip().lower()
    if tag:
        return tag in WIN_TYPES
    ext = (attr.get("type_extension") or "").strip().lower().lstrip(".")
    if ext:
        return ext in WIN_EXTS
    blob = " ".join(str(attr.get(k) or "") for k in
                    ("type_description", "magic")).strip().lower()
    if blob:
        if any(h in blob for h in NON_WIN_TEXT_HINTS):
            return False
        if any(h in blob for h in WIN_TEXT_HINTS):
            return True
    return _ext_of(attr.get("meaningful_name")) in WIN_EXTS


# ============================================================================= #
#  从 sigma 的 match_context 推导事件类型与匹配条件                              #
# ============================================================================= #
#
# 【这一段是本次升级的核心】。此前挖掘器只读 sigma_analysis_results 的 rule_title 与
# rule_level,把每条命中自带的 match_context 整个扔掉了 —— 而那里面正是「让这条规则
# 命中的那些字段原值」,Sysmon 口径。实测 308 个标记 100% 都带 context。
#
# 扔掉它的代价是双重的:
#   1. 事件类型只能靠标题关键词猜(KEYWORD_EVENT_HINTS),猜不中就整条标记不可观测;
#      而 context 里的 EventID 是【权威的】。
#   2. 匹配条件只能人工登记(MARKER_RULES 手写 43 条),于是 287 个挖出来的标记里
#      只有 37 个能下发给客户端 —— 引擎的词表被一张手写表卡住,不随数据增长。
#
# 而且手写表本身被数据证明有两处错:
#   · unsigned_image_loaded_into_lsass_process 被标为「表达不出」,理由是「ImageLoad 的
#     target 是被加载模块路径,不会叫 lsass.exe」。context 显示 Image=lsass.exe 是
#     【加载方】(即 actor)、ImageLoaded 才是模块(即 target)—— 字段填错了位置而已,
#     actor=*\lsass.exe 完全可表达。该标记有 395 个样本,是第二高频。
#   · files_with_system_process_name_in_unsuspected_locations 被写成
#     ProcessCreate + unsigned,而 context 是 EventID 11 + TargetFilename=
#     「...\Startup\SecurityHealthService.exe」「...\Temp\svchost.exe」—— 它是个
#     FileWrite 标记,事件类型与条件都错了。
#
# 推导出的条件【一律不覆盖 MARKER_RULES】:那张表里有人工判断(包括刻意标注
# unobservable 的语义理由),数据推导只补它没覆盖到的部分,以及在人工条目区分力不足时
# 追加实质条件。顺序见 resolve_mapping。

# Sysmon EventID -> 磐垒事件类型。取值对应 bulwark::EventType 的成员名。
# 空串 = 磐垒没有对应的事件维度,该标记按不可观测处理(如 PowerShell ScriptBlock 4104)。
SYSMON_EVENT_BY_ID = {
    "1": "ProcessCreate",
    "3": "NetworkConnect",
    "7": "ImageLoad",
    "8": "RemoteThread",
    "11": "FileWrite",
    "23": "FileDelete",
    "26": "FileDelete",
    "29": "FileWrite",          # Sysmon 29 = 可执行文件被创建
    "12": "RegistryWrite",
    "13": "RegistryWrite",
    "14": "RegistryWrite",
    "22": "DnsQuery",
    "4104": "",                 # PowerShell 脚本块日志:磐垒无此维度
    "4103": "",
    "10": "",                   # ProcessAccess:磐垒无此维度
}

# 事件类型 -> (context 字段, 条件槽位)。顺序即优先级:先试更有指向性的槽位。
#
# 关键是 Image 的语义随事件类型而变:进程创建里它是被创建的进程(actor),
# 注册表/文件/模块加载里它是【发起动作的进程】(也是 actor)。两种都落在 actor,
# 所以这张表统一把 Image 映到 actor —— 与客户端 DefenseRule 的 actorPattern 同义。
CTX_FIELD_BY_EVENT = {
    "ProcessCreate":   [("CommandLine", "cmdline"), ("Image", "actor"),
                        ("ParentImage", "parent")],
    "RegistryWrite":   [("TargetObject", "target"), ("Image", "actor")],
    "FileWrite":       [("TargetFilename", "target"), ("Image", "actor")],
    "FileDelete":      [("TargetFilename", "target"), ("Image", "actor")],
    "ImageLoad":       [("ImageLoaded", "target"), ("Image", "actor")],
    "NetworkConnect":  [("DestinationHostname", "target"), ("Image", "actor")],
    "DnsQuery":        [("QueryName", "target"), ("Image", "actor")],
    "RemoteThread":    [("TargetImage", "target"), ("SourceImage", "actor")],
}

# 样本数低于此值的标记【不做推导】。
#
# 比例门槛在小样本上形同虚设:n=2 时「1 个样本同意」就是 50%,直接过关。实测首版就因此
# 把单个样本的 C2 域名(potalgonabunbunsed.blogspot.com,1/2)和另一个样本的临时文件名
# (setup_gitlog.txt,3/8)推成了规则条件。取 6:配合下面 0.5 的路径门槛,至少要 3 个
# 互不相同的样本给出同一个片段。
MIN_DERIVE_SAMPLES = 6

# 各槽位的覆盖率门槛。【刻意不统一】,因为它们的失配代价完全不同:
#
#   target(主机名/域名):0.25 —— 这类取值本身就是精确值,不是片段。一条只认
#       icanhazip.com 的标记覆盖率虽低,但精度极高;而本引擎要求互证,单个标记的
#       召回不足由组合里的另一份证据补,不会因此误报。
#   target(路径)/cmdline:0.50 —— 片段要足够普遍才算「这条规则的特征」而非某个样本的痕迹。
#   actor:0.90 —— 只在「几乎总是这个程序」时才加。
#   parent:0.95 —— 父进程在真实攻击里变化极大(实测 cmd.exe 作父只占 37/115),
#       凭它收窄条件是在悄悄丢检出。
SLOT_MIN_RATIO = {"host": 0.25, "target": 0.50, "cmdline": 0.50,
                  "actor": 0.90, "parent": 0.95}
# 同一个片段在正常语料里的出现率上限。语料还小(63 份),所以它只是第二道保险,
# 主力是下面两张停用表 —— 靠 63 个样本去判「正常软件是否普遍如此」并不可靠。
ARTIFACT_MAX_BENIGN_RATIO = 0.02

# VT 沙箱会把样本改名再投放,这几个名字【全是沙箱产物】,推成 actor 条件等于
# 让规则去匹配一个真机上不存在的文件名。实测 context 里 Image 的前几名就是它们。
SANDBOX_BASENAMES = {
    "software.exe", "file.exe", "program.exe", "executable.exe", "sample.exe",
    "malware.exe", "default.dat.exe", "sample.bin", "taskdl.exe",
}
# 含这些片段的取值一律不采纳:沙箱专有路径、环境变量占位符、以及本次运行的临时目录。
SANDBOX_VALUE_BITS = (
    "%samplepath%", "<current_dir>", "<user>", "<hklm>", "<hkcu>",
    "\\users\\bruno\\", "capeoutput", "\\cape\\", "%windir%", "%temp%",
    "%appdata%", "%programfiles", "%localappdata%", "%userprofile%", "%programdata%",
)
# 通用到没有指向性的片段。判据是【全等】而不是包含 —— 否则 "\CurrentVersion\Run"
# 会被 "\CurrentVersion" 连坐否掉,而前者恰恰是最有价值的一条。
# 与客户端 derivedRegistryWatch 的 kTooWide 同一思路、同一判据。
UNIVERSAL_FRAGMENTS = {
    "\\windows", "\\windows\\system32", "\\windows\\syswow64", "\\system32",
    "\\program files", "\\program files (x86)", "\\programdata", "\\users",
    "\\users\\public", "\\appdata", "\\appdata\\local", "\\appdata\\roaming",
    "\\appdata\\local\\temp", "\\temp", "\\desktop", "\\documents",
    "hklm", "hkcu", "hku", "hklm\\software", "hkcu\\software", "\\software",
    "\\software\\microsoft", "\\microsoft", "\\microsoft\\windows",
    "\\windows\\currentversion", "\\currentversion", "\\policies", "\\classes",
    "\\control", "\\services", "\\parameters", "\\explorer", "\\shell",
    ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js",
}
# 命令行里出现即无意义的词(解释器自己的名字、通用开关)。
CMDLINE_STOP = {
    "powershell", "powershell.exe", "cmd", "cmd.exe", "cscript", "wscript",
    "rundll32", "regsvr32", "schtasks", "reg", "windowspowershell",
    "command", "true", "false", "null", "http", "https", "system32",
    "syswow64", "windows", "users", "temp", "appdata", "roaming", "local",
    "program", "files", "microsoft", "desktop", "bruno", "user",
}


def _norm_value(s):
    """把 context 里的取值归一到「客户端在真机上会看到的形状」。

    只做无歧义的替换:注册表根键的长写法 -> 短写法(客户端拿到的是内核路径,
    两种写法都可能出现,统一成短的再取片段);去掉角括号包装;统一小写与反斜杠。
    刻意【不】展开 %ENV% —— 展开成什么取决于机器,猜错比不猜更糟,故含 % 的取值直接弃用。
    """
    v = str(s or "").strip().strip('"').replace("/", "\\")
    v = v.replace("<HKLM>", "HKLM").replace("<HKCU>", "HKCU")
    v = re.sub(r"^HKEY_LOCAL_MACHINE", "HKLM", v, flags=re.I)
    v = re.sub(r"^HKEY_CURRENT_USER", "HKCU", v, flags=re.I)
    v = re.sub(r"^HKEY_USERS", "HKU", v, flags=re.I)
    # HKU\S-1-5-21-...\ 是按机器变的 SID,归一成 HKCU 才能跨机器比对。
    v = re.sub(r"^HKU\\S-1-[0-9\-]+\\", "HKCU\\\\", v, flags=re.I)
    return v.lower()


def _usable_value(v):
    if not v or len(v) < 5:
        return False
    if "%" in v:
        return False                      # 环境变量占位符,真机上匹配不到
    for bit in SANDBOX_VALUE_BITS:
        if bit in v:
            return False
    base = v.rsplit("\\", 1)[-1]
    if base in SANDBOX_BASENAMES:
        return False
    return True


# 用户名一段:\users\<某人>\ 里的 <某人> 是【本机事实】,跨机器一定失配。
# 用正则按结构剔除,而不是往停用表里堆名字 —— 首版只列了 bruno,于是另一个沙箱账户
# george 直接漏了过去,推出 "*\users\george\appdata\local*" 这种真机上永不命中的条件。
_USER_SEG_RE = re.compile(r"\\users\\(?!public\\|default\\|all users\\)[^\\]+\\", re.I)
# 长十六进制段 = GUID / 证书指纹 / NativeImages 目录名,同样是本机事实。
# 实测漏过一条:"...\nativeimages_v4.0.30319_64\system.manaa57fc8cc#\ace3bea4...\..."。
_HEXY_SEG_RE = re.compile(r"(^|\\)[0-9a-f]{8,}(\\|$)", re.I)


def _machine_specific(frag):
    """这个片段是不是只在某一台机器/某一次运行上成立。"""
    if _USER_SEG_RE.search(frag) or _HEXY_SEG_RE.search(frag):
        return True
    # 纯数字段(进程 ID、随机后缀)也没有跨机器意义。
    for seg in frag.split("\\"):
        if seg and seg.isdigit() and len(seg) >= 4:
            return True
    return False


def _path_candidates(v):
    """从一个路径型取值里取出所有「有指向性的连续片段」。

    做法:按 \\ 切段,枚举长度 2~4 段的连续子串。随机段(GUID、指纹、随机文件名)
    自然会因为跨样本覆盖率低而在后面被淘汰,不必在这里识别它们。
    额外单独产出 basename —— 「Temp 目录下有个叫 svchost.exe 的文件」这类特征
    全部信息都在文件名上。
    """
    segs = [s for s in v.split("\\") if s]
    out = set()
    for n in (2, 3, 4):
        for i in range(len(segs) - n + 1):
            frag = "\\" + "\\".join(segs[i:i + n])
            if len(frag) >= 6:
                out.add(frag)
    if segs:
        base = segs[-1]
        if len(base) >= 6 and "." in base:
            out.add("\\" + base)
    return out


def _cmdline_candidates(v):
    """从命令行里取出「像开关/关键词」的片段。

    只要词形片段,不要路径:路径部分随机性太高(样本自己的落地路径),而真正的特征
    是 Add-MpPreference / Set-ExecutionPolicy / -EncodedCommand 这类词。
    """
    out = set()
    for tok in re.findall(r"[A-Za-z][A-Za-z0-9\-_\.]{3,}", v):
        t = tok.strip(".-_").lower()
        if len(t) < 5 or t in CMDLINE_STOP:
            continue
        if t.endswith((".exe", ".dll", ".sys")):
            continue
        out.add(t)
    return out


def _host_candidates(v):
    """域名 / 主机名取值:整串就是特征,不切片。"""
    if re.match(r"^[a-z0-9\.\-]+\.[a-z]{2,}$", v) and len(v) >= 6:
        return {v}
    return set()


# 推导只用得到这几个字段。其余(Hashes / Product / FileVersion / IntegrityLevel ...)
# 一律不留 —— 这不是洁癖:context 一份可达几十个字段、单个样本命中数百次,
# 全量留存会把 995 个样本的证据堆成几百 MB,而这台机器同时在扛信誉查询。
CTX_KEEP_FIELDS = (
    "EventID", "Image", "CommandLine", "ParentImage", "TargetObject",
    "TargetFilename", "ImageLoaded", "QueryName", "DestinationHostname",
    "TargetImage", "SourceImage",
)
# 一个样本里同一条规则最多取几次命中。取 8:候选片段是按【样本】投票的,
# 同一样本内再多几次命中也只贡献同一票,留着纯占内存。
CTX_MAX_ENTRIES_PER_SAMPLE = 8
# 一个标记最多留几个样本的证据。覆盖率是比例估计,几百个样本足够稳定;
# 最高频标记有 629 个样本,不设上限只是让内存白涨。
CTX_MAX_GROUPS_PER_MARKER = 400


def extract_context(rep):
    """一份报告 -> {marker_id: [match_context 的 values 字典, ...]}(已按需裁剪)。

    与 extract_markers 分开而不是改它的返回值:后者有三个调用方(恶意侧、正常侧、
    正常侧重建),改签名要同时动三处,而这份证据只有推导阶段用得到。
    """
    out = collections.defaultdict(list)
    b = rep.get("behaviour") or {}
    if not isinstance(b, dict):
        return out
    for x in (b.get("sigma_analysis_results") or []):
        if not isinstance(x, dict):
            continue
        title = (x.get("rule_title") or "").strip()
        level = (x.get("rule_level") or "").strip().lower()
        if not title or level not in SIGMA_LEVELS:
            continue
        mid = slug(SYNONYMS.get(title.lower(), title.lower()))
        ctx = x.get("match_context")
        if not isinstance(ctx, list):
            continue
        for entry in ctx[:CTX_MAX_ENTRIES_PER_SAMPLE]:
            if not isinstance(entry, dict):
                continue
            vals = entry.get("values")
            if not isinstance(vals, dict):
                continue
            slim = {k: vals[k] for k in CTX_KEEP_FIELDS if vals.get(k)}
            if slim:
                out[mid].append(slim)
    return out


def _slot_candidates(ev, slot, field, group):
    """一个【样本】在某个槽位上贡献的候选片段集合(已去重 -> 一个样本一票)。

    按样本取并集而不是逐条计数,是本函数存在的全部理由:一份报告里同一条 Sigma 规则
    可能命中几百次(实测 registry_keys_set 最长 674 项),按条计数的话一个疯狂写注册表的
    样本就能独自决定这条规则的条件,而那恰恰是最不该被当作「跨样本一致特征」的情形。
    """
    out = set()
    for vals in group:
        raw = vals.get(field)
        if raw is None:
            continue
        v = _norm_value(raw)
        if not _usable_value(v):
            continue
        if slot == "cmdline":
            out |= _cmdline_candidates(v)
        elif slot == "target" and ev in ("NetworkConnect", "DnsQuery"):
            out |= _host_candidates(v)
        elif slot in ("actor", "parent"):
            # 主体只取文件名:完整路径是样本自己的落地位置,跨机器没有意义。
            base = v.rsplit("\\", 1)[-1]
            if len(base) >= 5 and base not in SANDBOX_BASENAMES:
                out.add("\\" + base)
        else:
            out |= _path_candidates(v)
    return out


def derive_conditions(evidence, benign_evidence):
    """从 match_context 推导 {marker_id: (event, cond_dict, 可读说明)}。

    evidence / benign_evidence 的形状是 {marker_id: [每个样本的 values 列表, ...]} ——
    【按样本分组】,不是拉平的。分组是承重的,理由见 _slot_candidates。

    推导只在【有足够跨样本一致性】时才产出:一个片段要覆盖 ARTIFACT_MIN_RATIO 以上的
    样本才算这条规则的特征。这是「宁可不给条件,也不给一个错条件」—— 不给条件只是少一个
    标记,给错条件要么变死规则、要么变误报源,两种在这个引擎上都实际发生过。
    """
    out = {}
    for mid, groups in evidence.items():
        n_samples = len(groups)
        if n_samples < 2:
            continue                       # 单样本推不出「跨样本一致的特征」

        # ---- 1) 事件类型:EventID 说了算(权威),取该标记里出现最多的那个 ----
        eids = collections.Counter()
        for group in groups:
            for vals in group:
                e = str(vals.get("EventID") or "").strip()
                if e:
                    eids[e] += 1
        if not eids:
            continue
        ev = ""
        for eid, _n in eids.most_common():
            ev = SYSMON_EVENT_BY_ID.get(eid, "")
            if ev:
                break
        if not ev:
            continue                       # 磐垒没有对应的事件维度(如 PowerShell 4104)
        slots = CTX_FIELD_BY_EVENT.get(ev)
        if not slots:
            continue

        if n_samples < MIN_DERIVE_SAMPLES:
            continue                       # 小样本上比例门槛形同虚设,见该常量处的说明

        ben_groups = benign_evidence.get(mid) or []
        nben = max(1, len(ben_groups))

        def pick(field, slot):
            """该槽位上最有代表性的片段,或 None。"""
            kind = "host" if (slot == "target" and ev in ("NetworkConnect", "DnsQuery")) else slot
            floor = n_samples * SLOT_MIN_RATIO.get(kind, 0.5)
            votes = collections.Counter()
            for group in groups:
                for cnd in _slot_candidates(ev, slot, field, group):
                    votes[cnd] += 1
            for cnd, hits in sorted(votes.items(), key=lambda kv: (-kv[1], -len(kv[0]), kv[0])):
                if hits < floor:
                    break                  # 已按票数降序,后面只会更低
                low = cnd.strip("\\").lower()
                if low in UNIVERSAL_FRAGMENTS or cnd.lower() in UNIVERSAL_FRAGMENTS:
                    continue
                if _machine_specific(cnd):
                    continue
                # 正常语料里也常见的片段一律弃用(第二道保险,主力是停用表)。
                bhit = sum(1 for bg in ben_groups
                           if cnd in _slot_candidates(ev, slot, field, bg))
                if bhit / nben > ARTIFACT_MAX_BENIGN_RATIO:
                    return None, "正常语料里也有 %d/%d" % (bhit, nben)
                return (cnd, hits), ""
            return None, ""

        # ---- 2) 最小充分条件,而不是「把相关的都 AND 上」----
        #
        # 这一段的取舍是本函数最容易做错的地方,首版就做错了:它把每个能填的槽位都填上,
        # 于是 powershell_defender_exclusion 被推成
        #   actor=*\powershell.exe AND cmdline=*add-mppreference* AND parent=*\cmd.exe
        # 而 cmd.exe 只是其中 37/115 个样本的父进程 —— 多出来的那个 AND 让这个标记
        # 【比事实更窄】,直接放掉另外 68%。标记是「一个动作」,不是「一条规则」:
        # 每多一个 AND 只可能降低召回,而精度已由「组合必须互证」那一层保证。
        #
        # 故:先取最有指向性的一个槽位(target / cmdline);只有当它单独还不够格
        # (区分力 < OK)时,才补 actor / parent —— 而且那两个槽位的覆盖率门槛极高。
        cond = {}
        notes = []
        primary = [(f, s) for f, s in slots if s in ("target", "cmdline")]
        secondary = [(f, s) for f, s in slots if s in ("actor", "parent")]
        for field, slot in primary:
            got, why = pick(field, slot)
            if got:
                cnd, hits = got
                cond[slot] = "*" + cnd + "*"
                notes.append("%s=%s(%d/%d)" % (slot, cond[slot], hits, n_samples))
                break                      # 一个实质条件就够
            elif why:
                notes.append("%s 候选被弃(%s)" % (slot, why))
        if condition_specificity(cond)[0] < MARKER_SPEC_OK:
            for field, slot in secondary:
                got, why = pick(field, slot)
                if not got:
                    continue
                cnd, hits = got
                cond[slot] = "*" + cnd     # actor/parent 用后缀式
                notes.append("%s=%s(%d/%d)" % (slot, cond[slot], hits, n_samples))
                if condition_specificity(cond)[0] >= MARKER_SPEC_OK:
                    break
        if not cond:
            continue
        out[mid] = (ev, cond, "; ".join(notes))
    return out


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
    # marker_id -> [每个样本贡献的 match_context values 列表]。按样本分组,见 derive_conditions。
    evidence = collections.defaultdict(list)
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
        # 多字段判据,不再只看 type_tag(见 is_windows_sample 的说明)。
        if not is_windows_sample(f):
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
        # 条件推导的原料。在【同一次扫描里】顺便收走 —— 报告是几百 KB 的 JSON,
        # 4600 份再解一遍纯属白花时间。
        for mid, vals in extract_context(rep).items():
            if vals and len(evidence[mid]) < CTX_MAX_GROUPS_PER_MARKER:
                evidence[mid].append(vals)
        samples.append((set(marks.keys()), sample_family(rep)))

    return samples, catalog, evidence, {
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
        return [], {}, {"benign_reports": 0, "benign_usable": 0}

    known = set(catalog.keys())
    out = []
    evidence = collections.defaultdict(list)
    total = 0
    skipped_platform = 0
    for (rep_s,) in con.execute("SELECT report FROM benign_reports"):
        try:
            rep = json.loads(rep_s or "{}")
        except Exception:
            continue
        total += 1
        f = rep.get("file") or {}
        if not is_windows_sample(f):
            skipped_platform += 1
            continue
        if not rep.get("behaviour_available"):
            continue
        # 只保留恶意侧也见过的标记:正常软件独有的标记不影响任何组合的区分度。
        out.append(set(extract_markers(rep).keys()) & known)
        # 正常侧的 context 用于否掉「正常软件里也有」的候选片段。
        # 注意 app.py 存的正常语料是 slim_benign_report 削过的,只保留了
        # sigma_analysis_results —— 削的时候没带 match_context,所以这里通常拿不到东西。
        # 空着也没关系:候选片段的主力过滤是 UNIVERSAL_FRAGMENTS 与沙箱停用表,
        # 而 63 份语料本来也支撑不了「正常软件是否普遍如此」这个判断。
        for mid, vals in extract_context(rep).items():
            if vals:
                evidence[mid].append(vals)
    return out, evidence, {"benign_reports": total,
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
# 由 main() 在推导完成后填入:{marker_id: (event, cond, note)}。
# 做成模块级而不是逐层传参:resolve_mapping 有四个调用点(observable_ids / persist /
# 统计 / 打印),逐个改签名只会让漏改某一处时静默走回旧逻辑。
DERIVED = {}
# {marker_id: {被判定为「填错字段」的槽位名}}。由 audit_hand_rules 填。
HAND_BAD_SLOTS = {}
# 槽位在 context 里对应哪个字段(按事件类型)。CTX_FIELD_BY_EVENT 的反向索引。
SLOT_TO_CTX_FIELD = {ev: {slot: field for field, slot in pairs}
                     for ev, pairs in CTX_FIELD_BY_EVENT.items()}
# 手写条目里的字面片段,在对应 context 字段里的出现率低于此值即判定为「填错了字段」。
# 取 0.10 而不是 0:沙箱取值里总有少量异常样本(如 lsass.exe 被投放到 Temp),
# 留一点余量,免得把「基本正确但有例外」的条目也判错。
HAND_SLOT_MIN_PRESENCE = 0.10


def audit_hand_rules(catalog, evidence):
    r"""拿 match_context 反向校验手写表的每个槽位,找出「字面片段填错了字段」的条目。

    为什么需要:手写映射的错法不是「条件写宽了」,而是【把值放进了错误的槽位】——
    这种错在服务端的任何统计里都看不见,只会让规则永不命中(死规则),或者让组合
    因为「主体互相冲突」被客户端整条剔除。实测三处:
      · unsigned_image_loaded_into_lsass_process:lsass 被填进 target,而它是 actor;
      · files_with_system_process_name_in_unsuspected_locations:事件类型填成
        ProcessCreate,而 context 是 EventID 11(文件创建);
      · script_interpreter_execution_from_suspicious_folder:\Temp\ 被填进 actor,
        而 context 里 Image 全是 System32 下的 powershell —— Temp 出现在【命令行】里。
        后果是它与 actor=*\powershell*.exe 的标记撞成「互斥主体」,让那条 support=19
        的 hard 组合在每个端点上都装不进去。
      判据:该槽位的字面片段在对应 context 字段的取值里出现率 < HAND_SLOT_MIN_PRESENCE。
    返回 {marker_id: {坏槽位...}},同时返回可读报告行供打印。
    """
    bad = {}
    lines = []
    hand = _normalized_marker_rules()
    for mid, rule in hand.items():
        if rule.get("unobservable"):
            continue
        groups = evidence.get(mid) or []
        if len(groups) < MIN_DERIVE_SAMPLES:
            continue                       # 样本太少,不足以判手写表错
        ev = rule.get("event", "")
        fields = SLOT_TO_CTX_FIELD.get(ev) or {}
        for slot in ("actor", "target", "cmdline", "parent"):
            pat = str(rule.get(slot) or "").strip()
            if not pat:
                continue
            lits = [s.lower() for s in pat.replace("?", "*").split("*") if len(s) >= 4]
            if not lits:
                continue
            field = fields.get(slot)
            if not field:
                # 该事件类型下这个槽位在 context 里没有对应字段 -> 无法校验,保持原状。
                continue
            seen = 0
            for group in groups:
                vals = [_norm_value(v.get(field)) for v in group if v.get(field)]
                if any(all(l in val for l in lits) or any(l in val for l in lits)
                       for val in vals):
                    seen += 1
            ratio = seen / len(groups)
            if ratio < HAND_SLOT_MIN_PRESENCE:
                bad.setdefault(mid, set()).add(slot)
                lines.append("  %-58s 槽位 %-7s 「%s」在 context 的 %s 里只出现 %d/%d"
                             % ((catalog.get(mid, (mid, "", ""))[0] or mid)[:58],
                                slot, pat, field, seen, len(groups)))
    return bad, lines


def resolve_mapping(marker_id, title):
    """标记 -> (是否可观测, 事件类型, 匹配条件 JSON)。

    四级,顺序即可信度:
      1. MARKER_RULES 登记表 —— 人工判断优先,包括刻意标注 unobservable 的那些;
         但若人工条目的【区分力不足】,用推导结果给它补上实质条件(见下方 augment)。
      2. 从 match_context 推导 —— 数据说话,覆盖手写表没登记的标记。
      3. 关键词兜底 —— 只给事件类型,不给条件(observable=0,网页上标为待确认)。
      4. 不可观测。
    不可观测的标记仍然入库、仍参与组合统计,只是客户端拿不到条件,无法自行置位。
    """
    global _MARKER_RULES_N
    if _MARKER_RULES_N is None:
        _MARKER_RULES_N = _normalized_marker_rules()
    rule = _MARKER_RULES_N.get(marker_id)
    derived = DERIVED.get(marker_id)

    if rule:
        if rule.get("unobservable"):
            # 【人工标注的不可观测可以被数据推翻】,但只在推导结果确实给出实质条件时。
            # 这正是 lsass 那条的情形:人工结论「表达不出」建立在「lsass 要填 target」
            # 这个错误前提上,而 context 证明它属于 actor。没有推导结果时保持原状。
            if derived:
                ev, cond, _note = derived
                if condition_specificity(cond)[0] >= MARKER_SPEC_OK:
                    return _observable_or_none(ev, cond)
            return 0, rule.get("event", ""), ""
        cond = _strip_absent({k: v for k, v in rule.items()
                              if k not in ("event", "unobservable", "why")})
        ev = rule["event"]
        # 【被 context 判定为填错字段的槽位一律去掉】。留着它只有两种结局:永不命中
        # (死规则),或者与别的标记撞成「主体互相冲突」把整条组合剔除 —— 后者实测
        # 让一条 support=19 的 hard 组合在每个端点上都装不进去。
        # 去掉之后条件若不够格,下面会用推导结果补上。
        for slot in (HAND_BAD_SLOTS.get(marker_id) or ()):
            cond.pop(slot, None)
        if not cond and derived:
            # 手写条件被判全错 -> 整条改用推导结果(含它推出的事件类型)。
            dev, dcond, _n = derived
            if condition_specificity(dcond)[0] >= MARKER_SPEC_OK:
                return _observable_or_none(dev, dcond)
        spec, _why = condition_specificity(cond)
        if spec < MARKER_SPEC_OK and derived:
            dev, dcond, _n = derived
            # 只在事件类型一致时合并:类型不一致说明人工表判错了维度(实测有此情形),
            # 那种情况整条改用推导结果,而不是把两个维度的条件掺在一起。
            if dev == ev:
                merged = dict(cond)
                for k, v in dcond.items():
                    merged.setdefault(k, v)
                if condition_specificity(merged)[0] >= MARKER_SPEC_OK:
                    return _observable_or_none(ev, merged)
            elif condition_specificity(dcond)[0] >= MARKER_SPEC_OK:
                return _observable_or_none(dev, dcond)
        return _observable_or_none(ev, cond)

    if derived:
        ev, cond, _note = derived
        if condition_specificity(cond)[0] >= MARKER_SPEC_OK:
            return 1, ev, json.dumps(cond, ensure_ascii=False)

    low = (title or "").lower()
    for words, ev in KEYWORD_EVENT_HINTS:
        if any(w in low for w in words):
            # 只猜事件类型、不给条件:observable=0 表示「还需人工补条件」,网页上可筛出来。
            return 0, ev, ""
    return 0, "", ""


def _observable_or_none(ev, cond):
    # 收口处统一剥掉未启用的「不含」条件:resolve_mapping 有多条返回路径,
    # 在每条上各剥一次必然漏掉一条,而漏掉的那条正好是最危险的半开状态。
    cond = _strip_absent(cond)
    """收口:【没有区分力的条件不算可观测】。

    这条不变式是补上来的,因为漏了它就出过一次真事故形态:手写条目的 actor 槽位被
    context 判定填错后被剔除,剩下一个空条件 {},却仍然以 observable=1 下发 ——
    那是一个匹配【该类型每一条事件】的标记。它还会让多个标记的指纹撞在一起,
    在客户端触发「证据重复」剔除(实测 redundant 从 1 条涨到 3 条),
    表面上像是挖掘变差了,实际是这里漏了收口。

    区分力为 NONE 时一律回退成不可观测:含它的组合会被客户端整条剔除,
    这正是应有的结果 —— 宁可少一条组合,不可让恒真项冒充证据。
    """
    if condition_specificity(cond)[0] <= MARKER_SPEC_NONE:
        return 0, ev, ""
    return 1, ev, json.dumps(cond, ensure_ascii=False)


def marker_specificity(marker_id, title):
    """标记在【最终下发形态】下的区分力。组合能不能算互证,以此为准。"""
    obs, _ev, cond_s = resolve_mapping(marker_id, title)
    if not obs:
        return MARKER_SPEC_NONE
    try:
        cond = json.loads(cond_s) if cond_s else {}
    except Exception:
        return MARKER_SPEC_NONE
    return condition_specificity(cond)[0]


def evidence_count(markers, catalog):
    """一条组合里有几个标记【真的能算一份证据】(区分力 >= OK)。"""
    n = 0
    for m in markers:
        title = catalog.get(m, (m, "", ""))[0]
        if marker_specificity(m, title) >= MARKER_SPEC_OK:
            n += 1
    return n


def client_would_reject(markers, catalog):
    """客户端 applyTable 会不会把这条组合剔掉。返回原因,不剔则返回空串。

    【为什么服务端要自己先算一遍】:服务端的组合数一直不等于端点的生效数 ——
    实测 v19 服务端 32 条、客户端只装 26 条,而这 6 条的损失在服务端的任何统计、
    网页上的任何计数里都看不见。「数字好看、实际不干活」是这个引擎反复出现的问题形态,
    根因就是两侧各有一套判据而只有一侧被统计。
    这里把客户端那两条【服务端可以提前算出来的】判据搬过来,使下发数 == 装载数。
    剩下两条(标记不可观测 / 单动作)已由 obs 过滤与 MIN_EVIDENCE_MARKERS 覆盖。

    判据必须与 AttackChainEngine::applyTable 逐字对齐,故这里照抄它的构造方式:
      · 主体冲突:>=2 个互不相同的非空 actor 模式 —— 客户端按【单个进程】记账,
        一个进程不可能同时是两个程序。
      · 证据重复:把每个标记归约成「事件类型 + 全部条件」的指纹,去重后少于标记数,
        说明这条组合声称的 N 个动作里有重复 —— 一个信号冒充多个。
    """
    conds = []
    for m in sorted(markers):
        title = catalog.get(m, (m, "", ""))[0]
        obs, ev, cond_s = resolve_mapping(m, title)
        if not obs:
            return "unobservable"
        try:
            cond = json.loads(cond_s) if cond_s else {}
        except Exception:
            cond = {}
        conds.append((ev, cond))
    actors = {str(c.get("actor") or "").strip().lower() for _e, c in conds}
    actors.discard("")
    if len(actors) >= 2:
        return "actor_conflict"
    # 指纹必须与客户端逐字对齐,含「不含」条件 —— 少了它,两个只在否定条件上不同的
    # 标记会被误判成「证据重复」,而它们判的是两件不同的事。
    fps = {"%s|%s|%s|%s|%s|%s|%s|%s|%s" % (ev,
                                 str(c.get("actor") or "").lower(),
                                 str(c.get("target") or "").lower(),
                                 str(c.get("cmdline") or "").lower(),
                                 str(c.get("parent") or "").lower(),
                                 "1" if c.get("unsigned") else "0",
                                 str(c.get("cmdline_absent") or "").lower(),
                                 str(c.get("target_absent") or "").lower(),
                                 str(c.get("parent_absent") or "").lower())
           for ev, c in conds}
    if len(fps) < len(conds):
        return "redundant"
    return ""


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
        # 【互证闸门】与上面的可达性过滤同一个道理:一条组合若只有不足两份真证据,
        # 它在客户端上等于「一个动作 + 一个恒真项」,而客户端会把命中登记为硬指标 ——
        # 于是软信号被提拔成处置依据。这种组合不该占用覆盖额度,否则它会把真正能
        # 补位的组合挤掉,自己又在下发后毫无判别力。
        # 实测 v19:32 条下发里 9 条含零区分力标记,26 条装载组合里 12 条依赖同一条。
        if evidence_count(p, catalog) < MIN_EVIDENCE_MARKERS:
            continue
        # 客户端装载时必然剔除的组合,不该占用覆盖额度 —— 它会把能补位的挤掉,
        # 自己又在端点上被丢弃,等于白丢检出(见 client_would_reject 的说明)。
        if client_would_reject(p, catalog):
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
    dropped_by_evidence = 0
    dropped_client_side = {}
    for markers, (support, fams) in patterns.items():
        # 互证闸门在这里【再挡一次】。select_cover 已经过滤过,但这是最后一道:
        # 表是按 marker_rows 落库并下发的,任何绕过 select_cover 的调用路径
        # (例如以后有人直接拿 deduped 去 persist)都不能把不足两份证据的组合发出去。
        if evidence_count(markers, catalog) < MIN_EVIDENCE_MARKERS:
            dropped_by_evidence += 1
            continue
        _rej = client_would_reject(markers, catalog)
        if _rej:
            dropped_client_side[_rej] = dropped_client_side.get(_rej, 0) + 1
            continue
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
    stats["patterns_dropped_no_evidence"] = dropped_by_evidence
    for _k, _v in dropped_client_side.items():
        stats["patterns_dropped_" + _k] = _v

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
    # 拿一份副本演练。挖掘会重写 engine_* 三张表并升版本号,而版本一升客户端就会去拉 ——
    # 没有一个能安全试跑的入口,就等于每次改挖掘逻辑都直接拿线上端点当试验场。
    ap.add_argument("--db", default="", help="指定数据库路径(演练用,默认读配置)")
    ap.add_argument("--explain-derived", action="store_true",
                    help="逐条打印从 match_context 推导出的条件及其依据")
    # 把「服务器会下发什么」原样吐出来,不写库。
    #
    # 为什么必须有它:服务端的组合数不等于客户端装载数 —— applyTable 还有四条剔除判据
    # (不可观测 / 单动作 / 主体冲突 / 证据重复)。实测 v19 服务端 32 条、客户端只装 26 条,
    # 而那 6 条的损失在服务端的任何统计里都看不见。没有这个出口,「改完之后端点上到底
    # 有几条生效」只能等上线后去客户端日志里数。
    ap.add_argument("--emit-payload", default="",
                    help="把下发用的 JSON 写到指定文件(不写库),供客户端装载模拟")
    args = ap.parse_args()

    db = args.db or load_db_path()
    con = sqlite3.connect(db, timeout=30)

    samples, catalog, evidence, stats = collect(con)
    if not samples:
        print("没有可用样本(归档里没有带沙箱行为的 Windows 报告)。")
        return 1

    # 正常语料。没有也能跑 —— 全部区分度逻辑在 n=0 时自动退化为「不生效」,
    # 结果与加入本机制之前完全一致,不会因为语料还没攒起来就把规则库砍空。
    benign_sets, benign_ctx, bstats = collect_benign(con, catalog)
    stats.update(bstats)
    benign = BenignCorpus(benign_sets)

    # ---- 从 match_context 推导条件(本次升级的核心,见该函数上方的长注释)----
    # 必须在任何 resolve_mapping 调用【之前】填好 DERIVED:observable_ids / select_cover /
    # persist 都会经它判定,填晚了就会有一部分判定走回旧的手写表结果。
    global DERIVED, HAND_BAD_SLOTS
    DERIVED = derive_conditions(evidence, benign_ctx)
    # 手写表校验要在 DERIVED 之后、任何 resolve_mapping 之前:被判错的槽位要靠
    # 推导结果补位,顺序颠倒就会先按错条件算出一批判定。
    HAND_BAD_SLOTS, _hand_bad_lines = audit_hand_rules(catalog, evidence)
    stats["hand_rules_mismapped"] = sum(len(v) for v in HAND_BAD_SLOTS.values())
    if _hand_bad_lines:
        print("=" * 66)
        print("手写映射表校验:以下槽位的字面片段在 match_context 里几乎不出现,")
        print("判定为【填错了字段】,已剔除该槽位(必要时改用推导结果)")
        print("=" * 66)
        for ln in _hand_bad_lines:
            print(ln)
        print()
    stats["markers_with_context"] = len(evidence)
    stats["markers_derived"] = len(DERIVED)
    # 手写表覆盖不到、纯靠推导才可观测的标记数 —— 这个数字就是本次升级解开的天花板。
    _hand = _normalized_marker_rules()
    stats["markers_derived_new"] = sum(1 for m in DERIVED if m not in _hand)
    spec_hist = collections.Counter()
    for mid, (title, _lv, _src) in catalog.items():
        spec_hist[marker_specificity(mid, title)] += 1
    stats["markers_spec_none"] = spec_hist[MARKER_SPEC_NONE]
    stats["markers_spec_weak"] = spec_hist[MARKER_SPEC_WEAK]
    stats["markers_spec_ok"] = spec_hist[MARKER_SPEC_OK]

    if args.explain_derived:
        # 打印【最终决定】而不是 DERIVED 的原始内容:两者可以不同(手写表优先、
        # 事件类型不一致时整条换用推导结果),只看原始内容会误以为推导直接生效了。
        print("=" * 66)
        print("标记的最终下发形态(手写表 / 推导 / 兜底 三者裁决之后)")
        print("=" * 66)
        rows = []
        for mid, (title, lv, _src) in catalog.items():
            obs, ev, cond_s = resolve_mapping(mid, title)
            try:
                cond = json.loads(cond_s) if cond_s else {}
            except Exception:
                cond = {}
            spec, why = condition_specificity(cond) if obs else (MARKER_SPEC_NONE, "不可观测")
            src = "手写表" if mid in _hand else ("推导" if mid in DERIVED else "兜底")
            # 样本数用推导原料的分组数:df 要等归约之后才算出来,而这里只是排序用的量级。
            rows.append((spec, -len(evidence.get(mid) or []), mid, title,
                         obs, ev, cond, why, src))
        rows.sort(key=lambda r: (-r[0], r[1], r[2]))
        for spec, negn, mid, title, obs, ev, cond, why, src in rows:
            if not obs:
                continue
            print("\n[区分力 %d · 来源 %s · %d 样本] %s" % (spec, src, -negn, title))
            print("    id     %s" % mid)
            print("    event  %s" % ev)
            print("    cond   %s" % json.dumps(cond, ensure_ascii=False, sort_keys=True))
            print("    评估   %s" % why)
            if mid in DERIVED:
                print("    推导依据 %s" % DERIVED[mid][2])
        print("\n---- 不可观测(客户端无法置位,含它的组合会被整条剔除)----")
        for spec, negn, mid, title, obs, ev, cond, why, src in rows:
            if obs:
                continue
            print("    %5d 样本  %-52s %s" % (-negn, title[:52], src))

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
    # 互证闸门的效果单独说清楚 —— 它是本次升级里唯一会【减少】下发条数的改动,
    # 不写明白就会被当成「挖掘退化了」。
    _blocked = [p for p in deduped
                if evidence_count(p, catalog) < MIN_EVIDENCE_MARKERS]
    print("  互证闸门:去冗余后 %d 条里有 %d 条不足 %d 份真证据(含恒真/软信号标记),"
          "已挡在覆盖选择之外" % (len(deduped), len(_blocked), MIN_EVIDENCE_MARKERS))
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

    if args.emit_payload:
        # 形状必须与 app.py 的 Store.engine_patterns() 逐字段一致 —— 这份 JSON 的用途是
        # 拿客户端的装载判据去过它,形状对不上就白测了。
        # 同样要过一遍互证闸门,否则吐出来的不是「会被存下来的那张表」。
        emit_pats = []
        used = set()
        for markers, (support, fams) in sorted(patterns.items(),
                                               key=lambda kv: sorted(kv[0])):
            if evidence_count(markers, catalog) < MIN_EVIDENCE_MARKERS:
                continue
            g = g_of(markers, support)
            if g == "weak":
                continue
            lv = max((_level_rank(catalog.get(m, ("", "", ""))[1]) for m in markers),
                     default=0)
            ids = sorted(markers)
            used.update(ids)
            emit_pats.append({
                "markers": ids, "n": len(ids), "support": support, "grade": g,
                "max_level": {3: "critical", 2: "high", 1: "medium"}.get(lv, "medium"),
                "families": ", ".join(fams), "benign_support": bsup.get(markers, 0),
            })
        emit_mk = {}
        for mid in sorted(used):
            title, level, source = catalog.get(mid, (mid, "medium", "sigma"))
            obs, ev, cond_s = resolve_mapping(mid, title)
            try:
                cond = json.loads(cond_s) if cond_s else {}
            except Exception:
                cond = {}
            emit_mk[mid] = {"title": title, "level": level, "source": source,
                            "samples": df.get(mid, 0),
                            "benign_samples": int((benign.df or {}).get(mid, 0)),
                            "observable": bool(obs), "event": ev, "match": cond}
        payload = {"version": 0, "label": "(dry-run)", "unchanged": False,
                   "patterns": emit_pats, "markers": emit_mk}
        with open(args.emit_payload, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False)
        print("\n已写出下发 JSON:%s(%d 条组合 / %d 个标记)"
              % (args.emit_payload, len(emit_pats), len(emit_mk)))

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
