/*++
    RegistryMonitor.c
    注册表防护(M4):CmRegisterCallbackEx。

    在注册表操作的 Pre 阶段拦截对"受保护注册表键"的危险操作:
    - RegNtPreSetValueKey      设置键值(如写入启动项)
    - RegNtPreDeleteValueKey   删除键值
    - RegNtPreDeleteKey        删除子键
    - RegNtPreRenameKey        改名(把受保护键改名可让所有【路径型】匹配整体失效)
    - RegNtPreSaveKey          hive 导出(reg save HKLM\SAM -> 离线破解,绕开 lsass)
    - RegNtPreLoadKey          hive 挂载(植入持久化配置 / 伪造策略)
    - RegNtPreSetKeySecurity   改 ACL(先放开权限,后续写入即"合法",防护被整体解除)
    - RegNtPreCreateKeyEx      建键(IFEO 劫持 / 服务植入都要先新建子键)

    后五类是在只有前三类的基础上补齐的:原实现对"改名绕过""hive 转储""ACL 篡改"
    "新建持久化键"这四条路完全不设防。其中 SaveKey 对凭据 hive 的拦截是【内置常量、
    零配置、恒生效】的(见 BlwRegIsCredentialHive),不依赖用户态下发任何名单。

    仅当目标键路径命中"受保护注册表键"列表时,才上报用户态裁决;
    裁决为 Block 时返回 STATUS_ACCESS_DENIED,阻止该注册表操作。

    回调可能在任意线程上下文、PASSIVE_LEVEL 被调用。我们只在 Active 且
    PASSIVE_LEVEL 时才询问用户态。
--*/

#include "Driver.h"

//
// ===== 受保护注册表键管理(线程安全)=====
//

void
BlwClearProtectedRegKeys(void)
{
    ExAcquireFastMutex(&g_Blw.RegLock);
    RtlZeroMemory(g_Blw.ProtectedRegKeys, sizeof(g_Blw.ProtectedRegKeys));
    InterlockedExchange(&g_Blw.ProtectedRegCount, 0);
    ExReleaseFastMutex(&g_Blw.RegLock);
}

void
BlwAddProtectedRegKey(_In_ PCWSTR Key, _In_ USHORT Length)
{
    ExAcquireFastMutex(&g_Blw.RegLock);
    BlwAddToList(g_Blw.ProtectedRegKeys, Key, Length);
    {
        LONG cnt = 0;
        ULONG i;
        for (i = 0; i < BLW_MAX_PROTECTED; i++) {
            if (g_Blw.ProtectedRegKeys[i].InUse) cnt++;
        }
        InterlockedExchange(&g_Blw.ProtectedRegCount, cnt);
    }
    ExReleaseFastMutex(&g_Blw.RegLock);
}

//
// 受保护键(软监控)匹配:只针对【键路径】部分,故用 KeyChars 限定匹配范围,
// 与原实现「只把键路径喂给匹配器」完全等价。
//
static BOOLEAN
BlwRegKeyIsProtected(_In_ PBLW_MATCH_CTX Ctx, _In_ USHORT KeyChars)
{
    BOOLEAN matched;
    ExAcquireFastMutex(&g_Blw.RegLock);
    matched = BlwMatchInListCtx(g_Blw.ProtectedRegKeys, g_Blw.ProtectedRegCount, Ctx, KeyChars);
    ExReleaseFastMutex(&g_Blw.RegLock);
    return matched;
}

//
// ===== 注册表「内核硬拦截」名单管理(命中即内核本地拒绝写入)=====
//

void
BlwClearRegHardBlock(void)
{
    ExAcquireFastMutex(&g_Blw.RegHardLock);
    RtlZeroMemory(g_Blw.RegHardBlock, sizeof(g_Blw.RegHardBlock));
    InterlockedExchange(&g_Blw.RegHardCount, 0);
    ExReleaseFastMutex(&g_Blw.RegHardLock);
}

void
BlwAddRegHardBlock(_In_ PCWSTR Key, _In_ USHORT Length)
{
    ExAcquireFastMutex(&g_Blw.RegHardLock);
    BlwAddToList(g_Blw.RegHardBlock, Key, Length);
    {
        LONG cnt = 0;
        ULONG i;
        for (i = 0; i < BLW_MAX_PROTECTED; i++) {
            if (g_Blw.RegHardBlock[i].InUse) cnt++;
        }
        InterlockedExchange(&g_Blw.RegHardCount, cnt);
    }
    ExReleaseFastMutex(&g_Blw.RegHardLock);
}

//
// 构造本次注册表操作的匹配目标,并【一次性】大写化。
//
// 目标形如 "键路径\值名";无值名、或拼接后装不进 BLW_MAX_PATH 时退化为纯 "键路径"
//(与原实现的兜底一致)。*OutKeyChars 返回其中「键路径」部分的字符数。
//
// 这样【一个 ctx、一次归一化】就同时支撑两种匹配范围:
//   * 硬拦截名单:匹配整个 "键\值"。键路径是它的前缀,所以原实现「先匹配键、未命中再匹配
//     键\值」的两次匹配,与这里的一次匹配结果完全等价(任何是键子串的模式,必然也是
//     "键\值" 的子串)。
//   * 受保护键软监控:用 UseChars=*OutKeyChars 只匹配键路径部分,与原实现等价。
//
// 顺带去掉了原实现在回调栈上另开的 1KB 拼接缓冲 —— 直接拼进 ctx 的归一化缓冲即可。
//
static void
BlwPrepareRegMatch(
    _Out_ PBLW_MATCH_CTX Ctx,
    _In_ PCUNICODE_STRING KeyPath,
    _In_opt_ PCUNICODE_STRING ValueName,
    _Out_ PUSHORT OutKeyChars)
{
    USHORT keyChars;
    USHORT valChars;
    USHORT i;

    *OutKeyChars = 0;

    BlwPrepareMatch(Ctx, KeyPath);
    if (Ctx->Chars == 0) {
        // 键路径本身超过 BLW_MAX_PATH 字符:不拼值名,由回退路径按整条键路径匹配。
        // UseChars 保持 0(= 匹配整个目标,此处即键路径),语义与原实现的兜底一致。
        return;
    }

    keyChars = Ctx->Chars;
    *OutKeyChars = keyChars;

    if (ValueName == NULL || ValueName->Buffer == NULL || ValueName->Length == 0) {
        return;   // 删键等无值名的操作:目标就是键路径
    }

    valChars = (USHORT)(ValueName->Length / sizeof(WCHAR));
    if ((ULONG)keyChars + 1 + (ULONG)valChars > BLW_MAX_PATH) {
        return;   // 装不下:退化为纯键路径匹配
    }

    Ctx->Up[keyChars] = L'\\';
    for (i = 0; i < valChars; i++) {
        Ctx->Up[keyChars + 1 + i] = BlwUpcaseChar(ValueName->Buffer[i]);
    }
    Ctx->Chars = (USHORT)(keyChars + 1 + valChars);
}

//
// 硬拦截匹配:把「键路径\值名」与硬拦截名单做子串匹配。
// 命中返回 TRUE(调用方据此在内核本地直接拒绝写入,不发 IPC、不等用户态)。
//
static BOOLEAN
BlwRegIsHardBlocked(_In_ PBLW_MATCH_CTX Ctx)
{
    BOOLEAN matched;
    ExAcquireFastMutex(&g_Blw.RegHardLock);
    matched = BlwMatchInListCtx(g_Blw.RegHardBlock, g_Blw.RegHardCount, Ctx, 0);
    ExReleaseFastMutex(&g_Blw.RegHardLock);
    return matched;
}

//
// ===== 内置「凭据 hive」硬拦(零配置、恒生效)=====
//
// \REGISTRY\MACHINE\SAM 保存本机账户口令哈希,\REGISTRY\MACHINE\SECURITY 保存 LSA 机密。
// `reg save HKLM\SAM x.hiv`(底层 ZwSaveKey)把它们导出成文件后即可离线破解 —— 这是一条
// 【完全绕开 lsass】的凭据窃取路径,因此现有的凭据反转储(CREDPROT,剥 lsass 的 PROCESS_VM_READ)
// 对它毫无作用。原实现没有挂 RegNtPreSaveKey,这条路是全开的。
//
// 做成内置常量而不是靠用户态下发名单,理由有两条:
//   1) 自足性 —— 服务没启动 / 被杀 / 策略为空时照样拦得住(与内核自足基线的设计一致);
//   2) 精度 —— 若把 \REGISTRY\MACHINE\SAM 加进通用 RegHardBlock,它会同时拦下对 SAM 的
//      SetValue,而创建用户 / 改密码正是由 lsass 走 SetValue 完成的,会直接打死账户管理。
//      内置判定只挂在 SaveKey 这一条通知上,故只拦「整份导出」,不影响任何正常读写。
//

// 前缀判定 + 边界检查:目标是否位于 Root 之下(Root 必须是【大写】字面量)。
// 要求 Root 之后是字符串结束或 '\\',避免 ...\SAMPLE 这类同前缀键被误命中。
static BOOLEAN
BlwRegPathUnder(
    _In_reads_(Chars) PCWSTR Buf,
    _In_ USHORT Chars,
    _In_ BOOLEAN Prepared,
    _In_reads_(RootChars) PCWSTR Root,
    _In_ USHORT RootChars)
{
    USHORT i;

    if (Buf == NULL || Chars < RootChars || RootChars == 0) {
        return FALSE;
    }
    for (i = 0; i < RootChars; i++) {
        WCHAR c = Prepared ? Buf[i] : BlwUpcaseChar(Buf[i]);
        if (c != Root[i]) {
            return FALSE;
        }
    }
    return (Chars == RootChars) || (Buf[RootChars] == L'\\');
}

static BOOLEAN
BlwRegIsCredentialHive(_In_ PBLW_MATCH_CTX Ctx, _In_ USHORT KeyChars)
{
    static const BLW_NAME_ENTRY kHives[] = {
        BLW_NAME(L"\\REGISTRY\\MACHINE\\SAM"),
        BLW_NAME(L"\\REGISTRY\\MACHINE\\SECURITY"),
    };

    PCWSTR  buf;
    USHORT  chars;
    BOOLEAN prepared;
    ULONG   i;

    if (Ctx == NULL) {
        return FALSE;
    }

    if (Ctx->Chars != 0) {
        buf = Ctx->Up;                                  // 已大写化
        chars = (KeyChars != 0 && KeyChars <= Ctx->Chars) ? KeyChars : Ctx->Chars;
        prepared = TRUE;
    } else if (Ctx->Original != NULL && Ctx->Original->Buffer != NULL &&
               Ctx->Original->Length > 0) {
        // 超长键路径的回退路径:逐字符即时大写化。SAM 下的深层子键被单独 save 也照样拦住。
        buf = Ctx->Original->Buffer;
        chars = (USHORT)(Ctx->Original->Length / sizeof(WCHAR));
        prepared = FALSE;
    } else {
        return FALSE;
    }

    for (i = 0; i < RTL_NUMBER_OF(kHives); i++) {
        if (BlwRegPathUnder(buf, chars, prepared, kHives[i].Name, kHives[i].Chars)) {
            return TRUE;
        }
    }
    return FALSE;
}

//
// CompleteName(RegNtPreCreateKeyEx)是否已经是绝对注册表路径。
// 绝对时直接用它做匹配目标;相对时需要拼在根键路径之后(见调用点)。
//
static BOOLEAN
BlwRegNameIsAbsolute(_In_opt_ PCUNICODE_STRING Name)
{
    static const WCHAR kPrefix[] = L"\\REGISTRY";
    const USHORT prefixChars = (USHORT)(RTL_NUMBER_OF(kPrefix) - 1);

    if (Name == NULL || Name->Buffer == NULL || Name->Length == 0) {
        return FALSE;
    }
    return BlwRegPathUnder(Name->Buffer, (USHORT)(Name->Length / sizeof(WCHAR)),
                           FALSE, kPrefix, prefixChars);
}

//
// 构造注册表事件并【仅异步上报】(report-only,绝不内核阻塞)。
//
// 为什么注册表改为「只记录不原地拦截」:
//   受保护注册表键是【宽子串】(\Services / \Internet Settings / \Tcpip\Parameters /
//   \WinSock2\Parameters / \Winlogon ...),这些键被系统组件每秒高频写入。
//   - 旧实现在此同步等用户态裁决(最长 1 秒)是全系统卡死的首要根因;
//   - 而「本地无条件拦截」又不可行 —— 直接拒绝所有对 \Services 的写入会让 SCM /
//     系统服务无法工作,等于把系统打死。
//   因此唯一安全且不卡死的选择:内核侧仅异步上报这些可疑写入,放行操作本身,
//   由用户态规则引擎按主体签名/规则判定后做补偿处置(还原键值 / 结束发起进程)。
//   这与项目既有的「进程创建 fire-and-forget + 启动后处置」模型一致。
//
// valueName 可选:写值/删值操作的值名,以 "键\值" 形式追加到 TargetPath。
//
static void
BlwReportRegOp(_In_ ULONG eventType, _In_ PCUNICODE_STRING keyPath,
    _In_opt_ PCUNICODE_STRING valueName)
{
    WCHAR target[BLW_MAX_PATH];
    UNICODE_STRING usTarget;
    USHORT keyChars = 0;

    if (!g_Blw.Active) {
        return;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;  // 高 IRQL 无法发送,直接放弃记录
    }

    // 上报的目标是 "键路径\值名"。只在【确实要上报】时才拼这个串(命中名单是低频事件),
    // 而不是像原来那样先在栈上铺开整个 2.1KB 的事件结构。
    if (keyPath != NULL && keyPath->Buffer != NULL && keyPath->Length > 0) {
        keyChars = (USHORT)(keyPath->Length / sizeof(WCHAR));
        if (keyChars > (BLW_MAX_PATH - 1)) {
            keyChars = BLW_MAX_PATH - 1;
        }
        RtlCopyMemory(target, keyPath->Buffer, (SIZE_T)keyChars * sizeof(WCHAR));
    }

    // 追加 "\值名"(若有,且尚有空间)。
    if (valueName != NULL && valueName->Buffer != NULL && valueName->Length > 0 &&
        keyChars < (BLW_MAX_PATH - 2)) {
        USHORT pos = keyChars;
        USHORT valChars = (USHORT)(valueName->Length / sizeof(WCHAR));

        target[pos++] = L'\\';
        if (valChars > (BLW_MAX_PATH - 1 - pos)) {
            valChars = (USHORT)(BLW_MAX_PATH - 1 - pos);
        }
        RtlCopyMemory(&target[pos], valueName->Buffer, (SIZE_T)valChars * sizeof(WCHAR));
        keyChars = (USHORT)(pos + valChars);
    }

    usTarget.Buffer = target;
    usTarget.Length = (USHORT)(keyChars * sizeof(WCHAR));
    usTarget.MaximumLength = usTarget.Length;

    // fire-and-forget,绝不等待 / 绝不阻塞
    BlwReportEvent(eventType, HandleToULong(PsGetCurrentProcessId()), 0,
                   &usTarget, NULL, 0, 0);
}

//
// 获取被操作注册表对象的完整键路径。调用方负责 CmCallbackReleaseKeyObjectIDEx 释放。
//
static BOOLEAN
BlwGetKeyPath(_In_opt_ PVOID RegObject, _Out_ PCUNICODE_STRING* OutName)
{
    PCUNICODE_STRING name = NULL;
    NTSTATUS status;

    *OutName = NULL;
    if (RegObject == NULL) {
        return FALSE;
    }

    status = CmCallbackGetKeyObjectIDEx(&g_Blw.RegCookie, RegObject, NULL, &name, 0);
    if (!NT_SUCCESS(status) || name == NULL) {
        return FALSE;
    }
    *OutName = name;
    return TRUE;
}

//
// 对已构造好的匹配目标做三级判定,并给出本次注册表操作的返回值。
// 抽成独立函数是因为现在有两种目标构造方式(已存在键对象 vs CreateKeyEx 的根键+子键名),
// 但判定与处置逻辑完全相同 —— 不能让它们各写一份、日后走偏。
//
// 返回 STATUS_ACCESS_DENIED = 内核本地拒绝该操作(真·行为前阻断,零 IPC);
// 返回 STATUS_SUCCESS       = 放行(命中软监控名单时已异步上报,由用户态事后处置)。
//
static NTSTATUS
BlwRegDecide(
    _In_ PBLW_MATCH_CTX Ctx,
    _In_ USHORT KeyChars,
    _In_ ULONG EventType,
    _In_ PCUNICODE_STRING ReportKey,
    _In_opt_ PCUNICODE_STRING ReportValue,
    _In_ BOOLEAN HardOnly,
    _In_ BOOLEAN BuiltinHive)
{
    //
    // 1) 内置凭据 hive(仅 SaveKey 传 BuiltinHive=TRUE):零配置、恒生效的内核硬拦。
    //    放在最前面 —— 它不依赖任何用户态下发的名单,服务未启动时也必须生效。
    //
    if (BuiltinHive && BlwRegIsCredentialHive(Ctx, KeyChars)) {
        BlwReportRegOp(EventType, ReportKey, ReportValue);   // 异步记录,不阻塞
        return STATUS_ACCESS_DENIED;
    }

    //
    // 2) 硬拦截名单:命中即【内核本地直接拒绝】,不发 IPC、不等用户态 —— 真·原地阻断且零延迟。
    //    名单必须是精确键值(如 \Winlogon\Shell),量极小,不会像宽热键那样产生高频命中。
    //
    if (g_Blw.RegHardCount > 0 && BlwRegIsHardBlocked(Ctx)) {
        BlwReportRegOp(EventType, ReportKey, ReportValue);
        return STATUS_ACCESS_DENIED;
    }

    //
    // 3) 软监控受保护键 -> 仅【异步上报】供用户态记录/处置,然后【放行】操作本身。
    //    这些是宽子串(\Services 等),无条件拦截会打死系统;也绝不同步等用户态(旧版卡死根因)。
    //    HardOnly=TRUE(CreateKeyEx)时跳过本级:建键路径上用宽子串上报会形成事件风暴。
    //
    if (!HardOnly && g_Blw.ProtectedRegCount > 0 && BlwRegKeyIsProtected(Ctx, KeyChars)) {
        BlwReportRegOp(EventType, ReportKey, ReportValue);
    }

    return STATUS_SUCCESS;
}

//
// 注册表回调主入口。
//
static NTSTATUS
BlwRegistryCallback(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2)
{
    REG_NOTIFY_CLASS notifyClass;
    PCUNICODE_STRING keyPath = NULL;
    PUNICODE_STRING valueName = NULL;
    PUNICODE_STRING completeName = NULL;   // 仅 CreateKeyEx:待创建键名(可能是相对名)
    PVOID regObject = NULL;
    ULONG eventType;
    BOOLEAN interesting = FALSE;
    BOOLEAN hardOnly = FALSE;      // TRUE = 只参与硬拦匹配,跳过软监控上报(避免事件风暴)
    BOOLEAN builtinHive = FALSE;   // TRUE = 额外走内置凭据 hive 硬拦(零配置、恒生效)

    UNREFERENCED_PARAMETER(CallbackContext);

    // 【自足基线】注册表硬拦截在无客户端时依旧生效;软监控上报(BlwReportRegOp)内部自带
    // Active 判空。空配置时下方(ProtectedRegCount==0 && RegHardCount==0)快速放行,零解析开销。
    if (Argument2 == NULL) {
        return STATUS_SUCCESS;
    }

    // 内核态发起的注册表操作豁免:本驱动自身把裁决缓存写回 \Policy 子键走 Zw*(PreviousMode=KernelMode),
    // 不应被自我保护的注册表硬拦(子串 "\Services\Bulwark")挡住 —— 否则内核连自己的基线都写不进去。
    // 威胁模型是用户态恶意软件的持久化篡改;用户态操作(PreviousMode=UserMode)一律照常判定拦截。
    if (ExGetPreviousMode() == KernelMode) {
        return STATUS_SUCCESS;
    }

    notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    switch (notifyClass) {
    case RegNtPreSetValueKey:
    {
        PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
        regObject = info->Object;
        valueName = info->ValueName;
        eventType = BlwEventRegistrySetValue;
        interesting = TRUE;
        break;
    }
    case RegNtPreDeleteValueKey:
    {
        PREG_DELETE_VALUE_KEY_INFORMATION info = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
        regObject = info->Object;
        valueName = info->ValueName;
        eventType = BlwEventRegistryDeleteValue;
        interesting = TRUE;
        break;
    }
    case RegNtPreDeleteKey:
    {
        PREG_DELETE_KEY_INFORMATION info = (PREG_DELETE_KEY_INFORMATION)Argument2;
        regObject = info->Object;
        eventType = BlwEventRegistryDeleteKey;
        interesting = TRUE;
        break;
    }

    //
    // ===== 以下五类是本次补齐的覆盖面 =====
    // 原实现只挂了「写值 / 删值 / 删键」三条通知,于是下面这些攻击手法完全不经过本驱动:
    //

    case RegNtPreRenameKey:
    {
        //
        // 改名:攻击者可以先把受保护键改个名字,让所有【基于路径】的匹配(包括本驱动的硬拦名单
        // 和用户态规则)统统失效,再从容操作。这是绕过路径型防护最省事的一招,必须堵住。
        // 把新名字并入匹配目标("键路径\新名"),故无论是「改走受保护键」还是「改成受保护键」
        // 都能被同一次匹配覆盖。
        //
        PREG_RENAME_KEY_INFORMATION info = (PREG_RENAME_KEY_INFORMATION)Argument2;
        regObject = info->Object;
        valueName = info->NewName;
        eventType = BlwEventRegistryDeleteKey;   // 语义上等价于「受保护键被移走」
        interesting = TRUE;
        break;
    }

    case RegNtPreSaveKey:
    {
        //
        // hive 导出:`reg save HKLM\SAM out.hiv` 把口令哈希整份导出后离线破解 ——
        // 这条路【不经过 lsass】,故现有的凭据反转储(剥 lsass 的 PROCESS_VM_READ)拦不住它。
        // 这里靠内置凭据 hive 判定做零配置硬拦(见 BlwRegIsCredentialHive)。
        //
        PREG_SAVE_KEY_INFORMATION info = (PREG_SAVE_KEY_INFORMATION)Argument2;
        regObject = info->Object;
        eventType = BlwEventRegistryHiveDump;
        interesting = TRUE;
        builtinHive = TRUE;   // 恒需解析键路径:内置硬拦不依赖任何用户态名单
        //
        // hardOnly 在这里【不是为了性能,而是为了语义诚实】:软监控名单是 \Services 这类宽子串,
        // 对它们做 hive 导出既不是威胁、也不会被拒绝。若允许软监控分支也上报 HiveDump,
        // 用户态就无法区分「这条 HiveDump 到底拦没拦」,只能保守标成「观测」——那真正拦下的
        // SAM 转储就会被显示成"事后处置"并触发无谓的补杀。
        // 设为 hardOnly 后,BlwEventRegistryHiveDump 【只可能】由拒绝分支产生,
        // 用户态因此可以无歧义地标记 kernelBlocked=true。
        //
        hardOnly = TRUE;
        break;
    }

    case RegNtPreLoadKey:
    {
        //
        // hive 挂载:把一份自带的 hive 文件挂进注册表,可用于植入持久化配置 / 伪造策略。
        //
        // 只处理 RegNtPreLoadKey(对应 REG_LOAD_KEY_INFORMATION),【不】处理 RegNtPreLoadKeyEx ——
        // 后者的 REG_LOAD_KEY_INFORMATION_V2 首成员是 Size 而非 Object,两者内存布局不同,
        // 若合并处理就会把一个 ULONG 当指针交给 CmCallbackGetKeyObjectIDEx,直接蓝屏。
        // 宁可少覆盖一条通知,也绝不引入这种解引用风险。
        //
        PREG_LOAD_KEY_INFORMATION info = (PREG_LOAD_KEY_INFORMATION)Argument2;
        regObject = info->Object;
        eventType = BlwEventRegistrySetValue;
        interesting = TRUE;
        break;
    }

    case RegNtPreSetKeySecurity:
    {
        //
        // 改 ACL:先把受保护键的权限改成「谁都能写」,再正常写入 —— 这样后续写入在系统看来
        // 完全合法。不拦 SetKeySecurity 的话,基于键路径的防护会被这一步整体解除。
        //
        PREG_SET_KEY_SECURITY_INFORMATION info = (PREG_SET_KEY_SECURITY_INFORMATION)Argument2;
        regObject = info->Object;
        eventType = BlwEventRegistrySetValue;
        interesting = TRUE;
        break;
    }

    case RegNtPreCreateKeyEx:
    {
        //
        // 建键:原实现只拦「已存在键的写值」,于是「创建一个全新的持久化键」是完全放开的 ——
        // 例如 IFEO 劫持要新建 \Image File Execution Options\<exe> 子键,映像劫持 / 服务植入
        // 也都是先建键再写值。虽然随后的写值会被拦,但把建键这一步也堵住才是完整的。
        //
        // 此时键【还不存在】,故没有 Object 可用:目标路径要由 RootObject 的路径 + CompleteName
        // 拼出(CompleteName 可能已是绝对路径,见 BlwRegNameIsAbsolute)。
        //
        // 只读 CompleteName / RootObject 这两个成员是刻意的:REG_CREATE_KEY_INFORMATION 与
        // REG_CREATE_KEY_INFORMATION_V1 在这两个成员上偏移相同,故无论系统投递哪个版本都安全。
        //
        // hardOnly:本通知【只参与硬拦名单匹配】,不做软监控上报 —— 受保护键是 \Services 这类
        // 宽子串,建键路径上按它上报会直接形成事件风暴。
        //
        PREG_CREATE_KEY_INFORMATION info = (PREG_CREATE_KEY_INFORMATION)Argument2;
        regObject = info->RootObject;
        completeName = info->CompleteName;
        if (completeName == NULL || completeName->Buffer == NULL || completeName->Length == 0) {
            return STATUS_SUCCESS;   // 无键名可判定
        }
        eventType = BlwEventRegistrySetValue;
        interesting = TRUE;
        hardOnly = TRUE;
        break;
    }

    default:
        return STATUS_SUCCESS;
    }

    if (!interesting) {
        return STATUS_SUCCESS;
    }

    // 已封禁主体(情报确认恶意):拒绝其任何注册表写值 / 删值 / 删键 —— 挡住持久化 / 劫持。
    // 封禁集非空时才查(空则零开销),无需解析键路径。
    if (g_Blw.BannedPidCount > 0 && BlwPidIsBanned(HandleToULong(PsGetCurrentProcessId()))) {
        return STATUS_ACCESS_DENIED;
    }

    //
    // 快速判空:既无「软监控」受保护键、又无「硬拦截」名单时,直接放行,绝不解析键路径
    //(性能关键)。系统每秒大量注册表写入,CmCallbackGetKeyObjectIDEx + 锁是热路径,
    // 空配置时跳过它消除绝大部分开销。
    //
    // 例外 builtinHive(SaveKey):内置凭据 hive 硬拦【不依赖任何用户态名单】,必须照常解析 ——
    // 否则服务未启动 / 策略为空时 `reg save HKLM\SAM` 就放过去了,那正是自足基线要杜绝的情形。
    // SaveKey 本身是极低频操作,恒解析没有性能代价。
    //
    if (!builtinHive && g_Blw.ProtectedRegCount == 0 && g_Blw.RegHardCount == 0) {
        return STATUS_SUCCESS;
    }
    // CreateKeyEx 只参与硬拦匹配(hardOnly),无硬拦名单时零开销放行 —— 不必为它解析根键路径。
    // 但 builtinHive(SaveKey)不受此约束:它的内置凭据 hive 硬拦与用户态名单无关,必须照常判定。
    if (hardOnly && !builtinHive && g_Blw.RegHardCount == 0) {
        return STATUS_SUCCESS;
    }

    //
    // ===== 构造匹配目标 =====
    // 两种情况:
    //   a) CreateKeyEx 且 CompleteName 已是绝对路径 -> 直接用它,连键对象都不用解析;
    //   b) 其余情况 -> 解析键对象路径,再把 值名 / 新名 / 相对子键名 拼在其后。
    // 两条分支拿到 ctx 后走的是同一个 BlwRegDecide,判定逻辑不分叉。
    //
    if (completeName != NULL && BlwRegNameIsAbsolute(completeName)) {
        BLW_MATCH_CTX ctx;
        USHORT keyChars = 0;

        BlwPrepareRegMatch(&ctx, completeName, NULL, &keyChars);
        return BlwRegDecide(&ctx, keyChars, eventType, completeName, NULL,
                            hardOnly, builtinHive);
    }

    if (BlwGetKeyPath(regObject, &keyPath)) {
        BLW_MATCH_CTX ctx;
        USHORT keyChars = 0;
        NTSTATUS decision;

        // 键路径(+ 值名 / 新名 / 相对子键名)只归一化一次,各名单的匹配共用这份结果。
        BlwPrepareRegMatch(&ctx, keyPath, completeName != NULL ? completeName : valueName,
                           &keyChars);

        decision = BlwRegDecide(&ctx, keyChars, eventType, keyPath,
                                completeName != NULL ? completeName : valueName,
                                hardOnly, builtinHive);

        CmCallbackReleaseKeyObjectIDEx(keyPath);
        return decision;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
BlwRegisterRegistryCallback(_In_ PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;
    UNICODE_STRING altitude;

    if (g_Blw.RegCallbackRegistered) {
        return STATUS_SUCCESS;
    }

    // 注册表回调高度(需唯一,数字越大越靠近应用层)
    RtlInitUnicodeString(&altitude, L"385200");

    status = CmRegisterCallbackEx(
        BlwRegistryCallback,
        &altitude,
        DriverObject,
        NULL,
        &g_Blw.RegCookie,
        NULL);

    if (NT_SUCCESS(status)) {
        g_Blw.RegCallbackRegistered = TRUE;
        KdPrint(("[Bulwark] Registry callback registered.\n"));
    } else {
        KdPrint(("[Bulwark] CmRegisterCallbackEx failed 0x%x\n", status));
    }
    return status;
}

void
BlwUnregisterRegistryCallback(void)
{
    if (g_Blw.RegCallbackRegistered) {
        CmUnRegisterCallback(g_Blw.RegCookie);
        g_Blw.RegCallbackRegistered = FALSE;
        KdPrint(("[Bulwark] Registry callback unregistered.\n"));
    }
}
