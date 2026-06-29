/*++
    RegistryMonitor.c
    注册表防护(M4):CmRegisterCallbackEx。

    在注册表操作的 Pre 阶段拦截对"受保护注册表键"的危险写入:
    - RegNtPreSetValueKey      设置键值(如写入启动项)
    - RegNtPreDeleteValueKey   删除键值
    - RegNtPreDeleteKey        删除子键

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

static BOOLEAN
BlwRegKeyIsProtected(_In_ PCUNICODE_STRING KeyPath)
{
    BOOLEAN matched;
    ExAcquireFastMutex(&g_Blw.RegLock);
    matched = BlwMatchInList(g_Blw.ProtectedRegKeys, KeyPath);
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
// 硬拦截匹配:把「键路径」或「键路径\值名」与硬拦截名单做子串匹配。
// 命中返回 TRUE(调用方据此在内核本地直接拒绝写入,不发 IPC、不等用户态)。
//
static BOOLEAN
BlwRegIsHardBlocked(_In_ PCUNICODE_STRING KeyPath, _In_opt_ PCUNICODE_STRING ValueName)
{
    BOOLEAN matched = FALSE;

    // 先按键路径匹配(覆盖删键、或整键级硬拦截)。
    ExAcquireFastMutex(&g_Blw.RegHardLock);
    matched = BlwMatchInList(g_Blw.RegHardBlock, KeyPath);

    // 未命中且有值名时,拼出 "键\值" 再匹配一次(覆盖按精确值名硬拦截,
    // 如 ...\Winlogon\Shell、...\<exe>\Debugger)。
    if (!matched && ValueName != NULL && ValueName->Buffer != NULL &&
        ValueName->Length > 0 && KeyPath != NULL && KeyPath->Buffer != NULL) {

        USHORT keyChars = KeyPath->Length / sizeof(WCHAR);
        USHORT valChars = ValueName->Length / sizeof(WCHAR);
        // 需要 key + '\' + value + NUL,限制在 BLW_MAX_PATH 内。
        if ((ULONG)keyChars + 1 + valChars < BLW_MAX_PATH) {
            // 用栈上缓冲拼接(BLW_MAX_PATH 宽字符,约 1KB,安全)。
            WCHAR combined[BLW_MAX_PATH];
            UNICODE_STRING usCombined;

            RtlCopyMemory(combined, KeyPath->Buffer, keyChars * sizeof(WCHAR));
            combined[keyChars] = L'\\';
            RtlCopyMemory(&combined[keyChars + 1], ValueName->Buffer, valChars * sizeof(WCHAR));

            usCombined.Buffer = combined;
            usCombined.Length = (USHORT)((keyChars + 1 + valChars) * sizeof(WCHAR));
            usCombined.MaximumLength = usCombined.Length;

            matched = BlwMatchInList(g_Blw.RegHardBlock, &usCombined);
        }
    }
    ExReleaseFastMutex(&g_Blw.RegHardLock);
    return matched;
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
    BLW_EVENT_MESSAGE msg;
    USHORT keyChars = 0;

    if (!g_Blw.Active) {
        return;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;  // 高 IRQL 无法发送,直接放弃记录
    }

    RtlZeroMemory(&msg, sizeof(msg));
    msg.EventId = (ULONG64)InterlockedIncrement64(&g_Blw.NextEventId);
    msg.Type = eventType;
    msg.ActorPid = HandleToULong(PsGetCurrentProcessId());
    msg.ParentPid = 0;

    if (keyPath != NULL && keyPath->Buffer != NULL && keyPath->Length > 0) {
        keyChars = keyPath->Length / sizeof(WCHAR);
        if (keyChars > (BLW_MAX_PATH - 1)) {
            keyChars = BLW_MAX_PATH - 1;
        }
        RtlCopyMemory(msg.TargetPath, keyPath->Buffer, keyChars * sizeof(WCHAR));
    }

    // 追加 "\值名"(若有,且尚有空间)。
    if (valueName != NULL && valueName->Buffer != NULL && valueName->Length > 0 &&
        keyChars < (BLW_MAX_PATH - 2)) {
        USHORT pos = keyChars;
        USHORT valChars = valueName->Length / sizeof(WCHAR);

        msg.TargetPath[pos++] = L'\\';
        if (valChars > (BLW_MAX_PATH - 1 - pos)) {
            valChars = BLW_MAX_PATH - 1 - pos;
        }
        RtlCopyMemory(&msg.TargetPath[pos], valueName->Buffer, valChars * sizeof(WCHAR));
        pos = (USHORT)(pos + valChars);
        msg.TargetPath[pos] = L'\0';
        msg.TargetPathLength = pos;
    } else {
        msg.TargetPath[keyChars] = L'\0';
        msg.TargetPathLength = keyChars;
    }

    BlwReportEvent(&msg);  // fire-and-forget,绝不等待 / 绝不阻塞
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
    PVOID regObject = NULL;
    ULONG eventType;
    BOOLEAN interesting = FALSE;

    UNREFERENCED_PARAMETER(CallbackContext);

    if (!g_Blw.Active || Argument2 == NULL) {
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
    default:
        return STATUS_SUCCESS;
    }

    if (!interesting) {
        return STATUS_SUCCESS;
    }

    // 快速判空:既无「软监控」受保护键、又无「硬拦截」名单时,直接放行,
    // 绝不解析键路径(性能关键)。系统每秒大量注册表写入,
    // CmCallbackGetKeyObjectIDEx + 锁是热路径,空配置时跳过它消除绝大部分开销。
    if (g_Blw.ProtectedRegCount == 0 && g_Blw.RegHardCount == 0) {
        return STATUS_SUCCESS;
    }

    if (BlwGetKeyPath(regObject, &keyPath)) {
        //
        // 1) 硬拦截名单:命中即【内核本地直接拒绝写入】(STATUS_ACCESS_DENIED),
        //    不发 IPC、不等用户态 —— 真·原地阻断且零延迟。这正是「彻底解决注册表防护」
        //    且不卡死的关键:名单必须是精确键值(如 \Winlogon\Shell),量极小,
        //    不会像宽热键那样产生高频命中。命中后仍异步上报一条供 UI 记录。
        //
        if (g_Blw.RegHardCount > 0 && BlwRegIsHardBlocked(keyPath, valueName)) {
            BlwReportRegOp(eventType, keyPath, valueName);  // 异步记录,不阻塞
            CmCallbackReleaseKeyObjectIDEx(keyPath);
            return STATUS_ACCESS_DENIED;   // 原地拒绝
        }

        //
        // 2) 影子模式(沙盒):影子进程的注册表写入。
        //    观察模式:全部放行,但上报行为事件,由用户态会话后回滚。
        //    拦截模式(默认):拦截注册表写入,返回 SUCCESS 让进程以为成功。
        //
        if (BlwPidIsShadow(HandleToULong(PsGetCurrentProcessId()))) {
            BOOLEAN observe = InterlockedCompareExchange(&g_Blw.ShadowObserveMode, 0, 0) != 0;
            BlwReportRegOp(eventType, keyPath, valueName);  // 两种模式都上报
            if (!observe) {
                // 拦截模式:阻止注册表写入
                CmCallbackReleaseKeyObjectIDEx(keyPath);
                return STATUS_ACCESS_DENIED;
            }
            // 观察模式:放行,让操作真实执行
            CmCallbackReleaseKeyObjectIDEx(keyPath);
            return STATUS_SUCCESS;
        }

        //
        // 3) 软监控受保护键 -> 仅【异步上报】供用户态记录/处置,然后【放行】操作本身。
        //    这些是宽子串(\Services 等),无条件拦截会打死系统;也绝不同步等用户态
        //    (那是旧版卡死根因)。由用户态规则引擎按主体身份事后处置(post-write kill)。
        //
        if (g_Blw.ProtectedRegCount > 0 && BlwRegKeyIsProtected(keyPath)) {
            BlwReportRegOp(eventType, keyPath, valueName);
        }
        CmCallbackReleaseKeyObjectIDEx(keyPath);
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
