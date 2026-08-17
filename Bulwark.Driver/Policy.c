/*++
    Policy.c
    内核自足基线(倒置 R0/R3 主从的地基):
      - 加载:DriverEntry 阶段从注册表读取防护策略,填充驱动本地各名单,使驱动在
        【用户态服务尚未启动 / 已被杀掉 / 从未安装】时依然具备完整的本地「行为前拦截」基线。
      - 持久化:内核把「已学习到的裁决」(执行前拦截 / 禁止加载 / 注册表硬拦)写回同一注册表键,
        于是「确认一次恶意」的裁决可跨【杀服务】与【重启】继续由内核独立执行,不依赖用户态。

    策略存放位置(REG_MULTI_SZ,位于服务注册表键 RegistryPath 下):
        HKLM\SYSTEM\CurrentControlSet\Services\<驱动服务名>\Policy
            ProtectedPaths / FileHardBlock / FileNoLoad / FileExecBlock /
            CmdHardBlock / ProtectedRegKeys / RegHardBlock / BlockIps

    写回由内核自身完成(ZwSetValueKey,KernelMode):RegistryMonitor 的注册表硬拦对
    KernelMode 发起的操作豁免,故本驱动能写自己的 \Policy 子键,而用户态(含恶意软件)
    仍被自我保护的 "\Services\Bulwark" 硬拦挡在门外 —— 只有内核能改这份基线。

    设计要点:
      * 加载仅在 DriverEntry(PASSIVE_LEVEL)一次;失败一律非致命(基线为空 = 等用户态下发)。
      * 写回在配置命令处理路径(PASSIVE_LEVEL)触发,频率低(仅确认恶意 / 连接时下发)。
      * 绝不在持有 FAST_MUTEX 时调用 Zw*(那会在 APC_LEVEL 调 PASSIVE 级 API);
        一律「持锁序列化到预分配缓冲 -> 放锁 -> 写注册表」。
      * 空策略键 / 缺失值:静默跳过,行为与「未配置」完全一致(向后安全)。
--*/

#include "Driver.h"

// 策略子键(相对于服务注册表键 RegistryPath)。
#define BLW_POLICY_SUBKEY  L"\\Policy"

// 单个 REG_MULTI_SZ 值的最大字节数(防御异常超大值导致的巨额分配)。
#define BLW_POLICY_VALUE_MAX  0x10000   // 64 KB

// 字符串名单 Add 接口的统一签名(BlwAddProtectedPath / BlwAddFileHardBlock / ...)。
typedef void (*BLW_ADD_STRING_FN)(_In_ PCWSTR Path, _In_ USHORT Length);

//
// 保存 DriverEntry 收到的服务注册表键(供加载与写回复用)。仅在 DriverEntry 调用一次。
//
void
BlwSaveRegistryPath(_In_opt_ PUNICODE_STRING RegistryPath)
{
    g_Blw.RegistryPath.Buffer = g_Blw.RegistryPathBuffer;
    g_Blw.RegistryPath.Length = 0;
    g_Blw.RegistryPath.MaximumLength = sizeof(g_Blw.RegistryPathBuffer);

    if (RegistryPath != NULL && RegistryPath->Buffer != NULL &&
        RegistryPath->Length > 0 &&
        RegistryPath->Length < sizeof(g_Blw.RegistryPathBuffer)) {
        RtlCopyMemory(g_Blw.RegistryPathBuffer, RegistryPath->Buffer, RegistryPath->Length);
        g_Blw.RegistryPath.Length = RegistryPath->Length;
    }
}

//
// 打开(或按需创建)<RegistryPath>\Policy 子键。全程 PASSIVE_LEVEL。
// Create=TRUE 用于写回(键不存在则创建);FALSE 用于加载(不存在即返回失败)。
//
static NTSTATUS
BlwOpenOrCreatePolicyKey(_In_ BOOLEAN Create, _Out_ PHANDLE OutKey)
{
    UNICODE_STRING subKey;
    UNICODE_STRING policyPath;
    OBJECT_ATTRIBUTES oa;
    PWCH buf;
    USHORT totalLen;
    NTSTATUS status;

    *OutKey = NULL;

    if (g_Blw.RegistryPath.Length == 0 || g_Blw.RegistryPath.Buffer == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    RtlInitUnicodeString(&subKey, BLW_POLICY_SUBKEY);
    if ((ULONG)g_Blw.RegistryPath.Length + subKey.Length + sizeof(WCHAR) > 0xFFFF) {
        return STATUS_UNSUCCESSFUL;
    }
    totalLen = g_Blw.RegistryPath.Length + subKey.Length;

    buf = (PWCH)BlwAllocPool(PagedPool, (SIZE_T)totalLen + sizeof(WCHAR), BLW_TAG);
    if (buf == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(buf, g_Blw.RegistryPath.Buffer, g_Blw.RegistryPath.Length);
    RtlCopyMemory((PUCHAR)buf + g_Blw.RegistryPath.Length, subKey.Buffer, subKey.Length);
    buf[totalLen / sizeof(WCHAR)] = L'\0';

    policyPath.Buffer = buf;
    policyPath.Length = totalLen;
    policyPath.MaximumLength = totalLen + sizeof(WCHAR);

    InitializeObjectAttributes(&oa, &policyPath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    if (Create) {
        ULONG disposition = 0;
        status = ZwCreateKey(OutKey, KEY_SET_VALUE, &oa, 0, NULL,
            REG_OPTION_NON_VOLATILE, &disposition);
    } else {
        status = ZwOpenKey(OutKey, KEY_READ, &oa);
    }

    ExFreePoolWithTag(buf, BLW_TAG);
    return status;
}

//
// 读取一个 REG_MULTI_SZ 值到分页池缓冲(WCHAR 数组,含尾部保护 NUL)。
// 成功返回缓冲(调用方 ExFreePoolWithTag 释放),*OutChars = 数据字符数;否则 NULL。
//
static PWCH
BlwQueryMultiSz(_In_ HANDLE KeyHandle, _In_ PCWSTR ValueName, _Out_ PULONG OutChars)
{
    UNICODE_STRING valName;
    NTSTATUS status;
    ULONG needed = 0;
    PKEY_VALUE_PARTIAL_INFORMATION info;
    PWCH out = NULL;

    *OutChars = 0;
    RtlInitUnicodeString(&valName, ValueName);

    status = ZwQueryValueKey(KeyHandle, &valName, KeyValuePartialInformation, NULL, 0, &needed);
    if (needed == 0 || needed > BLW_POLICY_VALUE_MAX) {
        return NULL;
    }

    info = (PKEY_VALUE_PARTIAL_INFORMATION)BlwAllocPool(PagedPool, needed, BLW_TAG);
    if (info == NULL) {
        return NULL;
    }

    status = ZwQueryValueKey(KeyHandle, &valName, KeyValuePartialInformation, info, needed, &needed);
    if (NT_SUCCESS(status) &&
        info->Type == REG_MULTI_SZ &&
        info->DataLength >= sizeof(WCHAR)) {

        ULONG chars = info->DataLength / sizeof(WCHAR);
        out = (PWCH)BlwAllocPool(PagedPool, (SIZE_T)(chars + 1) * sizeof(WCHAR), BLW_TAG);
        if (out != NULL) {
            RtlCopyMemory(out, info->Data, (SIZE_T)chars * sizeof(WCHAR));
            out[chars] = L'\0';   // 尾部保护 NUL,确保枚举不越界
            *OutChars = chars;
        }
    }

    ExFreePoolWithTag(info, BLW_TAG);
    return out;
}

//
// 枚举一个 REG_MULTI_SZ(NUL 分隔、双 NUL 结尾)的每一条非空字符串,逐条调用 Add。
//
static void
BlwApplyStringList(_In_ HANDLE KeyHandle, _In_ PCWSTR ValueName, _In_ BLW_ADD_STRING_FN Add)
{
    ULONG chars = 0;
    PWCH buf = BlwQueryMultiSz(KeyHandle, ValueName, &chars);
    ULONG i = 0;
    ULONG loaded = 0;

    if (buf == NULL) {
        return;
    }

    while (i < chars && buf[i] != L'\0') {
        ULONG start = i;
        USHORT len;

        while (i < chars && buf[i] != L'\0') {
            i++;
        }
        len = (USHORT)(i - start);
        if (len > 0 && len < BLW_MAX_PATH) {
            Add(&buf[start], len);
            loaded++;
        }
        i++;   // 跳过分隔 NUL
    }

    if (loaded > 0) {
        KdPrint(("[Bulwark] Policy: loaded %lu entries for %ws.\n", loaded, ValueName));
    }
    ExFreePoolWithTag(buf, BLW_TAG);
}

//
// 解析 "a.b.c.d" 或 "a.b.c.d:port"(port 缺省=0 表示任意)。输出主机字节序 IPv4 + 端口。
//
static BOOLEAN
BlwParseIpv4(_In_ PCWSTR s, _In_ ULONG len, _Out_ PULONG OutIpHost, _Out_ PUSHORT OutPort)
{
    ULONG octets[4] = { 0, 0, 0, 0 };
    ULONG oi = 0;
    ULONG cur = 0;
    ULONG port = 0;
    BOOLEAN haveDigit = FALSE;
    BOOLEAN inPort = FALSE;
    ULONG i;

    *OutIpHost = 0;
    *OutPort = 0;

    for (i = 0; i < len; i++) {
        WCHAR c = s[i];
        if (c >= L'0' && c <= L'9') {
            if (inPort) {
                port = port * 10 + (ULONG)(c - L'0');
                if (port > 65535) return FALSE;
            } else {
                cur = cur * 10 + (ULONG)(c - L'0');
                if (cur > 255) return FALSE;
                haveDigit = TRUE;
            }
        } else if (c == L'.' && !inPort) {
            if (!haveDigit || oi >= 3) return FALSE;
            octets[oi++] = cur;
            cur = 0;
            haveDigit = FALSE;
        } else if (c == L':' && !inPort) {
            if (!haveDigit || oi != 3) return FALSE;
            octets[oi++] = cur;
            cur = 0;
            haveDigit = FALSE;
            inPort = TRUE;
        } else {
            return FALSE;
        }
    }

    if (inPort) {
        if (oi != 4) return FALSE;
        *OutPort = (USHORT)port;
    } else {
        if (!haveDigit || oi != 3) return FALSE;
        octets[oi++] = cur;
        *OutPort = 0;
    }

    *OutIpHost = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
    return TRUE;
}

//
// 加载网络黑名单(REG_MULTI_SZ,每条 "a.b.c.d[:port]")。
//
static void
BlwLoadBlockIps(_In_ HANDLE KeyHandle)
{
    ULONG chars = 0;
    PWCH buf = BlwQueryMultiSz(KeyHandle, L"BlockIps", &chars);
    ULONG i = 0;
    ULONG loaded = 0;

    if (buf == NULL) {
        return;
    }

    while (i < chars && buf[i] != L'\0') {
        ULONG start = i;
        ULONG len;
        ULONG ip = 0;
        USHORT port = 0;

        while (i < chars && buf[i] != L'\0') {
            i++;
        }
        len = i - start;
        if (len > 0 && BlwParseIpv4(&buf[start], len, &ip, &port)) {
            BlwAddBlockIp(ip, port);
            loaded++;
        }
        i++;
    }

    if (loaded > 0) {
        KdPrint(("[Bulwark] Policy: loaded %lu network blocklist entries.\n", loaded));
    }
    ExFreePoolWithTag(buf, BLW_TAG);
}

//
// 从注册表加载防护策略基线。打开 <RegistryPath>\Policy 读各 REG_MULTI_SZ 名单。
// 全程 PASSIVE_LEVEL,失败非致命。须在 BlwSaveRegistryPath 之后调用。
//
void
BlwLoadPolicyFromRegistry(void)
{
    HANDLE hKey = NULL;
    NTSTATUS status = BlwOpenOrCreatePolicyKey(FALSE, &hKey);

    if (!NT_SUCCESS(status) || hKey == NULL) {
        // 无策略键 = 基线为空,等待用户态下发(全新安装 / 未配置的常态)。
        KdPrint(("[Bulwark] Policy: no \\Policy key (0x%x), baseline empty.\n", status));
        return;
    }

    BlwApplyStringList(hKey, L"ProtectedPaths",   BlwAddProtectedPath);
    BlwApplyStringList(hKey, L"FileHardBlock",    BlwAddFileHardBlock);
    BlwApplyStringList(hKey, L"FileNoLoad",       BlwAddFileNoLoad);
    BlwApplyStringList(hKey, L"FileExecBlock",    BlwAddFileExecBlock);
    BlwApplyStringList(hKey, L"ProtectedRegKeys", BlwAddProtectedRegKey);
    BlwApplyStringList(hKey, L"RegHardBlock",     BlwAddRegHardBlock);
    // 命令行硬拦(执行前拦截危险命令用法)。这一条对反勒索尤其关键:开机后服务尚未起来的那段
    // 空窗里,`vssadmin delete shadows` 这类一瞬间就完成的破坏动作照样被内核独立拦住。
    BlwApplyStringList(hKey, L"CmdHardBlock",     BlwAddCmdHardBlock);
    BlwLoadBlockIps(hKey);
    // 内核本地事后研判的离线情报:已知恶意 SHA-256(每条 64 位十六进制)。
    // 复用字符串名单枚举器,逐条交给 BlwAddKnownBadHex 解析入集合。
    BlwApplyStringList(hKey, L"KnownBadSha256",   BlwAddKnownBadHex);

    ZwClose(hKey);
    KdPrint(("[Bulwark] Policy baseline loaded from registry.\n"));
}

//
// 把某个名单当前内容序列化为 REG_MULTI_SZ 写回 <RegistryPath>\Policy\<ValueName>。
// 使「已学习裁决」跨杀服务 / 重启持久(下次开机由 BlwLoadPolicyFromRegistry 重新载入)。
//
// 铁律:不在持锁(FAST_MUTEX = APC_LEVEL)时调用 Zw*(PASSIVE_LEVEL API)。
// 故先在预分配缓冲上持锁序列化,放锁后再写注册表。空名单写单个 NUL(读端解析为空)。
//
static void
BlwPersistListToRegistry(_In_ PCWSTR ValueName, _In_ BLW_PROTECTED_PATH* List, _In_ PFAST_MUTEX Lock)
{
    SIZE_T maxChars;
    PWCH data;
    SIZE_T pos = 0;
    ULONG i;
    HANDLE hKey = NULL;

    if (g_Blw.RegistryPath.Length == 0) {
        return;   // 未保存服务键,无法持久化(非致命)
    }

    // 上界:每条最多 BLW_MAX_PATH 字符(含分隔 NUL),共 BLW_MAX_PROTECTED 条,加结尾 NUL。
    maxChars = (SIZE_T)BLW_MAX_PROTECTED * BLW_MAX_PATH + 1;
    data = (PWCH)BlwAllocPool(PagedPool, maxChars * sizeof(WCHAR), BLW_TAG);
    if (data == NULL) {
        return;
    }

    // 持锁序列化(仅内存拷贝,绝不在此调用任何 PASSIVE 级 API)。
    ExAcquireFastMutex(Lock);
    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        USHORT len;
        if (!List[i].InUse) {
            continue;
        }
        len = List[i].Length;
        if (len == 0 || len >= BLW_MAX_PATH) {
            continue;
        }
        if (pos + (SIZE_T)len + 1 > maxChars) {
            break;   // 越界保护(理论不会发生)
        }
        RtlCopyMemory(&data[pos], List[i].Path, (SIZE_T)len * sizeof(WCHAR));
        pos += len;
        data[pos++] = L'\0';   // 条目分隔 NUL
    }
    ExReleaseFastMutex(Lock);

    // 结尾 NUL(空名单 => 仅此一个 NUL,DataLength=2,读端正确解析为空)。
    if (pos >= maxChars) {
        pos = maxChars - 1;
    }
    data[pos++] = L'\0';

    // 放锁后写注册表(PASSIVE_LEVEL)。KernelMode 写入被 RegistryMonitor 硬拦豁免。
    if (NT_SUCCESS(BlwOpenOrCreatePolicyKey(TRUE, &hKey)) && hKey != NULL) {
        UNICODE_STRING valName;
        RtlInitUnicodeString(&valName, ValueName);
        ZwSetValueKey(hKey, &valName, 0, REG_MULTI_SZ, data, (ULONG)(pos * sizeof(WCHAR)));
        ZwClose(hKey);
        KdPrint(("[Bulwark] Policy: persisted %ws (%Iu chars).\n", ValueName, pos));
    }

    ExFreePoolWithTag(data, BLW_TAG);
}
//
// ============ 策略写回去抖(后台线程)============
//
// 为什么需要:原实现在每一条 BLW_CMD_ADD_* / CLEAR_* 里直接调用上面的写回函数,而服务连接时
// 的初始配置下发是几十上百条连续 ADD —— 每条都要分配约 66KB 分页池、把整份名单重新序列化、
// 再写一次注册表值。这在开机 / 服务重启这种最忙的时刻堆出一大批完全冗余的注册表 I/O
//(只有最后一次的内容才有意义),而且是 O(n²) 的。
//
// 现在:命令处理只做 BlwMarkPolicyDirty(置位 + 唤醒),真正的写回由本线程在被唤醒后【先等
// 一小段去抖窗口】再执行,于是一次配置下发收敛为「每个名单最多写一次」。
//
// 可靠性:卸载时 BlwStopPolicyPersist 会把剩余脏位刷完再等线程退出,因此「已学习裁决」
// (执行前拦截 / 禁止加载 / 注册表硬拦)不会因为延迟写回而丢失。
//

// 去抖窗口(100ns 单位)。取 300ms:足以吞掉整轮配置下发,又不会让「确认恶意后下发的
// 拦截项」在注册表里迟迟不落地。
#define BLW_POLICY_DEBOUNCE_100NS  (300LL * 10 * 1000)

//
// 把脏位对应的名单逐个写回。仅在写回线程(PASSIVE_LEVEL)调用。
//
static void
BlwFlushDirtyPolicy(_In_ LONG Dirty)
{
    if (Dirty == 0) {
        return;
    }
    if (Dirty & BLW_POLICY_DIRTY_PATHS) {
        BlwPersistListToRegistry(L"ProtectedPaths", g_Blw.ProtectedPaths, &g_Blw.PathLock);
    }
    if (Dirty & BLW_POLICY_DIRTY_FILEHARD) {
        BlwPersistListToRegistry(L"FileHardBlock", g_Blw.FileHardBlock, &g_Blw.FileHardLock);
    }
    if (Dirty & BLW_POLICY_DIRTY_NOLOAD) {
        BlwPersistListToRegistry(L"FileNoLoad", g_Blw.FileNoLoad, &g_Blw.FileNoLoadLock);
    }
    if (Dirty & BLW_POLICY_DIRTY_EXECBLOCK) {
        BlwPersistListToRegistry(L"FileExecBlock", g_Blw.FileExecBlock, &g_Blw.FileExecBlockLock);
    }
    if (Dirty & BLW_POLICY_DIRTY_REGKEYS) {
        BlwPersistListToRegistry(L"ProtectedRegKeys", g_Blw.ProtectedRegKeys, &g_Blw.RegLock);
    }
    if (Dirty & BLW_POLICY_DIRTY_REGHARD) {
        BlwPersistListToRegistry(L"RegHardBlock", g_Blw.RegHardBlock, &g_Blw.RegHardLock);
    }
    if (Dirty & BLW_POLICY_DIRTY_CMDHARD) {
        BlwPersistListToRegistry(L"CmdHardBlock", g_Blw.CmdHardBlock, &g_Blw.CmdHardLock);
    }
}

static VOID
BlwPolicyPersistThread(_In_ PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);

    for (;;) {
        LONG dirty;
        BOOLEAN stopping;

        KeWaitForSingleObject(&g_Blw.PolicyEvent, Executive, KernelMode, FALSE, NULL);

        stopping = (InterlockedCompareExchange(&g_Blw.PolicyStop, 0, 0) != 0);

        // 去抖:被唤醒后再等一小段,把同一轮配置下发里后续的 ADD 一并合并进来。
        // 停机时不等待,直接刷完退出。
        if (!stopping) {
            LARGE_INTEGER delay;
            delay.QuadPart = -BLW_POLICY_DEBOUNCE_100NS;   // 相对时间
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
            stopping = (InterlockedCompareExchange(&g_Blw.PolicyStop, 0, 0) != 0);
        }

        // 取走并清空脏位:此刻之后再标脏的会重新 set event,不会漏。
        dirty = InterlockedExchange(&g_Blw.PolicyDirtyMask, 0);
        BlwFlushDirtyPolicy(dirty);

        if (stopping) {
            // 退出前兜底再刷一次(去抖窗口内可能又有新的脏位)。
            dirty = InterlockedExchange(&g_Blw.PolicyDirtyMask, 0);
            BlwFlushDirtyPolicy(dirty);
            break;
        }
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

//
// 标脏并唤醒写回线程。命令处理路径唯一需要调用的持久化接口。
// 线程未就绪(启动失败)时退化为同步写回,保证「已学习裁决」仍能落地。
//
void
BlwMarkPolicyDirty(_In_ LONG DirtyBits)
{
    if (DirtyBits == 0) {
        return;
    }

    if (g_Blw.PolicyThread == NULL) {
        BlwFlushDirtyPolicy(DirtyBits);   // 退化路径:直接写
        return;
    }

    InterlockedOr(&g_Blw.PolicyDirtyMask, DirtyBits);
    KeSetEvent(&g_Blw.PolicyEvent, IO_NO_INCREMENT, FALSE);
}

NTSTATUS
BlwStartPolicyPersist(void)
{
    HANDLE threadHandle = NULL;
    NTSTATUS status;

    g_Blw.PolicyDirtyMask = 0;
    g_Blw.PolicyStop = 0;
    KeInitializeEvent(&g_Blw.PolicyEvent, SynchronizationEvent, FALSE);

    status = PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS,
        NULL, NULL, NULL, BlwPolicyPersistThread, NULL);
    if (!NT_SUCCESS(status)) {
        return status;   // 非致命:BlwMarkPolicyDirty 会退化为同步写回
    }

    ObReferenceObjectByHandle(threadHandle, THREAD_ALL_ACCESS, *PsThreadType,
        KernelMode, (PVOID*)&g_Blw.PolicyThread, NULL);
    ZwClose(threadHandle);

    KdPrint(("[Bulwark] Policy persist worker started.\n"));
    return STATUS_SUCCESS;
}

void
BlwStopPolicyPersist(void)
{
    InterlockedExchange(&g_Blw.PolicyStop, 1);
    KeSetEvent(&g_Blw.PolicyEvent, IO_NO_INCREMENT, FALSE);

    if (g_Blw.PolicyThread != NULL) {
        KeWaitForSingleObject(g_Blw.PolicyThread, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(g_Blw.PolicyThread);
        g_Blw.PolicyThread = NULL;
    }

    // 线程已退出:若还有残留脏位(例如线程从未成功启动),在此同步刷掉,绝不丢裁决。
    {
        LONG dirty = InterlockedExchange(&g_Blw.PolicyDirtyMask, 0);
        BlwFlushDirtyPolicy(dirty);
    }
    KdPrint(("[Bulwark] Policy persist worker stopped.\n"));
}
