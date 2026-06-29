/*++
    FileMonitor.c
    文件防护(M3):Minifilter I/O 预操作回调。

    监控:
    - IRP_MJ_CREATE 带 FILE_DELETE_ON_CLOSE:打开即删除
    - IRP_MJ_SET_INFORMATION 的 FileDispositionInformation(标记删除)
      与 FileRenameInformation(重命名/移动)
    - IRP_MJ_WRITE:就地加密检测(采样遥测,绝不拦截)——抓"打开→从头覆写→同名保存"
      这类既不改名也不删除的加密型勒索。

    命中"受保护路径/硬拦截名单"时用 STATUS_ACCESS_DENIED 原地拒绝;未命中名单的删除/
    重命名/首块写则在"文件行为遥测"开启时 fire-and-forget 上报,供用户态勒索时序聚合。

    拦截类回调运行在 PASSIVE_LEVEL,本地查表裁决,绝不同步等待用户态。

    影子文件系统虚拟化:
    当 ShadowFsRedirect 开启时,影子进程的文件写入/创建/删除/重命名被重定向到
    沙盒目录(BlwBuildSandboxPath 构建路径)。读取时先查沙盒,再查真实文件系统。
    通过修改 FILE_OBJECT->FileName 实现路径重定向,在 post-create 中恢复原路径。
--*/

#include "Driver.h"

//
// ===== 沙盒目录创建(供影子文件系统虚拟化使用)=====
//

// 递归创建沙盒目录结构。输入路径为沙盒内的完整路径(含文件名),
// 本函数只创建目录部分(去掉最后一个组件)。
static NTSTATUS
BlwCreateSandboxDirectoryFor(_In_ PCWSTR FullPath, _In_ USHORT PathChars)
{
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING dirPath;
    NTSTATUS status;
    HANDLE dirHandle = NULL;
    USHORT i;

    if (FullPath == NULL || PathChars < 3) {
        return STATUS_INVALID_PARAMETER;
    }

    // 找到最后一个反斜杠,截断得到目录路径
    for (i = PathChars; i > 0; i--) {
        if (FullPath[i - 1] == L'\\') {
            break;
        }
    }
    if (i == 0) {
        return STATUS_INVALID_PARAMETER;  // 无目录部分
    }

    // 临时截断(用栈上缓冲,不修改原始路径)
    {
        WCHAR dirBuf[BLW_MAX_PATH];
        if (i >= BLW_MAX_PATH) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        RtlCopyMemory(dirBuf, FullPath, i * sizeof(WCHAR));
        dirBuf[i] = L'\0';

        RtlInitUnicodeString(&dirPath, dirBuf);
        InitializeObjectAttributes(&oa, &dirPath,
            OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

        // 尝试创建目录(如果已存在则打开)
        status = ZwCreateFile(
            &dirHandle,
            FILE_LIST_DIRECTORY | SYNCHRONIZE,
            &oa,
            &(IO_STATUS_BLOCK){0},
            NULL,                          // AllocationSize
            FILE_ATTRIBUTE_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN_IF,                  // 打开或创建
            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            NULL, 0);

        if (NT_SUCCESS(status) && dirHandle != NULL) {
            ZwClose(dirHandle);
        }
    }

    return status;
}

//
// 判断沙盒中是否存在某个文件。用于影子进程读取时先查沙盒。
//
static BOOLEAN
BlwSandboxFileExists(_In_ PCWSTR SandboxPath, _In_ USHORT PathChars)
{
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING filePath;
    HANDLE fileHandle = NULL;
    NTSTATUS status;

    if (SandboxPath == NULL || PathChars == 0) {
        return FALSE;
    }

    RtlInitUnicodeString(&filePath, SandboxPath);
    InitializeObjectAttributes(&oa, &filePath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ZwCreateFile(
        &fileHandle,
        FILE_READ_ATTRIBUTES,
        &oa,
        &(IO_STATUS_BLOCK){0},
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,               // 仅打开,不创建
        FILE_NON_DIRECTORY_FILE,
        NULL, 0);

    if (NT_SUCCESS(status) && fileHandle != NULL) {
        ZwClose(fileHandle);
        return TRUE;
    }

    return FALSE;
}

//
// ===== 通用受保护项匹配(供文件 / 注册表复用)=====
//

// 在 List 中查找是否有某项是 Target 的子串(大小写不敏感)。调用方需自行持锁。
BOOLEAN
BlwMatchInList(_In_ BLW_PROTECTED_PATH* List, _In_ PCUNICODE_STRING Target)
{
    ULONG i;

    if (Target == NULL || Target->Buffer == NULL || Target->Length == 0) {
        return FALSE;
    }

    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        if (!List[i].InUse) {
            continue;
        }

        UNICODE_STRING item;
        item.Buffer = List[i].Path;
        item.Length = List[i].Length * sizeof(WCHAR);
        item.MaximumLength = item.Length;

        if (item.Length <= Target->Length) {
            USHORT targetChars = Target->Length / sizeof(WCHAR);
            USHORT itemChars = item.Length / sizeof(WCHAR);
            USHORT limit = targetChars - itemChars;
            USHORT s;

            for (s = 0; s <= limit; s++) {
                UNICODE_STRING window;
                window.Buffer = &Target->Buffer[s];
                window.Length = item.Length;
                window.MaximumLength = item.Length;
                if (RtlCompareUnicodeString(&window, &item, TRUE) == 0) {
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

// 向 List 追加一项。调用方需自行持锁。
void
BlwAddToList(_In_ BLW_PROTECTED_PATH* List, _In_ PCWSTR Path, _In_ USHORT Length)
{
    ULONG i;

    if (Length == 0 || Length > (BLW_MAX_PATH - 1)) {
        return;
    }

    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        if (!List[i].InUse) {
            RtlCopyMemory(List[i].Path, Path, Length * sizeof(WCHAR));
            List[i].Path[Length] = L'\0';
            List[i].Length = Length;
            List[i].InUse = TRUE;
            break;
        }
    }
}

//
// ===== 受保护路径管理(线程安全)=====
//

void
BlwClearProtectedPaths(void)
{
    ExAcquireFastMutex(&g_Blw.PathLock);
    RtlZeroMemory(g_Blw.ProtectedPaths, sizeof(g_Blw.ProtectedPaths));
    InterlockedExchange(&g_Blw.ProtectedPathCount, 0);
    ExReleaseFastMutex(&g_Blw.PathLock);
}

void
BlwAddProtectedPath(_In_ PCWSTR Path, _In_ USHORT Length)
{
    ExAcquireFastMutex(&g_Blw.PathLock);
    BlwAddToList(g_Blw.ProtectedPaths, Path, Length);
    // 重新计数(简单可靠,只发生在配置下发时,频率极低)
    {
        LONG cnt = 0;
        ULONG i;
        for (i = 0; i < BLW_MAX_PROTECTED; i++) {
            if (g_Blw.ProtectedPaths[i].InUse) cnt++;
        }
        InterlockedExchange(&g_Blw.ProtectedPathCount, cnt);
    }
    ExReleaseFastMutex(&g_Blw.PathLock);
}

//
// 子串匹配(大小写不敏感):Path 是否包含任一受保护路径片段。
//
BOOLEAN
BlwPathIsProtected(_In_ PCUNICODE_STRING Path)
{
    BOOLEAN matched;
    ExAcquireFastMutex(&g_Blw.PathLock);
    matched = BlwMatchInList(g_Blw.ProtectedPaths, Path);
    ExReleaseFastMutex(&g_Blw.PathLock);
    return matched;
}

//
// ===== 文件「内核硬拦截」名单管理(命中即拒绝写/删/改打开)=====
//

void
BlwClearFileHardBlock(void)
{
    ExAcquireFastMutex(&g_Blw.FileHardLock);
    RtlZeroMemory(g_Blw.FileHardBlock, sizeof(g_Blw.FileHardBlock));
    InterlockedExchange(&g_Blw.FileHardCount, 0);
    ExReleaseFastMutex(&g_Blw.FileHardLock);
}

void
BlwAddFileHardBlock(_In_ PCWSTR Path, _In_ USHORT Length)
{
    ExAcquireFastMutex(&g_Blw.FileHardLock);
    BlwAddToList(g_Blw.FileHardBlock, Path, Length);
    {
        LONG cnt = 0;
        ULONG i;
        for (i = 0; i < BLW_MAX_PROTECTED; i++) {
            if (g_Blw.FileHardBlock[i].InUse) cnt++;
        }
        InterlockedExchange(&g_Blw.FileHardCount, cnt);
    }
    ExReleaseFastMutex(&g_Blw.FileHardLock);
}

BOOLEAN
BlwFileIsHardBlocked(_In_ PCUNICODE_STRING Path)
{
    BOOLEAN matched;
    ExAcquireFastMutex(&g_Blw.FileHardLock);
    matched = BlwMatchInList(g_Blw.FileHardBlock, Path);
    ExReleaseFastMutex(&g_Blw.FileHardLock);
    return matched;
}

//
// ===== 「禁止加载」模块名单管理(命中且执行/映射意图打开即拒绝)=====
//

void
BlwClearFileNoLoad(void)
{
    ExAcquireFastMutex(&g_Blw.FileNoLoadLock);
    RtlZeroMemory(g_Blw.FileNoLoad, sizeof(g_Blw.FileNoLoad));
    InterlockedExchange(&g_Blw.FileNoLoadCount, 0);
    ExReleaseFastMutex(&g_Blw.FileNoLoadLock);
}

void
BlwAddFileNoLoad(_In_ PCWSTR Path, _In_ USHORT Length)
{
    ExAcquireFastMutex(&g_Blw.FileNoLoadLock);
    BlwAddToList(g_Blw.FileNoLoad, Path, Length);
    {
        LONG cnt = 0;
        ULONG i;
        for (i = 0; i < BLW_MAX_PROTECTED; i++) {
            if (g_Blw.FileNoLoad[i].InUse) cnt++;
        }
        InterlockedExchange(&g_Blw.FileNoLoadCount, cnt);
    }
    ExReleaseFastMutex(&g_Blw.FileNoLoadLock);
}

BOOLEAN
BlwFileIsNoLoad(_In_ PCUNICODE_STRING Path)
{
    BOOLEAN matched;
    ExAcquireFastMutex(&g_Blw.FileNoLoadLock);
    matched = BlwMatchInList(g_Blw.FileNoLoad, Path);
    ExReleaseFastMutex(&g_Blw.FileNoLoadLock);
    return matched;
}

//
// 构造文件事件并【仅异步上报】(不等待裁决)。拦截与否完全由内核本地
// 配置(受保护路径表)决定 —— 调用方在确认命中受保护路径后才调用本函数,
// 这里只负责把"已被内核拦截"的事实异步告知用户态供记录/告警。
// 绝不发同步 IPC,绝不阻塞 I/O 线程。
//
static void
BlwReportFileBlock(_In_ ULONG eventType, _In_ PCUNICODE_STRING fileName)
{
    BLW_EVENT_MESSAGE msg;
    USHORT chars;

    if (!g_Blw.Active) {
        return;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }

    RtlZeroMemory(&msg, sizeof(msg));
    msg.EventId = (ULONG64)InterlockedIncrement64(&g_Blw.NextEventId);
    msg.Type = eventType;
    msg.ActorPid = HandleToULong(PsGetCurrentProcessId());
    msg.ParentPid = 0;

    if (fileName != NULL && fileName->Buffer != NULL && fileName->Length > 0) {
        chars = fileName->Length / sizeof(WCHAR);
        if (chars > (BLW_MAX_PATH - 1)) {
            chars = BLW_MAX_PATH - 1;
        }
        RtlCopyMemory(msg.TargetPath, fileName->Buffer, chars * sizeof(WCHAR));
        msg.TargetPath[chars] = L'\0';
        msg.TargetPathLength = chars;
    }

    BlwReportEvent(&msg);
}

//
// 构造「文件行为遥测」事件并 fire-and-forget 上报(不阻断 I/O)。
// 与 BlwReportFileBlock 的区别:这是【未命中任何名单】的正常文件操作,内核不拦截,
// 仅把"某进程对某文件做了重命名/删除标记"这一事实异步告知用户态,供勒索时序聚合。
// 仅在 FileTelemetryEnabled 开启时上报;PASSIVE_LEVEL;绝不发同步 IPC。
//
static void
BlwReportFileTelemetry(_In_ ULONG eventType, _In_ PCUNICODE_STRING fileName)
{
    BLW_EVENT_MESSAGE msg;
    USHORT chars;

    if (!g_Blw.Active) {
        return;
    }
    if (InterlockedCompareExchange(&g_Blw.FileTelemetryEnabled, 0, 0) == 0) {
        return;  // 遥测未开启
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }

    RtlZeroMemory(&msg, sizeof(msg));
    msg.EventId = (ULONG64)InterlockedIncrement64(&g_Blw.NextEventId);
    msg.Type = BlwEventFileModify;
    msg.ActorPid = HandleToULong(PsGetCurrentProcessId());
    msg.ParentPid = eventType;  // 复用字段携带原始操作类型(删除标记 / 重命名),供用户态区分

    if (fileName != NULL && fileName->Buffer != NULL && fileName->Length > 0) {
        chars = fileName->Length / sizeof(WCHAR);
        if (chars > (BLW_MAX_PATH - 1)) {
            chars = BLW_MAX_PATH - 1;
        }
        RtlCopyMemory(msg.TargetPath, fileName->Buffer, chars * sizeof(WCHAR));
        msg.TargetPath[chars] = L'\0';
        msg.TargetPathLength = chars;
    }

    BlwReportEvent(&msg);   // 入队即返回,队列满则丢弃(遥测可丢)
}

//
// ===== I/O 预操作回调 =====
//

//
// IRP_MJ_CREATE:仅关注"打开即删除"(FILE_DELETE_ON_CLOSE)。
//
FLT_PREOP_CALLBACK_STATUS
BlwPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;
    ULONG createOptions;
    ACCESS_MASK desiredAccess;
    BOOLEAN deleteOnClose;
    BOOLEAN writeOrDeleteIntent;
    BOOLEAN executeIntent;
    BOOLEAN needHardCheck;
    BOOLEAN needProtCheck;
    BOOLEAN needNoLoadCheck;
    BOOLEAN needTelemetry;

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    if (!g_Blw.Active) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // 内核态发起的 I/O 不拦截,避免影响系统
    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // ===== 微内核隔离模式:透明文件系统虚拟化 =====
    // 对影子进程的文件操作,透明重定向到沙盒目录。
    // 写操作:在沙盒中创建/修改文件,真实文件系统不受影响。
    // 读操作:先查沙盒(有则读沙盒),再查真实文件(无则读真实)。
    // 程序完全正常运行,但所有变更发生在沙盒中。
    //
    if (BlwPidIsShadow(HandleToULong(PsGetCurrentProcessId())) &&
        InterlockedCompareExchange(&g_Blw.ShadowIsolationMode, 0, 0) != 0 &&
        g_Blw.SandboxPathLength > 0) {

        status = FltGetFileNameInformation(
            Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
        if (!NT_SUCCESS(status)) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        FltParseFileNameInformation(nameInfo);

        {
            WCHAR sandboxPath[BLW_MAX_PATH];
            USHORT sandboxLen = 0;

            if (BlwBuildSandboxPath(&nameInfo->Name, sandboxPath, BLW_MAX_PATH, &sandboxLen)) {
                ACCESS_MASK da = 0;
                ULONG co = Data->Iopb->Parameters.Create.Options;
                if (Data->Iopb->Parameters.Create.SecurityContext != NULL) {
                    da = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
                }
                BOOLEAN isWrite = (co & FILE_DELETE_ON_CLOSE) ||
                    (da & (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES |
                           FILE_WRITE_EA | DELETE | WRITE_DAC | WRITE_OWNER));
                BOOLEAN isRead = !isWrite && (da & (FILE_READ_DATA | FILE_EXECUTE | FILE_READ_ATTRIBUTES));

                if (isWrite) {
                    // 写操作:在沙盒中创建文件
                    BlwCreateSandboxDirectoryFor(sandboxPath, sandboxLen);
                    {
                        UNICODE_STRING sbPath;
                        OBJECT_ATTRIBUTES oa;
                        HANDLE sbHandle = NULL;
                        IO_STATUS_BLOCK sbIosb;
                        ULONG createDisp = co & 0xFFFF;

                        RtlInitUnicodeString(&sbPath, sandboxPath);
                        InitializeObjectAttributes(&oa, &sbPath,
                            OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

                        status = FltCreateFile(
                            FltObjects->Filter,
                            Data->RequestorMode == KernelMode ? NULL : Data->Iopb->TargetInstance,
                            &sbHandle,
                            da,
                            &oa,
                            &sbIosb,
                            Data->Iopb->Parameters.Create.AllocationSize.QuadPart > 0
                                ? &Data->Iopb->Parameters.Create.AllocationSize : NULL,
                            Data->Iopb->Parameters.Create.FileAttributes,
                            Data->Iopb->Parameters.Create.ShareAccess,
                            createDisp,
                            co & ~0xFFFF,
                            NULL, 0,
                            IO_IGNORE_SHARE_ACCESS_CHECK);

                        if (NT_SUCCESS(status) && sbHandle != NULL) {
                            // 上报行为(供分析)
                            BlwReportFileBlock(BlwEventShadowFileCreate, &nameInfo->Name);

                            // 关键:把沙盒文件句柄转为 FILE_OBJECT,替换 TargetFileObject
                            PFILE_OBJECT sbFileObj = NULL;
                            NTSTATUS refStatus = ObReferenceObjectByHandle(
                                sbHandle, 0, *IoFileObjectType, KernelMode, (PVOID*)&sbFileObj, NULL);
                            if (NT_SUCCESS(refStatus) && sbFileObj != NULL) {
                                // 替换:后续操作自动走沙盒
                                Data->Iopb->TargetFileObject = sbFileObj;
                                ObDereferenceObject(sbFileObj);
                            }
                            Data->IoStatus.Status = status;
                            Data->IoStatus.Information = sbIosb.Information;
                            FltReleaseFileNameInformation(nameInfo);
                            FltClose(sbHandle);
                            return FLT_PREOP_COMPLETE;
                        }
                    }
                } else if (isRead) {
                    // 读操作:先查沙盒中是否有文件
                    if (BlwSandboxFileExists(sandboxPath, sandboxLen)) {
                        // 沙盒中有文件,从沙盒读取
                        UNICODE_STRING sbPath;
                        OBJECT_ATTRIBUTES oa;
                        HANDLE sbHandle = NULL;
                        IO_STATUS_BLOCK sbIosb;

                        RtlInitUnicodeString(&sbPath, sandboxPath);
                        InitializeObjectAttributes(&oa, &sbPath,
                            OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

                        status = FltCreateFile(
                            FltObjects->Filter,
                            NULL,
                            &sbHandle,
                            da,
                            &oa,
                            &sbIosb,
                            NULL, 0, 0,
                            FILE_OPEN,
                            co & ~0xFFFF,
                            NULL, 0,
                            IO_IGNORE_SHARE_ACCESS_CHECK);

                        if (NT_SUCCESS(status) && sbHandle != NULL) {
                            PFILE_OBJECT sbFileObj = NULL;
                            NTSTATUS refStatus = ObReferenceObjectByHandle(
                                sbHandle, 0, *IoFileObjectType, KernelMode, (PVOID*)&sbFileObj, NULL);
                            if (NT_SUCCESS(refStatus) && sbFileObj != NULL) {
                                Data->Iopb->TargetFileObject = sbFileObj;
                                ObDereferenceObject(sbFileObj);
                            }
                            Data->IoStatus.Status = status;
                            Data->IoStatus.Information = sbIosb.Information;
                            FltReleaseFileNameInformation(nameInfo);
                            FltClose(sbHandle);
                            return FLT_PREOP_COMPLETE;
                        }
                    }
                    // 沙盒中没有文件,从真实文件系统读取
                }
            }
        }

        FltReleaseFileNameInformation(nameInfo);
        // 继续正常处理
    }

    //
    // ===== 原有的追踪模式(放行+追踪+回滚) =====

    createOptions = Data->Iopb->Parameters.Create.Options;
    deleteOnClose = (createOptions & FILE_DELETE_ON_CLOSE) ? TRUE : FALSE;

    // 取本次打开请求的期望访问权限(写/删/追加/改属性即视为「篡改意图」)。
    desiredAccess = 0;
    if (Data->Iopb->Parameters.Create.SecurityContext != NULL) {
        desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    }
    writeOrDeleteIntent = (deleteOnClose ||
        (desiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES |
                          FILE_WRITE_EA | DELETE | WRITE_DAC | WRITE_OWNER))) ? TRUE : FALSE;

    // 执行/映射意图:DLL/EXE 加载会以 FILE_EXECUTE 打开镜像。据此识别「加载」类打开,
    // 用于「禁止加载」名单的精准拦截(只拦执行映射,不影响把该文件当普通数据读)。
    executeIntent = (desiredAccess & FILE_EXECUTE) ? TRUE : FALSE;

    // 需要做硬拦截检查:有硬拦截名单 且 本次是写/删意图打开(只读打开一律放行)。
    needHardCheck = (g_Blw.FileHardCount > 0 && writeOrDeleteIntent);
    // 需要做受保护路径检查(原逻辑):有受保护路径 且 本次是 delete-on-close。
    needProtCheck = (g_Blw.ProtectedPathCount > 0 && deleteOnClose);
    // 需要做「禁止加载」检查:有禁止加载名单 且 本次是执行/映射意图打开。
    needNoLoadCheck = (g_Blw.FileNoLoadCount > 0 && executeIntent);

    // 需要做「文件行为遥测」:遥测开启 且 本次是 delete-on-close(打开即删除)。
    // 仅针对 delete-on-close 这一稀有且高价值的删除信号,不对普通写打开做任何处理,
    // 因此不引入每次 CREATE 的额外开销。
    needTelemetry =
        (InterlockedCompareExchange(&g_Blw.FileTelemetryEnabled, 0, 0) != 0) && deleteOnClose;

    // 四类都不需要 -> 直接放行,绝不解析文件名(性能关键)。
    // FltGetFileNameInformation 是昂贵调用,系统每秒数千次 CREATE 全做会显著拖慢 I/O。
    if (!needHardCheck && !needProtCheck && !needNoLoadCheck && !needTelemetry) {
        // 仍需检查影子模式:影子进程的 delete-on-close 需被拦截(防真实删除)。
        if (!BlwPidIsShadow(HandleToULong(PsGetCurrentProcessId()))) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        if (!deleteOnClose) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        // 影子进程 + delete-on-close:需要解析文件名后拦截
        needHardCheck = FALSE;
        needProtCheck = FALSE;
        needNoLoadCheck = FALSE;
        needTelemetry = TRUE;  // 复用遥测路径做上报
    }

    status = FltGetFileNameInformation(
        Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    FltParseFileNameInformation(nameInfo);

    //
    // 1) 文件硬拦截:命中名单且为写/删意图打开 -> 内核本地直接拒绝(只读打开已被
    //    needHardCheck 排除,因此读取这些文件不受影响)。比受保护路径更强:不仅防
    //    删除/重命名,还防内容篡改(任何带写权限的打开都被拒)。零 IPC、零等待。
    //
    if (needHardCheck && BlwFileIsHardBlocked(&nameInfo->Name)) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        BlwReportFileBlock(BlwEventFileDelete, &nameInfo->Name);  // 异步记录,不阻塞
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_COMPLETE;
    }

    //
    // 1b) 禁止加载名单:命中且本次为执行/映射意图打开 -> 内核本地直接拒绝。
    //     使已确认恶意的侧载 DLL/EXE 无法被任何进程加载(即便宿主是合法签名进程)。
    //     只读数据访问不受影响(executeIntent 已排除)。专治白加黑。
    //
    if (needNoLoadCheck && BlwFileIsNoLoad(&nameInfo->Name)) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        BlwReportFileBlock(BlwEventImageBlocked, &nameInfo->Name);  // 异步记录,不阻塞
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_COMPLETE;
    }

    //
    // 2) 受保护路径(原逻辑):仅针对 delete-on-close 的删除意图。命中即拒绝。
    //    受保护路径是用户态显式下发的高价值反篡改目标(SAM/hosts/sethc/启动项/任务计划等)。
    //
    if (needProtCheck && BlwPathIsProtected(&nameInfo->Name)) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        BlwReportFileBlock(BlwEventFileDelete, &nameInfo->Name);  // 异步记录,不阻塞
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_COMPLETE;   // 拒绝该操作
    }

    //
    // 3) 行为遥测:未命中任何名单的 delete-on-close(打开即删除)。不拦截,
    //    仅 fire-and-forget 上报供用户态勒索时序聚合(批量删除原文件是加密型勒索的常见步骤)。
    //
    if (needTelemetry) {
        BlwReportFileTelemetry(BlwEventFileDelete, &nameInfo->Name);
    }

    //
    // 4) 影子模式(沙盒):影子进程的 delete-on-close / 写意图打开。
    //    观察模式(ShadowObserveMode):全部放行,但上报行为事件,由用户态会话后回滚。
    //    拦截模式(默认):拦截破坏性操作,放行写入。
    //
    if (BlwPidIsShadow(HandleToULong(PsGetCurrentProcessId()))) {
        BOOLEAN observe = InterlockedCompareExchange(&g_Blw.ShadowObserveMode, 0, 0) != 0;
        if (observe) {
            // 观察模式:全部放行,但上报行为(文件删除/创建)供用户态回滚。
            if (deleteOnClose || writeOrDeleteIntent) {
                ULONG evtType = deleteOnClose ? BlwEventFileDelete : BlwEventShadowFileCreate;
                BlwReportFileBlock(evtType, &nameInfo->Name);
            }
            // 不拦截,让操作真实执行。
        } else {
            // 拦截模式:阻止删除,放行写入并记录。
            if (deleteOnClose) {
                Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                Data->IoStatus.Information = 0;
                BlwReportFileBlock(BlwEventFileDelete, &nameInfo->Name);
                FltReleaseFileNameInformation(nameInfo);
                return FLT_PREOP_COMPLETE;
            }
            if (writeOrDeleteIntent) {
                BOOLEAN criticalDir =
                    BlwMatchInList(g_Blw.ProtectedPaths, &nameInfo->Name) ||
                    BlwWideContainsCI(nameInfo->Name.Buffer,
                        nameInfo->Name.Length / sizeof(WCHAR),
                        L"\\System32\\Tasks\\");
                if (criticalDir) {
                    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                    Data->IoStatus.Information = 0;
                    BlwReportFileBlock(BlwEventFileDelete, &nameInfo->Name);
                    FltReleaseFileNameInformation(nameInfo);
                    return FLT_PREOP_COMPLETE;
                }
                BlwReportFileBlock(BlwEventShadowFileCreate, &nameInfo->Name);
            }
        }
    }

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

//
// IRP_MJ_SET_INFORMATION:关注删除标记与重命名。
//
FLT_PREOP_CALLBACK_STATUS
BlwPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    FILE_INFORMATION_CLASS infoClass;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;
    ULONG eventType;
    BOOLEAN interesting = FALSE;

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    if (!g_Blw.Active) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    switch (infoClass) {
    case FileDispositionInformation:
    case FileDispositionInformationEx:
        eventType = BlwEventFileDelete;
        interesting = TRUE;
        break;
    case FileRenameInformation:
    case FileRenameInformationEx:
        eventType = BlwEventFileRename;
        interesting = TRUE;
        break;
    default:
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!interesting) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // 既无受保护路径、又无文件硬拦截名单、又未开启文件行为遥测 -> 直接放行,
    // 跳过昂贵的文件名解析(每秒大量 SetInfo 全做会拖慢系统)。
    {
        BOOLEAN telemetryOn =
            InterlockedCompareExchange(&g_Blw.FileTelemetryEnabled, 0, 0) != 0;
        if (g_Blw.ProtectedPathCount == 0 && g_Blw.FileHardCount == 0 && !telemetryOn) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
    }

    status = FltGetFileNameInformation(
        Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    FltParseFileNameInformation(nameInfo);

    // 本地裁决:命中文件硬拦截名单 或 受保护路径,即直接拦截删除标记/重命名,不发同步 IPC。
    if ((g_Blw.FileHardCount > 0 && BlwFileIsHardBlocked(&nameInfo->Name)) ||
        (g_Blw.ProtectedPathCount > 0 && BlwPathIsProtected(&nameInfo->Name))) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        BlwReportFileBlock(eventType, &nameInfo->Name);  // 异步记录,不阻塞
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_COMPLETE;
    }

    //
    // 影子模式(沙盒):影子进程的删除标记/重命名 -> 拦截并记录"影子:拦截了X操作"。
    // 影子进程不应真正删除或重命名文件(破坏性操作),但允许写入(见 BlwPreWrite)。
    //
    if (BlwPidIsShadow(HandleToULong(PsGetCurrentProcessId()))) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        BlwReportFileBlock(eventType, &nameInfo->Name);  // 记录"影子:拦截了删除/重命名"
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_COMPLETE;
    }

    // 未命中任何名单的正常删除/重命名:不拦截,但若遥测开启则 fire-and-forget 上报,
    // 供用户态做勒索行为时序聚合(批量改写 / 扩展名同化 / 蜜罐触碰)。
    BlwReportFileTelemetry(eventType, &nameInfo->Name);

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

//
// IRP_MJ_WRITE:就地加密检测(采样遥测,绝不拦截)。
//
// 勒索软件除了"改名/删除原文件",更常见的是【打开文件 -> 从头覆写密文 -> 同名保存】,
// 这类就地加密既不改名也不删除,前面的 SET_INFORMATION 钩子抓不到。本钩子用极低成本的
// 采样把"用户态进程从文件头(偏移 0)发起写入"这一事实异步上报,喂给用户态勒索时序聚合
// (批量改写速率)。设计铁律:
//   * 仅遥测开启时才工作;关闭时第一行就返回,零开销。
//   * 只对【偏移 0 起写】采样 —— 加密通常重写整个文件,首块必从 0 写起;
//     普通追加写(日志/数据库)偏移非 0,直接放行,避免海量正常写入触发上报。
//   * 进程级采样:同一进程每 N 次符合条件的写才解析一次文件名并上报,
//     用全局计数器做廉价节流,绝不每次写都解析文件名(FltGetFileNameInformation 昂贵)。
//   * 绝不拦截、绝不发同步 IPC:只 fire-and-forget 入队,队列满即丢。
//
FLT_PREOP_CALLBACK_STATUS
BlwPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;
    LARGE_INTEGER byteOffset;
    LONG sample;

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    // 1) 遥测未开启 -> 立即放行(零开销,这是热路径的第一道闸)。
    if (InterlockedCompareExchange(&g_Blw.FileTelemetryEnabled, 0, 0) == 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (!g_Blw.Active) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    // 2) 内核态发起的写不关注(分页写/系统缓存回写等),避免噪声与重入。
    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    // 3) 只看"从文件头(偏移 0)起写"——加密重写整文件的首块特征。
    //    普通追加/随机写偏移非 0,直接放行(占绝大多数写,零解析开销)。
    byteOffset = Data->Iopb->Parameters.Write.ByteOffset;
    if (byteOffset.QuadPart != 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // 4) 采样节流:每 BLW_WRITE_SAMPLE_RATE 次"偏移 0 写"才真正解析并上报一次。
    //    用全局原子计数器做廉价取模,避免对每次写都做昂贵的文件名解析。
    //    勒索批量加密会产生大量"偏移 0 写",采样足以让用户态在窗口内聚合出高速率。
    sample = InterlockedIncrement(&g_Blw.WriteSampleCounter);
    if ((sample % BLW_WRITE_SAMPLE_RATE) != 0) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // 5) 文件名解析只能在 PASSIVE_LEVEL 安全进行;否则跳过本次采样(下次再说)。
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetFileNameInformation(
        Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    FltParseFileNameInformation(nameInfo);

    // fire-and-forget 上报为"重命名/改写"类遥测(用户态映射为 FileWrite 喂勒索聚合)。
    BlwReportFileTelemetry(BlwEventFileRename, &nameInfo->Name);

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
