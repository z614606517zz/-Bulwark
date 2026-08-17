/*++
    Cleanup.c
    内核级足迹清理:读取 / 强制删除【被独占锁定或已映射】的文件。

    为什么必须由驱动做:
      用户态清理恶意足迹时常遇到两种打不开:
        1) 目标被恶意进程以受限共享模式(甚至完全独占)持有 —— CreateFile 直接共享冲突;
        2) 目标是正在运行的 exe / 已加载的 dll —— 映像区占用,DeleteFile 必然失败。
      内核可以用 IoCreateFileEx + IO_IGNORE_SHARE_ACCESS_CHECK 绕过【共享访问检查】把它打开,
      再用 POSIX 语义删除把它立即从目录命名空间移除(数据在最后一个句柄关闭时回收)。
      这是用户态无论如何都做不到的一步,所以放在驱动里。

    对外只有两个入口,均由 Comms.c 在收到 BLW_CMD_QUARANTINE_READ / BLW_CMD_FORCE_DELETE
    时调用(即 BlwMessageNotify 路径,PASSIVE_LEVEL):
      * BlwCleanupReadFile   —— 纯读,供用户态做「可逆金库副本」;绝不改动原文件。
      * BlwCleanupForceDelete —— 强制删除。

    设计铁律:
      * 全程只返回 NTSTATUS,任何失败都交给用户态回退(它本来就有用户态清理与重启后删除两条
        后路),【绝不】因为清理失败而蓝屏。
      * 只在 PASSIVE_LEVEL 工作,入口自查 IRQL。
      * 只 FILE_OPEN(打开既有文件),绝不创建;只 FILE_NON_DIRECTORY_FILE,绝不碰目录。
      * 强制删除前必须过两道「不许删自己」的护栏:按入参路径预判 + 按打开后的真实文件名权威判定
        (见 BlwCleanupTargetIsProtected / BlwCleanupHandleIsProtected)。
--*/

#include "Driver.h"

// 部分旧 SDK 头未定义这些常量时兜底(WDK 10 均已定义,#ifndef 仅为稳妥)。
#ifndef IO_IGNORE_SHARE_ACCESS_CHECK
#define IO_IGNORE_SHARE_ACCESS_CHECK 0x0800
#endif
#ifndef FILE_DISPOSITION_DELETE
#define FILE_DISPOSITION_DELETE 0x00000001
#endif
#ifndef FILE_DISPOSITION_POSIX_SEMANTICS
#define FILE_DISPOSITION_POSIX_SEMANTICS 0x00000002
#endif
#ifndef FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE
#define FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE 0x00000010
#endif

//
// 把用户态给的路径规范成可用于内核打开的 NT 路径。
// 已是 NT 路径(以 '\' 开头,含 \??\、\Device\)原样;X:\... 这类 Win32 盘符路径补 \??\ 前缀。
//
static NTSTATUS
BlwBuildNtPath(_In_ PCWSTR InPath, _Out_writes_(OutChars) PWCHAR OutBuf, _In_ USHORT OutChars)
{
    UNICODE_STRING in;

    RtlInitUnicodeString(&in, InPath);
    if (in.Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InPath[0] == L'\\') {
        // 已是 NT 路径(\??\... 或 \Device\...):原样拷贝。
        USHORT chars = (USHORT)(in.Length / sizeof(WCHAR));
        if ((ULONG)chars + 1 > OutChars) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        RtlCopyMemory(OutBuf, InPath, in.Length);
        OutBuf[chars] = L'\0';
        return STATUS_SUCCESS;
    }

    // Win32 盘符路径:补 \??\ 前缀。
    {
        static const WCHAR pfx[] = { L'\\', L'?', L'?', L'\\' };
        USHORT chars = (USHORT)(in.Length / sizeof(WCHAR));
        USHORT need = (USHORT)(4 + chars);
        if ((ULONG)need + 1 > OutChars) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        RtlCopyMemory(OutBuf, pfx, sizeof(pfx));
        RtlCopyMemory(OutBuf + 4, InPath, in.Length);
        OutBuf[need] = L'\0';
        return STATUS_SUCCESS;
    }
}

//
// 【自毁护栏】目标是否属于「本产品自身内容」或「绝不允许被改一次的关键文件」。
//
// 这条命令以内核态发起、忽略共享访问检查、POSIX 语义删除,连正在运行的 exe / 已加载的 dll 都能
// 从命名空间里摘掉 —— 换句话说,只要用户态算错一次路径,就能把服务二进制、UI、甚至驱动自己的
// .sys 删掉;而本驱动的自保(SelfGuard / FileHardBlock)拦的是【用户态 I/O】,拦不住内核自己
// 发起的这一刀。
//
// 因此这里拿同一份自保名单反向校验一次:命中即拒绝执行。恶意样本的落地路径不会出现在自保名单里,
// 所以这道闸不会造成漏杀;判不出来时(路径为空)一律按命中处理,宁可拒绝也不误删。
//
// 只用于删除。读取是纯读、不改动任何东西,不受此限制(否则连自己的文件都没法做金库副本)。
//
// 这道闸查两次,因为单查入参字符串是不够的:
//   1) 开文件【之前】先拿入参字符串查一遍 —— 便宜,能挡住绝大多数情况,且连打开都省了;
//   2) 开文件【之后】再拿【规范化名】查一遍 —— 这次才是权威的。入参字符串可能是 8.3 短名
//      (C:\PROGRA~1\BULWAR~1\x.exe)或经挂载点/符号链接绕过来的形式,那样第 1 步的长名子串
//      根本匹配不上,闸就形同虚设。规范化名会把短名、挂载点、符号链接统一解开,而且它正是
//      BlwPreCreate 里名单本来被匹配的形式,所以判定口径也一致。
//
// 顺带说明为什么不能指望「本驱动自己的 BlwPreCreate 会拦住这次打开」:自保是 owner-aware 的,
// 而发起这条命令的服务进程本身就在受保护 PID 集里 -> 会被豁免。要防的恰恰是「服务算错路径」,
// 所以必须在这里自己再判一次。
//
static BOOLEAN
BlwCleanupMatchesSelfLists(_In_ PCUNICODE_STRING Target)
{
    BLW_MATCH_CTX ctx;

    if (Target == NULL || Target->Length == 0) {
        return TRUE;   // 判不了 -> 当作命中,拒绝
    }

    BlwPrepareMatch(&ctx, Target);

    if (g_Blw.SelfGuardCount > 0 && BlwFileIsSelfGuarded(&ctx)) {
        return TRUE;
    }
    if (g_Blw.FileHardCount > 0 && BlwFileIsHardBlocked(&ctx)) {
        return TRUE;
    }
    return FALSE;
}

// 第 1 步:按入参字符串预判(便宜,能挡住绝大多数情况)。
static BOOLEAN
BlwCleanupTargetIsProtected(_In_ PCWSTR Path)
{
    UNICODE_STRING us;

    RtlInitUnicodeString(&us, Path);
    if (us.Length == 0) {
        return TRUE;
    }
    // 名单是「大小写不敏感子串」匹配,与路径是 Win32 形式还是 NT 形式无关,可直接匹配原串。
    return BlwCleanupMatchesSelfLists(&us);
}

//
// 第 2 步:按已打开句柄的【文件系统自己的名字】权威判定。
//
// 用 ZwQueryInformationFile(FileNameInformation) 而不是 FltGetFileNameInformationUnsafe:
//   * 前者是文件系统的基本查询,NTFS/FAT/ReFS 一律可靠支持,不需要拿 FLT_INSTANCE;
//     后者传 Instance=NULL 时能否给出规范化名要看名字提供者,一旦它常态性失败,而本函数又是
//     「取不到名字就拒绝」的语义,就会把整个强制删除功能悄悄废掉 —— 那种失败模式不可接受。
//   * FileNameInformation 返回的是【卷内绝对路径】(如 \Program Files\Bulwark\x.exe):
//     已是长名(短名会被解开)、不含盘符。这正好和自保名单的写法对齐 —— 名单必须是与卷无关的
//     子串(否则在 BlwPreCreate 里对着 \Device\HarddiskVolumeN\... 也匹配不上),所以少了盘符
//     前缀完全不影响判定。
//
// 名字比缓冲长时(STATUS_BUFFER_OVERFLOW)按拿到的前缀判定即可:自保名单命中的是目录部分,
// 而目录部分正好在路径开头,前缀足够。只有【查询彻底失败】才按命中处理(拒绝删除)——
// 这时用户态收到失败状态,照常回退到用户态清理 / 重启后删除,产品行为只是降级,不会中断。
//
static BOOLEAN
BlwCleanupHandleIsProtected(_In_ HANDLE FileHandle)
{
    // FILE_NAME_INFORMATION 头 + 最多 BLW_MAX_PATH 个字符。走分页池:本操作极低频,
    // 分配成本无关紧要,不值得为它在栈上再压 1KB。
    const ULONG cbInfo = (ULONG)(sizeof(FILE_NAME_INFORMATION) + BLW_MAX_PATH * sizeof(WCHAR));
    PFILE_NAME_INFORMATION info;
    IO_STATUS_BLOCK iosb;
    UNICODE_STRING name;
    NTSTATUS status;
    BOOLEAN protectedTarget = TRUE;   // 判不出来就拒绝
    ULONG chars;

    info = (PFILE_NAME_INFORMATION)BlwAllocPool(PagedPool, cbInfo, BLW_TAG);
    if (info == NULL) {
        return TRUE;
    }

    RtlZeroMemory(&iosb, sizeof(iosb));
    status = ZwQueryInformationFile(FileHandle, &iosb, info, cbInfo, FileNameInformation);

    // STATUS_BUFFER_OVERFLOW:名字被截断,但前缀有效,足以判定目录部分。
    if (NT_SUCCESS(status) || status == STATUS_BUFFER_OVERFLOW) {
        chars = info->FileNameLength / sizeof(WCHAR);
        if (chars > BLW_MAX_PATH) {
            chars = BLW_MAX_PATH;      // 截断到缓冲实际容纳的长度
        }
        if (chars > 0) {
            name.Buffer = info->FileName;
            name.Length = (USHORT)(chars * sizeof(WCHAR));
            name.MaximumLength = name.Length;
            protectedTarget = BlwCleanupMatchesSelfLists(&name);
        }
    } else {
        KdPrint(("[Bulwark] Cleanup: FileNameInformation query failed 0x%x, refusing delete.\n",
                 status));
    }

    ExFreePoolWithTag(info, BLW_TAG);
    return protectedTarget;
}

//
// 以「忽略共享访问检查」打开一个既有文件(Disposition=FILE_OPEN,绝不创建)。
// 调用方负责 ZwClose。仅 PASSIVE_LEVEL。
//
// 注意:IoCreateFileEx 不改变调用线程的 previous mode,而本函数是在用户态服务的
// FilterSendMessage 线程上下文里跑的,因此这次打开【可能】被记为用户态发起,从而经过本驱动自己的
// BlwPreCreate。这没有问题:
//   * 删除路径上已经过 BlwCleanupTargetIsProtected 护栏,不会命中自保 / 硬拦名单,不会自我拦截;
//   * BlwPreCreate 是纯本地查表、绝不等待任何东西,所以也不存在重入死锁。
// 后续的 ZwSetInformationFile 是 Zw* 调用(previous mode = KernelMode),本驱动的
// BlwPreSetInformation 对内核态 I/O 直接放行。
//
static NTSTATUS
BlwCleanupOpen(_In_ PCWSTR Path, _In_ ACCESS_MASK Access, _In_ ULONG CreateOptions, _Out_ PHANDLE Handle)
{
    WCHAR ntBuf[BLW_MAX_PATH + 8];
    UNICODE_STRING ntPath;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;

    *Handle = NULL;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    status = BlwBuildNtPath(Path, ntBuf, (USHORT)RTL_NUMBER_OF(ntBuf));
    if (!NT_SUCCESS(status)) {
        return status;
    }
    RtlInitUnicodeString(&ntPath, ntBuf);
    InitializeObjectAttributes(&oa, &ntPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    RtlZeroMemory(&iosb, sizeof(iosb));

    // Options = IO_IGNORE_SHARE_ACCESS_CHECK:I/O 管理器跳过【共享访问检查】,于是能打开被别的
    // 进程以受限共享模式(甚至完全独占)持有的文件 —— 这正是用户态做不到、非驱动不可的关键一步。
    // 注意它只跳过共享检查,【不】跳过 ACL 检查:仍需对目标有相应权限(服务以 SYSTEM 运行)。
    status = IoCreateFileEx(
        Handle,
        Access,
        &oa,
        &iosb,
        NULL,                                                       // AllocationSize
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,                                                  // 只打开既有文件,绝不创建
        CreateOptions,
        NULL, 0,                                                    // EaBuffer / EaLength
        CreateFileTypeNone,
        NULL,                                                       // InternalParameters
        IO_IGNORE_SHARE_ACCESS_CHECK,                               // Options
        NULL);                                                      // DriverContext
    return status;
}

//
// 读取被占用文件的一段到 Buffer(内核缓冲)。到达文件尾返回成功且 *BytesRead=0。仅 PASSIVE_LEVEL。
// 纯读:不改文件内容、不改时间戳语义之外的任何东西。
//
NTSTATUS
BlwCleanupReadFile(_In_ PCWSTR Path, _In_ ULONG64 Offset,
                   _Out_writes_bytes_(BufLen) PVOID Buffer, _In_ ULONG BufLen, _Out_ PULONG BytesRead)
{
    HANDLE h = NULL;
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER off;
    NTSTATUS status;

    *BytesRead = 0;
    if (Buffer == NULL || BufLen == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    status = BlwCleanupOpen(Path, FILE_READ_DATA | SYNCHRONIZE,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT, &h);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(&iosb, sizeof(iosb));
    off.QuadPart = (LONGLONG)Offset;
    status = ZwReadFile(h, NULL, NULL, NULL, &iosb, Buffer, BufLen, &off, NULL);
    if (status == STATUS_END_OF_FILE) {
        status = STATUS_SUCCESS;   // 文件尾:读到 0 字节,用户态据此结束分块循环
        iosb.Information = 0;
    }
    if (NT_SUCCESS(status)) {
        *BytesRead = (ULONG)iosb.Information;
    }
    ZwClose(h);
    return status;
}

//
// 强制删除被占用 / 已映射的文件(POSIX 语义:仍有句柄打开也可立即从命名空间移除)。
// 仅 PASSIVE_LEVEL。返回 STATUS_SUCCESS 表示确实删掉了。
//
NTSTATUS
BlwCleanupForceDelete(_In_ PCWSTR Path)
{
    HANDLE h = NULL;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;
    FILE_DISPOSITION_INFORMATION_EX dispEx;
    FILE_DISPOSITION_INFORMATION disp;

    // 自毁护栏第 1 步:按入参字符串预判,命中即连文件都不打开。
    if (BlwCleanupTargetIsProtected(Path)) {
        KdPrint(("[Bulwark] Force-delete refused by path pre-check (self/hard-block): %ws\n", Path));
        return STATUS_ACCESS_DENIED;
    }

    status = BlwCleanupOpen(Path, DELETE | SYNCHRONIZE,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT, &h);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // 自毁护栏第 2 步(权威):按已打开句柄的规范化名再判一次,挡住 8.3 短名 / 挂载点 /
    // 符号链接绕过第 1 步的情况。此时还只拿到 DELETE 访问权、尚未下删除标记,拒绝是干净的。
    if (BlwCleanupHandleIsProtected(h)) {
        KdPrint(("[Bulwark] Force-delete refused by normalized-name check (self/hard-block): %ws\n", Path));
        ZwClose(h);
        return STATUS_ACCESS_DENIED;
    }

    // 首选:POSIX 强制删除 —— 即便别的进程仍持有该文件句柄,也立即把它从目录命名空间移除
    // (数据在最后一个句柄关闭时回收),并忽略只读属性。这才能删掉用户态删不掉的被占用文件。
    RtlZeroMemory(&iosb, sizeof(iosb));
    RtlZeroMemory(&dispEx, sizeof(dispEx));
    dispEx.Flags = FILE_DISPOSITION_DELETE | FILE_DISPOSITION_POSIX_SEMANTICS
                 | FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE;
    status = ZwSetInformationFile(h, &iosb, &dispEx, sizeof(dispEx), FileDispositionInformationEx);
    if (!NT_SUCCESS(status)) {
        // 回退:基础删除标记(文件系统不支持 Ex 时,如某些旧卷)。
        RtlZeroMemory(&iosb, sizeof(iosb));
        disp.DeleteFile = TRUE;
        status = ZwSetInformationFile(h, &iosb, &disp, sizeof(disp), FileDispositionInformation);
    }

    ZwClose(h);
    return status;
}
