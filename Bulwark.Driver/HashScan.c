/*++
    HashScan.c
    内核本地「事后研判」:用内置的已知恶意 SHA-256 集合(离线情报)对新建进程的映像做
    异步哈希扫描,命中即结束该进程(BlwKillProcessById)。使驱动在【无用户态、无网络】时
    也能自主识别并处置已知恶意样本 —— 这是「内核自足基线」的检测侧补充。

    设计铁律(与全局「零同步 IPC / 热路径零阻塞」一致):
      * 绝不在进程创建回调里读文件 / 算哈希(那是重 I/O,会拖垮进程创建热路径)。
        回调只把 PID 入队(自旋锁下写一个环形缓冲,微秒级),真正的读文件 + SHA-256 由
        独立系统线程在 PASSIVE_LEVEL 完成 —— 这就是「事后」:样本已启动,worker 稍后
        (通常几十毫秒内)算完哈希,命中则结束它。
      * 默认惰性:已知恶意集为空(默认)时,进程创建回调【根本不入队】(见 ProcessMonitor
        的 KnownBadCount>0 判空),本文件的重逻辑一律不触发 —— 风险路径需显式配置情报才启用。
      * SHA-256 为自带纯 C 实现(不依赖 BCrypt / ksecdd 等内核加密 API):即便实现有误,
        后果也只是「算出的摘要不匹配 -> 不处置」(fail-safe),绝不会因外部 API 行为不确定而蓝屏。
      * worker 通过 PsLookupProcessByProcessId 现取 PID 对应进程与映像:进程已退出则跳过;
        PID 复用也安全(哈希的是当前占用该 PID 的映像,命中即应处置)。
--*/

#include "Driver.h"

// ============================ SHA-256(自带纯 C 实现)============================

typedef struct _BLW_SHA256_CTX {
    ULONG   state[8];
    ULONG64 bitlen;
    UCHAR   data[64];
    ULONG   datalen;
} BLW_SHA256_CTX;

#define BLW_ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define BLW_SHR(x,n)  ((x) >> (n))
#define BLW_CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define BLW_MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BLW_EP0(x)  (BLW_ROTR(x,2)  ^ BLW_ROTR(x,13) ^ BLW_ROTR(x,22))
#define BLW_EP1(x)  (BLW_ROTR(x,6)  ^ BLW_ROTR(x,11) ^ BLW_ROTR(x,25))
#define BLW_SIG0(x) (BLW_ROTR(x,7)  ^ BLW_ROTR(x,18) ^ BLW_SHR(x,3))
#define BLW_SIG1(x) (BLW_ROTR(x,17) ^ BLW_ROTR(x,19) ^ BLW_SHR(x,10))

static const ULONG g_Sha256K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void
BlwSha256Init(_Out_ BLW_SHA256_CTX* c)
{
    c->datalen = 0;
    c->bitlen = 0;
    c->state[0] = 0x6a09e667; c->state[1] = 0xbb67ae85;
    c->state[2] = 0x3c6ef372; c->state[3] = 0xa54ff53a;
    c->state[4] = 0x510e527f; c->state[5] = 0x9b05688c;
    c->state[6] = 0x1f83d9ab; c->state[7] = 0x5be0cd19;
}

static void
BlwSha256Transform(_Inout_ BLW_SHA256_CTX* c, _In_reads_(64) const UCHAR* data)
{
    ULONG a, b, d, e, f, g, h, i, j, t1, t2, m[64];
    ULONG cc;

    for (i = 0, j = 0; i < 16; i++, j += 4) {
        m[i] = ((ULONG)data[j] << 24) | ((ULONG)data[j + 1] << 16) |
               ((ULONG)data[j + 2] << 8) | ((ULONG)data[j + 3]);
    }
    for (; i < 64; i++) {
        m[i] = BLW_SIG1(m[i - 2]) + m[i - 7] + BLW_SIG0(m[i - 15]) + m[i - 16];
    }

    a = c->state[0]; b = c->state[1]; cc = c->state[2]; d = c->state[3];
    e = c->state[4]; f = c->state[5]; g = c->state[6]; h = c->state[7];

    for (i = 0; i < 64; i++) {
        t1 = h + BLW_EP1(e) + BLW_CH(e, f, g) + g_Sha256K[i] + m[i];
        t2 = BLW_EP0(a) + BLW_MAJ(a, b, cc);
        h = g; g = f; f = e; e = d + t1;
        d = cc; cc = b; b = a; a = t1 + t2;
    }

    c->state[0] += a; c->state[1] += b; c->state[2] += cc; c->state[3] += d;
    c->state[4] += e; c->state[5] += f; c->state[6] += g; c->state[7] += h;
}

//
// 喂数据。原实现是逐字节 copy + 每字节判一次是否满 64 —— 对一个 64KB 的读块就是 65536 次
// 循环迭代和 65536 次分支。这里改为:先补满当前不完整的块,然后【整块直接压缩,完全不经过
// 中间缓冲】,最后把剩余不足一块的尾部存起来。摘要结果完全相同,只是少了逐字节搬运。
//
static void
BlwSha256Update(_Inout_ BLW_SHA256_CTX* c, _In_reads_(len) const UCHAR* data, _In_ ULONG len)
{
    ULONG offset = 0;

    // 1) 若当前有半块残留,先把它补满并压缩。
    if (c->datalen != 0) {
        ULONG need = 64 - c->datalen;
        if (len < need) {
            RtlCopyMemory(&c->data[c->datalen], data, len);
            c->datalen += len;
            return;
        }
        RtlCopyMemory(&c->data[c->datalen], data, need);
        BlwSha256Transform(c, c->data);
        c->bitlen += 512;
        c->datalen = 0;
        offset = need;
    }

    // 2) 整块直接压缩(不再逐字节搬进 c->data)。
    while (offset + 64 <= len) {
        BlwSha256Transform(c, &data[offset]);
        c->bitlen += 512;
        offset += 64;
    }

    // 3) 剩余尾部留到下次 / Final 处理。
    if (offset < len) {
        c->datalen = len - offset;
        RtlCopyMemory(c->data, &data[offset], c->datalen);
    }
}

static void
BlwSha256Final(_Inout_ BLW_SHA256_CTX* c, _Out_writes_(32) UCHAR* hash)
{
    ULONG i = c->datalen;

    // 填充
    if (c->datalen < 56) {
        c->data[i++] = 0x80;
        while (i < 56) c->data[i++] = 0x00;
    } else {
        c->data[i++] = 0x80;
        while (i < 64) c->data[i++] = 0x00;
        BlwSha256Transform(c, c->data);
        RtlZeroMemory(c->data, 56);
    }

    c->bitlen += (ULONG64)c->datalen * 8;
    c->data[63] = (UCHAR)(c->bitlen);
    c->data[62] = (UCHAR)(c->bitlen >> 8);
    c->data[61] = (UCHAR)(c->bitlen >> 16);
    c->data[60] = (UCHAR)(c->bitlen >> 24);
    c->data[59] = (UCHAR)(c->bitlen >> 32);
    c->data[58] = (UCHAR)(c->bitlen >> 40);
    c->data[57] = (UCHAR)(c->bitlen >> 48);
    c->data[56] = (UCHAR)(c->bitlen >> 56);
    BlwSha256Transform(c, c->data);

    // 大端输出 32 字节
    for (i = 0; i < 4; i++) {
        hash[i]      = (UCHAR)((c->state[0] >> (24 - i * 8)) & 0xff);
        hash[i + 4]  = (UCHAR)((c->state[1] >> (24 - i * 8)) & 0xff);
        hash[i + 8]  = (UCHAR)((c->state[2] >> (24 - i * 8)) & 0xff);
        hash[i + 12] = (UCHAR)((c->state[3] >> (24 - i * 8)) & 0xff);
        hash[i + 16] = (UCHAR)((c->state[4] >> (24 - i * 8)) & 0xff);
        hash[i + 20] = (UCHAR)((c->state[5] >> (24 - i * 8)) & 0xff);
        hash[i + 24] = (UCHAR)((c->state[6] >> (24 - i * 8)) & 0xff);
        hash[i + 28] = (UCHAR)((c->state[7] >> (24 - i * 8)) & 0xff);
    }
}

// ============================ 已知恶意集合管理 ============================

// 把一个十六进制字符转成 0..15,非法返回 0xFF。
static UCHAR
BlwHexVal(_In_ WCHAR c)
{
    if (c >= L'0' && c <= L'9') return (UCHAR)(c - L'0');
    if (c >= L'a' && c <= L'f') return (UCHAR)(10 + c - L'a');
    if (c >= L'A' && c <= L'F') return (UCHAR)(10 + c - L'A');
    return 0xFF;
}

void
BlwClearKnownBad(void)
{
    ExAcquireFastMutex(&g_Blw.KnownBadLock);
    RtlZeroMemory(g_Blw.KnownBadHashes, sizeof(g_Blw.KnownBadHashes));
    InterlockedExchange(&g_Blw.KnownBadCount, 0);
    ExReleaseFastMutex(&g_Blw.KnownBadLock);
}

// 追加一条已知恶意 SHA-256(以 64 个十六进制宽字符表示)。非法长度/字符则忽略。
void
BlwAddKnownBadHex(_In_ PCWSTR Hex, _In_ USHORT Length)
{
    UCHAR digest[32];
    USHORT i;

    if (Hex == NULL || Length != 64) {
        return;   // SHA-256 必须是 64 个十六进制字符
    }

    for (i = 0; i < 32; i++) {
        UCHAR hi = BlwHexVal(Hex[i * 2]);
        UCHAR lo = BlwHexVal(Hex[i * 2 + 1]);
        if (hi == 0xFF || lo == 0xFF) {
            return;   // 含非法字符,整条丢弃
        }
        digest[i] = (UCHAR)((hi << 4) | lo);
    }

    ExAcquireFastMutex(&g_Blw.KnownBadLock);
    if (g_Blw.KnownBadCount < BLW_MAX_HASHES) {
        // 去重(线性,配置期低频)
        BOOLEAN dup = FALSE;
        LONG n = g_Blw.KnownBadCount, k;
        for (k = 0; k < n; k++) {
            if (RtlEqualMemory(g_Blw.KnownBadHashes[k], digest, 32)) {
                dup = TRUE;
                break;
            }
        }
        if (!dup) {
            RtlCopyMemory(g_Blw.KnownBadHashes[g_Blw.KnownBadCount], digest, 32);
            InterlockedIncrement(&g_Blw.KnownBadCount);
        }
    }
    ExReleaseFastMutex(&g_Blw.KnownBadLock);
}

static BOOLEAN
BlwIsKnownBad(_In_reads_(32) const UCHAR* digest)
{
    BOOLEAN hit = FALSE;
    LONG n, i;

    ExAcquireFastMutex(&g_Blw.KnownBadLock);
    n = g_Blw.KnownBadCount;
    for (i = 0; i < n; i++) {
        // RtlEqualMemory 是 memcmp==0,首个不同字节就短路返回;RtlCompareMemory 则要
        // 一路数完「相同的字节数」,对必然不匹配的绝大多数条目纯属多做。
        if (RtlEqualMemory(g_Blw.KnownBadHashes[i], digest, 32)) {
            hit = TRUE;
            break;
        }
    }
    ExReleaseFastMutex(&g_Blw.KnownBadLock);
    return hit;
}

// ============================ 文件读取 + 哈希 ============================

#define BLW_HASH_CHUNK    (64 * 1024)
#define BLW_HASH_MAX_SIZE (128ULL * 1024 * 1024)   // 超过 128MB 不哈希(极少是恶意样本)

//
// 计算 NT 路径文件的 SHA-256。全程 PASSIVE_LEVEL(worker 线程)。成功返回 STATUS_SUCCESS。
//
// Buf 由调用方提供(worker 线程整个生命周期只分配一次的 BLW_HASH_CHUNK 缓冲)。原实现在
// 每扫一个文件时都做一次 64KB 分页池分配 + 释放 —— 开机 / 登录期间一批新进程就是一批
// 64KB 的分配抖动,而这块内存的用途完全一样,没有任何必要反复申请。
//
static NTSTATUS
BlwComputeFileSha256(
    _In_ PUNICODE_STRING NtPath,
    _Out_writes_(32) UCHAR* OutDigest,
    _In_reads_bytes_(BLW_HASH_CHUNK) PUCHAR buf)
{
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE hFile = NULL;
    NTSTATUS status;
    BLW_SHA256_CTX ctx;
    ULONG64 total = 0;

    RtlZeroMemory(OutDigest, 32);

    if (NtPath == NULL || NtPath->Buffer == NULL || NtPath->Length == 0 || buf == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    InitializeObjectAttributes(&oa, NtPath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ZwCreateFile(&hFile, FILE_READ_DATA | SYNCHRONIZE, &oa, &iosb, NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL, 0);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    BlwSha256Init(&ctx);
    for (;;) {
        RtlZeroMemory(&iosb, sizeof(iosb));
        status = ZwReadFile(hFile, NULL, NULL, NULL, &iosb,
            buf, BLW_HASH_CHUNK, NULL, NULL);
        if (!NT_SUCCESS(status) || iosb.Information == 0) {
            if (status == STATUS_END_OF_FILE) {
                status = STATUS_SUCCESS;
            }
            break;
        }
        BlwSha256Update(&ctx, buf, (ULONG)iosb.Information);
        total += iosb.Information;
        if (total > BLW_HASH_MAX_SIZE) {
            status = STATUS_FILE_TOO_LARGE;   // 放弃(fail-safe:不产生可匹配的摘要)
            break;
        }
    }

    if (NT_SUCCESS(status)) {
        BlwSha256Final(&ctx, OutDigest);
    }

    ZwClose(hFile);
    return status;
}

// ============================ 命中处置 + 异步 worker ============================

// 对确认为已知恶意的进程上报一条事件(供用户态记录,无客户端时自动跳过)。
static void
BlwReportHashHit(_In_ ULONG pid, _In_ PUNICODE_STRING image)
{
    // 「已阻断」信息型。两个路径字段都填,兼容用户态取任一字段。内部自带 Active 判空。
    BlwReportEvent(BlwEventImageBlocked, pid, 0, image, image, 0, 0);
}

// 处理一个待扫描 PID:现取进程 -> 取映像路径 -> 哈希 -> 命中已知恶意则结束进程。
// buf 为 worker 复用的读缓冲(见 BlwComputeFileSha256)。
static void
BlwProcessHashScan(_In_ ULONG pid, _In_ PUCHAR buf)
{
    PEPROCESS proc = NULL;
    PUNICODE_STRING imageName = NULL;
    NTSTATUS status;
    UCHAR digest[32];

    if (pid <= 4) {
        return;
    }

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &proc);
    if (!NT_SUCCESS(status) || proc == NULL) {
        return;   // 进程已退出
    }

    status = SeLocateProcessImageName(proc, &imageName);
    if (NT_SUCCESS(status) && imageName != NULL &&
        imageName->Buffer != NULL && imageName->Length > 0) {

        if (NT_SUCCESS(BlwComputeFileSha256(imageName, digest, buf)) && BlwIsKnownBad(digest)) {
            KdPrint(("[Bulwark] HashScan: known-bad match, banning + terminating PID %u.\n", pid));
            // 先封禁再结束:一旦内置情报确认恶意,该 PID 的任何后续行为(文件/注册表/网络/子进程)
            // 立即被各回调拒绝 —— 即便下面结束进程被反抗 / 滞后,封禁期间它也一个动作都做不成。
            BlwAddBannedPid(pid);
            BlwReportHashHit(pid, imageName);
            // 结束进程:BlwKillProcessById 自带硬护栏(PID>4 / 非受保护 / 非关键系统进程)。
            (void)BlwKillProcessById(pid);
        }
    }

    if (imageName != NULL) {
        ExFreePool(imageName);
    }
    ObDereferenceObject(proc);
}

// 后台哈希扫描线程:等 PID 入队 -> 逐个处理。所有重 I/O + 哈希都在此,完全不碰热路径。
static VOID
BlwHashWorkerThread(_In_ PVOID Context)
{
    PUCHAR buf;

    UNREFERENCED_PARAMETER(Context);

    // 读缓冲整个线程生命周期只分配一次(原实现每扫一个文件分配 / 释放一次 64KB)。
    buf = (PUCHAR)BlwAllocPool(PagedPool, BLW_HASH_CHUNK, BLW_TAG);
    if (buf == NULL) {
        // 分配不到就直接退出:哈希研判不可用(非致命),其余防护不受影响。
        // 入队方仍会照常入队并因无人消费而自然丢弃,绝不阻塞任何回调。
        KdPrint(("[Bulwark] Hash worker: read buffer alloc failed, scanning disabled.\n"));
        PsTerminateSystemThread(STATUS_SUCCESS);
        return;
    }

    for (;;) {
        KeWaitForSingleObject(&g_Blw.HashRingEvent, Executive, KernelMode, FALSE, NULL);

        for (;;) {
            LONG pid = 0;
            KIRQL oldIrql;
            BOOLEAN haveItem = FALSE;

            KeAcquireSpinLock(&g_Blw.HashRingLock, &oldIrql);
            if (g_Blw.HashRingTail != g_Blw.HashRingHead) {
                pid = g_Blw.HashRing[g_Blw.HashRingTail];
                g_Blw.HashRingTail = (g_Blw.HashRingTail + 1) & BLW_HASH_QUEUE_MASK;
                haveItem = TRUE;
            }
            KeReleaseSpinLock(&g_Blw.HashRingLock, oldIrql);

            if (!haveItem) {
                break;
            }
            BlwProcessHashScan((ULONG)pid, buf);
        }

        if (InterlockedCompareExchange(&g_Blw.HashWorkerStop, 0, 0) != 0) {
            break;
        }
    }

    ExFreePoolWithTag(buf, BLW_TAG);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

// 进程创建回调调用:把 PID 入队(自旋锁下写环 + 唤醒 worker),微秒级返回。满则丢弃。
void
BlwEnqueueHashScan(_In_ ULONG Pid)
{
    KIRQL oldIrql;
    LONG nextHead;
    BOOLEAN queued = FALSE;

    if (g_Blw.HashWorkerThread == NULL) {
        return;   // worker 未就绪
    }

    KeAcquireSpinLock(&g_Blw.HashRingLock, &oldIrql);
    nextHead = (g_Blw.HashRingHead + 1) & BLW_HASH_QUEUE_MASK;
    if (nextHead != g_Blw.HashRingTail) {
        g_Blw.HashRing[g_Blw.HashRingHead] = (LONG)Pid;
        g_Blw.HashRingHead = nextHead;
        queued = TRUE;
    }
    KeReleaseSpinLock(&g_Blw.HashRingLock, oldIrql);

    if (queued) {
        KeSetEvent(&g_Blw.HashRingEvent, IO_NO_INCREMENT, FALSE);
    }
    // 满则丢弃:漏扫一个新进程不致命(下次启动仍会被扫);绝不阻塞进程创建。
}

NTSTATUS
BlwStartHashWorker(void)
{
    HANDLE threadHandle = NULL;
    NTSTATUS status;

    g_Blw.HashRingHead = 0;
    g_Blw.HashRingTail = 0;
    g_Blw.HashWorkerStop = 0;
    KeInitializeSpinLock(&g_Blw.HashRingLock);
    KeInitializeEvent(&g_Blw.HashRingEvent, SynchronizationEvent, FALSE);

    status = PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS,
        NULL, NULL, NULL, BlwHashWorkerThread, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    ObReferenceObjectByHandle(threadHandle, THREAD_ALL_ACCESS, *PsThreadType,
        KernelMode, (PVOID*)&g_Blw.HashWorkerThread, NULL);
    ZwClose(threadHandle);

    KdPrint(("[Bulwark] Hash scan worker started.\n"));
    return STATUS_SUCCESS;
}

void
BlwStopHashWorker(void)
{
    InterlockedExchange(&g_Blw.HashWorkerStop, 1);
    KeSetEvent(&g_Blw.HashRingEvent, IO_NO_INCREMENT, FALSE);

    if (g_Blw.HashWorkerThread != NULL) {
        KeWaitForSingleObject(g_Blw.HashWorkerThread, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(g_Blw.HashWorkerThread);
        g_Blw.HashWorkerThread = NULL;
    }
    KdPrint(("[Bulwark] Hash scan worker stopped.\n"));
}
