/*++
    MatchCore.h
    名单匹配核心 —— 本驱动里【唯一】的字符串/路径判定实现,且【可在用户态编译】。

    ============================ 为什么要单独成文件 ============================

    驱动的拦截面几乎全部建立在「某个串是否命中某份名单」之上:文件硬拦 / 自保足迹 /
    禁止加载 / 禁止执行 / 受保护路径 / 注册表硬拦 / 命令行硬拦,七份名单共用同一套
    匹配基元。这些函数同时具备两个性质:
      * 它们是本驱动最容易出错的地方 —— 项目里已经有过两次实测事故都出在这儿
        (子串包含让 C:\temp\Windows\System32\csrss.exe 白拿关键进程豁免;
         `\WINDOWS\SYSTEM32\CMD.EXE` 进 FileExecBlock 把所有 .bat 钉死);
      * 它们是纯函数 —— 不碰 g_Blw、不取锁、不做 I/O、不依赖任何 IRQL 语义。

    第二条意味着它们可以在用户态原样编译并跑单元测试。这一点在本项目里价值极高:
    内核驱动【不能在开发机上加载】(回调出错直接蓝屏,加载测试只在带快照的 VM 里做),
    所以在此之前,匹配语义的任何改动都只有「编译通过」这一级验证。把这些函数隔离到
    一个不含内核依赖的编译单元后,cpp/tests/DriverMatchTest.cpp 就能把它们的判定逐形态
    钉死 —— 这是目前唯一能在本机对内核判定做出证伪的手段。

    ============================ 两种编译环境 ============================

      * 内核(默认):本头【不包含任何内核头文件】,由 Driver.h 在 include 过
        <fltKernel.h> / <ntddk.h> 之后再 include 它。与项目既有的头文件次序约定一致。
      * 用户态单测:定义 BLW_MATCHCORE_HOST 后,下面的 shim 段自备全部所需类型与宏,
        【刻意不包含 <windows.h>】—— 那会引入 UNICODE_STRING 是否已定义之类的环境差异。

    ============================ 不可破的约定 ============================

      1. 本文件里的一切【绝不】引用 g_Blw、绝不取锁、绝不调用任何只在某个 IRQL 可用的 API。
         线程安全由调用方持锁保证(各 BlwXxxIsYyy 包装函数负责)。
      2. 新增判定时,必须同时在 DriverMatchTest.cpp 里补上对应形态的断言。
      3. 模式串的存储约定(已大写化)见 BLW_PROTECTED_PATH。
--*/

#pragma once

#ifdef BLW_MATCHCORE_HOST

//
// ===================== 用户态(host 单测)编译垫片 =====================
//
// 只补齐本文件与 MatchCore.c 真正用到的类型和宏。故意不含 <windows.h>:
// 那会把「UNICODE_STRING 由哪个头定义」这种环境差异带进来,而我们只需要四个字段。
//
#include <sal.h>
#include <stddef.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>

typedef wchar_t            WCHAR;
typedef unsigned char      UCHAR;
typedef unsigned char      BOOLEAN;
typedef unsigned short     USHORT;
typedef unsigned long      ULONG;
typedef long               LONG;
typedef unsigned long long ULONG64;
typedef size_t             SIZE_T;
typedef const WCHAR*       PCWSTR;
typedef WCHAR*             PWCH;
typedef WCHAR*             PWSTR;
typedef const char*        PCSTR;
typedef void*              PVOID;

typedef struct _BLW_HOST_UNICODE_STRING {
    USHORT Length;          // 字节数(与内核 UNICODE_STRING 完全一致)
    USHORT MaximumLength;
    PWCH   Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;

#ifndef TRUE
#define TRUE  1
#define FALSE 0
#endif
#ifndef NULL
#define NULL ((void*)0)
#endif

#define FORCEINLINE                 static __forceinline
#define RTL_NUMBER_OF(a)            (sizeof(a) / sizeof((a)[0]))
#define C_ASSERT(e)                 typedef char __C_ASSERT__[(e) ? 1 : -1]
#define UNREFERENCED_PARAMETER(p)   ((void)(p))
#define RtlEqualMemory(d, s, n)     (!memcmp((d), (s), (n)))
#define RtlZeroMemory(d, n)         memset((d), 0, (n))
#define RtlCopyMemory(d, s, n)      memcpy((d), (s), (n))
#define RtlUpcaseUnicodeChar(c)     ((WCHAR)towupper((wint_t)(c)))
#define KdPrint(x)                  ((void)0)

FORCEINLINE void
RtlInitUnicodeString(_Out_ PUNICODE_STRING Dest, _In_opt_ PCWSTR Src)
{
    size_t n = (Src != NULL) ? wcslen(Src) : 0;
    Dest->Buffer = (PWCH)Src;
    Dest->Length = (USHORT)(n * sizeof(WCHAR));
    Dest->MaximumLength = Dest->Length;
}

#endif  // BLW_MATCHCORE_HOST

#include "Protocol.h"   // BLW_MAX_PATH / BLW_CMD_TOKEN_SEP(两端共用的协议常量)

#define BLW_MAX_PROTECTED 64   // 每份名单最多容纳的条数(定长数组,无动态分配)

//
// 一条受保护路径 / 模式。
//
// 【存储约定】Path 里保存的是【已大写化】的模式串(由 BlwAddToList 在加入时归一化一次)。
// 匹配始终是大小写不敏感的,预先归一化模式串使热路径上的比较退化为纯宽字符比较,不必再
// 对每个滑动窗口做一次大小写不敏感的整串比较(见 BLW_MATCH_CTX)。
// 副作用仅是「写回注册表 \Policy 的名单是大写形式」—— 这些值只被本驱动自己读回(读回后
// 再次归一化,幂等),用户态从不比较它们,故无任何行为影响。
//
typedef struct _BLW_PROTECTED_PATH {
    WCHAR   Path[BLW_MAX_PATH];   // 已大写化的模式串
    USHORT  Length;               // 字符数
    BOOLEAN InUse;
} BLW_PROTECTED_PATH, *PBLW_PROTECTED_PATH;

//
// ============ 大小写不敏感子串匹配的公共基元 ============
//
// 归一化单个宽字符,与 RtlCompareUnicodeString(..., TRUE) 共用同一套 Unicode 大写表,
// 因此基于它的比较与原来的「大小写不敏感整串比较」结果逐字符等价。
// ASCII(路径里的绝大多数字符)走内联快路,只有非 ASCII 才调 RtlUpcaseUnicodeChar。
// 可在任意 IRQL 调用。
//
// (host 单测里 RtlUpcaseUnicodeChar 被垫成 towupper —— 非 ASCII 的大写表可能与内核略有
//  出入,故单测只针对 ASCII 形态断言,不去验证非 ASCII 分支。)
//
FORCEINLINE WCHAR
BlwUpcaseChar(_In_ WCHAR c)
{
    if (c >= L'a' && c <= L'z') {
        return (WCHAR)(c - L'a' + L'A');
    }
    if (c < 0x80) {
        return c;   // 其余 ASCII 的大写形式就是自身
    }
    return RtlUpcaseUnicodeChar(c);
}

//
// ============ 卷前缀剥离:把「子串包含」升级为「锚定前缀」的基础 ============
//
// 【为什么必须有这个函数】
//
// 内核里同一个文件会以多种前缀出现:
//     \??\C:\Windows\System32\x.exe                  (进程创建回调的 CreateInfo->ImageFileName)
//     \Device\HarddiskVolume3\Windows\System32\x.exe (SeLocateProcessImageName / 规范化文件名)
// 原实现为了同时覆盖这两种形式,把「这个映像是不是系统组件」写成了【子串包含】判断
// (BlwWideContainsCI(path, L"\\Windows\\System32\\") 之类)。那是错的,而且是可直接利用的错:
//
//     C:\Users\<u>\Program Files\evil.exe        含有 "\Program Files\"
//     C:\temp\Windows\System32\csrss.exe         含有 "\Windows\System32\"
//
// 第一条让样本进了「可信系统路径」快速白名单 —— 进程创建既不拦也不上报,用户态根本看不到它。
// 第二条更严重:它同时满足 BlwIsCriticalSystemProcess 的两个条件(文件名命中关键进程名单 +
// 「位于系统目录」),于是那个样本获得了关键系统进程的全部豁免 —— 执行前拦截不拦它、
// BlwKillProcessById 拒绝结束它。而这两个目录用户都能自己创建,不需要任何权限。
//
// 正确做法是先剥掉卷标识,再对【剩余路径】做锚定前缀比较。本函数返回剩余路径的起始下标。
//
// 识别不出卷前缀时返回 0,调用方一律按「不匹配」处理 —— 方向是 fail-safe:白名单不命中意味着
// 多一次上报/多一层审查,而不是多一次放行。
//
FORCEINLINE BOOLEAN
BlwStartsWithCI(_In_reads_(Chars) PCWSTR Path, _In_ USHORT Chars,
                _In_ PCWSTR Literal, _In_ USHORT LiteralChars)
{
    USHORT i;

    if (Path == NULL || Chars < LiteralChars) {
        return FALSE;
    }
    for (i = 0; i < LiteralChars; i++) {
        if (BlwUpcaseChar(Path[i]) != BlwUpcaseChar(Literal[i])) {
            return FALSE;
        }
    }
    return TRUE;
}

FORCEINLINE USHORT
BlwVolumeRelativeOffset(_In_reads_(Chars) PCWSTR Path, _In_ USHORT Chars)
{
    if (Path == NULL || Chars < 3) {
        return 0;
    }

    // \??\C:\...  -> 剩余从下标 6 开始(即 "\Windows\...")
    if (BlwStartsWithCI(Path, Chars, L"\\??\\", 4)) {
        // \??\UNC\... 是网络路径,不可能是本机系统目录 -> 不识别(返回 0 = 不匹配)。
        if (BlwStartsWithCI(Path, Chars, L"\\??\\UNC\\", 8)) {
            return 0;
        }
        if (Chars >= 7 && Path[5] == L':' && Path[6] == L'\\') {
            return 6;
        }
        return 0;
    }

    // \Device\HarddiskVolumeN\...  -> 跳过数字,剩余从其后开始
    if (BlwStartsWithCI(Path, Chars, L"\\Device\\HarddiskVolume", 22)) {
        USHORT i = 22;
        while (i < Chars && Path[i] >= L'0' && Path[i] <= L'9') {
            i++;
        }
        // 必须真的读到过数字,且其后紧跟 '\'
        if (i > 22 && i < Chars && Path[i] == L'\\') {
            return i;
        }
        return 0;
    }

    // C:\...(极少见:内核路径通常带前缀,但归一化过的输入可能是这种形式)
    if (Chars >= 3 && Path[1] == L':' && Path[2] == L'\\') {
        return 2;
    }

    return 0;
}

//
// 「剥掉卷前缀后,剩余路径是否以 Literal 开头」。这是替代 BlwWideContainsCI 做系统目录判定的
// 唯一正确形式。Literal 必须以 '\' 开头(如 L"\\Windows\\System32\\")。
//
FORCEINLINE BOOLEAN
BlwVolumePathStartsWith(_In_opt_ PCWSTR Path, _In_ USHORT Chars,
                        _In_ PCWSTR Literal, _In_ USHORT LiteralChars)
{
    USHORT off;

    if (Path == NULL || Chars == 0) {
        return FALSE;
    }
    off = BlwVolumeRelativeOffset(Path, Chars);
    if (off == 0) {
        return FALSE;   // 认不出卷前缀 -> 不匹配(fail-safe)
    }
    return BlwStartsWithCI(Path + off, (USHORT)(Chars - off), Literal, LiteralChars);
}

// 便于书写:对宽字符串字面量自动算长度。
#define BLW_VOLPATH_STARTS(path, chars, lit) \
    BlwVolumePathStartsWith((path), (chars), (lit), (USHORT)(sizeof(lit) / sizeof(WCHAR) - 1))

//
// 预归一化的匹配目标。
//
// 一次文件 IRP_MJ_CREATE 最多要对 4 个名单做子串匹配,一次注册表写要对 2 个。原实现每个
// 名单、每个模式、每个窗口偏移都要重新做大小写归一化,同一条路径被反复归一化几十上百次。
// 现在改为:回调里把目标串【一次性】大写化进 Up[],之后所有名单匹配都只是宽字符比较
// (命中首尾字符后直接 RtlEqualMemory 整段),归一化成本从 O(名单数 × 模式长 × 路径长)
// 降到 O(路径长)。
//
// 目标超过 BLW_MAX_PATH 字符时不做预归一化(Chars=0),改由 Original 走「即时归一化」的
// 回退路径 —— 语义与快路径完全一致,只是不缓存归一化结果。这样绝不会因为路径过长而
// 漏掉本该命中的名单项(超长路径正是攻击者可能用来绕过的手法)。
//
typedef struct _BLW_MATCH_CTX {
    PCUNICODE_STRING Original;      // 原始目标(仅在 Chars==0 的回退路径使用,须在 ctx 生命周期内有效)
    USHORT           Chars;         // Up 中的有效字符数;0 = 未预归一化(走 Original 回退)
    WCHAR            Up[BLW_MAX_PATH];   // 已大写化的目标
} BLW_MATCH_CTX, *PBLW_MATCH_CTX;

//
// ============ 「路径以 \<文件名> 结尾」类名单的公共判定 ============
//
// 关键系统进程(14 条)、LOLBin(28 条)、高价值注入目标(10 条)都是这种「按文件名匹配」的
// 常量名单。原实现对每一条都做一次 RtlInitUnicodeString(内含 wcslen)+ RtlCompareUnicodeString
// 尾部比较 —— 一次进程创建要跑 42 次带 wcslen 的整串比较,一次跨进程建线程要跑 10 次。
//
// 现在:先【一次】反向扫描取出文件名,再用「长度 + 首字符」筛掉名单里绝大多数条目,只有极少数
// 候选才逐字符比较;条目长度在编译期由 BLW_NAME 算出,运行时不再有 wcslen。
// 语义与原尾部匹配一致,包括「路径中必须真的出现过 '\'」这一点。
//
typedef struct _BLW_NAME_ENTRY {
    PCWSTR Name;    // 文件名(不含前导 '\')
    USHORT Chars;   // Name 的字符数(编译期常量)
} BLW_NAME_ENTRY;

#define BLW_NAME(s) { (s), (USHORT)(sizeof(s) / sizeof(WCHAR) - 1) }

//
// ==================== 以下为 MatchCore.c 的对外接口 ====================
//

// 把目标串预归一化进 Ctx(每个回调对每个目标只做一次),供下面所有名单查询复用。
void     BlwPrepareMatch(_Out_ PBLW_MATCH_CTX Ctx, _In_opt_ PCUNICODE_STRING Target);

//
// 通用:在名单中做【子串】匹配(大小写不敏感)。线程安全由调用方持锁。
//   Count    - 名单中在用项数(必须与 List 内容在同一把锁下读取);用于扫完即止,
//              不再无谓地遍历剩余空槽。
//   UseChars - 只匹配 Ctx 目标的前 UseChars 个字符;0 = 匹配整个目标。
//              (注册表回调用它在同一个 "键\值" ctx 上分别做「整串」与「仅键部分」两种匹配。)
//
BOOLEAN  BlwMatchInListCtx(_In_ BLW_PROTECTED_PATH* List, _In_ LONG Count,
                           _In_ PBLW_MATCH_CTX Ctx, _In_ USHORT UseChars);

//
// 通用:在名单中做【路径锚定】匹配(大小写不敏感)。语义比上面的子串匹配严格,
// 专用于「禁止执行 / 禁止加载」两份名单 —— 详细理由与判据见 MatchCore.c 的实现处注释。
//
BOOLEAN  BlwMatchInListAnchoredCtx(_In_ BLW_PROTECTED_PATH* List, _In_ LONG Count,
                                   _In_ PBLW_MATCH_CTX Ctx);

// 向名单追加一项(内部会把模式串大写化后存入,见 BLW_PROTECTED_PATH 的存储约定)。
void     BlwAddToList(_In_ BLW_PROTECTED_PATH* List, _In_ PCWSTR Path, _In_ USHORT Length);

//
// 从名单中精确删除一项(整串、大小写不敏感)。返回 TRUE 表示确实删掉了一条。
//
// 【为什么需要它】原先协议只有「追加 / 整表清空」,撤销一条误判要靠用户态
// 「CLEAR + 重下发保留项」(Worker::reconcileKernelBlocksAfterTrust)。那条路有个真实漏洞:
// CLEAR 刻意不持久化(只有 ADD 才标脏),于是当保留项为空(要删的就是全部条目)时一次 ADD
// 都不会发生 -> 不标脏 -> 磁盘基线保持旧内容 -> 重启后被删的条目全部复活。
// 精确删除让「删除」本身成为一次标脏事件,写回必然发生。
//
BOOLEAN  BlwRemoveFromList(_In_ BLW_PROTECTED_PATH* List, _In_ PCWSTR Path, _In_ USHORT Length);

//
// 模式串里是否含「盘符 + 冒号 + 反斜杠」(如 C:\)。
//
// 这类条目对【文件路径名单】而言是【死条目】:匹配目标恒为 FLT_FILE_NAME_NORMALIZED
// 规范名(\Device\HarddiskVolumeN\...),其中不可能出现 "<字母>:\" 这个三字符序列
// (数据流名可以带 ':',但流名里不允许出现 '\')。所以它永远不会命中,只会白占 64 槽之一,
// 还会被内核写回注册表跨重启续留 —— 槽位耗尽后此后所有新裁决都被静默丢弃。
//
// 【只对文件路径名单使用】:CmdHardBlock 匹配的是原始命令行(里面出现 C:\ 完全正常),
// RegHardBlock 匹配的是注册表键\值名(值名允许含 ':'),这两份【绝不可】套用本判据。
//
BOOLEAN  BlwPatternHasDriveLetter(_In_opt_ PCWSTR Pattern, _In_ USHORT Chars);

// 宽字符串子串匹配(大小写不敏感)。Sub 为 NUL 结尾的短常量。供多模块复用。
BOOLEAN  BlwWideContainsCI(_In_ PCWSTR Str, _In_ USHORT StrChars, _In_ PCWSTR Sub);

// 「路径以 \<文件名> 结尾」类常量名单的公共判定(见上方 BLW_NAME_ENTRY 说明)。
BOOLEAN  BlwImageNameIn(_In_reads_(TableCount) const BLW_NAME_ENTRY* Table,
                        _In_ ULONG TableCount,
                        _In_opt_ PCWSTR Path, _In_ USHORT Chars);

//
// 一条「命令行硬拦」模式是否命中给定命令行:模式按 BLW_CMD_TOKEN_SEP('+')切分为多个
// token,【全部 token 都出现】才算命中(合取 / AND 语义)。直接吃原始串,不截断、不预归一化。
//
BOOLEAN  BlwCmdPatternMatches(_In_ const BLW_PROTECTED_PATH* Entry,
                              _In_reads_(TargetChars) PCWSTR Target,
                              _In_ ULONG TargetChars);

// 把一条「未必以 NUL 结尾」的模式串安全地打进调试输出(Release 下 KdPrint 是空宏)。
void     BlwLogPattern(_In_ PCSTR Reason, _In_opt_ PCWSTR Path, _In_ USHORT Chars);
