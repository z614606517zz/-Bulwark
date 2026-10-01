/*++
    MatchCore.c
    名单匹配核心的实现。约定见 MatchCore.h 顶部 —— 简述:本文件里的一切都是纯函数,
    【绝不】引用 g_Blw、绝不取锁、绝不调用任何只在特定 IRQL 可用的 API,因此可以在
    用户态原样编译并由 cpp/tests/DriverMatchTest.cpp 做单元测试。

    改这里的任何判定,都必须同时在 DriverMatchTest.cpp 里补上对应形态的断言 ——
    驱动不能在开发机上加载,单测是唯一能证伪这些判定的地方。
--*/

#ifdef BLW_MATCHCORE_HOST
#include "MatchCore.h"
#else
#include "Driver.h"     // 内核侧:经 Driver.h 取得内核头 + 本头(次序见 MatchCore.h 说明)
#endif

//
// 目标长于 BLW_MAX_PATH 字符时不预归一化(Chars=0),记下原串走回退路径 —— 见
// BLW_MATCH_CTX 的说明:宁可慢一点也绝不因路径过长而漏判。
//
void
BlwPrepareMatch(_Out_ PBLW_MATCH_CTX Ctx, _In_opt_ PCUNICODE_STRING Target)
{
    USHORT chars;
    USHORT i;

    Ctx->Original = Target;
    Ctx->Chars = 0;

    if (Target == NULL || Target->Buffer == NULL || Target->Length == 0) {
        return;
    }

    chars = (USHORT)(Target->Length / sizeof(WCHAR));
    if (chars > BLW_MAX_PATH) {
        return;   // 超长:留给 Original 回退路径处理
    }

    for (i = 0; i < chars; i++) {
        Ctx->Up[i] = BlwUpcaseChar(Target->Buffer[i]);
    }
    Ctx->Chars = chars;
}

//
// ======================= 匹配模式 =======================
//
// BlwMatchSubstring —— 历史语义:模式出现在目标的【任意位置】即命中。
//     ProtectedPaths / FileHardBlock / SelfGuard / ProtectedRegKeys / RegHardBlock 用它。
//     这些名单是【保护】语义,里面本来就有 "\START MENU\PROGRAMS\STARTUP\" 这类
//     出现在路径【中段】的目录片段,必须保持子串语义。
//
// BlwMatchAnchored  —— 收紧语义:模式必须【从目录边界起】,并且【到串尾(或数据流分隔符)止】。
//     FileNoLoad / FileExecBlock 用它。这两份是【拒绝】语义,误判的代价是「某个程序永久
//     起不来」,所以判据必须比保护类名单紧。
//
//     判据(三条,缺一不可):
//       起点边界: 模式以 '\' 开头(模式自带边界) | 匹配从目标串首起 | 前一字符是 '\'
//       终点边界: 模式以 '\' 结尾(目录前缀语义,其下全部内容均命中)
//                 | 匹配到目标串尾 | 其后紧跟 ':'(备用数据流,见下)
//
//     这条收紧堵住的是「模式出现在路径中段」造成的误伤,例如名单里有
//     `\USERS\X\TEMP\A.EXE` 时,子串语义会连带拦下:
//         ...\Temp\a.exe.bak          (备份文件)
//         ...\Temp\a.exe\sub\x.dll    (恰好叫 a.exe 的目录下的任何模块)
//     而这些都不是被判定为恶意的那个对象。
//
//     【为什么不用「卷相对锚定前缀」】那是更紧的形式,但会直接破坏两种现有用法:
//       * cpp/scripts/set-baseline-policy.ps1 的文档用法是 -FileExecBlock '\evil.exe'
//         —— 只给文件名片段,不是完整卷相对路径;
//       * Worker::enforceBlock / blacklistExec 下发的是「去盘符的完整路径」,虽然恰好
//         等于卷相对余部,但一旦目标路径的卷前缀认不出来(\Device\Mup\ 网络路径、
//         影子卷),前缀锚定就会整条失效 —— 那是把覆盖面丢掉换精度,方向错了。
//     「目录边界起 + 串尾止」两种用法都保得住,且不依赖卷前缀能否识别。
//
//     【为什么终点允许 ':'】`C:\x.txt:hidden.exe` 这种备用数据流(ADS)执行是已知手法,
//     规范名形如 ...\x.txt:hidden.exe。若只允许「到串尾止」,把 `\X.TXT` 钉进名单后
//     攻击者加一个流名就绕过了。流名里不允许出现 '\',故这一条不会引入新的中段匹配。
//
typedef enum _BLW_MATCH_MODE {
    BlwMatchSubstring = 0,
    BlwMatchAnchored = 1
} BLW_MATCH_MODE;

//
// 锚定模式下,位于 [Start, End) 的这次命中是否满足两端边界要求。
// 只比较 '\' 与 ':' 这两个 ASCII 字符,故无论 Target 是否已大写化,结果都一样。
//
static BOOLEAN
BlwAnchorsOk(
    _In_reads_(TargetChars) PCWSTR Target,
    _In_ USHORT TargetChars,
    _In_ PCWSTR Pattern,
    _In_ USHORT PatChars,
    _In_ USHORT Start)
{
    USHORT end = (USHORT)(Start + PatChars);

    // 起点边界
    if (Pattern[0] != L'\\' && Start != 0 && Target[Start - 1] != L'\\') {
        return FALSE;
    }

    // 终点边界
    if (Pattern[PatChars - 1] == L'\\') {
        return TRUE;   // 目录前缀语义:其下全部内容均命中
    }
    if (end == TargetChars) {
        return TRUE;
    }
    if (Target[end] == L':') {
        return TRUE;   // 备用数据流
    }
    return FALSE;
}

//
// 名单扫描的唯一实现。
//
// Prepared=TRUE  : Target 已大写化,窗口比较是纯宽字符比较(热路径)。
// Prepared=FALSE : Target 是原串,逐字符即时大写化后比较(超长目标的回退路径)。
// 两条分支使用同一套大写表,判定结果完全一致。
//
// 窗口过滤用「首字符 + 末字符」双锚点:两端都对上才做中间段的整段比较。原实现只比首字符,
// 而路径里首字符命中(尤其模式串以 '\\' 开头时)相当常见,双锚点把这些必然失败的整段比较
// 也一并剪掉。中间段用 RtlEqualMemory(编译为向量化 memcmp),比逐字符循环快得多。
//
static BOOLEAN
BlwMatchScan(
    _In_ BLW_PROTECTED_PATH* List,
    _In_ LONG Count,
    _In_reads_(TargetChars) PCWSTR Target,
    _In_ USHORT TargetChars,
    _In_ BOOLEAN Prepared,
    _In_ BLW_MATCH_MODE Mode)
{
    ULONG i;
    LONG  seen = 0;

    if (Target == NULL || TargetChars == 0 || Count <= 0) {
        return FALSE;
    }

    // seen < Count:扫到最后一个在用项就收尾,不再遍历剩余空槽(名单通常只有几条,
    // 原实现无论如何都要走满 64 槽)。Count 与 List 内容由调用方在同一把锁下读取,故一致。
    for (i = 0; i < BLW_MAX_PROTECTED && seen < Count; i++) {
        USHORT patChars;
        USHORT limit;
        USHORT s;
        PCWSTR p;
        WCHAR  first;
        WCHAR  last;

        if (!List[i].InUse) {
            continue;
        }
        seen++;

        // 模式串比目标长(或为空)绝不可能是其子串 —— 直接跳过,省掉整段滑窗。
        patChars = List[i].Length;
        if (patChars == 0 || patChars > TargetChars) {
            continue;
        }

        p = List[i].Path;              // 已在加入时大写化
        first = p[0];
        last = p[patChars - 1];
        limit = (USHORT)(TargetChars - patChars);

        if (Prepared) {
            for (s = 0; s <= limit; s++) {
                if (Target[s] != first) {
                    continue;
                }
                if (Target[s + patChars - 1] != last) {
                    continue;
                }
                if (Mode == BlwMatchAnchored &&
                    !BlwAnchorsOk(Target, TargetChars, p, patChars, s)) {
                    continue;
                }
                if (patChars <= 2 ||
                    RtlEqualMemory(&Target[s + 1], &p[1],
                                   (SIZE_T)(patChars - 2) * sizeof(WCHAR))) {
                    return TRUE;
                }
            }
        } else {
            for (s = 0; s <= limit; s++) {
                USHORT k;

                if (BlwUpcaseChar(Target[s]) != first) {
                    continue;
                }
                if (BlwUpcaseChar(Target[s + patChars - 1]) != last) {
                    continue;
                }
                if (Mode == BlwMatchAnchored &&
                    !BlwAnchorsOk(Target, TargetChars, p, patChars, s)) {
                    continue;
                }
                for (k = 1; (USHORT)(k + 1) < patChars; k++) {
                    if (BlwUpcaseChar(Target[s + k]) != p[k]) {
                        break;
                    }
                }
                if ((USHORT)(k + 1) >= patChars) {
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

//
// 两个对外入口共用的派发:按 Ctx 是否预归一化选择快路径 / 回退路径。
//
static BOOLEAN
BlwMatchDispatch(
    _In_ BLW_PROTECTED_PATH* List,
    _In_ LONG Count,
    _In_ PBLW_MATCH_CTX Ctx,
    _In_ USHORT UseChars,
    _In_ BLW_MATCH_MODE Mode)
{
    if (Ctx == NULL) {
        return FALSE;
    }

    if (Ctx->Chars != 0) {
        USHORT n = (UseChars == 0 || UseChars > Ctx->Chars) ? Ctx->Chars : UseChars;
        return BlwMatchScan(List, Count, Ctx->Up, n, TRUE, Mode);
    }

    // 回退:目标超过 BLW_MAX_PATH 字符,未做预归一化(极少见)。
    if (Ctx->Original != NULL && Ctx->Original->Buffer != NULL && Ctx->Original->Length > 0) {
        USHORT total = (USHORT)(Ctx->Original->Length / sizeof(WCHAR));
        USHORT n = (UseChars == 0 || UseChars > total) ? total : UseChars;
        return BlwMatchScan(List, Count, Ctx->Original->Buffer, n, FALSE, Mode);
    }
    return FALSE;
}

// 在 List 中查找是否有某项是 Ctx 目标(前 UseChars 个字符)的子串。调用方需自行持锁。
BOOLEAN
BlwMatchInListCtx(
    _In_ BLW_PROTECTED_PATH* List,
    _In_ LONG Count,
    _In_ PBLW_MATCH_CTX Ctx,
    _In_ USHORT UseChars)
{
    return BlwMatchDispatch(List, Count, Ctx, UseChars, BlwMatchSubstring);
}

// 同上,但用锚定判据(见 BLW_MATCH_MODE 的说明)。调用方需自行持锁。
BOOLEAN
BlwMatchInListAnchoredCtx(
    _In_ BLW_PROTECTED_PATH* List,
    _In_ LONG Count,
    _In_ PBLW_MATCH_CTX Ctx)
{
    return BlwMatchDispatch(List, Count, Ctx, 0, BlwMatchAnchored);
}

//
// 把一条「未必以 NUL 结尾」的模式串安全地打进调试输出。
// %wZ 按 UNICODE_STRING::Length 打印,不需要结尾 NUL,正好匹配 (Path, Chars) 这种传参形式。
//
void
BlwLogPattern(_In_ PCSTR Reason, _In_opt_ PCWSTR Path, _In_ USHORT Chars)
{
    UNICODE_STRING s;

    if (Path == NULL || Chars == 0 || Chars >= BLW_MAX_PATH) {
        RtlInitUnicodeString(&s, L"<invalid>");
    } else {
        s.Buffer = (PWCH)Path;
        s.Length = (USHORT)(Chars * sizeof(WCHAR));
        s.MaximumLength = s.Length;
    }

    KdPrint(("[Bulwark] %s: %wZ\n", Reason, &s));

    // Release 构建里 KdPrint 是空宏,这两行避免 C4100/C4189(/WX 下会直接编译失败)。
    UNREFERENCED_PARAMETER(Reason);
    UNREFERENCED_PARAMETER(s);
}

//
// 向 List 追加一项。调用方需自行持锁。
// 模式串在此【大写化一次】后存入(见 BLW_PROTECTED_PATH 的存储约定),使热路径上的匹配
// 不必再做任何大小写归一化。
//
// 先去重,再插入 —— 这一点是必需的,不是优化:
//   各名单都是 BLW_MAX_PROTECTED(64)条的【定长】数组,而「已学习裁决」会在每次服务连接时
//   整批重新下发一遍,命中时还会再下发一次。原实现只找第一个空槽就插入,于是同一条路径能
//   重复占掉几十个槽。真实现场:FileNoLoad 里 AUTOIT3.EXE 重复 11 次、64 个槽全部用尽,
//   FileExecBlock 里同一个 RuntimeBroker.exe 重复 4 次。
//   槽位一旦耗尽,下面的循环找不到空槽就静默返回,【此后所有新的恶意裁决都被丢弃】——
//   这是无声的能力退化,比多占一点内存严重得多。
//   重复项对匹配结果毫无影响(子串匹配命中任一条即返回),所以去重是纯收益。
//
void
BlwAddToList(_In_ BLW_PROTECTED_PATH* List, _In_ PCWSTR Path, _In_ USHORT Length)
{
    ULONG  i;
    ULONG  freeSlot = BLW_MAX_PROTECTED;   // == BLW_MAX_PROTECTED 表示没有空槽
    USHORT k;

    if (Length == 0 || Length > (BLW_MAX_PATH - 1)) {
        return;
    }

    // 一趟扫完:既找重复项,也记下第一个空槽。
    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        if (!List[i].InUse) {
            if (freeSlot == BLW_MAX_PROTECTED) {
                freeSlot = i;
            }
            continue;
        }
        if (List[i].Length != Length) {
            continue;
        }
        // List[i].Path 已是大写形式,故与大写化后的候选逐字符比较即为大小写不敏感比较。
        for (k = 0; k < Length; k++) {
            if (List[i].Path[k] != BlwUpcaseChar(Path[k])) {
                break;
            }
        }
        if (k == Length) {
            return;   // 已在名单里:不再占用第二个槽
        }
    }

    if (freeSlot == BLW_MAX_PROTECTED) {
        // 名单已满。明确记录下来,不让「裁决被丢弃」这件事无声发生。
        BlwLogPattern("List full, entry DROPPED", Path, Length);
        return;
    }

    for (k = 0; k < Length; k++) {
        List[freeSlot].Path[k] = BlwUpcaseChar(Path[k]);
    }
    List[freeSlot].Path[Length] = L'\0';
    List[freeSlot].Length = Length;
    List[freeSlot].InUse = TRUE;
}

//
// 从 List 中精确删除一项(整串、大小写不敏感)。调用方需自行持锁。
// 返回是否真的删掉了一条 —— 调用方据此决定是否标脏持久化(见 MatchCore.h 的说明)。
//
// 刻意做成【精确整串】而非「删掉所有会匹配到它的条目」:后者语义模糊,极易一次删掉本不该删的
// 条目;而用户态撤销时手上拿的就是它当初下发的那个串(内核写回注册表的也是同一个串,只是
// 大写形式),精确删除足够且无歧义。
//
BOOLEAN
BlwRemoveFromList(_In_ BLW_PROTECTED_PATH* List, _In_ PCWSTR Path, _In_ USHORT Length)
{
    ULONG  i;
    USHORT k;

    if (Path == NULL || Length == 0 || Length > (BLW_MAX_PATH - 1)) {
        return FALSE;
    }

    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        if (!List[i].InUse || List[i].Length != Length) {
            continue;
        }
        for (k = 0; k < Length; k++) {
            if (List[i].Path[k] != BlwUpcaseChar(Path[k])) {
                break;
            }
        }
        if (k == Length) {
            RtlZeroMemory(&List[i], sizeof(List[i]));   // 连带清掉 Path/Length/InUse
            return TRUE;
        }
    }
    return FALSE;
}

//
// 模式串里是否含「盘符 + 冒号 + 反斜杠」。判据与用途见 MatchCore.h 的声明处说明。
//
BOOLEAN
BlwPatternHasDriveLetter(_In_opt_ PCWSTR Pattern, _In_ USHORT Chars)
{
    USHORT i;

    if (Pattern == NULL || Chars < 3) {
        return FALSE;
    }

    for (i = 0; (USHORT)(i + 3) <= Chars; i++) {
        const WCHAR c = BlwUpcaseChar(Pattern[i]);

        if (c >= L'A' && c <= L'Z' && Pattern[i + 1] == L':' && Pattern[i + 2] == L'\\') {
            return TRUE;
        }
    }
    return FALSE;
}

//
// 大小写不敏感子串匹配(Sub 为 NUL 结尾的短常量)。
//
// 原实现对每个滑动窗口偏移都调一次 RtlCompareUnicodeString(...TRUE) —— 该调用内部会对两侧
// 逐字符做 Unicode 大写化,成本是 O(子串长度)。「可信系统目录」白名单有 11 条,一次进程创建
// 就是 11 × 路径长度 次这样的调用。
//
// 现在用「首字符 + 末字符」双锚点先筛:两端都对上才比中间,且全部用内联的 BlwUpcaseChar
// (ASCII 快路,无函数调用)。判定结果与原来完全一致 —— 同一套 Unicode 大写表。
//
BOOLEAN
BlwWideContainsCI(_In_ PCWSTR Str, _In_ USHORT StrChars, _In_ PCWSTR Sub)
{
    USHORT subChars = 0;
    USHORT limit;
    USHORT s;
    WCHAR  first;
    WCHAR  last;

    if (Str == NULL || Sub == NULL || StrChars == 0) {
        return FALSE;
    }

    while (subChars < BLW_MAX_PATH && Sub[subChars] != L'\0') {
        subChars++;
    }
    if (subChars == 0 || subChars > StrChars) {
        return FALSE;
    }

    first = BlwUpcaseChar(Sub[0]);
    last = BlwUpcaseChar(Sub[subChars - 1]);
    limit = (USHORT)(StrChars - subChars);

    for (s = 0; s <= limit; s++) {
        USHORT k;

        if (BlwUpcaseChar(Str[s]) != first) {
            continue;
        }
        if (BlwUpcaseChar(Str[s + subChars - 1]) != last) {
            continue;
        }
        for (k = 1; (USHORT)(k + 1) < subChars; k++) {
            if (BlwUpcaseChar(Str[s + k]) != BlwUpcaseChar(Sub[k])) {
                break;
            }
        }
        if ((USHORT)(k + 1) >= subChars) {
            return TRUE;
        }
    }
    return FALSE;
}

//
// 「路径以 \<文件名> 结尾」类常量名单的公共判定(见 MatchCore.h 的 BLW_NAME_ENTRY 说明)。
//
BOOLEAN
BlwImageNameIn(
    _In_reads_(TableCount) const BLW_NAME_ENTRY* Table,
    _In_ ULONG TableCount,
    _In_opt_ PCWSTR Path,
    _In_ USHORT Chars)
{
    USHORT nameStart;
    USHORT nameChars;
    ULONG  i;
    WCHAR  firstUp;

    if (Path == NULL || Chars == 0) {
        return FALSE;
    }

    // 反向定位最后一个 '\',其后即文件名。整条路径里没有 '\' 时不匹配 ——
    // 与原来「尾部匹配 \<名字>」的语义一致(那种写法也要求路径里出现 '\')。
    nameStart = Chars;
    while (nameStart > 0 && Path[nameStart - 1] != L'\\') {
        nameStart--;
    }
    if (nameStart == 0) {
        return FALSE;
    }

    nameChars = (USHORT)(Chars - nameStart);
    if (nameChars == 0) {
        return FALSE;
    }

    firstUp = BlwUpcaseChar(Path[nameStart]);

    for (i = 0; i < TableCount; i++) {
        USHORT k;

        if (Table[i].Chars != nameChars) {
            continue;   // 长度不同,不可能相等
        }
        if (BlwUpcaseChar(Table[i].Name[0]) != firstUp) {
            continue;   // 首字符不同,不可能相等
        }
        for (k = 1; k < nameChars; k++) {
            if (BlwUpcaseChar(Path[nameStart + k]) != BlwUpcaseChar(Table[i].Name[k])) {
                break;
            }
        }
        if (k == nameChars) {
            return TRUE;
        }
    }
    return FALSE;
}

//
// 单个 token 是否作为大小写不敏感子串出现在命令行中。
//
// Tok 已在加入名单时大写化;Target 是【原始命令行】,逐字符即时大写化后比较 —— 不预归一化
// 是刻意的:命令行可长达 32767 字符,预归一化就要么开大缓冲、要么截断,而截断会直接造成
// 「填充垫料把危险 token 推出截断范围」的绕过。逐字符比较的代价只在进程创建这条低频路径上。
//
// 窗口过滤沿用项目里其它匹配器的「首字符 + 末字符」双锚点:两端都对上才比中间段,
// 把绝大多数必然失败的比较剪掉。判定结果与逐窗口整串比较完全一致(同一套 Unicode 大写表)。
//
static BOOLEAN
BlwTokenInCmdLine(
    _In_reads_(TargetChars) PCWSTR Target,
    _In_ ULONG TargetChars,
    _In_reads_(TokChars) PCWSTR Tok,
    _In_ USHORT TokChars)
{
    ULONG limit;
    ULONG s;
    WCHAR first;
    WCHAR last;

    if (TokChars == 0 || (ULONG)TokChars > TargetChars) {
        return FALSE;
    }

    first = Tok[0];
    last = Tok[TokChars - 1];
    limit = TargetChars - TokChars;

    for (s = 0; s <= limit; s++) {
        USHORT k;

        if (BlwUpcaseChar(Target[s]) != first) {
            continue;
        }
        if (BlwUpcaseChar(Target[s + TokChars - 1]) != last) {
            continue;
        }
        for (k = 1; (USHORT)(k + 1) < TokChars; k++) {
            if (BlwUpcaseChar(Target[s + k]) != Tok[k]) {
                break;
            }
        }
        if ((USHORT)(k + 1) >= TokChars) {
            return TRUE;
        }
    }
    return FALSE;
}

//
// 一条模式是否命中命令行:模式按 BLW_CMD_TOKEN_SEP('+')切分为多个 token,
// 【全部 token 都出现】才算命中(合取 / AND 语义)。
//
// 为什么是合取而不是整串子串:整串子串对参数顺序和空格数量敏感,
// `vssadmin delete shadows /all` 与 `vssadmin /for=c: delete shadows` 只有前者能被
// 一条固定子串覆盖,攻击者调个顺序就绕过了。合取则与顺序、空格、大小写、是否带全路径无关。
//
// 空模式(全是分隔符、没有任何有效 token)返回 FALSE —— 绝不让一条配置错误的空模式
// 变成「匹配一切命令行」从而拦死整个系统。
//
BOOLEAN
BlwCmdPatternMatches(
    _In_ const BLW_PROTECTED_PATH* Entry,
    _In_reads_(TargetChars) PCWSTR Target,
    _In_ ULONG TargetChars)
{
    USHORT start = 0;
    USHORT i;
    BOOLEAN haveToken = FALSE;

    // i == Length 时收尾处理最后一段,故循环到 <= Length。
    for (i = 0; i <= Entry->Length; i++) {
        if (i == Entry->Length || Entry->Path[i] == BLW_CMD_TOKEN_SEP) {
            USHORT tokChars = (USHORT)(i - start);

            if (tokChars > 0) {
                haveToken = TRUE;
                if (!BlwTokenInCmdLine(Target, TargetChars, &Entry->Path[start], tokChars)) {
                    return FALSE;   // 有一个 token 不在命令行里 -> 整条模式不命中
                }
            }
            start = (USHORT)(i + 1);
        }
    }

    return haveToken;
}
