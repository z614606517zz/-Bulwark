/*++
    DriverMatchTest.c
    内核驱动名单匹配核心(Bulwark.Driver/MatchCore.c)的用户态单元测试。

    ============================ 为什么有这个测试 ============================

    驱动【不能在开发机上加载】—— 内核回调里出一点错就是蓝屏,加载验证只在带快照的测试
    虚拟机里做。在此之前,驱动侧匹配语义的任何改动都只有「编译通过」这一级验证,而项目里
    已经有过两次实测事故正是出在这几个函数上:

      * 子串包含让 C:\temp\Windows\System32\csrss.exe 同时满足「文件名是关键进程」与
        「位于系统目录」,白拿了关键系统进程的全部豁免(拦不住、也杀不掉);
      * `\WINDOWS\SYSTEM32\CMD.EXE` 被写进 FileExecBlock,按子串匹配的实际语义是
        「禁止任何 cmd.exe 启动」,所有 .bat / 安装包 / 编译脚本一起起不来,而名单还会被
        内核写回注册表跨重启续留。

    MatchCore.c 里的函数全是纯函数(不碰 g_Blw、不取锁、不依赖 IRQL),因此可以在用户态
    原样编译。本文件就是拿它们把上面那类判定逐形态钉死 —— 这是目前唯一能在本机对内核判定
    做出证伪的手段。

    ============================ 编译方式 ============================

    由 cpp/tests/CMakeLists.txt 的 driver_match_unit 目标编译:直接把
    Bulwark.Driver/MatchCore.c 加进来,并定义 BLW_MATCHCORE_HOST 打开 MatchCore.h 里的
    用户态垫片。本工程的 project() 只启用了 CXX,所以这两个 .c 在 CMake 侧被显式标成
    LANGUAGE CXX(理由写在 CMakeLists 里);代码本身是 C/C++ 双兼容的纯 C。

    退出码 0 = 全部通过;非 0 = 失败断言条数。
--*/

#include "MatchCore.h"

#include <stdio.h>

static int g_checks = 0;
static int g_failed = 0;

static void
Check(int ok, const char* what)
{
    g_checks++;
    if (!ok) {
        g_failed++;
        printf("  FAIL: %s\n", what);
    }
}

// ============================ 小工具 ============================

static void
MakeUs(UNICODE_STRING* us, const wchar_t* s)
{
    us->Buffer = (PWCH)s;
    us->Length = (USHORT)(wcslen(s) * sizeof(WCHAR));
    us->MaximumLength = us->Length;
}

static USHORT
Chars(const wchar_t* s)
{
    return (USHORT)wcslen(s);
}

static void
ListAdd(BLW_PROTECTED_PATH* list, const wchar_t* pattern)
{
    BlwAddToList(list, pattern, Chars(pattern));
}

static LONG
ListCount(const BLW_PROTECTED_PATH* list)
{
    LONG n = 0;
    ULONG i;
    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        if (list[i].InUse) {
            n++;
        }
    }
    return n;
}

static void
ListClear(BLW_PROTECTED_PATH* list)
{
    memset(list, 0, sizeof(BLW_PROTECTED_PATH) * BLW_MAX_PROTECTED);
}

// 名单里是否真的存在这一条(按存入后的大写形式比较)。
static BOOLEAN
ListHas(const BLW_PROTECTED_PATH* list, const wchar_t* patternUpper)
{
    const USHORT n = Chars(patternUpper);
    ULONG i;

    for (i = 0; i < BLW_MAX_PROTECTED; i++) {
        if (list[i].InUse && list[i].Length == n &&
            wcsncmp(list[i].Path, patternUpper, n) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

// 名单只放一条模式,再问「目标是否命中」——绝大多数用例都是这个形状。
static BOOLEAN
HitsSub(const wchar_t* pattern, const wchar_t* target)
{
    static BLW_PROTECTED_PATH list[BLW_MAX_PROTECTED];
    BLW_MATCH_CTX ctx;
    UNICODE_STRING us;

    ListClear(list);
    ListAdd(list, pattern);
    MakeUs(&us, target);
    BlwPrepareMatch(&ctx, &us);
    return BlwMatchInListCtx(list, ListCount(list), &ctx, 0);
}

static BOOLEAN
HitsAnchored(const wchar_t* pattern, const wchar_t* target)
{
    static BLW_PROTECTED_PATH list[BLW_MAX_PROTECTED];
    BLW_MATCH_CTX ctx;
    UNICODE_STRING us;

    ListClear(list);
    ListAdd(list, pattern);
    MakeUs(&us, target);
    BlwPrepareMatch(&ctx, &us);
    return BlwMatchInListAnchoredCtx(list, ListCount(list), &ctx);
}

static BOOLEAN
CmdHits(const wchar_t* pattern, const wchar_t* cmdline)
{
    static BLW_PROTECTED_PATH list[BLW_MAX_PROTECTED];

    ListClear(list);
    ListAdd(list, pattern);
    return BlwCmdPatternMatches(&list[0], cmdline, (ULONG)wcslen(cmdline));
}

// ============================ 1. 卷前缀剥离 ============================

static void
TestVolumeOffset(void)
{
    printf("[1] BlwVolumeRelativeOffset\n");

    // \??\C:\... -> 6(即 "\Windows\..." 的起点)
    Check(BlwVolumeRelativeOffset(L"\\??\\C:\\Windows\\x.exe",
                                  Chars(L"\\??\\C:\\Windows\\x.exe")) == 6,
          "\\??\\C:\\ -> 6");

    // \Device\HarddiskVolumeN\... -> 数字之后那个 '\'("\Device\HarddiskVolume" 恰好 22 字符)
    Check(BlwVolumeRelativeOffset(L"\\Device\\HarddiskVolume3\\Windows\\x.exe",
                                  Chars(L"\\Device\\HarddiskVolume3\\Windows\\x.exe")) == 23,
          "\\Device\\HarddiskVolume3\\ -> 23");
    Check(BlwVolumeRelativeOffset(L"\\Device\\HarddiskVolume12\\Windows\\x.exe",
                                  Chars(L"\\Device\\HarddiskVolume12\\Windows\\x.exe")) == 24,
          "\\Device\\HarddiskVolume12\\ -> 24(两位卷号)");

    // C:\...(归一化后的少见形式)
    Check(BlwVolumeRelativeOffset(L"C:\\Windows\\x.exe", Chars(L"C:\\Windows\\x.exe")) == 2,
          "C:\\ -> 2");

    // 认不出来的一律返回 0 —— 调用方按「不匹配」处理(fail-safe)
    Check(BlwVolumeRelativeOffset(L"\\??\\UNC\\srv\\share\\x.exe",
                                  Chars(L"\\??\\UNC\\srv\\share\\x.exe")) == 0,
          "\\??\\UNC\\(网络路径)-> 0");
    Check(BlwVolumeRelativeOffset(L"\\Device\\Mup\\srv\\share\\x.exe",
                                  Chars(L"\\Device\\Mup\\srv\\share\\x.exe")) == 0,
          "\\Device\\Mup\\ -> 0");
    Check(BlwVolumeRelativeOffset(L"\\Device\\HarddiskVolume\\x.exe",
                                  Chars(L"\\Device\\HarddiskVolume\\x.exe")) == 0,
          "HarddiskVolume 后没有数字 -> 0");
    Check(BlwVolumeRelativeOffset(L"ab", 2) == 0, "过短 -> 0");
    Check(BlwVolumeRelativeOffset(NULL, 0) == 0, "NULL -> 0");
}

// ============================ 2. 卷根锚定前缀(两起历史事故的回归哨兵)============

static void
TestVolumePathStartsWith(void)
{
    printf("[2] BLW_VOLPATH_STARTS(可信目录 / 关键进程判定的基础)\n");

#define VPS(p, lit) BLW_VOLPATH_STARTS((p), Chars(p), lit)

    // 事故一:用户自建目录曾借「子串包含」进入可信路径白名单 —— 必须不命中。
    Check(!VPS(L"C:\\Users\\u\\Program Files\\evil.exe", L"\\Program Files\\"),
          "用户自建的 \\Users\\u\\Program Files\\ 不算可信安装目录");
    Check(VPS(L"C:\\Program Files\\App\\a.exe", L"\\Program Files\\"),
          "真正的 C:\\Program Files\\ 算可信安装目录");

    // 事故二:C:\temp\Windows\System32\csrss.exe 曾同时满足「关键进程名」+「系统目录」。
    Check(!VPS(L"C:\\temp\\Windows\\System32\\csrss.exe", L"\\Windows\\System32\\"),
          "C:\\temp\\Windows\\System32\\ 不算系统目录");
    Check(VPS(L"\\Device\\HarddiskVolume2\\Windows\\System32\\csrss.exe",
              L"\\Windows\\System32\\"),
          "真正的 System32(\\Device 形式)算系统目录");
    Check(VPS(L"\\??\\C:\\Windows\\System32\\csrss.exe", L"\\Windows\\System32\\"),
          "真正的 System32(\\??\\C: 形式)算系统目录");

    // 认不出卷前缀 -> 不匹配(fail-safe:多一次上报,而不是多一次放行)
    Check(!VPS(L"\\Device\\Mup\\srv\\Windows\\System32\\x.exe", L"\\Windows\\System32\\"),
          "网络路径认不出卷 -> 不匹配");

#undef VPS
}

// ============================ 3. 按文件名匹配 ============================

static void
TestImageNameIn(void)
{
    static const BLW_NAME_ENTRY table[] = {
        BLW_NAME(L"cmd.exe"),
        BLW_NAME(L"csrss.exe"),
    };

    printf("[3] BlwImageNameIn\n");

#define NIN(p) BlwImageNameIn(table, RTL_NUMBER_OF(table), (p), Chars(p))

    Check(NIN(L"\\Device\\HarddiskVolume1\\Windows\\System32\\CMD.EXE"),
          "大小写不敏感命中");
    Check(NIN(L"\\??\\C:\\Windows\\System32\\cmd.exe"), "\\??\\ 形式命中");
    Check(!NIN(L"cmd.exe"), "整条路径里没有 '\\' -> 不匹配(与原尾部匹配语义一致)");
    Check(!NIN(L"C:\\x\\notcmd.exe"), "notcmd.exe 不是 cmd.exe");
    Check(!NIN(L"C:\\x\\cmd.exe.bak"), "cmd.exe.bak 不是 cmd.exe");
    Check(!NIN(L"C:\\x\\"), "以 '\\' 结尾(无文件名)-> 不匹配");
    Check(!NIN(L""), "空串 -> 不匹配");

#undef NIN
}

// ============================ 4. 宽串子串匹配 ============================

static void
TestWideContains(void)
{
    printf("[4] BlwWideContainsCI\n");

#define WC(s, sub) BlwWideContainsCI((s), Chars(s), sub)

    Check(WC(L"C:\\Users\\u\\AppData\\Local\\Temp\\x.dll", L"\\temp\\"),
          "大小写不敏感的中段命中");
    Check(WC(L"\\DEVICE\\HARDDISKVOLUME1\\USERS\\PUBLIC\\a.exe", L"\\Users\\Public\\"),
          "目标已大写也能命中");
    Check(!WC(L"C:\\x", L"\\this-is-longer-than-target\\"), "子串比目标长 -> 不匹配");
    Check(!WC(L"C:\\Users\\u\\x.dll", L"\\ProgramData\\"), "不含则不匹配");
    Check(!WC(L"", L"\\temp\\"), "空目标 -> 不匹配");
    Check(!WC(L"C:\\Temp\\x", L""), "空子串 -> 不匹配(绝不匹配一切)");

#undef WC
}

// ============================ 5. 名单增删:去重 / 满槽 / 精确删除 ============

static void
TestListAddRemove(void)
{
    static BLW_PROTECTED_PATH list[BLW_MAX_PROTECTED];
    wchar_t buf[64];
    int i;

    printf("[5] BlwAddToList / BlwRemoveFromList\n");

    ListClear(list);
    ListAdd(list, L"\\users\\u\\temp\\a.exe");
    ListAdd(list, L"\\USERS\\U\\TEMP\\A.EXE");   // 同一条,只是大小写不同
    ListAdd(list, L"\\Users\\U\\Temp\\a.exe");
    Check(ListCount(list) == 1, "大小写不同的同一条只占一个槽(去重)");
    Check(list[0].Length == Chars(L"\\users\\u\\temp\\a.exe"), "存入长度正确");
    Check(list[0].Path[1] == L'U', "存入时已大写化(存储约定)");

    // 满槽:第 65 条必须被丢弃,且不覆盖已有条目。
    ListClear(list);
    for (i = 0; i < BLW_MAX_PROTECTED + 3; i++) {
        swprintf(buf, RTL_NUMBER_OF(buf), L"\\dir%03d\\x.exe", i);
        ListAdd(list, buf);
    }
    Check(ListCount(list) == BLW_MAX_PROTECTED, "满槽后不再增长");
    Check(ListHas(list, L"\\DIR000\\X.EXE"), "满槽时先入的条目不被覆盖");
    Check(!ListHas(list, L"\\DIR064\\X.EXE"), "满槽后第 65 条被丢弃");

    // 精确删除
    ListClear(list);
    ListAdd(list, L"\\users\\u\\temp\\a.exe");
    ListAdd(list, L"\\users\\u\\temp\\b.exe");
    Check(ListCount(list) == 2, "删除前 2 条");
    Check(!BlwRemoveFromList(list, L"\\users\\u\\temp\\zzz.exe",
                             Chars(L"\\users\\u\\temp\\zzz.exe")),
          "删不存在的条目 -> FALSE(调用方据此决定不标脏)");
    Check(BlwRemoveFromList(list, L"\\USERS\\U\\TEMP\\A.EXE",
                            Chars(L"\\USERS\\U\\TEMP\\A.EXE")),
          "大小写不敏感的精确删除 -> TRUE");
    Check(ListCount(list) == 1, "删掉一条后剩 1 条");
    Check(!BlwRemoveFromList(list, L"\\users\\u\\temp\\a.exe",
                             Chars(L"\\users\\u\\temp\\a.exe")),
          "同一条不能删两次");
    // 删出来的槽必须能被复用(否则「误判 -> 删除 -> 再下发别的」会耗尽槽位)
    ListAdd(list, L"\\users\\u\\temp\\c.exe");
    Check(ListCount(list) == 2, "删除腾出的槽可被复用");
    Check(!BlwRemoveFromList(list, L"", 0), "空串删除 -> FALSE");
}

// ============================ 6. 子串语义(保护类名单必须保持)============

static void
TestSubstringSemantics(void)
{
    static BLW_PROTECTED_PATH list[BLW_MAX_PROTECTED];
    BLW_MATCH_CTX ctx;
    UNICODE_STRING us;

    printf("[6] BlwMatchInListCtx(子串语义)\n");

    // ProtectedPaths 里本来就有出现在路径【中段】的目录片段,这类必须保持子串语义。
    Check(HitsSub(L"\\START MENU\\PROGRAMS\\STARTUP\\",
                  L"\\Device\\HarddiskVolume1\\Users\\u\\AppData\\Roaming\\Microsoft"
                  L"\\Windows\\Start Menu\\Programs\\Startup\\evil.lnk"),
          "中段目录片段命中(启动目录)");
    Check(HitsSub(L"\\HOSTS", L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\etc\\hosts"),
          "hosts 命中");
    Check(!HitsSub(L"\\HOSTS", L"\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\etc\\lmhosts"),
          "lmhosts 不命中 \\HOSTS(前导 '\\' 挡住了)");

    // UseChars:注册表回调在同一个 "键\值" ctx 上分别做「整串」与「仅键部分」两种匹配。
    ListClear(list);
    ListAdd(list, L"\\WINLOGON\\SHELL");
    MakeUs(&us, L"\\REGISTRY\\MACHINE\\...\\WINLOGON\\SHELL");
    BlwPrepareMatch(&ctx, &us);
    Check(BlwMatchInListCtx(list, 1, &ctx, 0), "UseChars=0 匹配整个目标");
    Check(!BlwMatchInListCtx(list, 1, &ctx, (USHORT)Chars(L"\\REGISTRY\\MACHINE\\...\\WINLOGON")),
          "UseChars 截到键部分时,值名不参与匹配");

    // 空名单 / 空目标
    ListClear(list);
    MakeUs(&us, L"C:\\x");
    BlwPrepareMatch(&ctx, &us);
    Check(!BlwMatchInListCtx(list, 0, &ctx, 0), "空名单 -> 不匹配");
    BlwPrepareMatch(&ctx, NULL);
    Check(!BlwMatchInListCtx(list, 0, &ctx, 0), "NULL 目标 -> 不匹配");
}

// ============================ 7. 锚定语义(禁止执行 / 禁止加载)============

static void
TestAnchoredSemantics(void)
{
    printf("[7] BlwMatchInListAnchoredCtx(锚定语义)\n");

    // (a) 用户态 enforceBlock / blacklistExec 下发的形态:去盘符的完整路径。
    Check(HitsAnchored(L"\\users\\u\\temp\\a.exe",
                       L"\\Device\\HarddiskVolume1\\Users\\u\\Temp\\a.exe"),
          "去盘符完整路径 -> 命中");
    Check(HitsAnchored(L"\\users\\u\\temp\\a.exe", L"C:\\Users\\u\\Temp\\a.exe"),
          "同上(C:\\ 形式的目标)");

    // (b) 这几条在原来的子串语义下会误伤,锚定之后必须不再命中。
    Check(HitsSub(L"\\users\\u\\temp\\a.exe",
                  L"\\Device\\HarddiskVolume1\\Users\\u\\Temp\\a.exe.bak"),
          "回归对照:子串语义会命中 a.exe.bak");
    Check(!HitsAnchored(L"\\users\\u\\temp\\a.exe",
                        L"\\Device\\HarddiskVolume1\\Users\\u\\Temp\\a.exe.bak"),
          "锚定:备份文件 a.exe.bak 不再被命中");
    Check(!HitsAnchored(L"\\users\\u\\temp\\a.exe",
                        L"\\Device\\HarddiskVolume1\\Users\\u\\Temp\\a.exeX"),
          "锚定:a.exeX 不再被命中");
    Check(!HitsAnchored(L"\\users\\u\\temp\\a.exe",
                        L"\\Device\\HarddiskVolume1\\Users\\u\\Temp\\a.exe\\sub\\x.dll"),
          "锚定:恰好叫 a.exe 的【目录】下的模块不再被命中");

    // (c) 备用数据流(ADS)必须仍然命中 —— 否则加一个流名就绕过了。
    Check(HitsAnchored(L"\\users\\u\\temp\\a.exe",
                       L"\\Device\\HarddiskVolume1\\Users\\u\\Temp\\a.exe:payload"),
          "锚定:ADS(a.exe:payload)仍然命中");

    // (d) set-baseline-policy.ps1 文档里的用法:只给文件名片段。
    Check(HitsAnchored(L"\\evil.exe", L"\\Device\\HarddiskVolume1\\Users\\u\\evil.exe"),
          "基线用法 '\\evil.exe' -> 命中");
    Check(!HitsAnchored(L"\\evil.exe", L"\\Device\\HarddiskVolume1\\Users\\u\\notevil.exe"),
          "'\\evil.exe' 不命中 notevil.exe");
    Check(!HitsAnchored(L"\\evil.exe", L"\\Device\\HarddiskVolume1\\Users\\u\\evil.exe.txt"),
          "'\\evil.exe' 不命中 evil.exe.txt");

    // (e) 目录前缀形态(以 '\' 结尾):其下全部内容都算命中。
    Check(HitsAnchored(L"\\users\\u\\temp\\",
                       L"\\Device\\HarddiskVolume1\\Users\\u\\Temp\\anything.dll"),
          "目录前缀 -> 其下内容命中");
    Check(!HitsAnchored(L"\\users\\u\\temp\\",
                        L"\\Device\\HarddiskVolume1\\Users\\u\\Temporary\\x.dll"),
          "目录前缀不会误命中 Temporary\\");

    // (f) 不带前导 '\' 的模式:要求前一个字符是目录分隔符。
    Check(HitsAnchored(L"evil.exe", L"\\Device\\HarddiskVolume1\\u\\evil.exe"),
          "无前导 '\\' 的模式:落在目录边界 -> 命中");
    Check(!HitsAnchored(L"evil.exe", L"\\Device\\HarddiskVolume1\\u\\notevil.exe"),
          "无前导 '\\' 的模式:不在目录边界 -> 不命中");

    // (g) 网络路径(卷前缀认不出来)也必须照常判定 —— 锚定判据刻意不依赖卷前缀识别。
    Check(HitsAnchored(L"\\share\\evil.dll", L"\\Device\\Mup\\srv\\share\\evil.dll"),
          "网络路径(\\Device\\Mup\\)仍能命中");
}

// ============================ 8. 超长目标的回退路径 ============================

static void
TestLongTargetFallback(void)
{
    static wchar_t big[BLW_MAX_PATH + 200];
    static BLW_PROTECTED_PATH list[BLW_MAX_PROTECTED];
    BLW_MATCH_CTX ctx;
    UNICODE_STRING us;
    const wchar_t* tail = L"\\users\\u\\temp\\a.exe";
    USHORT i;
    USHORT pad = BLW_MAX_PATH + 40;

    printf("[8] 超长目标的即时归一化回退路径\n");

    // 构造一条超过 BLW_MAX_PATH 的路径,真正的判据藏在末尾 ——
    // 「用超长路径把名单判定顶掉」正是攻击者可能尝试的手法,回退路径必须与快路径等价。
    for (i = 0; i < pad; i++) {
        big[i] = (i % 20 == 0) ? L'\\' : L'a';
    }
    wcscpy_s(&big[pad], RTL_NUMBER_OF(big) - pad, tail);

    MakeUs(&us, big);
    BlwPrepareMatch(&ctx, &us);
    Check(ctx.Chars == 0, "超长目标不做预归一化(走 Original 回退)");
    Check(ctx.Original != NULL, "回退路径保留了原串");

    ListClear(list);
    ListAdd(list, tail);
    Check(BlwMatchInListCtx(list, 1, &ctx, 0), "回退路径:子串匹配仍然命中");
    Check(BlwMatchInListAnchoredCtx(list, 1, &ctx), "回退路径:锚定匹配仍然命中");

    ListClear(list);
    ListAdd(list, L"\\users\\u\\temp\\a.exe.bak");
    Check(!BlwMatchInListCtx(list, 1, &ctx, 0), "回退路径:不该命中的不命中");
}

// ============================ 9. 命令行硬拦:token 合取 ============================

static void
TestCmdPattern(void)
{
    printf("[9] BlwCmdPatternMatches(token 合取)\n");

    // 参数顺序 / 空格数量 / 大小写 / 是否带全路径,全都不该影响判定。
    Check(CmdHits(L"VSSADMIN+DELETE+SHADOWS", L"vssadmin.exe  Delete   Shadows /All /Quiet"),
          "多空格 + 混合大小写 -> 命中");
    Check(CmdHits(L"VSSADMIN+DELETE+SHADOWS",
                  L"C:\\Windows\\System32\\vssadmin.exe /for=c: delete shadows /quiet"),
          "全路径 + 参数顺序不同 -> 命中");
    Check(!CmdHits(L"VSSADMIN+DELETE+SHADOWS", L"vssadmin list shadows"),
          "缺一个 token -> 不命中(合取语义)");
    Check(!CmdHits(L"VSSADMIN+DELETE+SHADOWS", L"delete shadows"),
          "缺 vssadmin -> 不命中");

    // 两种根键写法都要覆盖(实测过的绕过:HKEY_LOCAL_MACHINE\SAM 不含子串 HKLM\SAM)
    Check(CmdHits(L"SAVE+HKLM\\SAM", L"reg save HKLM\\SAM c:\\out.hiv"), "短写法命中");
    Check(!CmdHits(L"SAVE+HKLM\\SAM", L"reg save HKEY_LOCAL_MACHINE\\SAM c:\\out.hiv"),
          "长写法不被短写法覆盖(这正是要额外列一条模式的原因)");

    // 空模式绝不能变成「匹配一切」——那等于拦死整个系统。
    Check(!CmdHits(L"+++", L"anything at all"), "全是分隔符的空模式 -> 不命中");
    Check(!CmdHits(L"+", L"anything at all"), "单个分隔符 -> 不命中");

    // 模式比命令行长
    Check(!CmdHits(L"AVERYLONGTOKENTHATCANNOTFIT", L"short"), "token 比命令行长 -> 不命中");

    // 单 token 模式
    Check(CmdHits(L"MIMIKATZ", L"C:\\x\\MiMiKatz.exe sekurlsa::logonpasswords"),
          "单 token 命中");
}

// ============================ 10. 带盘符的死条目判据 ============================

static void
TestDriveLetterPattern(void)
{
    printf("[10] BlwPatternHasDriveLetter(死条目判据)\n");

#define DL(p) BlwPatternHasDriveLetter((p), Chars(p))

    // 真实现场:\Policy\FileNoLoad 里 3 条带 C:\ 的条目永远匹配不上规范名,却各占一个槽。
    Check(DL(L"C:\\Users\\u\\a.exe"), "C:\\... -> 死条目");
    Check(DL(L"d:\\x"), "小写盘符也算");
    Check(DL(L"\\Users\\u\\z:\\weird"), "出现在中段也算");
    Check(!DL(L"\\Users\\u\\a.exe"), "去盘符的正常条目 -> 不是死条目");
    Check(!DL(L"\\Device\\HarddiskVolume3\\x"), "规范名形式 -> 不是死条目");
    Check(!DL(L"\\evil.exe"), "文件名片段 -> 不是死条目");
    Check(!DL(L"a:b"), "冒号后面不是 '\\' -> 不算(注册表值名允许含 ':')");
    Check(!DL(L"VSSADMIN+DELETE+SHADOWS"), "命令行模式 -> 不算");
    Check(!DL(L"C:"), "过短 -> 不算");
    Check(!BlwPatternHasDriveLetter(NULL, 0), "NULL -> 不算");

#undef DL
}

int
main(void)
{
    printf("Bulwark driver match-core unit test\n");

    TestVolumeOffset();
    TestVolumePathStartsWith();
    TestImageNameIn();
    TestWideContains();
    TestListAddRemove();
    TestSubstringSemantics();
    TestAnchoredSemantics();
    TestLongTargetFallback();
    TestCmdPattern();
    TestDriveLetterPattern();

    printf("\n%d checks, %d failed\n", g_checks, g_failed);
    return g_failed;
}
