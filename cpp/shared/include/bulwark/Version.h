#pragma once

// =====================================================================
//  产品版本的【唯一来源】。
//
//  为什么需要它:在线更新要做的第一件事就是「我现在是哪个版本、服务器那个是不是
//  更新」。而在此之前,版本号在整个产品里只有一处 —— UI 侧边栏的一句字面量
//  "v1.0.0 · Qt Edition"(MainWindow.cpp)。CMake 没有 project VERSION,两个
//  exe 也没有 VERSIONINFO 资源:右键属性看不到版本,Windows 也无从比较。
//  所以更新功能落地之前必须先把版本收敛成一处,否则「比较版本」这一步无从下手,
//  而且迟早会出现「界面显示 1.0.0、exe 属性空白、清单里写 1.2」三处互相矛盾。
//
//  本头文件同时被 C++ 和 .rc 资源脚本包含 —— rc.exe 会跑一遍 C 预处理器,
//  所以 C++ 部分必须用 RC_INVOKED 隔开,否则资源编译直接报错。
// =====================================================================

// 版本号本身在 VersionNumbers.h —— 那个文件是纯 ASCII 且被 .rc 直接包含。
// 别把数字搬回这里:rc.exe 按 ANSI 码页读本文件的中文注释会词法错乱,
// 进而静默丢掉后续的 #define,报出一个完全指错方向的 RC2104。详见那个文件的说明。
#include "bulwark/VersionNumbers.h"

#ifndef RC_INVOKED

#include <QString>
#include <QStringList>

namespace bulwark::version {

namespace detail {
// 把 BULWARK_VERSION_STRING 与三个数字宏钉在一起。字符串化操作符只在这里用 ——
// 这一段 rc.exe 永远看不到(在 RC_INVOKED 之外),所以不会再触发资源编译失败。
#define BULWARK_STRINGIFY_(x) #x
#define BULWARK_STRINGIFY(x)  BULWARK_STRINGIFY_(x)
constexpr const char* kFromNumbers = BULWARK_STRINGIFY(BULWARK_VERSION_MAJOR) "."
                                     BULWARK_STRINGIFY(BULWARK_VERSION_MINOR) "."
                                     BULWARK_STRINGIFY(BULWARK_VERSION_PATCH);
constexpr bool sameString(const char* a, const char* b)
{
    while (*a && *b) {
        if (*a != *b) return false;
        ++a; ++b;
    }
    return *a == *b;
}
static_assert(sameString(kFromNumbers, BULWARK_VERSION_STRING),
              "BULWARK_VERSION_STRING 与 MAJOR/MINOR/PATCH 不一致 —— 两处都要改。"
              "版本号是更新比较的唯一依据,不一致会让 exe 属性、界面、更新判定三处打架。");
} // namespace detail

// 本机构建的版本串,如 "1.1.0"。
inline QString current()
{
    return QString::fromLatin1(BULWARK_VERSION_STRING);
}

// 界面展示用,如 "v1.1.0 · Qt Edition"。
inline QString displayString()
{
    return QStringLiteral("v") + current()
           + QStringLiteral(" · ") + QString::fromLatin1(BULWARK_VERSION_SUFFIX);
}

// 把点分版本串规范成可比较的数字段。
//
// 刻意【不做】字符串比较:那样 "1.10.0" < "1.2.0"(逐字符 '1'<'2'),于是一个更新的
// 版本会被判成更旧,更新功能直接失效且不会报错。也刻意不折算成单个整数(major*10000
// 之类):那种做法在某一段超过进位基数时会静默溢出、把两个不同版本算成同一个。
inline QList<int> parse(const QString& v)
{
    QList<int> out;
    QString s = v.trimmed();
    if (s.startsWith(QLatin1Char('v')) || s.startsWith(QLatin1Char('V')))
        s = s.mid(1);
    // 允许 "1.1.0-beta2" 这种带后缀的形式:后缀不参与比较,截掉即可。
    const int dash = s.indexOf(QLatin1Char('-'));
    if (dash > 0)
        s = s.left(dash);
    const QStringList parts = s.split(QLatin1Char('.'), Qt::SkipEmptyParts);
    for (const QString& p : parts) {
        bool ok = false;
        const int n = p.trimmed().toInt(&ok);
        // 遇到非数字段就停:宁可比较得保守(少更新一次),也不要把无法解析的
        // 服务器字段当成 0 而误判出一个「更新版本」。
        if (!ok || n < 0)
            break;
        out.append(n);
    }
    return out;
}

// a 与 b 的大小:<0 = a 更旧,0 = 相同,>0 = a 更新。
// 段数不同时短的一方按 0 补齐("1.1" == "1.1.0")。
inline int compare(const QString& a, const QString& b)
{
    const QList<int> x = parse(a);
    const QList<int> y = parse(b);
    const int n = qMax(x.size(), y.size());
    for (int i = 0; i < n; ++i) {
        const int xi = i < x.size() ? x.at(i) : 0;
        const int yi = i < y.size() ? y.at(i) : 0;
        if (xi != yi)
            return xi < yi ? -1 : 1;
    }
    return 0;
}

// remote 是否比本机构建更新。空串/解析不出任何数字段 -> false(不提示更新)。
//
// 这个方向很重要:更新提示宁可漏报,不可误报。服务器返回垃圾时应当安静地什么都不做,
// 而不是弹一个「有新版本」然后让用户去下载一个解析不出来的东西。
inline bool isNewerThanCurrent(const QString& remote)
{
    if (parse(remote).isEmpty())
        return false;
    return compare(remote, current()) > 0;
}

} // namespace bulwark::version

#endif // RC_INVOKED
