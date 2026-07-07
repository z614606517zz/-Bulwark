#pragma once
#include <QString>
#include <QStringList>

// 引擎层通用小工具与共享类型。仅依赖 Qt6::Core,供所有分析器复用。
namespace bulwark::engine {

// 分析器统一评分结果:分数 + 人类可读理由(可多条)+ 是否为「硬」恶意指标。
// 硬指标(hardSignal=true)单独即可触发处置;软信号仅累加分数,需与硬指标互证。
struct ScoreResult {
    int score = 0;
    QStringList reasons;
    bool hardSignal = false;
};

namespace detail {

// UTF-8 C 字符串字面量 -> QString(引擎源码中的中文理由均以 UTF-8 存储)。
inline QString u(const char* s) { return QString::fromUtf8(s); }
inline QString u(const QString& s) { return s; }

// 取路径的叶子文件名并转小写(等价 C# 的 SafeFileName + ToLowerInvariant)。
// 兼容正/反斜杠与结尾分隔符;无分隔符时视整串为文件名。
inline QString fileNameLower(const QString& path) {
    if (path.isEmpty()) return QString();
    QString p = path;
    p.replace(QLatin1Char('/'), QLatin1Char('\\'));
    while (p.size() > 1 && p.endsWith(QLatin1Char('\\'))) p.chop(1);
    const int slash = p.lastIndexOf(QLatin1Char('\\'));
    const QString name = (slash >= 0) ? p.mid(slash + 1) : p;
    return name.toLower();
}

} // namespace detail
} // namespace bulwark::engine
