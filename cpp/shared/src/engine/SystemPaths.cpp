#include "bulwark/engine/SystemPaths.h"

namespace bulwark::engine {

QString SystemPaths::volumeRelative(const QString& path) {
    if (path.isEmpty()) return path;
    QString p = path;
    p.replace(QLatin1Char('/'), QLatin1Char('\\'));
    if (p.startsWith(QLatin1String("\\\\?\\"))) p = p.mid(4);
    else if (p.startsWith(QLatin1String("\\\\.\\"))) p = p.mid(4);
    if (p.size() >= 2 && p.at(1) == QLatin1Char(':')) return p.mid(2);
    return p;
}

} // namespace bulwark::engine
