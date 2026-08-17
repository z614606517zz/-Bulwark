#include "bulwark/service/AuditLog.h"
#include "bulwark/service/Logger.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QDateTime>
#include <QJsonDocument>

namespace bulwark::service {

namespace {
constexpr qint64 kMaxFileBytes = 16LL * 1024 * 1024;
}

AuditLog::AuditLog() {
    dir_ = QDir(programDataDir()).filePath(QStringLiteral("audit"));
    QDir().mkpath(dir_);
}

void AuditLog::writeRecord(const QJsonObject& record) {
    const QByteArray line = QJsonDocument(record).toJson(QJsonDocument::Compact) + "\r\n";

    QMutexLocker lk(&io_);
    const QString path = currentFilePath();
    QFile f(path);
    if (f.open(QIODevice::Append | QIODevice::WriteOnly)) {
        const qint64 written = f.write(line);
        f.close();
        if (written > 0)
            cachedBytes_ += written;   // 自己记账,省掉下一条为判断「写满没」而做的 stat
    }
    // 写入失败(磁盘满/权限)绝不影响主流程。
}

//
// 当前应写入的审计文件路径。
//
// 【为什么要缓存】writeRecord 是【每条事件都走】的路径(Worker::writeAudit 对所有终态裁决都
// 调它),而原实现每写一条都要把解析整个重跑一遍:取一次本地时间并格式化成 yyyyMMdd,然后
// 从 seq=1 开始逐个候选文件各做 exists() + size() 两次 stat。也就是说日志当天已经滚过 N 次
// 之后,每条事件要付 2N 次 stat —— 而事件风暴(勒索批量改文件 / 进程爆发)正是「审计条数最多、
// 主线程最吃紧」的时刻,这笔开销恰好在那时被按事件数线性放大。
//
// 现在把「当前是哪个文件 + 它有多大」记在成员里,只在两种情况下重新解析:
//   1) 日期戳变了(跨天滚动);
//   2) 当前文件已达到大小上限(滚到下一个 seq)。
// 推进判据与原先逐字节一致:仍是「先看容量、未满则追加」,所以单个文件最多超限一条记录 ——
// 与原实现相同的行为,文件命名规则(audit-yyyyMMdd.jsonl / .1.jsonl / .2.jsonl …)也未变,
// 既有的日志收集脚本不受影响。
//
// 一处有意接受的偏差:若【外部程序】也往同一个文件追加,cachedBytes_ 会低估,当前文件可能
// 略微超过上限,直到下一次跨天或重解析。审计目录只有本服务在写,而代价上限只是一个文件偏大,
// 不影响任何判定,故不为此每条事件重新 stat。
//
// 刻意【不】常驻持有文件句柄:那样还能再省掉每条一次 open/close,但 Qt 在 Windows 上打开
// 文件不带 FILE_SHARE_DELETE,当天的审计文件在服务运行期间就会变成删不掉、也无法被外部日志
// 轮转工具处理。对一个「必须让管理员能自主处置自己机器上的日志」的安全产品来说,这个代价
// 不值当 —— 真正的浪费在上面那 2N 次 stat,已经消掉了。
//
QString AuditLog::currentFilePath() {
    const QString day = QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd"));
    if (!cachedPath_.isEmpty() && day == cachedDay_ && cachedBytes_ < kMaxFileBytes)
        return cachedPath_;

    const QString baseName = QStringLiteral("audit-") + day;
    QString path = QDir(dir_).filePath(baseName + QStringLiteral(".jsonl"));
    int seq = 1;
    // 一个 QFileInfo 复用着走:它内部缓存 stat 结果,故 exists()+size() 只产生一次系统调用
    // (原先每轮构造两个临时 QFileInfo,是两次)。
    QFileInfo fi(path);
    while (fi.exists() && fi.size() >= kMaxFileBytes) {
        path = QDir(dir_).filePath(QStringLiteral("%1.%2.jsonl").arg(baseName).arg(seq++));
        fi.setFile(path);
    }

    cachedDay_ = day;
    cachedPath_ = path;
    cachedBytes_ = fi.exists() ? fi.size() : 0;
    return path;
}

} // namespace bulwark::service
