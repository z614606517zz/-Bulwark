#pragma once
#include <QString>
#include <QByteArray>
#include <QList>
#include <QUuid>
#include <QDateTime>
#include <QMutex>
#include <QJsonObject>
#include <functional>
#include <optional>

namespace bulwark::service {

// 隔离区条目(金库副本 + 元数据)。
struct QuarantineEntry {
    QUuid id = QUuid::createUuid();
    QString originalPath;
    QString fileName;
    QDateTime quarantinedUtc = QDateTime::currentDateTimeUtc();
    qint64 size = 0;
    QString sha256;
    QString reason;
    int actorPid = 0;

    QJsonObject toJson() const;
    static QuarantineEntry fromJson(const QJsonObject& o);
};

// 文件隔离管理:XOR 中和拷贝到 %ProgramData%\Bulwark\quarantine\ 金库(可逆还原),
// 删除原文件(锁定则计划重启删除),index.json 原子落盘。线程安全。
// 注:原 C++ 头已丢失,此处按 QuarantineManager.cpp 用法重建。
class QuarantineManager {
public:
    QuarantineManager();

    // waitForUnlock=true(默认):原文件被占用时,内部重试删除数次(累计约 5s)后才回退到
    // 「计划重启删除」——用于用户主动 / 后台线程调用(阻塞可接受)。waitForUnlock=false:仅尝试
    // 删除一次,锁定即回退,绝不睡眠——供在主线程上的初次足迹清理调用,避免卡住服务主线程
    // (锁定的残留改由后台重试线程稍后补隔离)。
    std::optional<QuarantineEntry> quarantine(const QString& filePath, const QString& reason,
                                              int actorPid, const QString& sha256 = QString(),
                                              bool waitForUnlock = true);
    QList<QuarantineEntry> list();
    bool restore(const QUuid& id);
    bool purge(const QUuid& id);

    static QString tryComputeSha256(const QString& path);

    // 注入「内核级清理」委托(EventSource=Driver 时由 main 接线;为空则纯用户态)。
    //  - reader:用户态因共享冲突 / 映像占用打不开读时,请内核以「忽略共享访问检查」读出整文件
    //    (out 收原始字节),用户态据此仍能中和写入金库(保住可逆隔离);返回 false 则回退。
    //  - deleter:用户态删不掉(共享冲突 / 已映射运行镜像)时,请内核 POSIX 强制删除;返回是否删成功。
    // 二者均为「试探 + 回退」:旧驱动 / 未连接时返回 false,退化为原有用户态清理,绝不破坏现有行为。
    void setKernelAssist(std::function<bool(const QString&, QByteArray&)> reader,
                         std::function<bool(const QString&)> deleter) {
        kernelReader_ = std::move(reader);
        kernelDeleter_ = std::move(deleter);
    }

private:
    QString storePathFor(const QUuid& id) const;
    void ensureLoaded();
    void saveIndex();

    static constexpr unsigned char kXorKey = 0x5A;
    QString dir_;
    QString indexPath_;
    QList<QuarantineEntry> entries_;
    bool loaded_ = false;
    QMutex io_;

    // 内核级清理委托(见 setKernelAssist)。仅在原文件被独占锁定 / 已映射运行镜像、用户态失败时才用。
    std::function<bool(const QString&, QByteArray&)> kernelReader_;
    std::function<bool(const QString&)> kernelDeleter_;
};

} // namespace bulwark::service
