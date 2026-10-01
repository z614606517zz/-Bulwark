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
#include <utility>

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

    // 「这个原路径此前已经隔离过,且金库副本还在」。判据与 quarantine() 开头那段去重【逐字
    // 相同】,公开出来只是为了让调用方能在付出昂贵代价【之前】问一句。
    //
    // 【为什么必须公开】quarantine() 内部的去重已经能保证不重做隔离,但调用方(足迹清理)
    // 在走到它之前会先对同一个文件做 WinVerifyTrust + SHA-256 两次全文件哈希 —— 实测对
    // 233MB 的样本合计约 1.7 秒。重复事件一多,这两次白算就把事件流水线堵死(实测 20 条
    // 排队事件独占了 40 秒)。语义上这也更诚实:调用方据此不再把「什么都没做」记成一次隔离。
    bool isAlreadyQuarantined(const QString& filePath);

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

    // 注入「先放开我们自己的独占锁」委托(由 main 接到 EventSourceCoordinator::suspendUserModeLock)。
    //
    // 【为什么必须有】无驱动模式下的执行前拦截(UserModeExecBlock)是对目标文件长期持有一个
    // share-mode-0 句柄。那把锁不只挡执行,连【读取和删除】一起挡 —— 包括我们自己。而 Worker 的
    // 处置顺序是先 blacklistExec 再 remediate(Worker.cpp 三处调用点都是这个次序),于是若不先放手,
    // 上面第 1 步的金库拷贝会因共享冲突直接失败,隔离整个做不成:等于用「不能再启动」换掉了
    // 「能被清除」,这笔交易不划算,也不是任何人想要的行为。
    //
    // 返回放开的句柄数(0 = 该路径本来就没被我们锁着,此时不必重试)。放手后条目转为「待重新武装」:
    // 若隔离成功、文件已不在,它就保持待武装,等同路径再次出现恶意文件时自动重新钉住。
    void setSelfUnlock(std::function<int(const QString&)> fn) { selfUnlock_ = std::move(fn); }

    // 注入「原文件删不掉时,至少让它不能再被执行」委托(由 main 接到 SystemHardening::denyExecute)。
    //
    // 【为什么必须有】删除阶梯全部走完仍删不掉时,本类退到 MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)
    // 并打一行「已计划在下次重启时删除(金库副本已就绪,隔离有效)」。那句话的后半段在实测里是
    // 不成立的:文件仍在原地、仍然可以双击运行。2026-09-30 的实测里 wps.exe 就是这样 ——
    // 内核强删返回 0xC0000121,退到计划重启删除,随后又被成功运行了 3 次,每次都重走一遍
    // 「杀进程 + 隔离」。也就是说这条退化路径把「隔离」降级成了「记了一笔账」,而日志说它有效。
    //
    // 拒绝执行 ACE 正好补这一段:它【只拒执行不拒读】,所以不影响我们已经做好的金库副本,也不
    // 影响重启时的删除;而且它是文件系统上的持久元数据,重启前的这段时间里一直有效。
    //
    // 返回 (是否已施加, 未施加的原因)。要求给出原因而不是只给 bool,是因为「没做到」的三种
    // 情形对用户的含义完全不同(开关没开 / 加固器不可用 / 施加失败),而本项目已经在
    // applyRegHardening 上栽过一次「能力不成立时一个字都不说」的坑。
    void setExecDenyFallback(std::function<std::pair<bool, QString>(const QString&)> fn) {
        execDeny_ = std::move(fn);
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
    // 放开自身独占锁的委托(见 setSelfUnlock)。仅在用户态读/删失败后才试,成功放手才重试一次。
    std::function<int(const QString&)> selfUnlock_;
    // 删不掉时的执行阻断委托(见 setExecDenyFallback)。只在退到「计划重启删除」那一支才用。
    std::function<std::pair<bool, QString>(const QString&)> execDeny_;
};

} // namespace bulwark::service
