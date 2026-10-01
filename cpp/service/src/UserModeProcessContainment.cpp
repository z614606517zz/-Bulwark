#include "bulwark/service/UserModeProcessContainment.h"
#include "bulwark/service/monitoring/ProcessInspector.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QMutexLocker>
#include <QTimer>

#include <windows.h>

namespace bulwark::service {

namespace {

using monitoring::ProcessInspector;

constexpr int kTtlTickMs = 5000;      // 冻结 TTL 巡检节奏;空表时不做任何事
constexpr int kWaitExitMs = 1500;     // 结束后确认死亡的等待上限

inline const wchar_t* wstr(const QString& s) {
    return reinterpret_cast<const wchar_t*>(s.utf16());
}

qint64 nowMs() { return QDateTime::currentMSecsSinceEpoch(); }

QString lower(const QString& s) {
    QString t = s;
    t.replace(QLatin1Char('/'), QLatin1Char('\\'));
    return t.toLower();
}

// 与 UserModeExecBlock::isRefusedPath 同一口径:系统目录与本产品自身一律不动。
// 这是本类【自己】的护栏,与 ProcessInspector::isCriticalProcess 叠加 —— 那一道看的是
// 「结束它会不会蓝屏」,这一道看的是「它是不是系统组件或我们自己」。两个问题不一样:
// 一个非关键的系统服务被冻住不会蓝屏,但同样会让机器不可用。
bool isProtectedImage(const QString& imagePath) {
    if (imagePath.trimmed().isEmpty())
        return false;   // 路径未知时不在这里拒绝,交给 isCriticalProcess 与 PID 护栏
    const QString p = lower(imagePath);
    static const QStringList kDirs = {
        QStringLiteral("\\windows\\system32\\"),
        QStringLiteral("\\windows\\syswow64\\"),
        QStringLiteral("\\windows\\winsxs\\"),
        QStringLiteral("\\windows\\servicing\\"),
    };
    for (const QString& d : kDirs) {
        if (p.contains(d))
            return true;
    }
    // 本产品自身(服务 / UI / 驱动安装目录)。按【目录】判而不是按文件名里含 bulwark ——
    // 后者会让 C:\Users\x\Downloads\bulwark_setup.exe 这种也被豁免,那是 Worker 那边
    // isSweepExemptPath 修过的同一个坑。
    const QString self = lower(QCoreApplication::applicationDirPath()) + QStringLiteral("\\");
    if (!self.isEmpty() && p.startsWith(self))
        return true;
    return false;
}

} // namespace

UserModeProcessContainment::UserModeProcessContainment(int maxEntries, int frozenTtlMs,
                                                       QObject* parent)
    : QObject(parent),
      maxEntries_(maxEntries > 0 ? maxEntries : 64),
      frozenTtlMs_(frozenTtlMs > 0 ? frozenTtlMs : 120000) {
    ttl_ = new QTimer(this);
    ttl_->setInterval(kTtlTickMs);
    connect(ttl_, &QTimer::timeout, this, &UserModeProcessContainment::onTtlTick);
    ttl_->start();
}

UserModeProcessContainment::~UserModeProcessContainment() {
    // 析构时解冻一切。服务正常停止时留下一堆被挂起的进程,对用户就是「一批程序莫名卡死」,
    // 而且没有任何东西会再来恢复它们(冻结不跨重启,也就没有 replay 能救)。
    QList<int> toThaw;
    QList<void*> jobs;
    {
        QMutexLocker lk(&mx_);
        for (auto it = entries_.constBegin(); it != entries_.constEnd(); ++it) {
            if (it.value().frozen)
                toThaw << it.key();
            if (it.value().job)
                jobs << it.value().job;
        }
        entries_.clear();
    }
    for (int pid : toThaw)
        ProcessInspector::tryResume(pid);
    if (!toThaw.isEmpty()) {
        log_.warning(QStringLiteral("进程收容:服务停止,已解冻 %1 个此前被冻结的进程"
                                    "(冻结不跨进程生命周期,留着就是无人认领的卡死)。")
                         .arg(toThaw.size()));
    }
    // Job 句柄关掉,但【限制不会因此解除】(实测 Q4)。这一点必须在日志里说清楚,否则
    // 排查的人会以为服务一停收容就没了。
    for (void* h : jobs) {
        if (h)
            ::CloseHandle(static_cast<HANDLE>(h));
    }
    if (!jobs.isEmpty()) {
        log_.warning(QStringLiteral("进程收容:已关闭 %1 个 Job 句柄。注意「禁止创建子进程」"
                                    "对那些进程【仍然有效】,直到它们自己退出 —— Windows 没有"
                                    "把进程移出 Job 的接口。")
                         .arg(jobs.size()));
    }
}

void UserModeProcessContainment::setImageLocker(LockImageFn fn) { lockImage_ = std::move(fn); }
void UserModeProcessContainment::setKernelKill(KernelKillFn fn) { kernelKill_ = std::move(fn); }

bool UserModeProcessContainment::refuseTarget(int pid, const QString& imagePath,
                                              QString* why) const {
    const auto no = [why](const QString& w) {
        if (why)
            *why = w;
        return true;
    };
    if (pid <= 4)
        return no(QStringLiteral("PID <= 4(Idle / System)"));
    if (pid == static_cast<int>(::GetCurrentProcessId()))
        return no(QStringLiteral("那是本服务自己"));
    if (isProtectedImage(imagePath))
        return no(QStringLiteral("系统目录 / 本产品自身的映像:%1").arg(imagePath));
    if (ProcessInspector::isCriticalProcess(pid))
        return no(QStringLiteral("关键系统进程(结束/冻结可能导致 0xEF 停机)"));
    return false;
}

// ---------------------------------------------------------------- 2.2 断子
bool UserModeProcessContainment::cutOffChildren(int pid, bool onlyWhenTerminating,
                                                const QString& why) {
    if (!onlyWhenTerminating) {
        // 见头文件:这个原语不可撤销,用错了用户永远查不出原因。把误用变成一条日志。
        log_.warning(QStringLiteral("进程收容:拒绝对 PID=%1 断子 —— 该动作【不可撤销】"
                                    "(Windows 无法把进程移出 Job),只允许在即将结束该进程时使用。"
                                    "调用方未声明正在终结流程。原因:%2")
                         .arg(pid)
                         .arg(why));
        return false;
    }
    QString refuse;
    if (refuseTarget(pid, QString(), &refuse)) {
        log_.warning(QStringLiteral("进程收容:拒绝对 PID=%1 断子(%2)。").arg(pid).arg(refuse));
        return false;
    }
    {
        QMutexLocker lk(&mx_);
        if (entries_.contains(pid) && entries_.value(pid).job)
            return true;   // 已收容,幂等
        if (entries_.size() >= maxEntries_ && !entries_.contains(pid)) {
            log_.warning(QStringLiteral("进程收容:已达上限 %1,拒绝对 PID=%2 断子"
                                        "(绝不静默挤掉已有条目)。")
                             .arg(maxEntries_)
                             .arg(pid));
            return false;
        }
    }

    HANDLE ph = ::OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, FALSE,
                              static_cast<DWORD>(pid));
    if (!ph) {
        log_.warning(QStringLiteral("进程收容:断子失败,打不开 PID=%1(winerr=%2)——"
                                    "【该进程此刻仍能创建子进程】。")
                         .arg(pid)
                         .arg(::GetLastError()));
        return false;
    }
    HANDLE job = ::CreateJobObjectW(nullptr, nullptr);
    if (!job) {
        const DWORD e = ::GetLastError();
        ::CloseHandle(ph);
        log_.warning(QStringLiteral("进程收容:CreateJobObject 失败(winerr=%1),PID=%2 未被断子。")
                         .arg(e)
                         .arg(pid));
        return false;
    }
    JOBOBJECT_BASIC_LIMIT_INFORMATION info{};
    info.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    info.ActiveProcessLimit = 1;   // 目标自己就占满了配额 -> 它再 CreateProcess 必失败
    if (!::SetInformationJobObject(job, JobObjectBasicLimitInformation, &info, sizeof(info))) {
        const DWORD e = ::GetLastError();
        ::CloseHandle(job);
        ::CloseHandle(ph);
        log_.warning(QStringLiteral("进程收容:设置 ActiveProcessLimit 失败(winerr=%1),"
                                    "PID=%2 未被断子(刻意不把一个【没有限制】的 Job 留在那里"
                                    "冒充收容)。")
                         .arg(e)
                         .arg(pid));
        return false;
    }
    const BOOL assigned = ::AssignProcessToJobObject(job, ph);
    const DWORD aerr = ::GetLastError();
    ::CloseHandle(ph);
    if (!assigned) {
        ::CloseHandle(job);
        log_.warning(QStringLiteral("进程收容:AssignProcessToJobObject 失败(winerr=%1),"
                                    "PID=%2 未被断子%3")
                         .arg(aerr)
                         .arg(pid)
                         .arg(aerr == ERROR_ACCESS_DENIED
                                  ? QStringLiteral("。错误 5 通常意味着目标已在一个不允许嵌套的"
                                                   "Job 里(Win8 以前不支持嵌套 Job)。")
                                  : QStringLiteral("。")));
        return false;
    }
    {
        QMutexLocker lk(&mx_);
        Entry& e = entries_[pid];
        e.job = job;
    }
    log_.warning(QStringLiteral("进程收容:PID=%1 已断子 —— 其后续创建子进程一律失败"
                                "(ERROR_NOT_ENOUGH_QUOTA 1816)。此动作【不可撤销】,"
                                "直到该进程退出。原因:%2")
                     .arg(pid)
                     .arg(why));
    return true;
}

bool UserModeProcessContainment::isChildrenCutOff(int pid) const {
    QMutexLocker lk(&mx_);
    return entries_.contains(pid) && entries_.value(pid).job != nullptr;
}

// ---------------------------------------------------------------- 2.3 可逆冻结
bool UserModeProcessContainment::freeze(int pid, const QString& imagePath, const QString& why,
                                       bool autoThaw) {
    QString refuse;
    if (refuseTarget(pid, imagePath, &refuse)) {
        log_.warning(QStringLiteral("进程收容:拒绝冻结 PID=%1(%2)。").arg(pid).arg(refuse));
        return false;
    }
    {
        QMutexLocker lk(&mx_);
        if (entries_.contains(pid) && entries_.value(pid).frozen)
            return true;   // 幂等
        if (entries_.size() >= maxEntries_ && !entries_.contains(pid)) {
            log_.warning(QStringLiteral("进程收容:已达上限 %1,拒绝冻结 PID=%2。")
                             .arg(maxEntries_)
                             .arg(pid));
            return false;
        }
    }
    if (!ProcessInspector::trySuspend(pid)) {
        log_.warning(QStringLiteral("进程收容:冻结 PID=%1 失败 —— 【它此刻仍在运行】,"
                                    "不要把本次处置说成已止损。映像:%2")
                         .arg(pid)
                         .arg(imagePath));
        return false;
    }
    {
        QMutexLocker lk(&mx_);
        Entry& e = entries_[pid];
        e.frozen = true;
        e.autoThaw = autoThaw;
        e.frozenAtMs = nowMs();
        e.imagePath = imagePath;
    }
    // 措辞刻意是「已冻结(执行前暂停)」而不是「已阻断」:动作可能已经部分发生,
    // 冻结买到的是【决定期间不再变坏】,不是「什么都没发生」。
    log_.warning(QStringLiteral("进程收容:PID=%1 已冻结(全部线程挂起,可恢复),%2。"
                                "原因:%3。映像:%4")
                     .arg(pid)
                     .arg(autoThaw
                              ? QStringLiteral("最长 %1 秒后自动解冻(尚未确认恶意)")
                                    .arg(frozenTtlMs_ / 1000)
                              : QStringLiteral("【不自动解冻】(已确认恶意且未能结束);"
                                               "在界面加白该程序即可解除"))
                     .arg(why)
                     .arg(imagePath));
    return true;
}

bool UserModeProcessContainment::thaw(int pid, const QString& why) {
    bool wasFrozen = false;
    QString img;
    qint64 heldMs = 0;
    {
        QMutexLocker lk(&mx_);
        auto it = entries_.find(pid);
        if (it != entries_.end() && it.value().frozen) {
            wasFrozen = true;
            img = it.value().imagePath;
            heldMs = nowMs() - it.value().frozenAtMs;
            it.value().frozen = false;
            it.value().frozenAtMs = 0;
            if (!it.value().job)
                entries_.erase(it);   // 没有 Job 就没有别的状态可留
        }
    }
    if (!wasFrozen)
        return false;
    const bool ok = ProcessInspector::tryResume(pid);
    if (ok) {
        log_.info(QStringLiteral("进程收容:PID=%1 已解冻(冻结 %2 ms)。原因:%3。映像:%4")
                      .arg(pid)
                      .arg(heldMs)
                      .arg(why)
                      .arg(img));
    } else {
        // 恢复失败必须喊出来:那意味着一个进程被我们挂在半空且我们放不开它。
        log_.warning(QStringLiteral("进程收容:PID=%1 解冻【失败】(winerr=%2)—— 该进程可能已退出;"
                                    "若仍存在则处于挂起状态且本服务已放弃对它的记录。映像:%3")
                         .arg(pid)
                         .arg(::GetLastError())
                         .arg(img));
    }
    return ok;
}

int UserModeProcessContainment::thawByPathNeedle(const QString& needle, const QString& why) {
    if (needle.trimmed().isEmpty())
        return 0;
    const QString n = lower(needle);
    QList<int> hit;
    {
        QMutexLocker lk(&mx_);
        for (auto it = entries_.constBegin(); it != entries_.constEnd(); ++it) {
            if (it.value().frozen && lower(it.value().imagePath).contains(n))
                hit << it.key();
        }
    }
    int n2 = 0;
    for (int pid : hit) {
        if (thaw(pid, why))
            ++n2;
    }
    return n2;
}

int UserModeProcessContainment::thawAll(const QString& why) {
    QList<int> all;
    {
        QMutexLocker lk(&mx_);
        for (auto it = entries_.constBegin(); it != entries_.constEnd(); ++it) {
            if (it.value().frozen)
                all << it.key();
        }
    }
    int n = 0;
    for (int pid : all) {
        if (thaw(pid, why))
            ++n;
    }
    return n;
}

bool UserModeProcessContainment::isFrozen(int pid) const {
    QMutexLocker lk(&mx_);
    return entries_.contains(pid) && entries_.value(pid).frozen;
}

QList<int> UserModeProcessContainment::frozenPids() const {
    QList<int> out;
    QMutexLocker lk(&mx_);
    for (auto it = entries_.constBegin(); it != entries_.constEnd(); ++it) {
        if (it.value().frozen)
            out << it.key();
    }
    return out;
}

qint64 UserModeProcessContainment::frozenForMs(int pid) const {
    QMutexLocker lk(&mx_);
    auto it = entries_.constFind(pid);
    if (it == entries_.constEnd() || !it.value().frozen)
        return -1;
    return nowMs() - it.value().frozenAtMs;
}

void UserModeProcessContainment::onTtlTick() {
    QList<int> expired;
    QList<int> dead;
    {
        QMutexLocker lk(&mx_);
        if (entries_.isEmpty())
            return;
        const qint64 t = nowMs();
        for (auto it = entries_.constBegin(); it != entries_.constEnd(); ++it) {
            // autoThaw=false 的条目刻意不设期限:那是已确认恶意且没能杀掉的进程,
            // 到期放行等于自己撤销自己的处置。解除路径是「用户加白 -> reconcile」。
            if (it.value().frozen && it.value().autoThaw
                && t - it.value().frozenAtMs >= frozenTtlMs_)
                expired << it.key();
        }
    }
    for (int pid : expired) {
        log_.warning(QStringLiteral("进程收容:PID=%1 冻结已超过 %2 秒仍无裁决,自动解冻 ——"
                                    "宁可放过也不把一个进程无声挂死(用户看到的会是「程序卡住」"
                                    "而不是任何安全提示)。")
                         .arg(pid)
                         .arg(frozenTtlMs_ / 1000));
        thaw(pid, QStringLiteral("冻结超时自动解冻(无人裁决)"));
    }
    // 顺带回收已退出进程留下的 Job 句柄,避免长时间运行后句柄堆积。
    {
        QMutexLocker lk(&mx_);
        for (auto it = entries_.constBegin(); it != entries_.constEnd(); ++it) {
            if (!it.value().frozen && it.value().job) {
                HANDLE ph = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                          static_cast<DWORD>(it.key()));
                if (!ph) {
                    dead << it.key();
                } else {
                    DWORD code = 0;
                    if (::GetExitCodeProcess(ph, &code) && code != STILL_ACTIVE)
                        dead << it.key();
                    ::CloseHandle(ph);
                }
            }
        }
        for (int pid : dead) {
            auto it = entries_.find(pid);
            if (it == entries_.end())
                continue;
            if (it.value().job)
                ::CloseHandle(static_cast<HANDLE>(it.value().job));
            entries_.erase(it);
        }
    }
}

// ---------------------------------------------------------------- 2.1 处置阶梯
QString UserModeProcessContainment::LadderResult::summary() const {
    QStringList done;
    if (imageLocked)
        done << QStringLiteral("已锁映像");
    if (frozen)
        done << QStringLiteral("已冻结");
    if (childrenCutOff)
        done << QStringLiteral("已断子");
    if (userModeKilled || kernelKilled)
        done << QStringLiteral("已请求结束");
    if (confirmedGone)
        done << QStringLiteral("已确认退出");
    if (done.isEmpty())
        return QStringLiteral("未能施加任何处置");
    // 这里是全函数最要紧的一句:确认退出与仅仅收容,对用户是两件不同的事。
    const QString tail = confirmedGone
                             ? QString()
                             : QStringLiteral(";【进程仍在运行】——已收容但未结束,需要人工处理");
    return done.join(QStringLiteral(" + ")) + tail;
}

UserModeProcessContainment::LadderResult
UserModeProcessContainment::disposeOf(int pid, const QString& imagePath,
                                      const QString& imagePathNeedle, const QString& why) {
    LadderResult r;
    const auto step = [&r](const QString& name, bool attempted, bool ok, const QString& detail) {
        LadderStep s;
        s.name = name;
        s.attempted = attempted;
        s.ok = ok;
        s.detail = detail;
        r.steps.push_back(s);
    };

    QString refuse;
    if (refuseTarget(pid, imagePath, &refuse)) {
        step(QStringLiteral("护栏"), true, false, refuse);
        log_.warning(QStringLiteral("处置阶梯:拒绝处置 PID=%1(%2)。原因:%3")
                         .arg(pid)
                         .arg(refuse)
                         .arg(why));
        return r;
    }

    // ① 锁映像 —— 放在最前面。1.1 实测可以锁正在运行的映像,先锁住就没有「临死前从同一
    //    路径把自己重新拉起来」或「把文件换成另一个再跑」的空窗。
    if (!imagePathNeedle.trimmed().isEmpty() && lockImage_) {
        const bool ok = lockImage_(imagePathNeedle);
        r.imageLocked = ok;
        step(QStringLiteral("锁映像"), true, ok,
             ok ? QStringLiteral("独占句柄已持有,该路径无法再被执行/改名/删除")
                : QStringLiteral("未能取得独占句柄(文件被占用或不存在)"));
    } else {
        step(QStringLiteral("锁映像"), false, false,
             imagePathNeedle.trimmed().isEmpty() ? QStringLiteral("调用方未给出路径子串")
                                                 : QStringLiteral("未注入加锁能力"));
    }

    // ② 冻结 —— 立刻停住全部线程,后面几步期间不会再有新破坏。
    {
        const bool ok = ProcessInspector::trySuspend(pid);
        r.frozen = ok;
        step(QStringLiteral("冻结"), true, ok,
             ok ? QStringLiteral("全部线程已挂起") : QStringLiteral("挂起失败(可能已退出)"));
        if (ok) {
            QMutexLocker lk(&mx_);
            Entry& e = entries_[pid];
            e.frozen = true;
            // 阶梯是「已确认恶意」的路径 -> 不自动解冻。如果后面几步把它杀掉了,这条记录
            // 会在 confirmedGone 分支里被清掉;没杀掉才留着,那正是我们要它停住的情形。
            e.autoThaw = false;
            e.frozenAtMs = nowMs();
            e.imagePath = imagePath;
        }
    }

    // ③ 断子 —— 此处允许:我们正在走终结流程(onlyWhenTerminating=true)。
    {
        const bool ok = cutOffChildren(pid, true, why);
        r.childrenCutOff = ok;
        step(QStringLiteral("断子"), true, ok,
             ok ? QStringLiteral("Job ActiveProcessLimit=1,后续 CreateProcess 返回 1816")
                : QStringLiteral("未能收容(详见上一条 warning)"));
    }

    // ④ 结束进程树 —— 先叶后根,每个都过关键进程护栏。
    {
        const int killed = ProcessInspector::terminateProcessTree(pid);
        r.killedInTree = killed;
        r.userModeKilled = killed > 0;
        step(QStringLiteral("结束进程树"), true, killed > 0,
             QStringLiteral("用户态结束 %1 个(含后代)").arg(killed));
    }

    // ⑤ 内核兜底补刀 —— 有驱动时 ZwTerminateProcess。无驱动时如实记为不可用,
    //    绝不把「没这个能力」写成「失败」,两者对排查的含义完全不同。
    if (kernelKill_) {
        const bool ok = kernelKill_(pid);
        r.kernelKilled = ok;
        step(QStringLiteral("内核补刀"), true, ok,
             ok ? QStringLiteral("已下发 BLW_CMD_KILL_PID")
                : QStringLiteral("驱动未连接或拒绝"));
    } else {
        step(QStringLiteral("内核补刀"), false, false,
             QStringLiteral("无内核驱动(本次为纯用户态处置)"));
    }

    // ⑥ 确认死亡 —— 结束是异步的,而且被别人持有句柄的僵尸进程仍留在快照里,
    //    所以只有 waitForExit 说死了才允许对外讲「已结束」。
    {
        const bool gone = ProcessInspector::waitForExit(pid, kWaitExitMs);
        r.confirmedGone = gone;
        step(QStringLiteral("确认退出"), true, gone,
             gone ? QStringLiteral("已确认退出") : QStringLiteral("未能确认退出(仍在运行或无法查询)"));
    }

    if (r.confirmedGone) {
        // 进程已死:它的冻结/收容记录没有意义了,清掉(Job 句柄一并关闭)。
        QMutexLocker lk(&mx_);
        auto it = entries_.find(pid);
        if (it != entries_.end()) {
            if (it.value().job)
                ::CloseHandle(static_cast<HANDLE>(it.value().job));
            entries_.erase(it);
        }
    }

    log_.warning(QStringLiteral("处置阶梯 PID=%1:%2。原因:%3。映像:%4")
                     .arg(pid)
                     .arg(r.summary())
                     .arg(why)
                     .arg(imagePath));
    for (const LadderStep& s : r.steps) {
        log_.info(QStringLiteral("  阶梯· %1:%2 —— %3")
                      .arg(s.name)
                      .arg(!s.attempted ? QStringLiteral("未尝试")
                                        : (s.ok ? QStringLiteral("成功") : QStringLiteral("失败")))
                      .arg(s.detail));
    }
    return r;
}

QStringList UserModeProcessContainment::describeState() const {
    QStringList out;
    QMutexLocker lk(&mx_);
    const qint64 t = nowMs();
    for (auto it = entries_.constBegin(); it != entries_.constEnd(); ++it) {
        out << QStringLiteral("PID=%1 frozen=%2%3 cutOff=%4 image=%5")
                   .arg(it.key())
                   .arg(it.value().frozen ? QStringLiteral("true") : QStringLiteral("false"))
                   .arg(it.value().frozen
                            ? QStringLiteral("(%1ms)").arg(t - it.value().frozenAtMs)
                            : QString())
                   .arg(it.value().job ? QStringLiteral("true") : QStringLiteral("false"))
                   .arg(it.value().imagePath);
    }
    return out;
}

} // namespace bulwark::service
