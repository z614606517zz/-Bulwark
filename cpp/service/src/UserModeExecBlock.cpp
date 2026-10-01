#include "bulwark/service/UserModeExecBlock.h"
#include "bulwark/service/AtomicFile.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMutexLocker>
#include <QTimer>

#include <windows.h>

namespace bulwark::service {

namespace {

constexpr int kRearmIntervalMs = 30000; // 30s:待武装条目重试节奏,空表时不做任何事

// 把 QString 交给 Win32 宽字符 API。
inline const wchar_t* wstr(const QString& s) {
    return reinterpret_cast<const wchar_t*>(s.utf16());
}

QString nowIso() {
    return QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
}

// 规范化:统一反斜杠 + 去尾部空白。刻意【不】转小写(要拿去 CreateFileW),
// 大小写无关只用在 QHash 的键上。
QString normalize(const QString& p) {
    QString s = p.trimmed();
    s.replace(QLatin1Char('/'), QLatin1Char('\\'));
    return s;
}

// 系统固定盘符列表(C:\ D:\ ...)。needle 是去盘符子串,必须逐盘试。
QStringList fixedDrives() {
    QStringList out;
    wchar_t buf[512] = {};
    const DWORD n = ::GetLogicalDriveStringsW(511, buf);
    if (n == 0 || n > 511)
        return out;
    for (const wchar_t* p = buf; *p; p += ::wcslen(p) + 1) {
        if (::GetDriveTypeW(p) != DRIVE_FIXED)
            continue;
        QString d = QString::fromWCharArray(p); // "C:\"
        if (d.endsWith(QLatin1Char('\\')))
            d.chop(1);                          // -> "C:"
        out << d;
    }
    return out;
}

} // namespace

UserModeExecBlock::UserModeExecBlock(int maxEntries, QObject* parent)
    : QObject(parent), maxEntries_(maxEntries > 0 ? maxEntries : 256) {
    rearm_ = new QTimer(this);
    rearm_->setInterval(kRearmIntervalMs);
    connect(rearm_, &QTimer::timeout, this, &UserModeExecBlock::rearmPending);
    rearm_->start();
}

UserModeExecBlock::~UserModeExecBlock() {
    QMutexLocker lock(&mx_);
    // 进程退出即释放全部句柄。此后文件重新可执行 —— 这正是「不跨重启」那条边界的由来,
    // 清单留在盘上,下次 replay() 重新武装。
    for (Entry& e : entries_)
        releaseLocked(e);
}

QString UserModeExecBlock::manifestPath() const {
    return QDir(programDataDir()).filePath(QStringLiteral("usermode_execblock.json"));
}

// ---------------------------------------------------------------------------
// 路径判定
// ---------------------------------------------------------------------------

// 把「去盘符子串」解析成真实存在的绝对路径。可能命中多个盘(内核按子串匹配本来就是盘符无关的,
// 用户态要保持同样的覆盖面就得逐盘加锁)。
QStringList UserModeExecBlock::resolveNeedle(const QString& needle) const {
    const QString n = normalize(needle);
    QStringList out;
    if (n.isEmpty())
        return out;

    // 已经是完整路径(带盘符)或 UNC:直接用。
    if ((n.size() >= 2 && n[1] == QLatin1Char(':')) || n.startsWith(QStringLiteral("\\\\"))) {
        if (QFileInfo(n).isFile())
            out << QDir::toNativeSeparators(n);
        return out;
    }

    // 去盘符子串:逐个固定盘拼回去。
    if (!n.startsWith(QLatin1Char('\\')))
        return out; // 既不是绝对路径也不是 \ 开头的子串,形状不对,不猜
    for (const QString& d : fixedDrives()) {
        const QString cand = d + n;
        if (QFileInfo(cand).isFile())
            out << QDir::toNativeSeparators(cand);
    }
    return out;
}

// 绝不加锁的路径。
//
// Worker 在调用点已经有三道闸(加白豁免 / isSweepExemptPath / 子串过短),但本类是个危险原语:
// share-mode-0 不只挡执行,还挡读取、改名、删除。一旦钉错对象,后果比内核那份名单更重
// —— 内核那份只挡执行,这一份会让文件连备份和卸载都做不了。故这里【自己再守一道】,不把安全性
// 寄托在调用方的纪律上。rebuild_full.ps1 头部至今记着内核名单曾把 CMD.EXE 钉进去、整机起不了
// cmd 的那次事故;本类不给这种事故留第二次机会。
bool UserModeExecBlock::isRefusedPath(const QString& absPath) const {
    const QString p = QDir::toNativeSeparators(absPath).toLower();
    if (p.isEmpty())
        return true;

    const QFileInfo fi(absPath);
    if (!fi.isFile())
        return true; // 目录 / 不存在:不是本原语的对象

    const QString sysRoot =
        QDir::toNativeSeparators(qEnvironmentVariable("SystemRoot", QStringLiteral("C:\\Windows")))
            .toLower();
    const QStringList refusedPrefixes = {
        sysRoot + QStringLiteral("\\system32"),
        sysRoot + QStringLiteral("\\syswow64"),
        sysRoot + QStringLiteral("\\winsxs"),
        sysRoot + QStringLiteral("\\servicing"),
        // 本产品自身目录:锁住自己的映像会让升级、卸载、以及驱动分发全部失败。
        QDir::toNativeSeparators(QCoreApplication::applicationDirPath()).toLower(),
    };
    for (const QString& pre : refusedPrefixes) {
        if (!pre.isEmpty() && p.startsWith(pre))
            return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// 加锁 / 释放
// ---------------------------------------------------------------------------

bool UserModeExecBlock::armLocked(Entry& e) {
    releaseLocked(e); // 重新解析前先放开旧句柄,避免自己占着导致重复计数

    const QStringList targets = resolveNeedle(e.needle);
    for (const QString& t : targets) {
        if (isRefusedPath(t)) {
            log_.warning(QStringLiteral("用户态禁止执行:拒绝对该路径加锁(系统目录 / 本产品自身):%1").arg(t));
            continue;
        }
        // dwShareMode = 0 是唯一能挡住执行的取值(见头文件实测第 5 条)。
        // FILE_FLAG_BACKUP_SEMANTICS 不加:本类只处理普通文件,目录已在 isRefusedPath 挡掉。
        const HANDLE h = ::CreateFileW(wstr(t), GENERIC_READ, 0 /*独占*/, nullptr,
                                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            const DWORD err = ::GetLastError();
            // 如实记录失败原因。ERROR_SHARING_VIOLATION 说明别人(可能就是样本自己)正以
            // 冲突模式占着;此时我们【没有】拦截能力,绝不假装有。
            log_.warning(QStringLiteral("用户态禁止执行:抢不到独占句柄(winerr=%1),该文件此刻【未被拦截】:%2")
                             .arg(err)
                             .arg(t));
            continue;
        }
        e.resolved << t;
        e.handles << static_cast<void*>(h);
    }
    return !e.handles.isEmpty();
}

void UserModeExecBlock::releaseLocked(Entry& e) {
    for (void* h : e.handles) {
        if (h && h != INVALID_HANDLE_VALUE)
            ::CloseHandle(static_cast<HANDLE>(h));
    }
    e.handles.clear();
    e.resolved.clear();
}

// ---------------------------------------------------------------------------
// 名单增删
// ---------------------------------------------------------------------------

bool UserModeExecBlock::addEntry(const QString& needle, bool exec) {
    const QString n = normalize(needle);
    if (n.isEmpty())
        return false;
    // 与 Worker 同一道护栏:过短的子串会误伤无关进程。
    if (n.size() < 6)
        return false;

    const QString key = n.toLower();
    QMutexLocker lock(&mx_);

    auto it = entries_.find(key);
    if (it == entries_.end()) {
        // 约束 4:上限。拒绝新增而不是挤掉旧条目 —— 静默丢弃一条已确认恶意的封堵更危险。
        if (entries_.size() >= maxEntries_) {
            log_.warning(QStringLiteral("用户态禁止执行名单已达上限 %1 条,拒绝新增:%2"
                                        "(请先在界面加白/清理已有条目;绝不静默挤掉旧条目)")
                             .arg(maxEntries_)
                             .arg(n));
            return false;
        }
        Entry e;
        e.needle = n;
        e.since = nowIso();
        it = entries_.insert(key, e);
    }

    if (exec)
        it->inExec = true;
    else
        it->inModule = true;

    const bool armed = it->handles.isEmpty() ? armLocked(*it) : true;
    save();

    if (armed) {
        log_.warning(QStringLiteral("用户态%1:已独占锁定 %2 个路径,该映像此后无法启动/加载(亦无法被改名或删除):%3")
                         .arg(exec ? QStringLiteral("禁止执行") : QStringLiteral("禁止加载"))
                         .arg(it->resolved.size())
                         .arg(it->resolved.join(QStringLiteral(" | "))));
    } else {
        log_.warning(QStringLiteral("用户态%1:条目已登记但【当前未生效】(文件不存在或抢不到独占句柄),"
                                    "每 %2 秒重试:%3")
                         .arg(exec ? QStringLiteral("禁止执行") : QStringLiteral("禁止加载"))
                         .arg(kRearmIntervalMs / 1000)
                         .arg(n));
    }
    return armed;
}

bool UserModeExecBlock::blockExecPath(const QString& needle) {
    return addEntry(needle, /*exec=*/true);
}

bool UserModeExecBlock::blockModuleLoad(const QString& needle) {
    return addEntry(needle, /*exec=*/false);
}

bool UserModeExecBlock::clearListLocked(bool exec) {
    int released = 0;
    for (auto it = entries_.begin(); it != entries_.end();) {
        if (exec)
            it->inExec = false;
        else
            it->inModule = false;
        if (!it->inExec && !it->inModule) {
            if (!it->handles.isEmpty())
                ++released;
            releaseLocked(*it);
            it = entries_.erase(it);
        } else {
            ++it;
        }
    }
    save();
    log_.warning(QStringLiteral("用户态「%1」名单已整表清空(释放 %2 条独占锁)—— 加白对账随后会重下发未加白条目。")
                     .arg(exec ? QStringLiteral("禁止执行") : QStringLiteral("禁止加载"))
                     .arg(released));
    return true;
}

// 这两个返回 true 而不是「内核是否受理」:用户态清空一定成功(就是关句柄)。
// Worker::reconcileKernelBlocksAfterTrust 以返回值决定是否重下发 keep 列表,故必须为 true,
// 否则加白撤销会走进「清空失败,条目仍在生效」的分支,而实际上我们已经放开了。
bool UserModeExecBlock::clearExecBlock() {
    QMutexLocker lock(&mx_);
    return clearListLocked(/*exec=*/true);
}

bool UserModeExecBlock::clearModuleNoLoad() {
    QMutexLocker lock(&mx_);
    return clearListLocked(/*exec=*/false);
}

QStringList UserModeExecBlock::persistedExecBlockList() const {
    QMutexLocker lock(&mx_);
    QStringList out;
    for (const Entry& e : entries_)
        if (e.inExec)
            out << e.needle;
    return out;
}

QStringList UserModeExecBlock::persistedModuleNoLoadList() const {
    QMutexLocker lock(&mx_);
    QStringList out;
    for (const Entry& e : entries_)
        if (e.inModule)
            out << e.needle;
    return out;
}

// ---------------------------------------------------------------------------
// 处置协议:隔离/删除前先放手
// ---------------------------------------------------------------------------

int UserModeExecBlock::suspendForRemediation(const QString& absPath) {
    QMutexLocker lock(&mx_);
    const QString want = QDir::toNativeSeparators(normalize(absPath)).toLower();
    int n = 0;
    for (Entry& e : entries_) {
        if (e.handles.isEmpty())
            continue;
        bool hit = want.isEmpty();
        if (!hit) {
            for (const QString& r : e.resolved) {
                if (r.toLower() == want) {
                    hit = true;
                    break;
                }
            }
        }
        if (!hit)
            continue;
        n += e.handles.size();
        releaseLocked(e);
    }
    if (n > 0) {
        log_.info(QStringLiteral("用户态禁止执行:为处置(隔离/取哈希/删除)临时放开 %1 个独占句柄:%2")
                      .arg(n)
                      .arg(want.isEmpty() ? QStringLiteral("(全部)") : absPath));
    }
    return n;
}

void UserModeExecBlock::setSuspended(bool suspended) {
    if (suspended_ == suspended)
        return;
    suspended_ = suspended;

    if (suspended) {
        // 先停重试表再放句柄。反过来的话中间那一瞬 rearmPending() 可能刚好跑起来,把正在被放开的
        // 条目又锁回去 —— 待机就变成了「时好时坏」,而且从日志上看不出原因。
        if (rearm_)
            rearm_->stop();
        int handles = 0, armed = 0;
        {
            QMutexLocker lock(&mx_);
            for (Entry& e : entries_) {
                if (e.handles.isEmpty())
                    continue;
                ++armed;
                handles += static_cast<int>(e.handles.size());
                releaseLocked(e);
            }
        }
        log_.warning(QStringLiteral("用户态禁止执行:已进入待机 —— 放开 %1 条(%2 个独占句柄)并停止重试,"
                                    "名单原样保留。待机期间这些文件【可以被执行】。")
                         .arg(armed)
                         .arg(handles));
        return;
    }

    int armed = 0, pending = 0;
    {
        QMutexLocker lock(&mx_);
        for (Entry& e : entries_) {
            if (!e.handles.isEmpty())
                continue;
            if (armLocked(e))
                ++armed;
            else
                ++pending;
        }
    }
    if (rearm_)
        rearm_->start();
    log_.info(QStringLiteral("用户态禁止执行:已退出待机 —— 重新武装 %1 条,待武装 %2 条(重试表已恢复)。")
                  .arg(armed)
                  .arg(pending));
}

// ---------------------------------------------------------------------------
// 重试 / 落盘 / 重放
// ---------------------------------------------------------------------------

void UserModeExecBlock::rearmPending() {
    // 待机中一律不武装。定时器此刻本该是停着的,这一句是防止将来有人在别处 start() 它 ——
    // 待机的语义是「不持任何独占句柄」,靠"定时器没在跑"来保证太脆。
    if (suspended_)
        return;
    QMutexLocker lock(&mx_);
    int armed = 0, pending = 0;
    for (Entry& e : entries_) {
        if (!e.handles.isEmpty())
            continue;
        if (armLocked(e))
            ++armed;
        else
            ++pending;
    }
    if (armed > 0) {
        log_.warning(QStringLiteral("用户态禁止执行:%1 条待武装条目已重新生效(文件重新出现或占用已解除);"
                                    "仍有 %2 条待武装。")
                         .arg(armed)
                         .arg(pending));
    }
}

int UserModeExecBlock::armedCount() const {
    QMutexLocker lock(&mx_);
    int n = 0;
    for (const Entry& e : entries_)
        if (!e.handles.isEmpty())
            ++n;
    return n;
}

int UserModeExecBlock::pendingCount() const {
    QMutexLocker lock(&mx_);
    int n = 0;
    for (const Entry& e : entries_)
        if (e.handles.isEmpty())
            ++n;
    return n;
}

void UserModeExecBlock::save() const {
    QJsonArray arr;
    for (const Entry& e : entries_) {
        QJsonObject o;
        o[QStringLiteral("needle")] = e.needle;
        o[QStringLiteral("exec")] = e.inExec;
        o[QStringLiteral("module")] = e.inModule;
        o[QStringLiteral("since")] = e.since;
        arr.append(o);
    }
    QJsonObject root;
    root[QStringLiteral("version")] = 1;
    root[QStringLiteral("entries")] = arr;
    writeFileAtomically(manifestPath(),
                        QJsonDocument(root).toJson(QJsonDocument::Indented),
                        QStringLiteral("用户态禁止执行名单"));
}

int UserModeExecBlock::replay() {
    QFile f(manifestPath());
    if (!f.open(QIODevice::ReadOnly)) {
        log_.info(QStringLiteral("用户态禁止执行:无历史名单,从空开始。"));
        return 0;
    }
    const QByteArray bytes = f.readAll();
    f.close();

    QJsonParseError err{};
    const QJsonDocument doc = QJsonDocument::fromJson(bytes, &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject()) {
        log_.warning(QStringLiteral("用户态禁止执行:名单解析失败(%1),本次从空开始(原文件保留以便排查)。")
                         .arg(err.errorString()));
        return 0;
    }

    const QJsonArray arr = doc.object().value(QStringLiteral("entries")).toArray();
    int armed = 0, pending = 0, skipped = 0;
    {
        QMutexLocker lock(&mx_);
        for (const QJsonValue& v : arr) {
            const QJsonObject o = v.toObject();
            const QString n = normalize(o.value(QStringLiteral("needle")).toString());
            if (n.size() < 6)
                continue;
            const bool ex = o.value(QStringLiteral("exec")).toBool();
            const bool mo = o.value(QStringLiteral("module")).toBool();
            if (!ex && !mo)
                continue;
            if (entries_.size() >= maxEntries_) {
                ++skipped;
                continue;
            }
            Entry e;
            e.needle = n;
            e.inExec = ex;
            e.inModule = mo;
            e.since = o.value(QStringLiteral("since")).toString(nowIso());
            auto it = entries_.insert(n.toLower(), e);
            if (armLocked(*it))
                ++armed;
            else
                ++pending;
        }
    }

    // 这条日志是「不跨重启」那条边界的证据:服务停到这一刻之间,名单里的文件是可以执行的。
    log_.warning(QStringLiteral("用户态禁止执行:名单重放完成 —— 已生效 %1 条,待武装 %2 条%3。"
                                "注意:服务未运行期间(含开机到本服务启动之间)这些文件【可以被执行】,"
                                "跨重启的持久拦截需要内核驱动或文件 DACL 拒绝执行。")
                     .arg(armed)
                     .arg(pending)
                     .arg(skipped > 0 ? QStringLiteral(",因超上限跳过 %1 条").arg(skipped) : QString()));
    return armed;
}

} // namespace bulwark::service
