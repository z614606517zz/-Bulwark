#include "bulwark/service/UserModeBehaviorSource.h"
#include "bulwark/engine/RuleEngine.h"
#include "bulwark/models/Enums.h"
#include "bulwark/models/SecurityEvent.h"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QFileSystemWatcher>
#include <QStandardPaths>
#include <QStringList>
#include <QTimer>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <objbase.h>   // CoInitializeEx / CoCreateInstance
#include <shlobj.h>    // IShellLinkW / IPersistFile / CLSID_ShellLink

namespace bulwark::service {

namespace {

// 合成 ActorPid(>4):用户态无真实 PID,但勒索监视器要求 ActorPid>0 才评估;这些事件
// UserModeObserved=false 且不结束进程,不存在误杀风险。与 .NET SyntheticActorPid 一致。
constexpr int kSyntheticActorPid = 0x0B00000;
const QString kCanaryName = QStringLiteral("~$Bulwark_\xE8\xAF\xB7\xE5\x8B\xBF\xE5\x88\xA0\xE9\x99\xA4_DoNotDelete.docx");

QString expandEnv(const QString& p) {
    if (p.isEmpty()) return p;
    wchar_t buf[1024] = {};
    const DWORD n = ::ExpandEnvironmentStringsW(reinterpret_cast<LPCWSTR>(p.utf16()), buf, 1024);
    return (n == 0 || n > 1024) ? p : QString::fromWCharArray(buf);
}

// 解析 .lnk 快捷方式目标(IShellLink)。失败返回空。
QString resolveLnk(const QString& lnkPath) {
    QString result;
    const HRESULT hrInit = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    IShellLinkW* link = nullptr;
    if (SUCCEEDED(::CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER,
                                     IID_IShellLinkW, reinterpret_cast<void**>(&link)))) {
        IPersistFile* pf = nullptr;
        if (SUCCEEDED(link->QueryInterface(IID_IPersistFile, reinterpret_cast<void**>(&pf)))) {
            if (SUCCEEDED(pf->Load(reinterpret_cast<LPCOLESTR>(lnkPath.utf16()), STGM_READ))) {
                wchar_t target[MAX_PATH] = {};
                if (SUCCEEDED(link->GetPath(target, MAX_PATH, nullptr, SLGP_UNCPRIORITY)))
                    result = QString::fromWCharArray(target);
            }
            pf->Release();
        }
        link->Release();
    }
    if (hrInit == S_OK || hrInit == S_FALSE)
        ::CoUninitialize();
    return result;
}

// 从自启动项数据/文件解析被持久化的可执行路径(带引号、首 token、.lnk 目标、环境变量)。
QString resolveAutorunTarget(const QString& data) {
    if (data.trimmed().isEmpty()) return QString();
    QString s = expandEnv(data.trimmed());
    if (s.endsWith(QStringLiteral(".lnk"), Qt::CaseInsensitive)) {
        const QString t = resolveLnk(s);
        if (!t.isEmpty()) return t;
    }
    if (s.startsWith(QLatin1Char('"'))) {
        const int end = s.indexOf(QLatin1Char('"'), 1);
        if (end > 1) return s.mid(1, end - 1);
    }
    if (QFileInfo::exists(s)) return s;
    const int sp = s.indexOf(QLatin1Char(' '));
    if (sp > 0) {
        const QString first = s.left(sp);
        if (QFileInfo::exists(first)) return first;
    }
    return s;
}

QStringList canaryFolders() {
    QStringList out;
    for (auto loc : { QStandardPaths::DocumentsLocation, QStandardPaths::DesktopLocation,
                      QStandardPaths::PicturesLocation }) {
        const QString d = QStandardPaths::writableLocation(loc);
        if (!d.isEmpty()) out << d;
    }
    return out;
}

QStringList startupFolders() {
    QStringList out;
    const QString appData = qEnvironmentVariable("APPDATA");
    const QString progData = qEnvironmentVariable("ProgramData");
    if (!appData.isEmpty())
        out << appData + QStringLiteral("\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
    if (!progData.isEmpty())
        out << progData + QStringLiteral("\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
    return out;
}

// (HKEY, 子键, 根名)三元组:自启动注册表位置。
struct RegLoc { HKEY root; const wchar_t* sub; const char* rootName; };
QList<RegLoc> autorunRegLocations() {
    return {
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKLM" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", "HKLM" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKLM" },
        { HKEY_CURRENT_USER,  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU" },
        { HKEY_CURRENT_USER,  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKCU" },
        { HKEY_CURRENT_USER,  L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", "HKCU" },
    };
}

QString regReadString(HKEY key, const wchar_t* valueName) {
    DWORD type = 0, cb = 0;
    if (::RegQueryValueExW(key, valueName, nullptr, &type, nullptr, &cb) != ERROR_SUCCESS)
        return QString();
    if ((type != REG_SZ && type != REG_EXPAND_SZ) || cb == 0)
        return QString();
    QByteArray buf(static_cast<int>(cb) + 2, '\0');
    if (::RegQueryValueExW(key, valueName, nullptr, &type,
                           reinterpret_cast<LPBYTE>(buf.data()), &cb) != ERROR_SUCCESS)
        return QString();
    QString s = QString::fromWCharArray(reinterpret_cast<const wchar_t*>(buf.constData()));
    return (type == REG_EXPAND_SZ) ? expandEnv(s) : s;
}

// 读取一个自启动键的全部值(name -> data)。
QHash<QString, QString> readAutorunValues(HKEY root, const wchar_t* sub) {
    QHash<QString, QString> out;
    HKEY key = nullptr;
    if (::RegOpenKeyExW(root, sub, 0, KEY_READ, &key) != ERROR_SUCCESS)
        return out;
    DWORD idx = 0;
    wchar_t nameBuf[16384];
    for (;;) {
        DWORD nameLen = 16384;
        const LONG r = ::RegEnumValueW(key, idx++, nameBuf, &nameLen, nullptr, nullptr, nullptr, nullptr);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS && r != ERROR_MORE_DATA) break;
        const QString name = QString::fromWCharArray(nameBuf, static_cast<int>(nameLen));
        if (name.isEmpty()) continue;
        out.insert(name, regReadString(key, reinterpret_cast<LPCWSTR>(name.utf16())));
    }
    ::RegCloseKey(key);
    return out;
}

} // namespace

UserModeBehaviorSource::UserModeBehaviorSource(bulwark::engine::RuleEngine& engine, QObject* parent)
    : EventSource(parent), engine_(engine) {
    startupDirs_ = startupFolders();
    watcher_ = new QFileSystemWatcher(this);
    connect(watcher_, &QFileSystemWatcher::directoryChanged, this, &UserModeBehaviorSource::onDirectoryChanged);
    connect(watcher_, &QFileSystemWatcher::fileChanged, this, &UserModeBehaviorSource::onFileChanged);
    regTimer_ = new QTimer(this);
    regTimer_->setInterval(4000); // 每 4s 轮询注册表自启动基线增量
    connect(regTimer_, &QTimer::timeout, this, &UserModeBehaviorSource::pollRegistry);
}

UserModeBehaviorSource::~UserModeBehaviorSource() { stop(); }

} // namespace bulwark::service

namespace bulwark::service {

void UserModeBehaviorSource::start() {
    if (started_) return;
    started_ = true;
    startStartupWatchers();
    deployCanaries();
    snapshotStartup();
    scanRegistryDelta(/*emitEvents=*/false); // 建立注册表基线,首轮不报
    regTimer_->start();
    log_.info(QStringLiteral("用户态持续行为监控已启动(自启动持久化 + 勒索诱饵)。"));
}

void UserModeBehaviorSource::stop() {
    if (regTimer_) regTimer_->stop();
    if (watcher_) {
        const QStringList dirs = watcher_->directories();
        const QStringList files = watcher_->files();
        if (!dirs.isEmpty()) watcher_->removePaths(dirs);
        if (!files.isEmpty()) watcher_->removePaths(files);
    }
    started_ = false;
}

void UserModeBehaviorSource::startStartupWatchers() {
    for (const QString& dir : startupDirs_) {
        if (QFileInfo::exists(dir)) {
            watcher_->addPath(dir);
            log_.info(QStringLiteral("监视启动文件夹:%1").arg(dir));
        }
    }
}

void UserModeBehaviorSource::snapshotStartup() {
    for (const QString& dir : startupDirs_) {
        QSet<QString> set;
        QDir d(dir);
        if (d.exists())
            for (const QFileInfo& fi : d.entryInfoList(QDir::Files | QDir::NoDotAndDotDot))
                set.insert(QStringLiteral("%1|%2|%3").arg(fi.fileName())
                               .arg(fi.size()).arg(fi.lastModified().toMSecsSinceEpoch()));
        startupBaseline_.insert(dir, set);
    }
}

void UserModeBehaviorSource::deployCanaries() {
    if (!canaryEnabled_) return;
    for (const QString& dir : canaryFolders()) {
        if (!QFileInfo::exists(dir)) continue;
        const QString path = QDir(dir).filePath(kCanaryName);
        if (!QFileInfo::exists(path)) {
            QFile f(path);
            if (!f.open(QIODevice::WriteOnly)) continue;
            f.write(QString::fromUtf8(
                "\xE6\xAD\xA4\xE6\x96\x87\xE4\xBB\xB6\xE4\xB8\xBA\xE7\xA3\x90\xE5\x9E\x92\xE4\xB8\xBB\xE5\x8A\xA8\xE9\x98\xB2"
                "\xE5\xBE\xA1\xE7\x9A\x84\xE5\x8B\x92\xE7\xB4\xA2\xE8\xAF\xB1\xE9\xA5\xB5\xEF\xBC\x8C\xE8\xAF\xB7\xE5\x8B"
                "\xBF\xE5\x88\xA0\xE9\x99\xA4\xE6\x88\x96\xE4\xBF\xAE\xE6\x94\xB9\xE3\x80\x82\r\n"
                "This is a Bulwark ransomware canary (honeypot) file. Do not delete or modify.\r\n").toUtf8());
            f.close();
        }
        ::SetFileAttributesW(reinterpret_cast<LPCWSTR>(QDir::toNativeSeparators(path).utf16()),
                             FILE_ATTRIBUTE_HIDDEN);
        const QString native = QDir::toNativeSeparators(path);
        canaryFiles_.insert(native);
        engine_.addCanaryFile(native);   // 登记蜜罐:引擎侧命中即判强勒索信号
        watcher_->addPath(path);         // 监视诱饵文件本身
    }
    if (!canaryFiles_.isEmpty())
        log_.info(QStringLiteral("已投放 %1 个勒索诱饵文件并登记蜜罐。").arg(canaryFiles_.size()));
}

void UserModeBehaviorSource::onDirectoryChanged(const QString& dir) {
    if (!enabled_) return;
    QDir d(dir);
    QSet<QString> current;
    for (const QFileInfo& fi : d.entryInfoList(QDir::Files | QDir::NoDotAndDotDot)) {
        const QString sig = QStringLiteral("%1|%2|%3").arg(fi.fileName())
                                .arg(fi.size()).arg(fi.lastModified().toMSecsSinceEpoch());
        current.insert(sig);
        if (startupBaseline_.value(dir).contains(sig)) continue; // 已知,跳过
        const QString full = QDir::toNativeSeparators(fi.absoluteFilePath());
        if (canaryFiles_.contains(full)) continue;               // 保险:忽略我方诱饵
        const QString target = resolveAutorunTarget(fi.absoluteFilePath());
        emitAutorunFile(full, target.isEmpty() ? full : target);
    }
    startupBaseline_[dir] = current;
}

void UserModeBehaviorSource::onFileChanged(const QString& path) {
    if (!enabled_ || !canaryEnabled_) return;
    const QString full = QDir::toNativeSeparators(path);
    if (!canaryFiles_.contains(full)) return; // 只处理诱饵

    bulwark::SecurityEvent e;
    e.type = QFileInfo::exists(path) ? bulwark::EventType::FileWrite : bulwark::EventType::FileDelete;
    e.actorPid = kSyntheticActorPid;
    e.actorPath = QString::fromUtf8("(\xE7\x94\xA8\xE6\x88\xB7\xE6\x80\x81\xE8\xA1\x8C\xE4\xB8\xBA\xE7\x9B\x91"
                                    "\xE6\x8E\xA7\xC2\xB7\xE5\x8B\x92\xE7\xB4\xA2\xE8\xAF\xB1\xE9\xA5\xB5)");
    e.target = full;
    e.userModeObserved = false;
    e.detail = QString::fromUtf8("\xE5\x8B\x92\xE7\xB4\xA2\xE8\xAF\xB1\xE9\xA5\xB5\xE6\x96\x87\xE4\xBB\xB6\xE8\xA2\xAB"
                                 "\xE6\x94\xB9\xE5\x86\x99/\xE5\x88\xA0\xE9\x99\xA4\xEF\xBC\x88\xE7\x96\x91\xE4\xBC"
                                 "\xBC\xE5\x8B\x92\xE7\xB4\xA2\xE6\x89\xB9\xE9\x87\x8F\xE5\x8A\xA0\xE5\xAF\x86\xEF\xBC\x89");
    emit eventProduced(e);
    log_.warning(QStringLiteral("勒索诱饵被触碰:%1 —— 疑似勒索行为!").arg(full));

    // 诱饵可能被删除/加密:尽力重建并重新纳入监视,持续覆盖后续加密。
    if (!QFileInfo::exists(path)) {
        QFile f(path);
        if (f.open(QIODevice::WriteOnly)) {
            f.write(QByteArrayLiteral("Bulwark canary\r\n"));
            f.close();
            ::SetFileAttributesW(reinterpret_cast<LPCWSTR>(QDir::toNativeSeparators(path).utf16()),
                                 FILE_ATTRIBUTE_HIDDEN);
        }
    }
    if (QFileInfo::exists(path) && !watcher_->files().contains(path))
        watcher_->addPath(path);
}

void UserModeBehaviorSource::pollRegistry() {
    if (!enabled_) return;
    scanRegistryDelta(/*emitEvents=*/true);
}

void UserModeBehaviorSource::scanRegistryDelta(bool emitEvents) {
    for (const RegLoc& loc : autorunRegLocations()) {
        const QString keyId = QString::fromLatin1(loc.rootName) + QStringLiteral("\\")
                              + QString::fromWCharArray(loc.sub);
        const QHash<QString, QString> current = readAutorunValues(loc.root, loc.sub);
        auto it = regBaseline_.find(keyId);
        if (it == regBaseline_.end()) {
            regBaseline_.insert(keyId, current); // 首次:仅建基线
            continue;
        }
        if (emitEvents) {
            const QHash<QString, QString> baseline = it.value(); // 拷贝,随后安全更新
            for (auto ci = current.constBegin(); ci != current.constEnd(); ++ci) {
                auto bi = baseline.find(ci.key());
                const bool isNew = (bi == baseline.end());
                const bool changed = !isNew && bi.value().compare(ci.value(), Qt::CaseInsensitive) != 0;
                if (isNew || changed) {
                    const QString regPath = keyId + QStringLiteral("\\") + ci.key();
                    const QString target = resolveAutorunTarget(ci.value());
                    emitAutorunReg(regPath, ci.key(), ci.value(), target.isEmpty() ? ci.value() : target);
                }
            }
        }
        it.value() = current; // 更新基线
    }
}

void UserModeBehaviorSource::emitAutorunFile(const QString& filePath, const QString& target) {
    bulwark::SecurityEvent e;
    e.type = bulwark::EventType::FileWrite;
    e.actorPid = 0; // 用户态无法归因发起进程;以被持久化程序评估可信度
    e.actorPath = target;
    e.target = filePath;
    e.userModeObserved = false;
    e.detail = QString::fromUtf8("\xE5\x90\x91\xE5\x90\xAF\xE5\x8A\xA8\xE6\x96\x87\xE4\xBB\xB6\xE5\xA4\xB9\xE5\x86\x99"
                                 "\xE5\x85\xA5\xE8\x87\xAA\xE5\x90\xAF\xE5\x8A\xA8\xE7\xA8\x8B\xE5\xBA\x8F\xEF\xBC\x88"
                                 "\xE6\x8C\x81\xE4\xB9\x85\xE5\x8C\x96\xEF\xBC\x89");
    emit eventProduced(e);
    log_.info(QStringLiteral("检测到启动文件夹新增/变更:%1").arg(filePath));
}

void UserModeBehaviorSource::emitAutorunReg(const QString& regPath, const QString& valueName,
                                            const QString& valueData, const QString& target) {
    bulwark::SecurityEvent e;
    e.type = bulwark::EventType::RegistryWrite;
    e.actorPid = 0;
    e.actorPath = target;
    e.target = regPath;
    e.userModeObserved = false;
    e.detail = QStringLiteral("\xE6\x96\xB0\xE5\xA2\x9E/\xE5\x8F\x98\xE6\x9B\xB4\xE8\x87\xAA\xE5\x90\xAF\xE5\x8A\xA8"
                              "\xE9\xA1\xB9\xEF\xBC\x9A%1 = %2").arg(valueName, valueData);
    emit eventProduced(e);
    log_.info(QStringLiteral("检测到自启动注册表变更:%1").arg(regPath));
}

} // namespace bulwark::service
