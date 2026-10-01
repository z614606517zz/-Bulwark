#include "bulwark/service/OccupiedFileAccess.h"
#include "bulwark/service/Logger.h"

#include <QFileInfo>
#include <QStringList>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <RestartManager.h>

#include <atomic>

namespace bulwark::service::occupied {

namespace {

Logger& log() {
    static Logger l(QStringLiteral("OccupiedFile"));
    return l;
}

inline const wchar_t* wstr(const QString& s) {
    return reinterpret_cast<const wchar_t*>(s.utf16());
}

constexpr qint64 kMaxReadBytes = 512LL * 1024 * 1024; // 与驱动侧 kernelReadFile 同一上限

// 启用一个特权。返回 true 表示确实启用了(ERROR_NOT_ALL_ASSIGNED 视为失败 —— 那说明
// 令牌根本不持有它,继续用备份语义只会得到一个令人困惑的 5)。
bool enableOne(const wchar_t* name, QString& why) {
    HANDLE tok = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(),
                            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) {
        why = QStringLiteral("OpenProcessToken 失败(%1)").arg(::GetLastError());
        return false;
    }
    LUID luid{};
    if (!::LookupPrivilegeValueW(nullptr, name, &luid)) {
        why = QStringLiteral("LookupPrivilegeValue 失败(%1)").arg(::GetLastError());
        ::CloseHandle(tok);
        return false;
    }
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    ::SetLastError(ERROR_SUCCESS);
    const BOOL ok = ::AdjustTokenPrivileges(tok, FALSE, &tp, 0, nullptr, nullptr);
    const DWORD err = ::GetLastError();
    ::CloseHandle(tok);
    if (!ok) {
        why = QStringLiteral("AdjustTokenPrivileges 失败(%1)").arg(err);
        return false;
    }
    if (err == ERROR_NOT_ALL_ASSIGNED) {
        why = QStringLiteral("本进程令牌未持有该特权(1300)");
        return false;
    }
    return true;
}

} // namespace

bool enableBackupPrivileges() {
    // 只做一次:特权是进程级状态,反复调用无意义,且会把日志刷满。
    static std::atomic<bool> done{false};
    static std::atomic<bool> result{false};
    bool expected = false;
    if (!done.compare_exchange_strong(expected, true))
        return result.load();

    QString whyB, whyR;
    const bool b = enableOne(SE_BACKUP_NAME, whyB);
    const bool r = enableOne(SE_RESTORE_NAME, whyR);
    result.store(b);

    if (b && r) {
        log().info(QStringLiteral("已启用备份/还原特权(SeBackupPrivilege + SeRestorePrivilege)——"
                                 "此后可读取/删除因 DACL 拒绝而打不开的文件(注意:对文件被独占占用"
                                 "导致的共享冲突无效,那只有内核能豁免)。"));
    } else {
        log().warning(QStringLiteral("备份/还原特权未能全部启用(SeBackup:%1;SeRestore:%2)——"
                                     "因 DACL 拒绝而读不了/删不掉的文件将无法处理。")
                          .arg(b ? QStringLiteral("已启用") : whyB)
                          .arg(r ? QStringLiteral("已启用") : whyR));
    }
    return b;
}

bool readWithBackupSemantics(const QString& path, QByteArray& out, QString& why) {
    out.clear();
    if (!enableBackupPrivileges()) {
        why = QStringLiteral("备份特权不可用");
        return false;
    }

    // FILE_SHARE_READ|WRITE|DELETE:我们尽可能宽容,免得自己成为别人的阻碍。
    // 注意这【不能】让我们绕过别人设的 share-mode-0 —— 共享冲突无解,见头文件。
    const HANDLE h = ::CreateFileW(wstr(path), GENERIC_READ,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                   nullptr, OPEN_EXISTING,
                                   FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        const DWORD e = ::GetLastError();
        why = (e == ERROR_SHARING_VIOLATION)
                  ? QStringLiteral("共享冲突(32)—— 文件正被独占占用,备份特权对此无效")
                  : QStringLiteral("打开失败(%1)").arg(e);
        return false;
    }

    LARGE_INTEGER size{};
    if (!::GetFileSizeEx(h, &size)) {
        why = QStringLiteral("取文件大小失败(%1)").arg(::GetLastError());
        ::CloseHandle(h);
        return false;
    }
    if (size.QuadPart > kMaxReadBytes) {
        why = QStringLiteral("文件过大(%1 字节,上限 %2)").arg(size.QuadPart).arg(kMaxReadBytes);
        ::CloseHandle(h);
        return false;
    }

    out.resize(static_cast<int>(size.QuadPart));
    qint64 total = 0;
    while (total < size.QuadPart) {
        DWORD got = 0;
        const DWORD want = static_cast<DWORD>(
            std::min<qint64>(size.QuadPart - total, 1 << 20)); // 1MB 一块
        if (!::ReadFile(h, out.data() + total, want, &got, nullptr) || got == 0) {
            why = QStringLiteral("读取失败(%1,已读 %2/%3)")
                      .arg(::GetLastError()).arg(total).arg(size.QuadPart);
            ::CloseHandle(h);
            out.clear();
            return false;
        }
        total += got;
    }
    ::CloseHandle(h);
    return true;
}

bool deleteWithBackupSemantics(const QString& path, QString& why) {
    if (!enableBackupPrivileges()) {
        why = QStringLiteral("备份特权不可用");
        return false;
    }
    // DELETE + FILE_FLAG_DELETE_ON_CLOSE:句柄一关文件即消失。备份语义让 DACL 不挡我们,
    // 但同样【不能】越过别人的独占占用。
    const HANDLE h = ::CreateFileW(wstr(path), DELETE,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                   nullptr, OPEN_EXISTING,
                                   FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_DELETE_ON_CLOSE,
                                   nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        const DWORD e = ::GetLastError();
        why = (e == ERROR_SHARING_VIOLATION)
                  ? QStringLiteral("共享冲突(32)—— 文件正被独占占用,备份特权对此无效")
                  : QStringLiteral("以删除意图打开失败(%1)").arg(e);
        return false;
    }
    ::CloseHandle(h);   // 关闭即触发删除

    if (QFileInfo::exists(path)) {
        why = QStringLiteral("已请求删除但文件仍存在(可能有其它句柄未关闭,删除将延后到最后一个句柄关闭时)");
        return false;
    }
    return true;
}

QString describeHolders(const QString& path) {
    DWORD session = 0;
    WCHAR key[CCH_RM_SESSION_KEY + 1] = {};
    if (::RmStartSession(&session, 0, key) != ERROR_SUCCESS)
        return {};

    QString result;
    const wchar_t* files[1] = { wstr(path) };
    if (::RmRegisterResources(session, 1, files, 0, nullptr, 0, nullptr) == ERROR_SUCCESS) {
        UINT needed = 0, have = 0;
        DWORD reason = 0;
        // 先问数量(返回 ERROR_MORE_DATA 并回填 needed),再按量取。
        ::RmGetList(session, &needed, &have, nullptr, &reason);
        if (needed > 0 && needed < 256) {
            QVector<RM_PROCESS_INFO> infos(static_cast<int>(needed));
            have = needed;
            if (::RmGetList(session, &needed, &have, infos.data(), &reason) == ERROR_SUCCESS) {
                const DWORD self = ::GetCurrentProcessId();
                QStringList parts;
                for (UINT i = 0; i < have; ++i) {
                    const RM_PROCESS_INFO& pi = infos[static_cast<int>(i)];
                    QString one = QStringLiteral("pid=%1 %2")
                                      .arg(pi.Process.dwProcessId)
                                      .arg(QString::fromWCharArray(pi.strAppName));
                    if (pi.strServiceShortName[0])
                        one += QStringLiteral("(服务 %1)")
                                   .arg(QString::fromWCharArray(pi.strServiceShortName));
                    if (pi.Process.dwProcessId == self)
                        one += QStringLiteral("[本服务自身]");
                    parts << one;
                }
                result = parts.join(QStringLiteral("; "));
            }
        }
    }
    ::RmEndSession(session);
    return result;
}

} // namespace bulwark::service::occupied
