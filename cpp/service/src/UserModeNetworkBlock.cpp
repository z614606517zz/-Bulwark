#include "bulwark/service/UserModeNetworkBlock.h"
#include "bulwark/service/IpBlockPolicy.h"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QMutexLocker>

// winsock2 必须在 windows.h 之前,否则 windows.h 会拉进旧的 winsock.h 造成重定义。
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <fwpmu.h>

namespace bulwark::service {

namespace {

QString nowIso() {
    return QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
}

// 点分四段 -> 主机字节序 quint32。WFP 的 FWPM_CONDITION_IP_REMOTE_ADDRESS 在 V4 层用
// FWP_UINT32 且【要求主机字节序】(不是网络序)—— 这一点写错的话过滤器会装上但永不命中,
// 是这套 API 最容易踩的坑,故此处显式注明。
bool ipv4ToHostOrder(const QString& ip, quint32& out) {
    int b[4] = { 0, 0, 0, 0 };
    if (!parseIpv4Octets(ip, b))
        return false;
    out = (static_cast<quint32>(b[0]) << 24) | (static_cast<quint32>(b[1]) << 16) |
          (static_cast<quint32>(b[2]) << 8) | static_cast<quint32>(b[3]);
    return true;
}

} // namespace

UserModeNetworkBlock::UserModeNetworkBlock(int maxEntries)
    : maxEntries_(maxEntries > 0 ? maxEntries : 256) {}

UserModeNetworkBlock::~UserModeNetworkBlock() {
    QMutexLocker lock(&mx_);
    if (engine_) {
        // 动态会话:关句柄即自动删除本会话添加的全部过滤器,不需要逐条删。
        ::FwpmEngineClose0(engine_);
        engine_ = nullptr;
    }
}

// 本类不落盘(理由见头文件)。但初版曾写过 usermode_netblock.json,留在盘上会让人误以为
// 那份清单仍然生效 —— 一个看起来像配置、其实早已没人读的文件,比没有文件更容易误导排查。
// 故启动时如发现就删掉并明说。
void UserModeNetworkBlock::removeLegacyManifest() const {
    const QString p = QDir(programDataDir()).filePath(QStringLiteral("usermode_netblock.json"));
    if (!QFile::exists(p))
        return;
    if (QFile::remove(p)) {
        log_.info(QStringLiteral("已删除早期版本遗留的用户态网络封禁清单(%1)——"
                                 "本功能改为纯会话内生效,出站黑名单以 appsettings 的 "
                                 "BlockedRemoteEndpoints 为唯一权威。")
                      .arg(p));
    } else {
        log_.warning(QStringLiteral("早期版本遗留的用户态网络封禁清单删不掉(%1);它已不再被读取,"
                                    "留在盘上只会误导排查,建议手工删除。")
                         .arg(p));
    }
}

QString UserModeNetworkBlock::keyOf(const QString& ip, quint16 port) {
    return port > 0 ? QStringLiteral("%1:%2").arg(ip.trimmed().toLower()).arg(port)
                    : ip.trimmed().toLower();
}

bool UserModeNetworkBlock::isOpen() const {
    QMutexLocker lock(&mx_);
    return engine_ != nullptr;
}

bool UserModeNetworkBlock::open() {
    QMutexLocker lock(&mx_);
    if (engine_)
        return true;

    // 动态会话:本进程退出即自动清除所有过滤器(见头文件「生命周期」一节的三条理由)。
    FWPM_SESSION0 session{};
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    HANDLE h = nullptr;
    const DWORD rc = ::FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &h);
    if (rc != ERROR_SUCCESS) {
        // 最常见的失败是权限不足(需要 FWPM_ACTRL_ADD;本服务为 LocalSystem 正常满足)与
        // BFE 服务未运行。如实记录 —— 此后每次 blockIp 都会返回 false,不会假装拦住了。
        log_.error(QStringLiteral("用户态网络封禁不可用:打开 WFP 引擎失败(rc=%1)。"
                                 "此后所有出站封禁请求都将如实返回失败,不会假装已拦截。")
                       .arg(rc));
        return false;
    }
    engine_ = h;
    log_.info(QStringLiteral("用户态网络封禁已就绪(WFP 动态会话;过滤器随本进程退出自动清除,"
                             "每次启动按当前配置重建)。"));
    removeLegacyManifest();
    return true;
}

// ---------------------------------------------------------------------------
// 过滤器增删
// ---------------------------------------------------------------------------

bool UserModeNetworkBlock::addFilterLocked(Entry& e) {
    if (!engine_)
        return false;

    quint32 addrHost = 0;
    if (!ipv4ToHostOrder(e.ip, addrHost))
        return false;

    FWPM_FILTER_CONDITION0 conds[2]{};
    UINT32 nConds = 0;

    conds[nConds].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    conds[nConds].matchType = FWP_MATCH_EQUAL;
    conds[nConds].conditionValue.type = FWP_UINT32;
    conds[nConds].conditionValue.uint32 = addrHost;   // 主机字节序,见 ipv4ToHostOrder 注释
    ++nConds;

    if (e.port > 0) {
        conds[nConds].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
        conds[nConds].matchType = FWP_MATCH_EQUAL;
        conds[nConds].conditionValue.type = FWP_UINT16;
        conds[nConds].conditionValue.uint16 = e.port;
        ++nConds;
    }

    const QString name = QStringLiteral("Bulwark egress block %1").arg(keyOf(e.ip, e.port));
    std::wstring wname(reinterpret_cast<const wchar_t*>(name.utf16()));

    FWPM_FILTER0 filter{};
    filter.displayData.name = const_cast<wchar_t*>(wname.c_str());
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    // 内置通用子层。自建子层需要额外注册且在动态会话里没有收益 —— 我们只加 BLOCK,
    // 不需要独立的仲裁空间。
    filter.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
    filter.action.type = FWP_ACTION_BLOCK;
    filter.weight.type = FWP_EMPTY;      // 交给 BFE 自动定权重
    filter.numFilterConditions = nConds;
    filter.filterCondition = conds;

    UINT64 id = 0;
    const DWORD rc = ::FwpmFilterAdd0(engine_, &filter, nullptr, &id);
    if (rc != ERROR_SUCCESS) {
        log_.warning(QStringLiteral("用户态网络封禁:下发过滤器失败(rc=%1),该地址此刻【未被拦截】:%2")
                         .arg(rc)
                         .arg(keyOf(e.ip, e.port)));
        return false;
    }
    e.filterId = id;
    return true;
}

bool UserModeNetworkBlock::deleteFilterLocked(Entry& e) {
    if (!engine_ || e.filterId == 0)
        return false;
    const DWORD rc = ::FwpmFilterDeleteById0(engine_, e.filterId);
    if (rc != ERROR_SUCCESS) {
        log_.warning(QStringLiteral("用户态网络封禁:删除过滤器失败(rc=%1,id=%2),该封禁可能仍在生效:%3")
                         .arg(rc)
                         .arg(e.filterId)
                         .arg(keyOf(e.ip, e.port)));
        return false;
    }
    e.filterId = 0;
    return true;
}

// ---------------------------------------------------------------------------
// 对外接口
// ---------------------------------------------------------------------------

bool UserModeNetworkBlock::blockIp(const QString& ip, quint16 port) {
    const QString addr = ip.trimmed();
    if (addr.isEmpty())
        return false;

    // 与规则侧共用同一道闸(IpBlockPolicy.h)。刻意在本类内部【再】过一遍,不依赖调用方纪律:
    // 把 8.8.8.8 或某个 Cloudflare 前端整段封掉,后果是整机大面积断网,比漏拦一个 C2 严重得多。
    if (isUnsafeToBlanketBlockIp(addr)) {
        log_.warning(QStringLiteral("用户态网络封禁已拒绝(该地址不可整段封禁:私网/环回/公共解析器/"
                                    "共享 CDN 前端,或非 IPv4):%1")
                         .arg(addr));
        return false;
    }

    QMutexLocker lock(&mx_);
    if (!engine_) {
        log_.warning(QStringLiteral("用户态网络封禁:WFP 引擎未就绪,该地址未被拦截:%1").arg(addr));
        return false;
    }

    const QString key = keyOf(addr, port);
    if (entries_.contains(key))
        return entries_[key].filterId != 0;   // 已在封禁中,如实回报是否真的装上了

    if (entries_.size() >= maxEntries_) {
        log_.warning(QStringLiteral("用户态网络封禁名单已达上限 %1 条,拒绝新增:%2"
                                    "(绝不静默挤掉已有条目)")
                         .arg(maxEntries_)
                         .arg(key));
        return false;
    }

    Entry e;
    e.ip = addr;
    e.port = port;
    e.since = nowIso();
    const bool ok = addFilterLocked(e);
    if (!ok)
        return false;

    entries_.insert(key, e);
    log_.warning(QStringLiteral("用户态网络封禁已生效:%1 的出站连接此后被 WFP 在 connect 阶段拒绝"
                                "(调用方将收到 WSAEACCES)。")
                     .arg(key));
    return true;
}

int UserModeNetworkBlock::unblockIp(const QString& ip, quint16 port) {
    QMutexLocker lock(&mx_);
    const QString key = keyOf(ip, port);
    auto it = entries_.find(key);
    if (it == entries_.end())
        return 0;
    const bool ok = deleteFilterLocked(*it);
    entries_.erase(it);
    log_.warning(QStringLiteral("用户态网络封禁已解除:%1(过滤器删除%2)")
                     .arg(key)
                     .arg(ok ? QStringLiteral("成功") : QStringLiteral("失败,详见上一条警告")));
    return ok ? 1 : 0;
}

int UserModeNetworkBlock::clearAll() {
    QMutexLocker lock(&mx_);
    int n = 0;
    for (auto it = entries_.begin(); it != entries_.end(); ++it) {
        if (deleteFilterLocked(*it))
            ++n;
    }
    entries_.clear();
    if (n > 0)
        log_.warning(QStringLiteral("用户态网络封禁名单已整表清空(删除 %1 条 WFP 过滤器)。").arg(n));
    return n;
}

QStringList UserModeNetworkBlock::blockedList() const {
    QMutexLocker lock(&mx_);
    QStringList out;
    for (auto it = entries_.constBegin(); it != entries_.constEnd(); ++it)
        out << keyOf(it.value().ip, it.value().port);
    return out;
}

} // namespace bulwark::service
