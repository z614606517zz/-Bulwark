#pragma once
#include "bulwark/service/Logger.h"

#include <QHash>
#include <QMutex>
#include <QString>
#include <QStringList>

#include <cstdint>

namespace bulwark::service {

// 用户态出站封禁原语(WFP)—— 无内核驱动时的网络前拦截。
//
// ============================ 它是什么 ============================
// 在 WFP 的 FWPM_LAYER_ALE_AUTH_CONNECT_V4 层挂 FWP_ACTION_BLOCK 过滤器,按【远端地址
// (可选端口)】匹配。命中时 connect() 当场失败并返回 WSAEACCES(10013),数据一个字节都出不去。
// 这是真正的「连接前」拦截,不是事后补偿。
//
// 为什么不用 Windows 防火墙规则(netsh advfirewall / New-NetFirewallRule):那套规则属于
// MpsSvc,任何拿到管理员的恶意软件都能删掉或直接关掉防火墙服务(本产品自己就有一条规则专门
// 检测「关防火墙」命令,正说明这是常见手法)。WFP 过滤器挂在我们自己的会话里,由 BFE(基础
// 筛选引擎,受保护服务)执行,防火墙开关不影响它。内核侧本来也走 WFP,这里是同一条路的用户态版。
//
// ============================ 生命周期:纯会话内,配置是唯一权威 ============================
// FwpmEngineOpen0 用 FWPM_SESSION_FLAG_DYNAMIC 打开:过滤器随本进程退出【自动消失】。
// WFP 本来支持 FWPM_FILTER_FLAG_PERSISTENT(跨重启续拦),这里刻意不用,理由有三:
//
//  1. 【没有撤销口就不能做持久】加白撤销(约束 3)要求撤掉一切拦截,而本产品目前【没有任何
//     地方能撤销 IP 封禁】—— reconcileKernelBlocksAfterTrust 只管禁止执行/禁止加载两份名单,
//     碰不到网络。持久过滤器一旦下错,用户看到的是「某个程序连不上网、防火墙里什么规则都没有、
//     卸载本产品也还在」。那是最难排查的一类故障,比丢失拦截严重得多。
//  2. 【与内核侧当前行为一致,不悄悄变强】内核那份 IP 黑名单在每次 pushInitialConfig 时先
//     BLW_CMD_CLEAR_BLOCKIP 再从 options.BlockedRemoteEndpoints 重建 —— 即运行时加进去的
//     封禁在驱动重连时本来就会丢。用户态这一份保持同样的语义,不会出现「无驱动模式反而封得
//     更死、更难解」这种反直觉的事。
//  3. 【进程退出即自愈】服务崩溃 / 被强杀 / 被卸载时过滤器自动清除,不留孤儿。
//
// 【本类刻意【不】做落盘清单 —— 这一条是改出来的,不是一开始就想清楚的】
// 初版给它配了 JSON 清单 + 启动重放,那等于把持久性从过滤器层挪到清单层又加了回来,和上面
// 三条理由直接冲突,并且造出一个真实的「撤不掉」:部署方把某个地址从 appsettings 的
// BlockedRemoteEndpoints 里删掉、重启服务,重放却会照旧把它封上 —— 配置不再是权威,而用户
// 没有任何别的手段解除它。这正是约束 3 要防的形态,故清单整个去掉。
//
// 于是语义变得简单且可预期:每次启动按【当前配置】重建一份,进程退出即全部消失。
// 「解除某条封禁」= 从配置里删掉它再重启服务,这是一条部署方看得懂、做得到的撤销路径。
// 代价如实记录:服务未运行期间这些地址可连通;要跨重启的网络前拦截只能靠内核驱动。
//
// 将来把它接到「情报确认恶意」那条运行时路径时,必须同时做两件事,否则又会退回无撤销状态:
//   · 封禁时记下触发它的 actorPath(哪个主体导致的);
//   · reconcileKernelBlocksAfterTrust 里按该 actorPath 是否已加白来决定解除 ——
//     「我把这个程序加白了,别再封它要连的地址」才是用户真正需要的那个撤销语义。
//
// ============================ 诚实的能力边界 ============================
// * 【只支持 IPv4】。与现有全链路一致:isUnsafeToBlanketBlockIp 对非 IPv4 直接判定「不可封」,
//   内核侧 parseIpEndpoint 也只解析出 quint32。故 IPv6 的 C2 地址封不了 —— 这是既有缺口,
//   本类不假装补上了。
// * 【按地址,不按域名】。攻击者换 IP / 用 CDN 就绕过;共享基础设施更是不能整段封,那正是
//   isUnsafeToBlanketBlockIp 存在的理由(现场数据:68 个「学到的 C2 地址」里 48 个是公共
//   基础设施)。本类内部【也】过这道闸,不把安全性寄托在调用方纪律上。
// * 【只拦出站 connect】。入站、以及已建立连接上的后续流量不在范围内(已连上的 socket 不会
//   因为新加过滤器而断开)。
class UserModeNetworkBlock {
public:
    // maxEntries:过滤器条数上限(约束:规则注入必须有上限)。超限拒绝新增并大声记录。
    explicit UserModeNetworkBlock(int maxEntries = 256);
    ~UserModeNetworkBlock();

    // 打开 WFP 引擎会话(动态)。失败返回 false 并记明原因;此后所有 block 调用都如实返回 false。
    // 顺带清理旧版本可能遗留的落盘清单(见上「刻意不做清单」一节)。
    bool open();
    bool isOpen() const;

    // 追加一条封禁。port=0 表示该地址的所有端口。
    // 返回 true 仅表示【过滤器确实已装上】—— 引擎没开、地址不安全、超上限、FwpmFilterAdd0
    // 失败,一律返回 false 并记录原因,绝不谎报一个不存在的拦截。
    bool blockIp(const QString& ip, quint16 port = 0);

    // 撤销单条 / 整表清空(加白撤销的抓手)。返回实际删掉的过滤器数。
    int unblockIp(const QString& ip, quint16 port = 0);
    int clearAll();

    // 当前生效的封禁条目("ip" 或 "ip:port"),供对账与 UI 展示。
    QStringList blockedList() const;

private:
    struct Entry {
        QString ip;
        quint16 port = 0;
        quint64 filterId = 0;   // FwpmFilterAdd0 回填的 id,删除时用
        QString since;
    };

    static QString keyOf(const QString& ip, quint16 port);
    bool addFilterLocked(Entry& e);          // 调用方须持 mx_
    bool deleteFilterLocked(Entry& e);       // 调用方须持 mx_
    void removeLegacyManifest() const;       // 删掉旧版本遗留的清单(本类不再落盘)

    mutable QMutex mx_;
    QHash<QString, Entry> entries_;          // "ip:port" -> 条目
    void* engine_ = nullptr;                 // HANDLE(WFP 引擎),避免在头里引 fwpmu.h
    int maxEntries_ = 256;
    Logger log_{QStringLiteral("bulwark.service.NetBlock")};
};

} // namespace bulwark::service
