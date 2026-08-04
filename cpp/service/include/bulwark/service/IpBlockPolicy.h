#pragma once
#include <QSet>
#include <QString>
#include <QStringList>

//
// 「这个 IP 能不能被做成整段封禁规则」的统一判定。
//
// 两个地方会把一个 IP 变成持久化的 Block 规则,过去各自为政、都没有粒度约束:
//   · Worker::buildRulesFromProfile —— 把行为画像里的 contactedIps 逐条转成
//     {type=NetworkConnect, targetPattern="<ip>:*", action=Block};
//   · ThreatFoxFeed::toRules       —— 把 feed 的 ip:port 型 IOC 去掉端口后同样整段封。
// 两者都要先过本判定。放在头文件里是为了让这两处共用同一份名单 —— 分成两份迟早走偏。
//
// 为什么必须有这道闸:
//   一条 "<ip>:*" 规则的含义是「这个地址的所有端口、永久禁止连接」。对攻击者自建的 VPS
//   没问题,对共享基础设施则是灾难 —— 一个 Cloudflare 前端 IP 背后是成千上万个互不相干的
//   站点,把它整段封掉等于把这些站点一起打死;封掉 8.8.8.8 等于让直连该解析器的程序全部断网。
//
//   而「某个恶意进程连过这个地址」根本推不出「这个地址属于攻击者」:连通性探测走公共 DNS,
//   载荷托管在 CDN 后面,C2 面板套 Cloudflare。要封的是【域名 / URL / 哈希】这类攻击者独占的
//   标识,而不是共享 IP。ThreatFox 这种外部源同样适用 —— 它给出的置信度是对「这个 IOC 与该
//   家族相关」的置信度,不是对「整段封禁这个 IP 是安全的」的置信度。
//
//   实测(现场 rules.json):68 个学到的「C2 地址」里 48 个是公共基础设施,占 71% ——
//   含 8.8.8.8 / 8.8.4.4 / 1.1.1.1、23 个 Cloudflare、6 个 Fastly、3 个 Akamai、Telegram、
//   一个内网地址 192.168.0.13,以及两条非法 IPv6。用户侧表现为「装了防护后一堆软件
//   打不开 / 登不上 / 更新不了」,且规则落盘,重启依旧。
//
namespace bulwark::service {

// 解析点分四段 IPv4;成功写入 Out[4]。任何非 IPv4 形式(含 IPv6、畸形串)返回 false。
inline bool parseIpv4Octets(const QString& ipv4, int Out[4]) {
    const QStringList parts = ipv4.split(QLatin1Char('.'));
    if (parts.size() != 4)
        return false;
    for (int i = 0; i < 4; ++i) {
        bool ok = false;
        const int v = parts[i].toInt(&ok);
        if (!ok || v < 0 || v > 255)
            return false;
        Out[i] = v;
    }
    return true;
}

//
// 返回 true = 【绝不可】把该地址做成整段封禁规则(调用方应跳过这条 IOC)。
//
inline bool isUnsafeToBlanketBlockIp(const QString& ip) {
    int b[4] = { 0, 0, 0, 0 };

    // 非 IPv4(含 IPv6 与畸形串):不生成规则。"<ip>:*" 这种拼装对 IPv6 本就产出无效模式
    //(现场就落过 a83f:8110:... 这样的坏规则),宁可不收也不要往规则库里塞坏条目。
    if (!parseIpv4Octets(ip, b))
        return true;

    // 私网 / 环回 / 链路本地 / CGNAT / 组播 / 保留:不可能是「攻击者的 C2 地址」。
    if (b[0] == 10) return true;
    if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;
    if (b[0] == 192 && b[1] == 168) return true;
    if (b[0] == 127) return true;
    if (b[0] == 169 && b[1] == 254) return true;
    if (b[0] == 0) return true;
    if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return true;
    if (b[0] >= 224) return true;

    // 公共 DNS 解析器:封掉即断网,而恶意软件拿它们做连通性探测再普通不过。
    static const QSet<QString> kPublicResolvers = {
        QStringLiteral("8.8.8.8"),         QStringLiteral("8.8.4.4"),          // Google
        QStringLiteral("1.1.1.1"),         QStringLiteral("1.0.0.1"),          // Cloudflare
        QStringLiteral("9.9.9.9"),         QStringLiteral("149.112.112.112"),  // Quad9
        QStringLiteral("208.67.222.222"),  QStringLiteral("208.67.220.220"),   // OpenDNS
        QStringLiteral("223.5.5.5"),       QStringLiteral("223.6.6.6"),        // AliDNS
        QStringLiteral("119.29.29.29"),    QStringLiteral("182.254.116.116"),  // DNSPod
        QStringLiteral("114.114.114.114"), QStringLiteral("114.114.115.115"),  // 114DNS
        QStringLiteral("180.76.76.76"),                                        // Baidu
        QStringLiteral("117.50.10.10"),    QStringLiteral("52.80.66.66"),       // OneDNS
        QStringLiteral("101.226.4.6"),     QStringLiteral("218.30.118.6"),      // 360
        QStringLiteral("4.2.2.1"),         QStringLiteral("4.2.2.2"),           // Level3
    };
    if (kPublicResolvers.contains(ip))
        return true;

    //
    // 共享 CDN / 反向代理前端网段:一个 IP 服务大量互不相干的租户,整段封禁必然误伤。
    //
    // 只收「天然多租户共享」的前端段。云厂商的通用计算段(EC2 / GCE / 通用 Azure)【不】列入 ——
    // 那些确实常被用来架 C2,且不会被无关站点共享,按 IP 封是恰当的。
    //
    struct Range { int a, b0, b1; };   // 匹配 a.b0~a.b1.x.x
    static const Range kSharedFrontends[] = {
        { 104, 16,  28 },   // Cloudflare
        { 172, 64,  71 },   // Cloudflare
        { 162, 158, 159 },  // Cloudflare
        { 188, 114, 114 },  // Cloudflare
        { 173, 245, 245 },  // Cloudflare
        { 198, 41,  41 },   // Cloudflare
        { 151, 101, 101 },  // Fastly
        { 199, 232, 232 },  // Fastly
        { 146, 75,  75 },   // Fastly
        { 23,  32,  67 },   // Akamai
        { 23,  192, 223 },  // Akamai
        { 2,   16,  23 },   // Akamai
        { 96,  16,  17 },   // Akamai
        { 184, 24,  31 },   // Akamai
        { 192, 229, 229 },  // Edgecast / Verizon
        { 93,  184, 184 },  // Edgecast
        { 74,  125, 125 },  // Google 前端
        { 142, 250, 251 },  // Google 前端
        { 172, 217, 217 },  // Google 前端
        { 216, 58,  58 },   // Google 前端
        { 34,  117, 117 },  // Google Cloud 前端(ipinfo.io 等)
        { 208, 95,  95 },   // ip-api.com 等 IP 归属查询服务
        { 149, 154, 154 },  // Telegram
        { 91,  108, 108 },  // Telegram
        { 13,  107, 107 },  // Microsoft 前端
        { 20,  99,  99 },   // Microsoft / Azure 前端
    };
    for (const Range& r : kSharedFrontends) {
        if (b[0] == r.a && b[1] >= r.b0 && b[1] <= r.b1)
            return true;
    }

    return false;
}

} // namespace bulwark::service
