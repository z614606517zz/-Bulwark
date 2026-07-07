#pragma once
#include <QString>
#include <QStringList>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonValue>

namespace bulwark {

// 恶意样本的「行为画像」——来自情报源的沙箱报告(如 VirusTotal 的
// /files/{sha256}/behaviour_summary)。它补齐了本机无法本地观测到的全局知识:
// 该样本已知会释放哪些文件、写哪些注册表、外联哪些 IP/域名、建哪些服务等。
//
// 两个用途:
//   (1) 清理:把这些「已知释放物 / 持久化」在本机落地区匹配并清除,而不仅是隔离主体;
//   (2) 主动防护:据这些 IOC(释放文件哈希/名、外联 IP、注册表键)生成拦截规则,
//       让同族样本再来时被直接拦下。
//
// header-only(inline JSON),避免新增 .cpp 与改动 CMakeLists,保持增量构建。
struct ThreatBehaviorProfile {
    QString sha256;   // 关联样本哈希(小写十六进制)
    QString source;   // 提供该画像的情报源名(VirusTotal / HybridAnalysis …,可多个)
    bool fetched = false; // 是否成功取到行为报告(否则以下均空,调用方据此判断)

    QStringList droppedFileNames;  // 释放/写入文件的 basename(小写,去重)—— 用于生成拦截规则
    QStringList droppedFilePaths;  // 释放文件的原始(沙箱)完整路径 —— 清理时翻译到本机用户目录
    QStringList droppedFileHashes; // 释放文件的 sha256(小写,可空)
    QStringList registryKeysSet;   // 写入的注册表键(可能含 \\值名)
    QStringList processNames;      // 创建进程涉及的可执行名(小写 *.exe)
    QStringList contactedIps;      // 外联 "ip" 或 "ip:port"
    QStringList contactedDomains;  // 外联 / DNS 查询域名(小写)
    QStringList serviceNames;      // 创建 / 启动的服务名
    QStringList mutexes;           // 互斥体名(family 指纹,主要用于展示)

    bool isEmpty() const {
        return droppedFileNames.isEmpty() && droppedFileHashes.isEmpty()
            && registryKeysSet.isEmpty() && processNames.isEmpty()
            && contactedIps.isEmpty() && contactedDomains.isEmpty()
            && serviceNames.isEmpty() && mutexes.isEmpty();
    }

    int iocCount() const {
        return droppedFileNames.size() + droppedFileHashes.size() + registryKeysSet.size()
             + processNames.size() + contactedIps.size() + contactedDomains.size()
             + serviceNames.size() + mutexes.size();
    }

    QJsonObject toJson() const {
        auto arr = [](const QStringList& l) {
            QJsonArray a;
            for (const QString& s : l) a.append(s);
            return a;
        };
        QJsonObject o;
        o["sha256"] = sha256;
        o["source"] = source;
        o["fetched"] = fetched;
        o["droppedFileNames"] = arr(droppedFileNames);
        o["droppedFilePaths"] = arr(droppedFilePaths);
        o["droppedFileHashes"] = arr(droppedFileHashes);
        o["registryKeysSet"] = arr(registryKeysSet);
        o["processNames"] = arr(processNames);
        o["contactedIps"] = arr(contactedIps);
        o["contactedDomains"] = arr(contactedDomains);
        o["serviceNames"] = arr(serviceNames);
        o["mutexes"] = arr(mutexes);
        return o;
    }

    static ThreatBehaviorProfile fromJson(const QJsonObject& o) {
        auto lst = [](const QJsonValue& v) {
            QStringList l;
            const QJsonArray a = v.toArray();
            for (const QJsonValue& e : a) l << e.toString();
            return l;
        };
        ThreatBehaviorProfile p;
        p.sha256 = o.value(QStringLiteral("sha256")).toString();
        p.source = o.value(QStringLiteral("source")).toString();
        p.fetched = o.value(QStringLiteral("fetched")).toBool();
        p.droppedFileNames = lst(o.value(QStringLiteral("droppedFileNames")));
        p.droppedFilePaths = lst(o.value(QStringLiteral("droppedFilePaths")));
        p.droppedFileHashes = lst(o.value(QStringLiteral("droppedFileHashes")));
        p.registryKeysSet = lst(o.value(QStringLiteral("registryKeysSet")));
        p.processNames = lst(o.value(QStringLiteral("processNames")));
        p.contactedIps = lst(o.value(QStringLiteral("contactedIps")));
        p.contactedDomains = lst(o.value(QStringLiteral("contactedDomains")));
        p.serviceNames = lst(o.value(QStringLiteral("serviceNames")));
        p.mutexes = lst(o.value(QStringLiteral("mutexes")));
        return p;
    }
};

} // namespace bulwark
