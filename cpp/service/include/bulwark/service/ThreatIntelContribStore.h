#pragma once
#include <QDateTime>
#include <QJsonObject>
#include <QMutex>
#include <QString>
#include <QStringList>
#include <QVector>

#include "bulwark/models/FileReputation.h"
#include "bulwark/models/ThreatBehaviorProfile.h"

namespace bulwark::service {

// 威胁情报共享的本机暂存队列(%ProgramData%\Bulwark\pending_intel_upload.jsonl)。
//
// 用途:云查杀确认恶意/可疑的样本,其「病毒信息 + 行为数据」先落在这里,由
// ThreatIntelUploader 每天凌晨批量上传中央服务器;上传成功即删除本地暂存。
// 整条链路默认关闭,由 RuntimeSettings::cloudBehaviorUploadEnabled 控制。
//
// 隐私边界(本类是这条边界的唯一执行点,刻意收在这一处而非散落各调用点):
//   记录只含 —— 样本 SHA-256、判定、引擎计数、威胁名、情报源名、扫描时间(UTC),
//               以及沙箱行为 IOC:释放物文件名/哈希、注册表键、进程名、外联 IP/域名、
//               服务名、互斥体。
//   刻意剔除 —— ① locatedLocalPaths:本机实际落地路径,含盘符/用户目录,是最直接的
//                  隐私泄露面;② droppedFilePaths:沙箱内的完整路径,可能嵌着沙箱侧的
//                  用户名片段,对情报价值又几乎为零(droppedFileNames 已覆盖有用部分);
//                  ③ 被扫文件在本机的路径与文件名 —— 全程不进记录,只留哈希;
//                  ④ 计算机名 / 用户名 / 文件内容 —— 从来不收集。
//   sanitize() 在【写盘之前】执行,所以这些字段连落盘都不会,不存在「上传时才过滤、
//   但本地文件里已经躺着」的窗口。
class ThreatIntelContribStore {
public:
    // 一条待上传记录。构造走 fromScan(),不直接拼装,确保必经 sanitize()。
    struct Record {
        QString sha256;
        QString verdict;      // "malicious" / "suspicious"
        int malicious = 0;
        int totalEngines = 0;
        QString threatLabel;
        QString source;       // 命中的情报源名(VirusTotal / MalwareBazaar …)
        QDateTime scannedUtc;
        bool hasBehavior = false;
        QStringList droppedFileNames;
        QStringList droppedFileHashes;
        QStringList registryKeysSet;
        QStringList processNames;
        QStringList contactedIps;
        QStringList contactedDomains;
        QStringList serviceNames;
        QStringList mutexes;

        QJsonObject toJson() const;                        // 上传负载 / 落盘格式(同一份)
        static Record fromJson(const QJsonObject& o);
    };

    ThreatIntelContribStore();

    // 由「病毒信息 + 行为画像」组装一条脱敏记录。verdict 非恶意/可疑则返回 false(不收集)。
    static bool fromScan(const bulwark::FileReputation& rep,
                         const bulwark::ThreatBehaviorProfile& profile, Record* out);

    // 追加一条(按哈希去重:同一样本已在队列里则合并 IOC,不重复排队)。线程安全。
    void append(const Record& rec);

    // 取出当前全部待上传记录(不删除;上传成功后由 removeUploaded 精确删除)。
    QVector<Record> snapshot() const;

    // 删除这些哈希对应的记录(上传成功的那批)。返回实际删除条数。
    int removeUploaded(const QStringList& sha256List);

    // 清空本地暂存并删除磁盘文件。用户关闭共享开关时调用 —— 撤回即刻生效。
    // 返回清掉的条数。
    int purgeAll();

    int count() const;

private:
    void load();
    void save(); // 全量重写(队列很小,且要支持删除,不用追加模式)

    // 一条记录内每个 IOC 列表的条目上限:限制单条体积,避免个别样本的巨型沙箱报告
    // 把上传负载撑爆(curl 走命令行传 body,有长度上限,见 ThreatIntelUploader)。
    static constexpr int kMaxPerList = 64;
    // 队列容量上限:超出时丢弃最旧的。共享情报是「锦上添花」,不值得无界占用用户磁盘。
    static constexpr int kMaxRecords = 500;

    QString path_;
    QVector<Record> records_;
    mutable QMutex lock_;
};

} // namespace bulwark::service
