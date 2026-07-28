#pragma once
#include <QString>
#include <QStringList>
#include <QDateTime>
#include <QJsonObject>
#include "bulwark/models/Enums.h"

namespace bulwark {

// 进程管理页的一行:一个在跑进程的取证快照。
//
// 与「活动日志」互补 —— 日志回答「发生了什么」,这里回答「现在还有什么在跑」。字段选取
// 全部围绕定性判断:签名与发布者、映像路径与命令行、启动来源(具体服务名 / 计划任务名)、
// 是否本机首见、是否已被用户信任、是否关键系统进程(决定能不能结束)。
//
// riskScore / riskReasons 是【只读提示】,由静态取证特征汇总而来(未签名 + 用户可写目录 +
// 无窗口宿主等),遵循产品原则:软信号只提分不据此自动处置,页面上也只做着色提示,不做
// 任何自动动作 —— 结束进程永远只由用户显式点击触发。
struct ProcessEntry {
    int pid = 0;
    int parentPid = 0;
    QString name;                 // 映像文件名(如 svchost.exe)
    QString imagePath;            // 完整路径(可空:受保护/已退出进程可能取不到)
    QString commandLine;          // 可空(需要权限;截断到 1024)
    QString parentName;           // 父进程映像文件名(可空)
    QString userName;             // 运行用户(DOMAIN\user;可空)
    QDateTime startTimeUtc;       // 启动时间(无效表示未知)
    qint64 workingSetBytes = 0;   // 私有工作集近似(内存占用)
    int threadCount = 0;
    int sessionId = 0;
    bool is64Bit = true;
    bool elevated = false;        // 是否高完整性/提权
    bool isSigned = false;        // 带可信 Authenticode 签名
    bool signatureMismatch = false; // 内嵌签名但校验失败(篡改/盗证书特征)
    QString publisher;            // 签名主体(可空)
    QString fileDescription;      // 版本资源里的描述(可空)
    QString sha256;               // 可空(按需计算;列表默认不算,详情才算)

    // ---- 启动来源溯源:把 svchost.exe 还原成具体服务、把任务宿主还原成具体计划任务 ----
    ProcessOriginKind originKind = ProcessOriginKind::Unknown;
    QString originService;        // 服务名(共享宿主可能多个,", " 连接)
    QString originServiceDisplay; // 服务显示名
    QString originTask;           // 计划任务完整路径
    QString originDetail;         // 判定依据/置信度说明

    // ---- 运行时标记 ----
    bool isCritical = false;      // 关键系统进程:结束会蓝屏,UI 必须禁用「结束」
    bool isProtectedSelf = false; // 本软件自身组件(服务/UI):自我保护,不允许从这里结束
    bool isTrusted = false;       // 命中用户信任名单(文件/文件夹)
    int riskScore = 0;            // 只读静态提示分
    QStringList riskReasons;      // 只读静态提示原因

    QString originLabel() const;  // 与 SecurityEvent::originLabel() 同一措辞

    QJsonObject toJson() const;
    static ProcessEntry fromJson(const QJsonObject& o);
};

} // namespace bulwark
