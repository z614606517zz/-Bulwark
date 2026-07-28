#pragma once
#include <QString>
#include <QDateTime>
#include <QList>

// 进程取证辅助:Authenticode 签名校验(嵌入式 + 目录/catalog)、文件 SHA-256、
// 证书画像(指纹/有效期/吊销)、按 PID 读取命令行/父进程、主动处置(结束进程树,
// 带关键进程防蓝屏底线)。Windows 专用。对应 .NET Bulwark.Service/Monitoring/ProcessInspector.cs。
//
// 说明:内核/ETW 进程事件只带映像路径,不带命令行,而大量规则(LOLBin、勒索
// vssadmin、WMI 持久化、bcdedit、certutil 等)依赖命令行特征——故此处按 PID 回填。
namespace bulwark::service::monitoring {

class ProcessInspector {
public:
    // 签名证书详情(由 getCertInfo 填充;无签名/读取失败时字段为空/false)。
    struct CertInfo {
        QString   thumbprint;                 // SHA-1 指纹,大写十六进制;无则为空
        QDateTime notAfterUtc;                // 无效(isNull)表示未知
        QDateTime notBeforeUtc;
        QDateTime signingTimeUtc;             // 无效表示未能可信地确定签名时间
        bool      signedAfterCertExpiry = false;
        bool      revoked = false;
    };

    // ---- 签名 / 取证 --------------------------------------------------------
    // 是否带【可信】Authenticode 签名(先验嵌入式,再回退目录签名)。
    static bool    isSigned(const QString& path);
    // 签名证书发行主体(CN 优先),失败/无签名返回空。仅读证书,不验证信任链。
    static QString tryGetPublisher(const QString& path);
    // 文件 SHA-256(大写十六进制);超过 256MB 或失败返回空。
    static QString tryComputeSha256(const QString& path);
    // 是否内嵌了签名(无论是否验证通过)——区分"完全没签名"与"签名但校验失败"。
    static bool    hasEmbeddedSignature(const QString& path);
    // 签名失配:内嵌了签名但信任校验不过(篡改/盗证书的典型特征)。
    static bool    isSignatureMismatch(const QString& path);
    // 提取证书画像(指纹/有效期/吊销;签名时间保守留空,详见 .cpp 注释)。
    static CertInfo getCertInfo(const QString& path);

    // ---- 进程自省 ----------------------------------------------------------
    // 解析 PID 的可执行文件完整路径(QueryFullProcessImageName,比 MainModule 可靠)。
    static QString tryGetProcessImagePath(int pid);
    // 读取 PID 的命令行(PEB -> ProcessParameters -> CommandLine)。仅 64 位宿主。
    static QString tryGetCommandLine(int pid);
    // 取 PID 的父进程 PID(NtQueryInformationProcess.InheritedFromUniqueProcessId)。
    static int     tryGetParentPid(int pid);
    // 枚举当前所有进程 PID(Toolhelp32 快照;跳过 PID<=4)。供兜底扫描遍历在跑进程。
    static QList<int> enumeratePids();

    // ---- 主动处置 ----------------------------------------------------------
    // 为当前进程启用 SeDebugPrivilege(进程级一次性;返回首次尝试的真实结果)。
    static bool ensureDebugPrivilege();
    // PID 是否为关键系统进程(内核 IsProcessCritical 权威标记 + 名单 + 路径校验;
    // fail-safe:无法确认即视为关键,绝不冒险结束以防 0xEF 蓝屏)。
    static bool isCriticalProcess(int pid);
    // 强制结束进程(命中关键进程直接跳过);先确保 SeDebugPrivilege。
    static bool tryTerminateProcess(int pid);
    // 结束进程及其所有后代(先叶后根;PID 复用防护;每个仍走关键进程安全门槛)。
    static int  terminateProcessTree(int rootPid);
    // 挂起 / 恢复进程的所有线程(VT 研判期间冻结可疑进程,防止研判窗口内造成破坏)。成功返回 true。
    static bool trySuspend(int pid);
    static bool tryResume(int pid);

    // 是否对证书做【在线】吊销校验(CRL/OCSP 联网)。默认 false:仅用本机缓存 CRL,
    // 绝不联网、不阻塞富化管线。由宿主按配置(OnlineCertRevocationCheck)注入。
    inline static bool onlineRevocationCheck = false;
};

} // namespace bulwark::service::monitoring
