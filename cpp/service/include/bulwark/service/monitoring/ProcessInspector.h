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

    // 内嵌签名的【原始】WinVerifyTrust 状态码,不做任何塌缩。
    //
    // 存在的理由:isSigned() / isSignatureMismatch() 把所有非成功状态都合并成
    // 「不可信」,于是「文件被改过」和「这台机器没导入我们的自签根证书」变成同一个
    // 答案。用于威胁打分时这没问题(两者都值得怀疑),但用于【在线更新的准入】就
    // 是错的:自签测试证书在目标机器上「根不受信任」恰恰是常态,而那会让每一次
    // 更新都被判成「疑似篡改」而拒装 —— 这个 bug 真实发生过。
    // 调用方需要区分「摘要不匹配(必须拒)」和「链不受信(可接受,信任锚点是钉死
    // 的指纹)」时,用这个函数自己判状态码。
    static long    embeddedSignatureStatus(const QString& path);
    // 提取证书画像(指纹/有效期/吊销;签名时间保守留空,详见 .cpp 注释)。
    static CertInfo getCertInfo(const QString& path);

    // 一次性取齐富化阶段要用的文件取证事实(与逐项接口共用同一批缓存表)。
    //
    // 存在的理由是【省掉重复的 stat】:上面每个逐项接口内部都要先算一遍「文件身份」
    // (小写路径|大小|修改时刻)作为缓存键,而算身份就是一次 QFileInfo stat。Worker::enrich
    // 对同一个 path 连着调 4~5 个,再加一次为取文件体积的 QFileInfo,合计对同一文件 stat 5~6
    // 遍 —— 即便这些事实全部命中缓存。本接口把它收敛成一次。
    // 求值范围与 enrich 的调用序列一一对应,结论完全一致。详见 .cpp 里的说明。
    struct ForensicFacts {
        bool     trustedSignature = false;  // 等同 isSigned()
        bool     embeddedSignature = false; // 等同 hasEmbeddedSignature();仅在无可信签名时求值
        QString  publisher;                 // 等同 tryGetPublisher()
        QString  sha256;                    // 等同 tryComputeSha256()
        CertInfo cert;                      // 等同 getCertInfo();仅在 includeCert 时求值
        // 路径是否指向一个真实存在的普通文件,以及它的体积。分成两个字段而不是拿
        // 「fileSize > 0」当存在判据:0 字节的文件是存在的,调用方需要能区分这两种情况。
        bool     isRealFile = false;
        qint64   fileSize = 0;
    };
    static ForensicFacts collectForensics(const QString& path, bool includeCert);

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
    // 等待 PID 真正退出,最多 msTimeout 毫秒。true = 已确认退出。
    // 用于「结束进程之后如实确认是否真的死了」:结束是异步的,而且被别人持有句柄的僵尸进程
    // 仍会留在进程快照里,所以不能用「PID 还在不在快照里」来判定。
    // 打不开且错误为 ERROR_INVALID_PARAMETER(PID 不存在)视为已退出;其余打不开的情况
    // 视为无法确认(返回 false),绝不把"看不见"说成"已清除"。
    static bool waitForExit(int pid, int msTimeout = 0);
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
