#pragma once

#include <QList>
#include <QString>

#include <functional>

#include "bulwark/service/BulwarkOptions.h"

// =====================================================================
//  在线更新的客户端侧:取清单 -> 下载 -> 逐文件校验。
//
//  为什么整套放在服务端进程里,而不是 UI
//  ------------------------------------------------------------------
//  UI 已经有 QNetworkAccessManager(AiScanner 在用),看上去直接在 UI 里发请求最省事。
//  但更新端点与信誉代理是同一台服务器,而端点在发布包里是【混淆存放】的、令牌也只在
//  服务端配置里 —— 让 UI 去取就得把解混淆逻辑和令牌一并搬过去,等于把「端点不落明文」
//  这件事做废。所以 UI 只负责界面,经 IPC 请求服务端代办;端点和令牌一步都不出这个进程。
//
//  安全边界(与 bulwark/UpdateTrust.h 配套,两侧都做一遍)
//  ------------------------------------------------------------------
//  服务器给的 SHA-256 只能证明「下载没坏」,证明不了「这是我们发的」—— 服务器被拿下或
//  TLS 被拆开时,攻击者同时控制文件和哈希。唯一的信任锚点是:每个 PE 都必须带 Authenticode
//  签名,且签名者指纹在编译期钉死的名单里。本类按顺序做四道校验,任一不过即整份放弃:
//     1) 文件名在白名单内且不含任何路径成分(清单是服务器给的,按不可信输入处理);
//     2) 落盘大小与清单一致;
//     3) SHA-256 与清单一致;
//     4) Authenticode 签名存在 + 签名者指纹命中钉死名单。
//
//  「整份放弃」是刻意的:装了一半的更新会让机器上出现「新 exe + 旧驱动」这种组合,
//  比不更新危险得多。
//
//  线程:check() / download() 都是阻塞的(内部走 curl.exe),调用方必须在工作线程里用。
// =====================================================================
namespace bulwark::service {

struct UpdateFileInfo {
    QString name;      // 载荷文件名(已过白名单)
    qint64  size = 0;
    QString sha256;    // 小写十六进制
    QString url;       // 相对路径,如 /v1/update/file/stable/bulwark_ui.exe
};

struct UpdateInfo {
    bool ok = false;             // 清单取到并解析成功
    bool available = false;      // 服务器有比本机更新的版本
    QString error;               // ok=false 时的原因(可直接给用户看)
    QString version;             // 远端版本,如 "1.2.0"
    QString label;               // 展示用标题
    QString notes;               // 更新说明(markdown 风格文本)
    QString publishedUtc;
    qint64  totalBytes = 0;
    QList<UpdateFileInfo> files;
};

struct UpdateDownloadResult {
    bool ok = false;
    QString error;
    QString stagingDir;   // 校验通过的载荷所在目录
    int verified = 0;      // 通过全部四道校验的文件数
};

struct UpdateApplyResult {
    bool ok = false;
    QString error;          // 失败原因,可直接给用户看
    int replaced = 0;       // 已就位的新文件数
    bool rolledBack = false;
    bool needsRestart = true;   // 新映像要下次启动才生效
};

class UpdateService {
public:
    explicit UpdateService(const BulwarkOptions& options);

    bool isConfigured() const { return enabled_ && !baseUrl_.isEmpty(); }
    // 掩码后的端点,可安全写进日志/回给 UI(绝不回真实地址)。
    QString maskedEndpoint() const { return maskedUrl_; }

    // 取清单并与本机版本比较。阻塞。
    UpdateInfo check();

    // 下载并校验 info 里的全部文件。阻塞。
    // onProgress(已完成文件数, 总文件数, 当前文件名, 阶段说明) —— 供 UI 显示进度。
    UpdateDownloadResult download(const UpdateInfo& info,
                                  const std::function<void(int, int, QString, QString)>& onProgress = {});

    // 就地应用已下载的更新。阻塞。
    //
    // 为什么由【服务自己】做,而不是提权脚本
    // ------------------------------------------------------------------
    // 上一版是 UI 启动一个提权 PowerShell 脚本去替换文件。那条路走不通,而且不是某一个
    // bug,是方向错了 —— 脚本是「外部进程」,而本产品会自我保护,于是它每一步都被自己挡:
    //   · 写安装目录被内核 SelfGuard 拒(规则原文:仅放行本产品自身进程写入);
    //   · 结束自己的进程被内核自我保护拒,而 Stop-Process 是【静默失败】的,
    //     于是脚本以为停干净了,继续往下走,替换时才报「拒绝访问」;
    //   · 跑脚本的 powershell.exe 被攻击链检测打成勒索软件并内核封禁。
    // 服务自身不受这些限制:它就是 SelfGuard 放行的那个主体。
    //
    // 为什么不需要先结束进程
    // ------------------------------------------------------------------
    // Windows 锁住的是「正在运行的映像文件的内容」,不是它的目录项:改名是允许的。
    // 实测(自编译的常驻 PE,已确认进程确实运行于该文件):
    //     覆盖正在运行的 exe   = 拒绝(哈希未变,写入没落地)
    //     重命名正在运行的 exe = 成功
    //     在原名放新文件       = 成功
    //     进程仍在运行         = 是
    //     残留排入重启删除队列 = 成功
    // 所以流程是「旧的改名让位 -> 新的放到原名」,运行中的进程继续从改名后的文件执行,
    // 下次启动即用新映像。不杀进程,也就没有「杀不掉」这个失败模式。
    //
    // 任何一步失败都按日志回退已改动的文件,宁可整份不装 —— 装一半会得到
    // 「新 exe + 旧驱动」这种从未测试过的组合。
    UpdateApplyResult apply(const UpdateInfo& info, const QString& stagingDir);

    // 暂存根目录:%LOCALAPPDATA%\Bulwark\update
    //
    // 刻意【不放】%ProgramData%\Bulwark 或安装目录:那两处都在内核 SelfGuard 守护范围内,
    // 非本产品进程写入会被直接拒绝(见 DriverEventSource 下发的三条自保路径)。往那里下载
    // 会得到一个「权限被拒」且原因极难看懂的失败。
    static QString stagingRoot();

private:
    // 单个文件的四道校验。失败时 error 写明是哪一道。
    bool verifyFile(const QString& path, const UpdateFileInfo& want, QString* error) const;

    bool enabled_ = false;
    QString baseUrl_;
    QString maskedUrl_;
    QString token_;
    QString channel_;
    int timeoutSecs_ = 15;
    int downloadTimeoutSecs_ = 180;
    QStringList extraThumbprints_;
};

} // namespace bulwark::service
