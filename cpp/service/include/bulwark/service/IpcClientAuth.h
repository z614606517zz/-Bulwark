#pragma once
#include <QString>
#include <QStringList>

namespace bulwark::service {

//
// ============ 控制管道(Bulwark.Control)客户端认证 ============
//
// 为什么必须有这一层:控制管道上能下发的都是【最高权限动作】——关闭防护总开关、把任意路径
// 加入信任名单(并连带清空内核已封禁主体、剔除内核禁止执行/禁止加载条目)、结束任意进程树、
// 把隔离区里的恶意载荷还原回原位。服务以 SYSTEM 运行,而管道的 DACL 必须放开到普通用户
// (UI 以普通用户身份、可能在另一个会话运行),所以【连接权限本身不能作为安全边界】,
// 唯一可靠的边界是在应用层认证「连进来的到底是谁」。
//
// 在此之前:服务对任何连入的客户端立即处理任何消息类型,零校验 —— 任意本地低权限进程都能
// 一条消息关掉整套防护。配置里 EnforceUiClientSignature / UiClientAllowedThumbprints /
// UiClientAllowedPublishers 三项虽已定义并被解析,但代码中从无一处消费,README 宣称的
// 「仅放行指定签名的 UI 连管道」实际不存在。本模块补上它。
//
// ---- 两层策略 ----
//
// 【强制层·不可关闭】客户端映像必须位于服务安装目录下,且文件名在 allowedImageNames 内
// (默认仅 bulwark_ui.exe)。这是真正阻止任意进程的主控制,且不依赖代码签名 —— 对当前
// 尚未做签名的构建同样有效。它之所以够强,是因为与另外两道内核防护咬合:
//   * 内核 SelfGuard(owner-aware):非本产品进程对安装目录的写/删/改名一律
//     STATUS_ACCESS_DENIED —— 攻击者无法把自己的程序放进安装目录冒名;
//   * 内核自我保护剥权(ObCallbacks):非受保护进程对已连接 UI 的 PROCESS_VM_WRITE /
//     CREATE_THREAD 等权限被剥离 —— 攻击者也无法注入合法 UI 借它的身份说话。
// 三者合起来,才使「同目录 + 同名」成为一个攻击者跨不过去的判定。
//
// 【可选加固层】enforceSignature=true 时额外要求映像持有【可信】Authenticode 签名;
// 若指纹/发布者白名单非空,还必须命中其中之一。正式发布做了代码签名后应打开。
//
// ---- fail-closed ----
//
// 取不到客户端 PID 或映像路径时【拒绝】。这与项目其它地方普遍的 fail-open 取向相反,
// 是刻意的:其余 fail-open 的失败后果是「少检测一次」,而这里失败后果是「放进一个身份
// 不明的进程,让它拿到关闭防护的权限」。宁可 UI 连不上(用户立刻能发现并看日志),
// 也不能让认证在出错时静默失效。
//
class IpcClientAuth {
public:
    struct Policy {
        // 服务安装目录。强制层按【小写、反斜杠、带尾分隔符】的前缀匹配,由 configure 归一化。
        QString installDir;
        // 允许连接的映像文件名(小写)。留空则回退为默认的 bulwark_ui.exe。
        QStringList allowedImageNames;
        // 可选加固:要求有效签名。
        bool enforceSignature = false;
        // 指纹白名单(SHA-1)。configure 会去掉空格/冒号并转大写,故填写格式随意。
        QStringList allowedThumbprints;
        // 发布者白名单(子串匹配,大小写不敏感)。
        QStringList allowedPublishers;
    };

    struct Result {
        bool    ok = false;
        quint32 pid = 0;
        QString imagePath;
        QString reason;   // 通过时是简短说明;拒绝时是可直接展示给用户的原因
    };

    // 由 main 在启动时注入一次(线程安全:仅启动期写,之后只读)。
    static void configure(const Policy& policy);

    // 认证一个已接受的连接。socketDescriptor 传 QLocalSocket::socketDescriptor()
    // (Windows 上即命名管道的【服务端】句柄,GetNamedPipeClientProcessId 需要它)。
    static Result authenticate(qintptr socketDescriptor);

    // 供日志/诊断:当前生效的策略摘要(不含任何密钥)。
    static QString policySummary();
};

} // namespace bulwark::service
