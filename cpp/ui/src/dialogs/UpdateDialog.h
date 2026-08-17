#pragma once
#include <QDialog>
#include <QPoint>

#include "bulwark/ipc/Payloads.h"

class IpcClient;
class QLabel;
class QProgressBar;
class QPushButton;
class QTextBrowser;
class QVBoxLayout;

// 在线更新弹窗。
//
// 界面顺序刻意与用户的决策顺序一致:先看清「从哪个版本到哪个版本」,再看「这次改了什么」,
// 最后才是「下载」。更新说明不是装饰 —— 这个操作会替换内核驱动,把说明折叠或省掉,等于让
// 用户盲签。
//
// 网络与校验都在服务端:本类只发两条 IPC 请求(检查 / 下载),然后把回来的结论渲染出来。
// 端点和令牌一步都不进 UI 进程。
//
// 关于「应用更新」:下载并通过四道校验之后,主按钮变成「立即安装」,再发第三条 IPC 请求,
// 由【服务自身】就地替换安装目录里的文件。UI 不提权、不启动脚本、不碰安装目录 ——
// 服务正是内核 SelfGuard 放行的那个主体,而替换用「旧映像改名让位」,不需要结束任何进程,
// 所以整个过程没有 UAC、没有黑窗口、防护也不中断。新映像在下次启动时生效。
//
// 曾经的做法是让 UI 拉起提权脚本去换文件,已整段删除;为什么走不通,见 .cpp 里
// Stage::Downloaded 分支上的注释。
class UpdateDialog : public QDialog
{
    Q_OBJECT
public:
    explicit UpdateDialog(IpcClient* ipc, QWidget* parent = nullptr);
    ~UpdateDialog() override;

    // 当前是否有更新弹窗开着。MainWindow 用它决定要不要为「启动后自动检查」的结果弹
    // 托盘气泡:用户自己点「检查更新」时弹窗里已经把结论写清楚了,再弹一个气泡是噪音。
    static bool isAnyOpen() { return s_openCount > 0; }

protected:
    void mousePressEvent(QMouseEvent* e) override;
    void mouseMoveEvent(QMouseEvent* e) override;

private slots:
    void onCheckResult(const bulwark::ipc::UpdateCheckResponsePayload& p);
    void onProgress(const bulwark::ipc::UpdateProgressPayload& p);
    void onDownloadFinished(const bulwark::ipc::UpdateDownloadResponsePayload& p);
    void onApplyFinished(const bulwark::ipc::UpdateApplyResponsePayload& p);

private:
    void setBusy(const QString& text);
    void onPrimaryClicked();

    // 主按钮的语义随阶段变化(下载 / 立即安装)。用显式状态表达,而不是「用完就换一个
    // connect」——后者是这个弹窗的第一个 bug:原来在渲染结果时用
    //   connect(btn, &QPushButton::clicked, this, [lambda], Qt::UniqueConnection)
    // 想防重复连接,但 Qt::UniqueConnection 只支持成员函数,对 lambda 无效:Qt 直接拒绝
    // 这次连接并打一条警告,于是按钮【完全没有】处理函数,点下去毫无反应。
    // 现在只在构造时连一次到成员函数,由这个状态决定该做什么。
    enum class Stage { Checking, Available, Downloading, Downloaded, Failed };
    Stage m_stage = Stage::Checking;

    IpcClient* m_ipc = nullptr;
    QLabel* m_title = nullptr;
    QLabel* m_subtitle = nullptr;
    QLabel* m_status = nullptr;
    QTextBrowser* m_notes = nullptr;
    QProgressBar* m_bar = nullptr;
    QPushButton* m_primary = nullptr;   // 下载 / 立即安装 / 重试安装
    QPushButton* m_cancel = nullptr;    // 取消 / 关闭
    QString m_stagingDir;
    QPoint m_dragOffset;

    static int s_openCount;
};
