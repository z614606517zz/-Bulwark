#pragma once
#include <QDialog>
#include "bulwark/models/ProcessEntry.h"

class IpcClient;
class QLabel;

// 进程详情:一个进程的完整取证画像 —— 身份(路径/命令行/签名/发布者/描述)、
// 运行态(启动时间/内存/线程/会话/位数/提权/用户)、以及最关键的【启动来源】
// (具体是哪个服务、哪个计划任务,含判定依据与置信度)。
//
// 唯一的「动作」是按需计算 SHA-256(默认不算:列表里对几百个进程算哈希毫无必要)。
// 结束 / 挂起 / 隔离等处置一律留在进程管理页上做,详情窗口保持只读,避免误点。
class ProcessDetailDialog : public QDialog
{
    Q_OBJECT
public:
    ProcessDetailDialog(const bulwark::ProcessEntry& entry, IpcClient* ipc,
                        QWidget* parent = nullptr);

private:
    IpcClient* m_ipc = nullptr;
    int m_pid = 0;
    QLabel* m_hashValue = nullptr;
};
