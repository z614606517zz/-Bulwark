#pragma once
#include <QDialog>

#include "bulwark/ipc/Payloads.h"

class IpcClient;

// 一条攻击链命中的详情:与攻击链页右侧检查器同一份内容(chainview::fill),放在独立、
// 可放大的窗口里 —— 主体路径、凑齐的动作(原 Sigma 规则名,很长)、家族都能完整阅读、选中复制。
// 传入 ipc 时可以从这里继续打开攻击关系图。
class AttackChainDetailDialog : public QDialog
{
    Q_OBJECT
public:
    explicit AttackChainDetailDialog(const bulwark::ipc::AttackChainHitPayload& hit, QWidget* parent = nullptr,
                                     IpcClient* ipc = nullptr);
};
