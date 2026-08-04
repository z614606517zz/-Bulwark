#pragma once
#include <QDialog>

#include "bulwark/ipc/Payloads.h"

// 一条攻击链命中的详情。攻击链页的表格有 9 列,主体路径 / 组合动作名(原 Sigma 规则名)/
// 家族列必然被截断,这里给出全量字段且文本可选中复制。
//
// 版式与 ProcessDetailDialog 一致(头部 Topbar + 分组卡 + 底部主按钮)—— 详情类弹窗在本产品
// 里是这一套写法,不另立门户。
class AttackChainDetailDialog : public QDialog
{
    Q_OBJECT
public:
    explicit AttackChainDetailDialog(const bulwark::ipc::AttackChainHitPayload& hit,
                                     QWidget* parent = nullptr);
};
