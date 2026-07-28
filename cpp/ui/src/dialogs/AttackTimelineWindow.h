#pragma once
#include <QDialog>
#include "bulwark/models/SecurityEvent.h"

class IpcClient;

// Attack-timeline window: double-click an intercept/activity row to reconstruct
// the attack — process provenance chain (incl. the concrete service / scheduled
// task that launched the actor), evidence-chain timeline (who/what/why, scored +
// ATT&CK-tagged), techniques, and forensic details for one SecurityEvent.
//
// 传入 ipc 时底部会多一个「查看攻击关系图」入口:时间线是这条事件【自己】的证据链,
// 攻击图是它在整棵进程树里的位置 —— 两个视角互补,放在一起最省事。
class AttackTimelineWindow : public QDialog
{
    Q_OBJECT
public:
    explicit AttackTimelineWindow(const bulwark::SecurityEvent& event, QWidget* parent = nullptr,
                                  IpcClient* ipc = nullptr);
};
