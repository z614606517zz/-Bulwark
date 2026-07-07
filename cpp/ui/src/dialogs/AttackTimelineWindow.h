#pragma once
#include <QDialog>
#include "bulwark/models/SecurityEvent.h"

// Attack-timeline window: double-click an intercept/activity row to reconstruct
// the attack — process provenance chain, evidence-chain timeline (who/what/why,
// scored + ATT&CK-tagged), techniques, and forensic details for one SecurityEvent.
class AttackTimelineWindow : public QDialog
{
    Q_OBJECT
public:
    explicit AttackTimelineWindow(const bulwark::SecurityEvent& event, QWidget* parent = nullptr);
};
