#pragma once
#include <QHash>
#include <QString>
#include <QWidget>

class IpcClient;
class QLabel;
class QVBoxLayout;

// The overview page: protection hero banner, key stat cards, a recent-activity
// feed and a protection-dimensions panel — all bound to live service data via
// the shared IpcClient (event log, settings, rules/quarantine snapshots).
class DashboardPage : public QWidget
{
    Q_OBJECT
public:
    explicit DashboardPage(IpcClient* ipc, QWidget* parent = nullptr);

private:
    QWidget* buildHero();
    QWidget* buildStats();
    QWidget* buildActivity();
    QWidget* buildDimensions();

    IpcClient* m_ipc = nullptr;

    // Live-updated widgets.
    QLabel* m_heroTitle = nullptr;
    QLabel* m_heroSub = nullptr;
    QLabel* m_statBlocked = nullptr;
    QLabel* m_statEvents = nullptr;
    QLabel* m_statQuarantine = nullptr;
    QLabel* m_statRules = nullptr;
    QLabel* m_statAi = nullptr;
    QVBoxLayout* m_activityBox = nullptr;
    QHash<QString, QWidget*> m_dimRows; // dimension key -> row (holds a status dot)

    int m_blockedCount = 0;
    int m_eventCount = 0;
    int m_activityRows = 0;
    int m_aiCount = 0;
    int m_aiTokens = 0;
};
