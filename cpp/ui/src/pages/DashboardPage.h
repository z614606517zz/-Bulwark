#pragma once
#include <QDateTime>
#include <QHash>
#include <QList>
#include <QString>
#include <QUuid>
#include <QWidget>

class GlowCard;
class IpcClient;
class QGridLayout;
class QLabel;
class QResizeEvent;
class QShowEvent;
class QVBoxLayout;
class ShieldEmblem;

// The overview page: the protection hero (animated shield emblem + honest
// four-state status + quick actions), stat tiles that open the page they count,
// the last 24 hours as an hourly bar chart, a 「需要关注」 list of the few things
// that genuinely need the user, the live activity feed and the protection
// dimensions — all bound to live service data through the shared IpcClient.
class DashboardPage : public QWidget
{
    Q_OBJECT
public:
    explicit DashboardPage(IpcClient* ipc, QWidget* parent = nullptr);

protected:
    // 指标卡按可用宽度折行,见 relayoutStats()。
    void resizeEvent(QResizeEvent* e) override;
    void showEvent(QShowEvent* e) override;

private:
    struct Dimension {
        QLabel* dot = nullptr;
        QLabel* state = nullptr;
        int on = -1; // -1 = unknown (no settings yet), 0 = off, 1 = on
    };

    QWidget* buildHero();
    QWidget* buildStats();
    QWidget* buildChart();
    QWidget* buildAttention();
    QWidget* buildActivity();
    QWidget* buildDimensions();
    void relayoutStats();
    void setDimension(const QString& key, int on);
    void refreshHero();
    void refreshAttention();
    void requestChart(bool force);

    // 指标卡的最小宽度:22pt 数字 + 名称 + 图标徽章 + 左右各 18 的内边距。
    static constexpr int kStatCardMinWidth = 176;

    IpcClient* m_ipc = nullptr;

    // Hero.
    GlowCard* m_hero = nullptr;
    ShieldEmblem* m_emblem = nullptr;
    QLabel* m_heroTitle = nullptr;
    QLabel* m_heroSub = nullptr;
    QLabel* m_kernelPill = nullptr;
    QLabel* m_dimsPill = nullptr;

    // The facts the hero is derived from. Default is "unknown" — the page never
    // claims protection it hasn't been told about.
    bool m_connected = false;
    bool m_haveSettings = false;
    bool m_protectionEnabled = false;
    bool m_kernelConnected = false;
    QString m_kernelStatus;

    // Stat tiles.
    QLabel* m_statBlocked = nullptr;
    QLabel* m_statEvents = nullptr;
    QLabel* m_statQuarantine = nullptr;
    QLabel* m_statRules = nullptr;
    QLabel* m_statAi = nullptr;
    QLabel* m_statAiCaption = nullptr;
    QGridLayout* m_statsGrid = nullptr;
    QList<QWidget*> m_statCards;
    int m_statCols = 0; // 当前列数(0 = 还没排过)

    // 24 h chart (its own timeline query; only its own response is accepted).
    QWidget* m_chart = nullptr;
    QLabel* m_chartNote = nullptr;
    QUuid m_chartRequest;
    QDateTime m_chartFetched;

    // 需要关注.
    QVBoxLayout* m_attentionBox = nullptr;
    int m_unenforced = 0;    // blocks this session that nothing actually enforced
    int m_hardChains = 0;    // attack-chain hits graded 「确定恶意」 this session

    // Activity feed + dimensions.
    QVBoxLayout* m_activityBox = nullptr;
    QLabel* m_activityEmpty = nullptr;
    QHash<QString, Dimension> m_dims;

    int m_blockedCount = 0;
    int m_eventCount = 0;
    int m_activityRows = 0;
    int m_aiCount = 0;
    int m_aiTokens = 0;
};
