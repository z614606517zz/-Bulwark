#pragma once
#include <QDateTime>
#include <QJsonObject>
#include <QList>
#include <QObject>
#include <QString>
#include <QUuid>
#include <functional>

#include "ai/StaticFeatureExtractor.h"
#include "bulwark/ipc/Payloads.h"
#include "bulwark/models/Enums.h"
#include "bulwark/models/SecurityEvent.h"

class QNetworkAccessManager;

// One AI research result (maps to AiScanResponsePayload + display fields).
struct AiScanResult {
    QUuid eventId;                          // service event id (null for manual scans)
    QString fileName;
    QString filePath;
    bool available = false;                 // model reachable + gave a usable verdict
    bool malicious = false;
    bulwark::VerdictAction recommendation = bulwark::VerdictAction::Allow;
    QString confidence;                     // 高 / 中 / 低
    QString summary;
    int tokens = 0;
    qint64 elapsedMs = 0;
    QDateTime timestampUtc = QDateTime::currentDateTimeUtc();
    QString source;                         // 双击 / 手动

    // Persisted to %ProgramData%\Bulwark\ai_scan_history.json so the AI page keeps
    // its research records across restarts (AI scans run UI-side, so the full
    // record only exists here — the service only ever sees a slim verdict echo).
    QJsonObject toJson() const;
    static AiScanResult fromJson(const QJsonObject& o);
};

// One AI-suggested defense rule (natural-language -> rule). The payload is ready
// to hand to the service's AddRule; note is a short human explanation for review.
struct AiSuggestedRule {
    bulwark::ipc::AddRulePayload payload;
    QString note;
};

// UI-side AI client (OpenAI-compatible chat completions). Two capabilities, both
// async via QNetworkAccessManager and fail-open on any error/timeout:
//   1) scan(): judge a program's maliciousness from STATIC features only (never
//      executes the sample) -> finished(AiScanResult);
//   2) generateRules(): turn a natural-language security intent into 1..5 review-
//      able defense rules -> rulesSuggested(list). Config comes from live settings.
class AiScanner : public QObject
{
    Q_OBJECT
public:
    explicit AiScanner(QObject* parent = nullptr);

    void setConfig(const QString& baseUrl, const QString& apiKey, const QString& model);
    bool isConfigured() const;

    // 静态特征提取上限(RuntimeSettings 的 aiScanBinarySampleLimitMb /
    // aiScanScriptTextLimitKb / aiScanMaxStrings)。此前这三项只在 JSON 里读写、无人消费,
    // 提取器用的是硬编码常量。
    void setStaticLimits(const StaticFeatureLimits& limits) { m_limits = limits; }

    // 月度 token 额度守卫(RuntimeSettings 的 aiCreditGuardEnabled / aiMonthlyCreditBudget)。
    // 此前这两项同样只被序列化、从未被消费 —— 也就是说「额度守卫」这个功能根本不存在,
    // 而默认预算写着 41 亿,给人一种有在计数的错觉。
    //
    // 现在:每次 chat 调用累计返回的 usage.total_tokens,按【自然月】统计并持久化到
    // %ProgramData%\Bulwark\ai_credit.json;超预算后所有 AI 请求直接 fail-open 拒绝
    // (不发网络请求),并经 creditExhausted 通知 UI。fail-open 而不是 fail-closed 是刻意的:
    // 额度用尽属于「问不到 AI」,按本项目既定原则绝不因此影响实时防护。
    void setCreditGuard(bool enabled, qint64 monthlyBudget);
    qint64 creditUsedThisMonth() const { return m_creditUsed; }
    qint64 creditBudget() const { return m_creditBudget; }

    void scan(const bulwark::SecurityEvent& e, const QString& source); // research a (service) event
    void scanFile(const QString& path, const QString& source);          // manual file scan
    void generateRules(const QString& request);                         // NL -> suggested rules
    void generateCleanupScript(const bulwark::ipc::RemediationReportPayload& report); // VT IOC -> PS cleanup script

signals:
    void finished(const AiScanResult& result);
    void rulesSuggested(const QList<AiSuggestedRule>& rules);
    void cleanupScriptGenerated(const QString& script);
    // 本月 AI token 额度已用尽(仅在额度守卫开启时发出)。UI 可据此提示用户。
    void creditExhausted(qint64 used, qint64 budget);

private:
    QString buildUserPrompt(const bulwark::SecurityEvent& e) const;
    QString endpoint() const;
    // Shared OpenAI-compatible chat call. onDone(ok, content, tokens) runs on the
    // main thread; ok=false on transport error / timeout / empty (fail-open).
    void postChat(const QString& systemPrompt, const QString& userPrompt,
                  std::function<void(bool ok, const QString& content, int tokens)> onDone);

    // 额度账本的读写(%ProgramData%\Bulwark\ai_credit.json)。按自然月滚动:
    // 月份变了就清零重计,不需要额外的定时任务。
    void loadCredit();
    void saveCredit() const;
    // 本次调用是否被额度守卫拦下(拦下时发 creditExhausted 并返回 true)。
    bool creditBlocked();
    void addCreditUsage(int tokens);

    QNetworkAccessManager* m_net = nullptr;
    QString m_base;
    QString m_key;
    QString m_model;
    StaticFeatureLimits m_limits;          // 静态特征提取上限(默认值 = 原硬编码常量)

    bool    m_creditGuard = false;         // 额度守卫开关
    qint64  m_creditBudget = 0;            // 月度 token 预算(<=0 视为不限)
    qint64  m_creditUsed = 0;              // 本月已用 token
    QString m_creditMonth;                 // 账本所属月份 "yyyy-MM",用于跨月清零
};
