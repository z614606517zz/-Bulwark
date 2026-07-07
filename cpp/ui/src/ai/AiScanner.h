#pragma once
#include <QDateTime>
#include <QJsonObject>
#include <QList>
#include <QObject>
#include <QString>
#include <QUuid>
#include <functional>

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

    void scan(const bulwark::SecurityEvent& e, const QString& source); // research a (service) event
    void scanFile(const QString& path, const QString& source);          // manual file scan
    void generateRules(const QString& request);                         // NL -> suggested rules

signals:
    void finished(const AiScanResult& result);
    void rulesSuggested(const QList<AiSuggestedRule>& rules);

private:
    QString buildUserPrompt(const bulwark::SecurityEvent& e) const;
    QString endpoint() const;
    // Shared OpenAI-compatible chat call. onDone(ok, content, tokens) runs on the
    // main thread; ok=false on transport error / timeout / empty (fail-open).
    void postChat(const QString& systemPrompt, const QString& userPrompt,
                  std::function<void(bool ok, const QString& content, int tokens)> onDone);

    QNetworkAccessManager* m_net = nullptr;
    QString m_base;
    QString m_key;
    QString m_model;
};
