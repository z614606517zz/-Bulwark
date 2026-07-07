#pragma once
#include <QList>
#include <QMutex>
#include <QString>

#include "ai/AiScanner.h" // AiScanResult

// UI-side persistence for AI research records.
//
// Unlike every other history in Bulwark (rules / events / quarantine / VT), which
// lives in the service, AI research runs in the UI process (the model HTTP call is
// UI-side) and the full record — file, verdict, confidence, tokens, summary —
// only ever exists here. So the "AI 研判" page persists its own history to
// %ProgramData%\Bulwark\ai_scan_history.json and backfills it on startup, instead
// of losing every record when the UI closes. Shape mirrors the service's
// VtScanHistoryStore (JSON array, capped, newest-first reads, thread-safe).
class AiScanHistoryStore {
public:
    AiScanHistoryStore();

    void append(const AiScanResult& record); // add one result; trims oldest past the cap
    QList<AiScanResult> getAll() const;        // time-descending (newest first)
    void clear();                              // 清空全部研判记录并落盘

private:
    void load();
    void save();

    static constexpr int kMaxRecords = 1000;
    QString path_;
    QList<AiScanResult> records_;
    mutable QMutex lock_;
};
