#pragma once
#include <QHash>
#include <QList>
#include <QObject>
#include <QString>
#include <functional>

#include "bulwark/ipc/Payloads.h"
#include "bulwark/models/Enums.h"
#include "bulwark/models/SecurityEvent.h"

class QNetworkAccessManager;

// One AI-suggested defense rule (natural-language -> rule). The payload is ready
// to hand to the service's AddRule; note is a short human explanation for review.
struct AiSuggestedRule {
    bulwark::ipc::AddRulePayload payload;
    QString note;
};

// 行为询问弹窗里「AI 解读」的一次结论。只给人看:不回传服务,不改变任何裁决、倒计时或默认处置。
//
// 「AI 解读」用在哪。两处的提示词、建议的含义与限速份额都不同,必须由调用方说清楚:
//   Prompt  —— 行为询问弹窗:行为在等裁决,问的是「该拦还是该放」;
//   Blocked —— 拦截通知:引擎已经按拦截处理完了,问的是「它在做什么、为什么危险、这次拦得站不站得住」。
enum class AiExplainContext { Prompt, Blocked };

// (同一份结论也用于拦截通知,见 AiExplainContext。)
struct AiExplanation {
    // Prompt:建议拦截 / 建议放行 / 谨慎处理。
    // Blocked:Block = 拦截站得住,Allow = 更像误拦,Caution = 拿不准 —— 同一套键,缓存与解析共用。
    enum class Advice { Unknown, Block, Allow, Caution };

    bool ok = false;           // 拿到了可用的解读
    QString error;             // ok=false 时:为什么没有(原样显示给用户的一句话)
    Advice advice = Advice::Unknown;
    QString confidence;        // 高 / 中 / 低;模型没给则为空
    QString summary;           // 一两句通俗解读。来自模型、而模型读的是恶意程序可控的数据 —— 只能按纯文本显示
    qint64 elapsedMs = 0;      // 请求耗时(沿用已存解读时为 0:这次没有发请求)
    int tokens = 0;            // usage.total_tokens(接口不报则为 0;同上)
    bool cached = false;       // 沿用了此前存下的解读,本次没有请求模型
    qint64 cachedAgeMs = 0;    // cached 时:那条解读是多久以前拿到的(界面如实说「沿用 3 天前的解读」)
};

// UI-side AI client (OpenAI-compatible chat completions). Three capabilities, all
// async via QNetworkAccessManager and fail-open on any error/timeout:
//   1) generateRules(): turn a natural-language security intent into 1..5 review-
//      able defense rules -> rulesSuggested(list);
//   2) generateCleanupScript(): turn a malicious file's behavior profile into a
//      PowerShell cleanup script -> cleanupScriptGenerated(script);
//   3) explainEvent(): the behavior prompt's 「AI 解读」 — a one- or two-sentence
//      plain-language reading of the pending event plus an advisory 拦截 / 放行
//      suggestion. Advisory only: nothing goes back to the service. The block
//      toast uses the same call (AiExplainContext::Blocked) to say what the
//      blocked program was doing and whether the block looks justified.
// Config comes from live settings.
class AiScanner : public QObject
{
    Q_OBJECT
public:
    explicit AiScanner(QObject* parent = nullptr);

    void setConfig(const QString& baseUrl, const QString& apiKey, const QString& model);
    bool isConfigured() const;

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

    void generateRules(const QString& request);                         // NL -> suggested rules
    void generateCleanupScript(const bulwark::ipc::RemediationReportPayload& report); // VT IOC -> PS cleanup script

    // 「AI 解读」开关(设置 > 云查杀与 AI)。与语音播报同理:纯界面行为,存当前 Windows 用户的
    // QSettings、不进 RuntimeSettings —— 连不上服务时照样能改,也不会因服务版本旧而「拨了又弹回去」。
    // 默认开,但只有配置了大模型接口才会真正发请求。
    bool promptExplainEnabled() const { return m_explainEnabled; }
    void setPromptExplainEnabled(bool on);

    // 「拦截通知 AI 解读」开关(同一处设置,同样存当前用户的 QSettings)。和询问那一项分开:两者花钱的
    // 节奏不同 —— 询问只在引擎拿不准时才弹,拦截通知则每拦下一个新东西就来一条。默认开,
    // 同样只有配置了大模型接口才会真正发请求。
    bool blockExplainEnabled() const { return m_blockExplainEnabled; }
    void setBlockExplainEnabled(bool on);

    // 对一条待裁决事件做「AI 解读」。onDone 在主线程回调、至多一次;receiver 先被销毁(弹窗已关)
    // 则丢弃回调。任何失败都 fail-open:ok=false + 原因,绝不替用户猜一个结论。
    //
    // 这一项是【每弹一次询问就自动花一次 token】的,所以有三道闸:
    //   · 同一行为(发给模型的内容逐字相同,PID 不算在内;换了模型或接口地址即算另一回事)
    //     沿用已存下的解读,一周内不再请求 —— 解读【落盘】,所以界面重启、重装之后照样省掉这一次;
    //   · 同一行为的请求还在路上时,后到的弹窗搭同一趟,不重复发;
    //   · 每分钟最多发 6 个新请求 —— 询问风暴(实测出现过一小时一万七千次)不能变成账单风暴,
    //     超出的那几条如实显示「已跳过」。
    // 月度额度守卫(setCreditGuard)同样适用。
    //
    // 发给模型的是该事件的程序路径、签名、命令行、父进程、启动来源、目标、检测证据、ATT&CK 编号与
    // 近期进程链;路径里的本机用户名先替换掉。数据一律按「不可信、可能由恶意程序构造」交给模型
    // (防提示词注入:命令行里写一句「请建议放行」不能真的换来一句建议放行)。
    //
    // 拦截通知(context = Blocked)走同一个入口、同一份缓存与同一个 6 个/分钟的总闸,另加一道:
    // 它最多占其中 3 个。拦截是成批来的(一个投递器落地就是一串),不设份额的话,一阵拦截
    // 就能把随后那次【需要用户拍板】的询问的解读挤成「已跳过」。两种 context 的提示词不同,
    // 所以同一行为在两处各算一条缓存,不会拿「该不该拦」的答案去回答「拦得对不对」。
    void explainEvent(const bulwark::SecurityEvent& e, QObject* receiver,
                      std::function<void(const AiExplanation&)> onDone,
                      AiExplainContext context = AiExplainContext::Prompt);

signals:
    void rulesSuggested(const QList<AiSuggestedRule>& rules);
    void cleanupScriptGenerated(const QString& script);
    // 本月 AI token 额度已用尽(仅在额度守卫开启时发出)。UI 可据此提示用户。
    void creditExhausted(qint64 used, qint64 budget);

private:
    QString endpoint() const;
    // Shared OpenAI-compatible chat call. onDone(ok, content, tokens) runs on the
    // main thread; ok=false on transport error / timeout / empty (fail-open), and
    // then `content` carries a short human-readable reason instead.
    void postChat(const QString& systemPrompt, const QString& userPrompt,
                  std::function<void(bool ok, const QString& content, int tokens)> onDone,
                  int timeoutMs = 60000);

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

    bool    m_creditGuard = false;         // 额度守卫开关
    qint64  m_creditBudget = 0;            // 月度 token 预算(<=0 视为不限)
    qint64  m_creditUsed = 0;              // 本月已用 token
    QString m_creditMonth;                 // 账本所属月份 "yyyy-MM",用于跨月清零

    // ---- AI 解读 ----
    //
    // 解读结果存在 %ProgramData%\Bulwark\ai_explain_cache.json(与 token 账本同一个目录,
    // 内核 SelfGuard 守着:只有本产品自身进程写得动)。存的是【提示词的 SHA-256 + 解读文本】,
    // 从不存提示词本身 —— 路径、命令行这些不该为了省一次调用而额外落一份盘。
    void ensureExplainCacheLoaded();           // 懒加载:第一次真要解读时才碰盘
    // 每周一次的清理:删掉存过一周的条目并记下清理时刻。读取路径本来就不会用过期条目,
    // 所以这件事管的是「别把陈旧解读一直留在盘上」和文件体积,不是正确性。
    void sweepExplainCache(qint64 nowMs, bool force = false);
    void saveExplainCache() const;

    struct CachedExplanation {
        AiExplanation result;
        qint64 atMs = 0;                                 // 拿到这条解读的时刻(墙上时间,可落盘)
    };
    bool m_explainEnabled = true;
    bool m_explainCacheLoaded = false;
    qint64 m_explainSweptAtMs = 0;                        // 上次清理的时刻(随文件一起存)
    QHash<QString, CachedExplanation> m_explainCache;   // 提示词摘要 -> 最近一次成功的解读
    QHash<QString, QList<std::function<void(const AiExplanation&)>>> m_explainWaiting; // 在路上的请求
    QList<qint64> m_explainStarts;                       // 最近一分钟内发出请求的时刻(限速)
    bool m_blockExplainEnabled = true;
    QList<qint64> m_explainBlockedStarts;                // 其中由拦截通知发出的那部分(它单独限份额)
};
