#pragma once
#include <QColor>
#include <QElapsedTimer>
#include <QFrame>

#include "ai/AiScanner.h"   // AiExplanation / AiExplainContext

class IconTile;
class QLabel;
class QTimer;

// 「AI 解读」那条紫水晶横幅(与 Banner 同一画法:浅底 + 细边 + 左侧 3.5px 色条)。两处在用:
//
//   行为询问弹窗(Prompt,完整版):
//   [✦] AI 解读  [建议拦截] [置信度 高]                   2.4s · 1186 tok
//       一两句通俗解读……
//
//   拦截通知(Blocked,紧凑版 —— toast 只有 412 宽,抬头放不下「建议 + 置信度 + 耗时」三样):
//   [✦] AI 解读  [拦截合理] [置信度 高]          (疑似误拦 / 难以判断)
//       一两句通俗解读……
//       2.4s · 1186 tok
//
// 它是一条证据,不是结论:建议只写在 pill 里,不改变任何裁决、倒计时、默认处置或已做的处置。
// 失败照实说「暂不可用:原因」,整条退成中性灰 —— 没拿到解读不能长得像拿到了。
// 显示的是模型输出,而模型读的是恶意程序可控的数据:一律按纯文本显示。
class AiInsightPanel : public QFrame
{
public:
    explicit AiInsightPanel(AiExplainContext context, bool compact = false, QWidget* parent = nullptr);

    void setLoading();

    // hardIndicator:引擎是否已在这次行为里检出硬恶意指标。模型与引擎意见相左(建议放行 / 判成误拦)
    // 时如实标出来,而不是让一句模型的话安静地盖过证据 —— 命令行里写一句「这是安全的」不该就能
    // 换来一个绿色建议。
    void setResult(const AiExplanation& r, bool hardIndicator);

protected:
    void paintEvent(QPaintEvent*) override;

private:
    QLabel* bodyLabel(const QColor& color) const;
    void setTone(const QColor& c);
    void setMeta(const QString& text);

    AiExplainContext m_context;
    bool m_compact = false;
    QColor m_color;                 // 紫水晶 = AI 的专用色;失败时退成 textMuted
    IconTile* m_tile = nullptr;
    QLabel* m_caption = nullptr;
    QLabel* m_advice = nullptr;
    QLabel* m_confidence = nullptr;
    QLabel* m_meta = nullptr;
    QLabel* m_text = nullptr;       // 紧凑版是 WrapLabel —— 改字必须走 setPlainText()(见 .cpp)
    QLabel* m_note = nullptr;
    QTimer* m_ticker = nullptr;
    QElapsedTimer m_since;
};
