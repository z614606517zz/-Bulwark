#include "dialogs/AiInsightPanel.h"
#include "design/Components.h"
#include "design/IconTile.h"
#include "design/Theme.h"
#include "widgets/WrapLabel.h"

#include <QHBoxLayout>
#include <QLabel>
#include <QPainter>
#include <QPainterPath>
#include <QTimer>
#include <QVBoxLayout>

namespace {

QString u(const char* s) { return QString::fromUtf8(s); }

// 沿用已存解读时,那条解读的年龄。写成「刚才 / 5 分钟前 / 3 小时前 / 2 天前」,
// 而不是一句笼统的「已缓存」——「三天前的结论」这件事本身就是用户判断可信度的依据。
QString cachedAgeText(qint64 ms)
{
    const qint64 mins = ms / 60000;
    if (mins < 2)
        return u("刚才");
    if (mins < 60)
        return u(" %1 分钟前").arg(mins);
    const qint64 hours = mins / 60;
    if (hours < 24)
        return u(" %1 小时前").arg(hours);
    return u(" %1 天前").arg(qMax<qint64>(1, hours / 24));
}

// WrapLabel::setText 遮蔽(而不是覆写)QLabel::setText:经 QLabel* 调用会绕过它,画出来的还是旧字。
void setPlainText(QLabel* l, const QString& s)
{
    if (auto* w = dynamic_cast<WrapLabel*>(l))
        w->setText(s);
    else
        l->setText(s);
}

} // namespace

AiInsightPanel::AiInsightPanel(AiExplainContext context, bool compact, QWidget* parent)
    : QFrame(parent), m_context(context), m_compact(compact), m_color(theme::accentAlt())
{
    setAttribute(Qt::WA_StyledBackground, false);
    auto* h = new QHBoxLayout(this);
    h->setContentsMargins(compact ? 12 : 16, compact ? 8 : 10, compact ? 10 : 12, compact ? 8 : 10);
    h->setSpacing(compact ? 8 : 10);
    m_tile = compact ? new IconTile(QStringLiteral("sparkles"), m_color, 22, 12)
                     : new IconTile(QStringLiteral("sparkles"), m_color, 26, 14);
    h->addWidget(m_tile, 0, Qt::AlignTop);

    auto* col = new QVBoxLayout;
    col->setContentsMargins(0, 0, 0, 0);
    col->setSpacing(compact ? 4 : 5);
    auto* head = new QHBoxLayout;
    head->setContentsMargins(0, 0, 0, 0);
    head->setSpacing(compact ? 6 : 8);
    m_caption = ui::coloredText(u("AI 解读"), 9, 600, m_color);
    head->addWidget(m_caption, 0, Qt::AlignVCenter);
    m_advice = ui::pill(QString(), theme::textMuted());
    m_advice->hide();
    head->addWidget(m_advice, 0, Qt::AlignVCenter);
    m_confidence = ui::pill(QString(), m_color);
    m_confidence->hide();
    head->addWidget(m_confidence, 0, Qt::AlignVCenter);
    head->addStretch(1);
    m_meta = ui::label(QString(), "muted");
    if (!compact)
        head->addWidget(m_meta, 0, Qt::AlignVCenter);
    col->addLayout(head);

    m_text = bodyLabel(theme::textSecondary());
    m_text->hide();
    col->addWidget(m_text);
    m_note = bodyLabel(theme::warning());
    m_note->hide();
    col->addWidget(m_note);
    if (compact) {
        // 紧凑版:耗时 / token / 「沿用几天前的解读」单独一行,放在解读下面(抬头放不下)。
        m_meta->hide();
        col->addWidget(m_meta);
    }
    h->addLayout(col, 1);

    m_ticker = new QTimer(this);
    m_ticker->setInterval(1000);
    connect(m_ticker, &QTimer::timeout, this, [this] {
        setMeta(u("正在解读… %1 秒").arg(m_since.elapsed() / 1000));
    });

    setAccessibleName(u("AI 解读"));
    setToolTip(m_context == AiExplainContext::Blocked
                   ? u("由「设置 → 云查杀与 AI」里配置的大模型生成,仅供参考:不参与裁决,"
                       "也不改变已经做出的处置。可在同一处关闭。")
                   : u("由「设置 → 云查杀与 AI」里配置的大模型生成,仅供参考:不参与裁决,"
                       "不改变倒计时与默认处置。可在同一处关闭。"));
}

void AiInsightPanel::setLoading()
{
    m_since.start();
    setMeta(u("正在解读…"));
    m_ticker->start();
}

void AiInsightPanel::setResult(const AiExplanation& r, bool hardIndicator)
{
    m_ticker->stop();
    if (!r.ok) {
        setTone(theme::textMuted());
        setMeta(QString());
        setPlainText(m_text, u("暂不可用:") + r.error);
        m_text->setStyleSheet(QStringLiteral("color:%1; font-size:9pt;").arg(theme::textMuted().name()));
        m_text->show();
        setAccessibleDescription(m_text->text());
        return;
    }

    const bool blocked = m_context == AiExplainContext::Blocked;
    // 相左 = 引擎有硬指标,模型却站到「没事」那一边(询问里建议放行 / 通知里判成误拦)。
    const bool conflict = hardIndicator && r.advice == AiExplanation::Advice::Allow;
    switch (r.advice) {
    case AiExplanation::Advice::Block:
        ui::stylePill(m_advice, blocked ? u("拦截合理") : u("建议拦截"), theme::danger());
        break;
    case AiExplanation::Advice::Allow:
        // 通知里的「疑似误拦」一律琥珀而不是绿:东西已经被拦了,模型这句话的意思是「值得你复查一下」,
        // 不是「这是安全的」—— 画成绿色就等于替用户做了放行的决定。
        if (blocked)
            ui::stylePill(m_advice, u("疑似误拦"), theme::warning());
        else
            ui::stylePill(m_advice, u("建议放行"), conflict ? theme::warning() : theme::success());
        break;
    case AiExplanation::Advice::Caution:
        ui::stylePill(m_advice, blocked ? u("难以判断") : u("谨慎处理"), theme::warning());
        break;
    case AiExplanation::Advice::Unknown:
        break;
    }
    m_advice->setVisible(r.advice != AiExplanation::Advice::Unknown);
    if (!r.confidence.isEmpty())
        ui::stylePill(m_confidence, u("置信度 ") + r.confidence, m_color);
    m_confidence->setVisible(!r.confidence.isEmpty());

    if (r.cached) {
        // 如实说这条解读是什么时候拿到的:三天前的结论和刚才的结论,可信度不一样。
        setMeta(u("沿用%1的解读").arg(cachedAgeText(r.cachedAgeMs)));
        m_meta->setToolTip(blocked ? u("同一行为的解读会在本机保存一周,期间再次拦截直接沿用,"
                                       "不再请求大模型(也不再消耗 token)。到期自动清理。")
                                   : u("同一行为的解读会在本机保存一周,期间再次询问直接沿用,"
                                       "不再请求大模型(也不再消耗 token)。到期自动清理。"));
    } else {
        QString meta = QString::number(r.elapsedMs / 1000.0, 'f', 1) + QStringLiteral("s");
        if (r.tokens > 0)
            meta += QStringLiteral(" · %1 tok").arg(r.tokens);
        setMeta(meta);
    }

    setPlainText(m_text, r.summary);
    m_text->show();
    if (conflict) {
        setPlainText(m_note, blocked ? u("引擎检出了硬恶意指标,与「疑似误拦」的判断相左 —— 请以依据为准。")
                                     : u("引擎在这次行为里检出了硬恶意指标,与这条放行建议相左 —— 请以上方证据为准。"));
        m_note->show();
    }
    setAccessibleDescription((m_advice->isVisible() ? m_advice->text() + u(":") : QString()) + r.summary
                             + (conflict ? u(" ") + m_note->text() : QString()));
}

void AiInsightPanel::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);
    const QRectF r = QRectF(rect()).adjusted(0.5, 0.5, -0.5, -0.5);
    const qreal radius = m_compact ? 10 : 12;
    QPainterPath shape;
    shape.addRoundedRect(r, radius, radius);
    p.fillPath(shape, theme::blend(m_color, theme::surface(), 0.12));
    p.setPen(QPen(theme::blend(m_color, theme::surface(), 0.34), 1.0));
    p.drawPath(shape);
    p.save();
    p.setClipPath(shape);
    p.fillRect(QRectF(r.left(), r.top(), 3.5, r.height()), m_color);
    p.restore();
}

// 下面几行显示的是模型输出,而模型读的是恶意程序可控的数据(命令行、文件描述……):
// 一律按纯文本显示,绝不让 QLabel 自动识别成富文本(否则一段 <a href> / <img> 就能混进弹窗)。
//
// 紧凑版用 WrapLabel:通知卡片宽度写死,QLabel 的 wordWrap 只在空格处断行,模型回一个长文件名
// 或路径就会把卡片撑宽、右侧被裁(ToastWindow 里那两行换成 WrapLabel 是同一个原因)。
QLabel* AiInsightPanel::bodyLabel(const QColor& color) const
{
    if (m_compact) {
        auto* w = new WrapLabel;
        w->setTextFormat(Qt::PlainText);
        w->setStyleSheet(QStringLiteral("color:%1; font-size:9pt;").arg(color.name()));
        return w;
    }
    auto* l = new QLabel;
    l->setTextFormat(Qt::PlainText);
    l->setWordWrap(true);
    l->setTextInteractionFlags(Qt::TextSelectableByMouse);
    l->setStyleSheet(QStringLiteral("color:%1; font-size:9.5pt;").arg(color.name()));
    return l;
}

void AiInsightPanel::setTone(const QColor& c)
{
    m_color = c;
    m_tile->set(QStringLiteral("sparkles"), c);
    m_caption->setStyleSheet(QStringLiteral("font-size:9pt; font-weight:600; color:%1;").arg(c.name()));
    update();
}

void AiInsightPanel::setMeta(const QString& text)
{
    m_meta->setText(text);
    if (m_compact)
        m_meta->setVisible(!text.isEmpty()); // 抬头外面单独一行:空着就别占一行高
}
