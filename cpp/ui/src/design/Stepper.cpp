#include "design/Stepper.h"
#include "design/Icons.h"
#include "design/Theme.h"

#include <QFontMetricsF>
#include <QPainter>

namespace {
constexpr qreal kD = 22.0;  // node diameter
constexpr qreal kLabelGap = 7.0;
QString u(const char* s) { return QString::fromUtf8(s); }
} // namespace

Stepper::Stepper(const QStringList& labels, QWidget* parent) : QWidget(parent), m_labels(labels)
{
    for (int i = 0; i < m_labels.size(); ++i)
        m_states.append(State::Pending);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    setAccessibleName(u("进度"));
    syncAccessible();
}

void Stepper::setLabel(int step, const QString& label)
{
    if (step < 0 || step >= m_labels.size())
        return;
    m_labels[step] = label;
    syncAccessible();
    update();
}

void Stepper::setState(int step, State s)
{
    if (step < 0 || step >= m_states.size() || m_states[step] == s)
        return;
    m_states[step] = s;
    syncAccessible();
    update();
}

Stepper::State Stepper::state(int step) const
{
    return (step >= 0 && step < m_states.size()) ? m_states[step] : State::Pending;
}

void Stepper::setProgress(int current, State currentState)
{
    for (int i = 0; i < m_states.size(); ++i)
        m_states[i] = i < current ? State::Done : (i == current ? currentState : State::Pending);
    syncAccessible();
    update();
}

QSize Stepper::sizeHint() const
{
    QFont f = font();
    f.setPointSizeF(9.0);
    const QFontMetricsF fm(f);
    qreal w = 0;
    for (const QString& l : m_labels)
        w += fm.horizontalAdvance(l) + 28;
    return {int(w), int(kD + kLabelGap + fm.height() + 4)};
}

QSize Stepper::minimumSizeHint() const
{
    return {int(m_labels.size()) * 56, sizeHint().height()};
}

void Stepper::paintEvent(QPaintEvent*)
{
    const int n = int(m_labels.size());
    if (n == 0)
        return;
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);

    QFont lf = font();
    lf.setPointSizeF(9.0);
    const QFontMetricsF fm(lf);
    // Keep the first / last labels inside the widget.
    const qreal padL = qMax(kD / 2 + 1, fm.horizontalAdvance(m_labels.first()) / 2 + 2);
    const qreal padR = qMax(kD / 2 + 1, fm.horizontalAdvance(m_labels.last()) / 2 + 2);
    const qreal span = qMax<qreal>(1.0, width() - padL - padR);
    const qreal cy = 1 + kD / 2;
    auto cx = [&](int i) { return n == 1 ? width() / 2.0 : padL + span * i / (n - 1); };

    // connectors
    for (int i = 0; i + 1 < n; ++i) {
        const bool done = m_states[i] == State::Done;
        p.setPen(QPen(done ? theme::blend(theme::success(), theme::surface(), 0.7) : theme::borderStrong(),
                      done ? 2.0 : 1.5));
        p.drawLine(QPointF(cx(i) + kD / 2 + 4, cy), QPointF(cx(i + 1) - kD / 2 - 4, cy));
    }

    for (int i = 0; i < n; ++i) {
        const State s = m_states[i];
        const QRectF node(cx(i) - kD / 2, cy - kD / 2, kD, kD);
        QColor rim = theme::borderStrong();
        QColor fill = theme::field();
        QColor ink = theme::textMuted();
        switch (s) {
        case State::Pending: break;
        case State::Skipped: rim = theme::border(); break;
        case State::Active:
            rim = theme::accent();
            fill = theme::blend(theme::accent(), theme::surface(), 0.22);
            ink = theme::accentSoft();
            p.setPen(Qt::NoPen);
            p.setBrush(theme::tint(theme::accent(), 0.16));
            p.drawEllipse(node.adjusted(-4, -4, 4, 4));
            break;
        case State::Done:
            rim = theme::success();
            fill = theme::blend(theme::success(), theme::surface(), 0.20);
            ink = theme::success();
            break;
        case State::Error:
            rim = theme::danger();
            fill = theme::blend(theme::danger(), theme::surface(), 0.20);
            ink = theme::danger();
            break;
        }
        p.setPen(QPen(rim, s == State::Active ? 1.6 : 1.2));
        p.setBrush(fill);
        p.drawEllipse(node.adjusted(0.5, 0.5, -0.5, -0.5));

        const QRectF g = node.adjusted(5, 5, -5, -5);
        if (s == State::Done) {
            AppIcon::draw(p, QStringLiteral("check"), g, ink, 1.8);
        } else if (s == State::Error) {
            AppIcon::draw(p, QStringLiteral("close"), g, ink, 1.8);
        } else if (s == State::Skipped) {
            AppIcon::draw(p, QStringLiteral("minus"), g, ink, 1.6);
        } else {
            QFont nf = font();
            nf.setPointSizeF(8.5);
            nf.setWeight(QFont::DemiBold);
            p.setFont(nf);
            p.setPen(ink);
            p.drawText(node, Qt::AlignCenter, QString::number(i + 1));
        }

        QFont f = lf;
        f.setWeight(s == State::Active ? QFont::DemiBold : QFont::Normal);
        p.setFont(f);
        p.setPen(s == State::Active  ? theme::textPrimary()
                 : s == State::Done  ? theme::textSecondary()
                 : s == State::Error ? theme::danger()
                                     : theme::textMuted());
        const qreal lw = fm.horizontalAdvance(m_labels[i]) + 8;
        p.drawText(QRectF(cx(i) - lw / 2, cy + kD / 2 + kLabelGap, lw, fm.height() + 2),
                   Qt::AlignHCenter | Qt::AlignTop, m_labels[i]);
    }
}

void Stepper::syncAccessible()
{
    QStringList parts;
    for (int i = 0; i < m_labels.size(); ++i) {
        QString st;
        switch (m_states[i]) {
        case State::Pending: st = u("未开始"); break;
        case State::Active:  st = u("进行中"); break;
        case State::Done:    st = u("已完成"); break;
        case State::Error:   st = u("失败");   break;
        case State::Skipped: st = u("已跳过"); break;
        }
        parts << QStringLiteral("%1 %2").arg(m_labels[i], st);
    }
    setAccessibleDescription(parts.join(QStringLiteral(", ")));
}
