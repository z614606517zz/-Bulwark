#include "design/Segmented.h"
#include "design/Theme.h"

#include <QAbstractButton>
#include <QButtonGroup>
#include <QEnterEvent>
#include <QFocusEvent>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QLinearGradient>
#include <QPainter>

#include <utility>

namespace {
constexpr int kPad = 3; // track padding around the segments
} // namespace

// One segment. Painted entirely here; the parent Segmented paints the track.
class SegmentButton : public QAbstractButton
{
public:
    SegmentButton(Segmented* owner, const QString& text, const QVariant& data)
        : QAbstractButton(owner), m_owner(owner), m_data(data)
    {
        setText(text);
        setCheckable(true);
        setCursor(Qt::PointingHandCursor);
        setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed);
        syncAccessible();
    }

    QVariant data() const { return m_data; }

    void setCount(int n)
    {
        if (n == m_count)
            return;
        m_count = n;
        syncAccessible();
        updateGeometry();
        update();
    }
    int countValue() const { return m_count; }

    void setAccent(const QColor& c)
    {
        m_accent = c;
        update();
    }

    void setLabel(const QString& t)
    {
        setText(t);
        syncAccessible();
        updateGeometry();
        update();
    }

    QSize sizeHint() const override
    {
        const QFont f = labelFont();
        const QFontMetrics fm(f);
        int w = fm.horizontalAdvance(text());
        if (m_count >= 0)
            w += 6 + QFontMetrics(countFont()).horizontalAdvance(QString::number(m_count));
        const bool compact = m_owner->isCompact();
        return {w + (compact ? 20 : 26), compact ? 24 : 28};
    }
    QSize minimumSizeHint() const override { return sizeHint(); }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        const QRectF r = QRectF(rect()).adjusted(0.5, 0.5, -0.5, -0.5);
        const qreal radius = r.height() / 2.0;
        const bool on = isChecked();

        if (on) {
            // The "thumb": a raised, top-lit capsule — cut from the page's hue when
            // it has one. The tinted fill stays as dark as the neutral thumb, so the
            // label and the status-coloured counts on it keep their contrast; the
            // hue shows mostly in the rim.
            const QColor hue = m_owner->identity();
            QLinearGradient g(r.topLeft(), r.bottomLeft());
            QLinearGradient rim(r.topLeft(), r.bottomLeft());
            if (hue.isValid()) {
                g.setColorAt(0.0, theme::blend(hue, theme::surfaceAlt(), 0.14));
                g.setColorAt(1.0, theme::blend(hue, theme::surface(), 0.10));
                rim.setColorAt(0.0, theme::blend(hue, theme::borderLit(), 0.55));
                rim.setColorAt(1.0, theme::blend(hue, theme::border(), 0.30));
            } else {
                g.setColorAt(0.0, theme::blend(theme::textPrimary(), theme::surfaceHi(), 0.07));
                g.setColorAt(1.0, theme::surfaceHi());
                rim.setColorAt(0.0, theme::borderLit());
                rim.setColorAt(1.0, theme::border());
            }
            p.setPen(QPen(QBrush(rim), 1.0));
            p.setBrush(g);
            p.drawRoundedRect(r, radius, radius);
        } else if (m_hover && isEnabled()) {
            p.setPen(Qt::NoPen);
            p.setBrush(theme::tint(theme::textPrimary(), 0.045));
            p.drawRoundedRect(r, radius, radius);
        }
        if (m_keyboardFocus && hasFocus()) {
            p.setPen(QPen(theme::accent(), 1.5));
            p.setBrush(Qt::NoBrush);
            p.drawRoundedRect(r.adjusted(0.5, 0.5, -0.5, -0.5), radius, radius);
        }

        const QFont lf = labelFont();
        const QFont cf = countFont();
        const QFontMetrics lfm(lf), cfm(cf);
        const QString countText = m_count >= 0 ? QString::number(m_count) : QString();
        const int lw = lfm.horizontalAdvance(text());
        const int cw = countText.isEmpty() ? 0 : 6 + cfm.horizontalAdvance(countText);
        const qreal x0 = (width() - (lw + cw)) / 2.0;

        QColor lc = on ? theme::textPrimary()
                       : (m_hover ? theme::blend(theme::textPrimary(), theme::textSecondary(), 0.5)
                                  : theme::textSecondary());
        if (!isEnabled())
            lc = theme::textDisabled();
        p.setFont(lf);
        p.setPen(lc);
        p.drawText(QRectF(x0, 0, lw + 1, height()), Qt::AlignVCenter | Qt::AlignLeft, text());
        if (!countText.isEmpty()) {
            // On the thumb a plain count steps up to textSecondary: textMuted falls
            // just short of 4.5:1 on the raised capsule.
            QColor cc = on ? theme::textSecondary() : theme::textMuted();
            if (m_count > 0 && m_accent.isValid())
                cc = m_accent;
            if (!isEnabled())
                cc = theme::textDisabled();
            p.setFont(cf);
            p.setPen(cc);
            p.drawText(QRectF(x0 + lw + 6, 0, cw, height()), Qt::AlignVCenter | Qt::AlignLeft, countText);
        }
    }

    void enterEvent(QEnterEvent* e) override { m_hover = true; update(); QAbstractButton::enterEvent(e); }
    void leaveEvent(QEvent* e) override { m_hover = false; update(); QAbstractButton::leaveEvent(e); }

    void focusInEvent(QFocusEvent* e) override
    {
        m_keyboardFocus = e->reason() == Qt::TabFocusReason || e->reason() == Qt::BacktabFocusReason
                          || e->reason() == Qt::OtherFocusReason;
        QAbstractButton::focusInEvent(e);
        update();
    }
    void focusOutEvent(QFocusEvent* e) override
    {
        m_keyboardFocus = false;
        QAbstractButton::focusOutEvent(e);
        update();
    }

    void keyPressEvent(QKeyEvent* e) override
    {
        const int idx = int(m_owner->m_buttons.indexOf(this));
        switch (e->key()) {
        case Qt::Key_Left:
        case Qt::Key_Up:
            m_owner->step(idx, -1);
            return;
        case Qt::Key_Right:
        case Qt::Key_Down:
            m_owner->step(idx, +1);
            return;
        case Qt::Key_Home:
            m_owner->step(-1, +1);
            return;
        case Qt::Key_End:
            m_owner->step(m_owner->count(), -1);
            return;
        default:
            break;
        }
        QAbstractButton::keyPressEvent(e);
    }

private:
    QFont labelFont() const
    {
        QFont f = font();
        f.setPointSizeF(m_owner->isCompact() ? 9.0 : 9.5);
        f.setWeight(isChecked() ? QFont::DemiBold : QFont::Medium);
        return f;
    }
    QFont countFont() const
    {
        QFont f = font();
        f.setPointSizeF(m_owner->isCompact() ? 8.5 : 9.0);
        f.setWeight(QFont::DemiBold);
        return f;
    }
    void syncAccessible()
    {
        setAccessibleName(m_count >= 0 ? QStringLiteral("%1 %2 %3").arg(text()).arg(m_count)
                                             .arg(QString::fromUtf8("条"))
                                       : text());
    }

    Segmented* m_owner;
    QVariant m_data;
    int m_count = -1;
    QColor m_accent;
    bool m_hover = false;
    bool m_keyboardFocus = false;
};

Segmented::Segmented(QWidget* parent) : QWidget(parent)
{
    m_group = new QButtonGroup(this);
    m_group->setExclusive(true);
    m_row = new QHBoxLayout(this);
    m_row->setContentsMargins(kPad, kPad, kPad, kPad);
    m_row->setSpacing(2);
    setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    connect(m_group, &QButtonGroup::idToggled, this, [this](int id, bool on) {
        if (!on)
            return;
        syncFocus();
        for (SegmentButton* b : std::as_const(m_buttons))
            b->updateGeometry(); // the checked label is semibold: widths shift slightly
        emit currentChanged(id);
    });
}

int Segmented::addSegment(const QString& text, const QVariant& data)
{
    auto* b = new SegmentButton(this, text, data);
    const int id = int(m_buttons.size());
    m_buttons.append(b);
    m_group->addButton(b, id);
    m_row->addWidget(b);
    if (id == 0) {
        QSignalBlocker block(m_group);
        b->setChecked(true);
    }
    syncFocus();
    return id;
}

void Segmented::setText(int index, const QString& text)
{
    if (index >= 0 && index < m_buttons.size())
        m_buttons[index]->setLabel(text);
}

void Segmented::setCount(int index, int count)
{
    if (index >= 0 && index < m_buttons.size())
        m_buttons[index]->setCount(count);
}

void Segmented::setAccent(int index, const QColor& color)
{
    if (index >= 0 && index < m_buttons.size())
        m_buttons[index]->setAccent(color);
}

int Segmented::currentIndex() const { return m_group->checkedId(); }

QVariant Segmented::currentData() const { return data(currentIndex()); }

QVariant Segmented::data(int index) const
{
    return (index >= 0 && index < m_buttons.size()) ? m_buttons[index]->data() : QVariant();
}

int Segmented::indexOfData(const QVariant& d) const
{
    for (int i = 0; i < m_buttons.size(); ++i)
        if (m_buttons[i]->data() == d)
            return i;
    return -1;
}

void Segmented::setCurrentIndex(int index)
{
    if (index < 0 || index >= m_buttons.size() || index == currentIndex())
        return;
    m_buttons[index]->setChecked(true); // idToggled -> currentChanged
}

void Segmented::setCompact(bool compact)
{
    m_compact = compact;
    for (SegmentButton* b : std::as_const(m_buttons))
        b->updateGeometry();
    updateGeometry();
    update();
}

void Segmented::setIdentity(const QColor& hue)
{
    m_identity = hue;
    for (SegmentButton* b : std::as_const(m_buttons))
        b->update();
}

void Segmented::step(int from, int delta)
{
    int i = from + delta;
    while (i >= 0 && i < m_buttons.size()) {
        if (m_buttons[i]->isEnabled()) {
            m_buttons[i]->setChecked(true);
            m_buttons[i]->setFocus(Qt::OtherFocusReason);
            return;
        }
        i += delta;
    }
}

// Roving tab stop: only the current segment is in the Tab chain.
void Segmented::syncFocus()
{
    const int cur = currentIndex();
    for (int i = 0; i < m_buttons.size(); ++i)
        m_buttons[i]->setFocusPolicy(i == cur ? Qt::StrongFocus : Qt::ClickFocus);
}

void Segmented::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);
    const QRectF r = QRectF(rect()).adjusted(0.5, 0.5, -0.5, -0.5);
    const qreal radius = r.height() / 2.0;
    p.setPen(QPen(theme::border(), 1.0));
    p.setBrush(theme::field());
    p.drawRoundedRect(r, radius, radius);
}
