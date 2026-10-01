#include "design/RecordDelegate.h"
#include "design/Format.h"
#include "design/Icons.h"
#include "design/RecordModel.h"
#include "design/Theme.h"

#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QScrollBar>
#include <QTimer>

namespace {

QFont sized(QFont f, qreal pt, QFont::Weight w)
{
    f.setPointSizeF(pt);
    f.setWeight(w);
    return f;
}

QFont mono(qreal pt)
{
    QFont f;
    f.setFamilies({QStringLiteral("Cascadia Mono"), QStringLiteral("Consolas")});
    f.setPointSizeF(pt);
    return f;
}

QColor colorOr(const QVariant& v, const QColor& fallback)
{
    const QColor c = v.value<QColor>();
    return c.isValid() ? c : fallback;
}

// A soft status capsule (same recipe as ui::stylePill, painted).
qreal drawCapsule(QPainter* p, const QRectF& r, const QString& text, const QColor& c, const QFont& f)
{
    p->setPen(QPen(theme::blend(c, theme::surface(), 0.34), 1.0));
    p->setBrush(theme::blend(c, theme::surface(), 0.14));
    p->drawRoundedRect(r.adjusted(0.5, 0.5, -0.5, -0.5), r.height() / 2.0, r.height() / 2.0);
    p->setFont(f);
    p->setPen(c);
    p->drawText(r, Qt::AlignCenter, text);
    return r.width();
}

} // namespace

RecordDelegate::RecordDelegate(QObject* parent) : QStyledItemDelegate(parent) {}

QSize RecordDelegate::sizeHint(const QStyleOptionViewItem&, const QModelIndex& idx) const
{
    if (idx.data(rec::Header).toBool())
        return {200, idx.data(rec::Leading).toBool() ? kHeaderH - 8 : kHeaderH};
    return {200, kRowH};
}

void RecordDelegate::paint(QPainter* p, const QStyleOptionViewItem& opt, const QModelIndex& idx) const
{
    if (idx.data(rec::Header).toBool())
        paintHeader(p, opt.rect, idx, false);
    else
        paintRecord(p, opt, idx);
}

void RecordDelegate::paintHeader(QPainter* p, const QRect& band, const QModelIndex& header, bool pinned) const
{
    p->save();
    p->setRenderHint(QPainter::Antialiasing, true);
    QRectF r(band);
    if (pinned) {
        p->fillRect(r, theme::surface());
        p->setPen(QPen(theme::border(), 1.0));
        p->drawLine(QPointF(r.left() + 12, r.bottom() + 0.5), QPointF(r.right() - 12, r.bottom() + 0.5));
    } else if (!header.data(rec::Leading).toBool()) {
        r.setTop(r.top() + 8); // breathing room between groups
    }

    const QString group = header.data(rec::Group).toString();
    qreal x = r.left() + 18;
    const qreal cy = r.center().y();
    if (m_collapsible) {
        const bool collapsed = m_isCollapsed && m_isCollapsed(group);
        AppIcon::draw(*p, collapsed ? QStringLiteral("chevron-right") : QStringLiteral("chevron-down"),
                      QRectF(x - 2, cy - 7, 14, 14), theme::textMuted(), 1.7);
        x += 18;
    }

    const QColor gc = colorOr(header.data(rec::GroupColor),
                              m_identity.isValid() ? m_identity : theme::textMuted());
    QFont ef = sized(p->font(), 8.8, QFont::Bold);
    ef.setLetterSpacing(QFont::AbsoluteSpacing, 0.8);
    const QString title = header.data(Qt::DisplayRole).toString();
    const QFontMetricsF efm(ef);
    p->setFont(ef);
    p->setPen(gc);
    const qreal noteW = 180;
    const QString shownTitle = efm.elidedText(title, Qt::ElideRight, qMax<qreal>(40, r.right() - x - noteW));
    p->drawText(QRectF(x, r.top(), r.width(), r.height()), Qt::AlignLeft | Qt::AlignVCenter, shownTitle);
    x += efm.horizontalAdvance(shownTitle) + 8;

    const QFont cf = sized(p->font(), 8.8, QFont::Normal);
    p->setFont(cf);
    p->setPen(theme::textMuted());
    p->drawText(QRectF(x, r.top(), 60, r.height()), Qt::AlignLeft | Qt::AlignVCenter,
                QString::number(header.data(rec::GroupCount).toInt()));

    const QString note = header.data(rec::GroupNote).toString();
    if (!note.isEmpty())
        p->drawText(QRectF(r.right() - 18 - noteW, r.top(), noteW, r.height()),
                    Qt::AlignRight | Qt::AlignVCenter,
                    QFontMetricsF(cf).elidedText(note, Qt::ElideRight, noteW));
    p->restore();
}

void RecordDelegate::paintRecord(QPainter* p, const QStyleOptionViewItem& opt, const QModelIndex& idx) const
{
    p->save();
    p->setRenderHint(QPainter::Antialiasing, true);
    const QRect r = opt.rect;
    const bool selected = opt.state.testFlag(QStyle::State_Selected);
    const bool hover = opt.state.testFlag(QStyle::State_MouseOver);
    const bool focus = opt.state.testFlag(QStyle::State_HasFocus);
    const bool dim = idx.data(rec::Dim).toBool();
    const QRectF card = QRectF(r).adjusted(6, 2, -6, -2);

    // ---- background ----
    if (selected) {
        p->setPen(QPen(theme::blend(theme::accent(), theme::surface(), focus ? 0.62 : 0.38), 1.0));
        p->setBrush(theme::blend(theme::accent(), theme::surface(), 0.15));
        p->drawRoundedRect(card.adjusted(0.5, 0.5, -0.5, -0.5), 10, 10);
    } else {
        if (hover) {
            p->setPen(Qt::NoPen);
            p->setBrush(theme::tint(theme::textPrimary(), 0.035));
            p->drawRoundedRect(card, 10, 10);
        }
        if (focus) {
            p->setPen(QPen(theme::tint(theme::accent(), 0.65), 1.0));
            p->setBrush(Qt::NoBrush);
            p->drawRoundedRect(card.adjusted(0.5, 0.5, -0.5, -0.5), 10, 10);
        }
    }

    const QColor accent = idx.data(rec::Accent).value<QColor>();
    if (accent.isValid()) {
        p->setPen(Qt::NoPen);
        p->setBrush(accent);
        p->drawRoundedRect(QRectF(card.left() + 1.5, card.top() + 12, 3.0, card.height() - 24), 1.5, 1.5);
    }

    // ---- check box (check mode): the row's selection, in QCheckBox's indicator recipe ----
    qreal lead = card.left() + 10;
    if (m_checkable) {
        const QRectF cb(card.left() + 12, r.center().y() - 9.0, 18.0, 18.0);
        const QRectF rim = cb.adjusted(0.5, 0.5, -0.5, -0.5);
        if (selected) {
            // Jade rim rather than the indicator's dark one: it has to stand out
            // against the selected row's own jade-tinted fill.
            p->setPen(QPen(theme::accent(), 1.0));
            p->setBrush(QBrush(theme::brandGradient(cb)));
            p->drawRoundedRect(rim, 6, 6);
            AppIcon::draw(*p, QStringLiteral("check"), cb.adjusted(3.4, 3.4, -3.4, -3.4), theme::accentInk(), 1.9);
        } else {
            // An empty box must still read as a control (>= 3:1 against the row),
            // which borderStrong() alone does not reach.
            p->setPen(QPen(hover ? theme::accent() : theme::blend(theme::textMuted(), theme::surface(), 0.66), 1.0));
            p->setBrush(theme::field());
            p->drawRoundedRect(rim, 6, 6);
        }
        lead = cb.right() + 12;
    }

    // ---- glyph tile (and the timeline rail behind it) ----
    constexpr qreal box = 32;
    const qreal ix = lead;
    const qreal iy = r.center().y() - box / 2.0;
    if (m_rail) {
        const QAbstractItemModel* m = idx.model();
        const QModelIndex prev = idx.sibling(idx.row() - 1, 0);
        const QModelIndex next = idx.row() + 1 < m->rowCount() ? idx.sibling(idx.row() + 1, 0) : QModelIndex();
        const bool up = prev.isValid() && !prev.data(rec::Header).toBool();
        const bool down = next.isValid() && !next.data(rec::Header).toBool();
        const qreal cx = ix + box / 2.0;
        const qreal top = up ? r.top() : r.center().y();
        const qreal bottom = down ? r.bottom() + 1 : r.center().y();
        if (bottom > top) {
            p->setPen(QPen(theme::borderStrong(), 1.5));
            p->drawLine(QPointF(cx, top), QPointF(cx, bottom));
        }
    }
    QColor ic = colorOr(idx.data(rec::IconColor), theme::textSecondary());
    if (dim)
        ic = theme::blend(ic, theme::surface(), 0.55);
    {
        const QRectF t(ix + 0.5, iy + 0.5, box - 1, box - 1);
        QLinearGradient g(t.topLeft(), t.bottomRight());
        g.setColorAt(0.0, theme::blend(ic, theme::surface(), 0.24));
        g.setColorAt(1.0, theme::blend(ic, theme::surface(), 0.10));
        p->setPen(QPen(theme::blend(ic, theme::surface(), 0.32), 1.0));
        p->setBrush(g);
        p->drawRoundedRect(t, 9, 9);
        AppIcon::draw(*p, idx.data(rec::Icon).toString(), QRectF(ix + 8, iy + 8, 16, 16), ic, 1.6);
    }

    // ---- right cluster (laid out right to left) ----
    qreal right = card.right() - 12;
    const QDateTime when = idx.data(rec::Time).toDateTime();
    const QString meta = when.isValid() ? fmt::relativeTime(when) : idx.data(rec::Meta).toString();
    if (!meta.isEmpty()) {
        const QFont mf = sized(opt.font, 9.0, QFont::Normal);
        const qreal w = QFontMetricsF(mf).horizontalAdvance(meta);
        p->setFont(mf);
        p->setPen(theme::textMuted());
        p->drawText(QRectF(right - w, r.top(), w + 1, r.height()), Qt::AlignRight | Qt::AlignVCenter, meta);
        right -= w + 14;
    }
    const QString pill = idx.data(rec::Pill).toString();
    if (!pill.isEmpty()) {
        const QFont pf = sized(opt.font, 8.8, QFont::DemiBold);
        const qreal w = QFontMetricsF(pf).horizontalAdvance(pill) + 18;
        drawCapsule(p, QRectF(right - w, r.center().y() - 11, w, 22), pill,
                    colorOr(idx.data(rec::PillColor), theme::textSecondary()), pf);
        right -= w + 10;
    }
    const QString score = idx.data(rec::Score).toString();
    if (!score.isEmpty()) {
        const QFont sf = sized(opt.font, 11.0, QFont::Bold);
        const qreal w = QFontMetricsF(sf).horizontalAdvance(score);
        p->setFont(sf);
        p->setPen(colorOr(idx.data(rec::ScoreColor), theme::textSecondary()));
        p->drawText(QRectF(right - w, r.top(), w + 1, r.height()), Qt::AlignRight | Qt::AlignVCenter, score);
        right -= w + 12;
    }

    // ---- text column ----
    const qreal tx = ix + box + 12;
    const qreal tw = qMax<qreal>(40.0, right - tx);
    const QString title = idx.data(Qt::DisplayRole).toString();
    const QString sub = idx.data(rec::Subtitle).toString();
    const QStringList chips = idx.data(rec::Chips).toStringList();
    const QVariantList chipColors = idx.data(rec::ChipColors).toList();
    const bool two = !sub.isEmpty() || !chips.isEmpty();

    const QFont tf = sized(opt.font, 10.0, QFont::DemiBold);
    p->setFont(tf);
    p->setPen(dim ? theme::textSecondary() : theme::textPrimary());
    const QRectF titleR(tx, two ? r.top() + 9 : r.top(), tw, two ? 22 : r.height());
    p->drawText(titleR, Qt::AlignLeft | Qt::AlignVCenter,
                QFontMetricsF(tf).elidedText(title, Qt::ElideRight, tw));

    if (two) {
        qreal x = tx;
        const qreal y = r.top() + 32;
        constexpr qreal lh = 19;
        const QFont cf = sized(opt.font, 8.5, QFont::Medium);
        const QFontMetricsF cfm(cf);
        qreal chipsW = 0;
        for (const QString& c : chips)
            chipsW += cfm.horizontalAdvance(c) + 14 + 6;

        if (!sub.isEmpty()) {
            const bool isMono = idx.data(rec::SubtitleMono).toBool();
            const QFont sf = isMono ? mono(8.8) : sized(opt.font, 9.0, QFont::Normal);
            const QFontMetricsF sfm(sf);
            const qreal avail = chips.isEmpty() ? tw : qMax(tw * 0.5, tw - chipsW - 8);
            const QString s = sfm.elidedText(sub, isMono ? Qt::ElideMiddle : Qt::ElideRight, avail);
            p->setFont(sf);
            p->setPen(theme::textMuted());
            p->drawText(QRectF(x, y, avail, lh), Qt::AlignLeft | Qt::AlignVCenter, s);
            x += sfm.horizontalAdvance(s) + 10;
        }
        for (int i = 0; i < chips.size(); ++i) {
            const qreal cw = cfm.horizontalAdvance(chips[i]) + 14;
            if (x + cw > tx + tw) {
                const QString more = QStringLiteral("+%1").arg(chips.size() - i);
                if (x + cfm.horizontalAdvance(more) <= tx + tw) {
                    p->setFont(cf);
                    p->setPen(theme::textMuted());
                    p->drawText(QRectF(x, y, 40, lh), Qt::AlignLeft | Qt::AlignVCenter, more);
                }
                break;
            }
            const QRectF cr(x, y + 0.5, cw, lh - 1);
            QColor cc = i < chipColors.size() ? chipColors[i].value<QColor>() : QColor();
            if (cc.isValid() && dim)
                cc = theme::blend(cc, theme::textMuted(), 0.45);
            if (cc.isValid()) {
                // A tinted capsule in the chip's own colour (kind or status). The text
                // keeps the full colour: every status / kind hue still clears 4.5:1 on
                // this fill (cinnabar, the darkest, 4.7:1).
                p->setPen(QPen(theme::blend(cc, theme::surface(), 0.30), 1.0));
                p->setBrush(theme::blend(cc, theme::surface(), 0.10));
            } else {
                p->setPen(QPen(theme::border(), 1.0));
                p->setBrush(theme::blend(theme::textSecondary(), theme::surface(), 0.08));
            }
            p->drawRoundedRect(cr.adjusted(0.5, 0.5, -0.5, -0.5), 6, 6);
            p->setFont(cf);
            p->setPen(cc.isValid() ? cc : (dim ? theme::textMuted() : theme::textSecondary()));
            p->drawText(cr, Qt::AlignCenter, chips[i]);
            x += cw + 6;
        }
    }

    // Hairline between records (not under the selected / hovered row).
    if (!selected && !hover) {
        p->setPen(QPen(theme::blend(theme::border(), theme::surface(), 0.7), 1.0));
        p->drawLine(QPointF(tx, r.bottom() + 0.5), QPointF(card.right() - 12, r.bottom() + 0.5));
    }
    p->restore();
}

// ---- RecordListView -------------------------------------------------------------

RecordListView::RecordListView(QWidget* parent) : QListView(parent)
{
    setObjectName(QStringLiteral("RecordList"));
    m_delegate = new RecordDelegate(this);
    setItemDelegate(m_delegate);
    setFrameShape(QFrame::NoFrame);
    setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    verticalScrollBar()->setSingleStep(24);
    setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    setMouseTracking(true);
    viewport()->setAttribute(Qt::WA_Hover, true);
    viewport()->setAutoFillBackground(false);
    setSelectionBehavior(QAbstractItemView::SelectRows);
    setSelectionMode(QAbstractItemView::SingleSelection);
    setEditTriggers(QAbstractItemView::NoEditTriggers);
    setUniformItemSizes(true);
    setResizeMode(QListView::Adjust);
    setLayoutMode(QListView::SinglePass);
    setFocusPolicy(Qt::StrongFocus);
    setContextMenuPolicy(Qt::CustomContextMenu);

    m_clock = new QTimer(this);
    m_clock->setInterval(30000);
    connect(m_clock, &QTimer::timeout, viewport(), qOverload<>(&QWidget::update));
    m_clock->start();
}

void RecordListView::setStickyHeaders(bool on)
{
    m_sticky = on;
    viewport()->update();
}

void RecordListView::setBottomInset(int px)
{
    px = qMax(0, px);
    if (px == m_bottomInset)
        return;
    m_bottomInset = px;
    setViewportMargins(0, 0, 0, px);
}

void RecordListView::keyboardSearch(const QString& search)
{
    // Check mode: type-ahead lands on its match through setCurrentIndex(), which
    // in MultiSelection *toggles* that row — a stray letter key would tick (or
    // untick) a record, possibly one scrolled out of sight. Only Space toggles.
    if (selectionMode() == QAbstractItemView::MultiSelection)
        return;
    QListView::keyboardSearch(search);
}

QModelIndex RecordListView::headerFor(const QModelIndex& idx) const
{
    for (QModelIndex i = idx; i.isValid(); i = i.sibling(i.row() - 1, 0)) {
        if (i.data(rec::Header).toBool())
            return i;
        if (i.row() == 0)
            break;
    }
    return {};
}

void RecordListView::paintEvent(QPaintEvent* e)
{
    QListView::paintEvent(e);
    m_stickyRect = QRect();
    m_stickyGroup.clear();
    if (!m_sticky || !model() || model()->rowCount() == 0)
        return;
    const QModelIndex top = indexAt(QPoint(24, 1));
    if (!top.isValid())
        return;
    const QModelIndex hdr = headerFor(top);
    if (!hdr.isValid())
        return;
    const QRect hr = visualRect(hdr);
    if (hr.isValid() && hr.top() >= 0)
        return; // the real header is on screen

    QRect band(0, 0, viewport()->width(), RecordDelegate::kStickyH);
    // The next group's header pushes the pinned one up as it arrives.
    for (int row = top.row() + 1; row < model()->rowCount(); ++row) {
        const QModelIndex i = model()->index(row, 0);
        const QRect vr = visualRect(i);
        if (!vr.isValid() || vr.top() > band.bottom() + 2)
            break;
        if (i.data(rec::Header).toBool()) {
            if (vr.top() < band.height())
                band.moveTop(vr.top() - band.height());
            break;
        }
    }
    QPainter p(viewport());
    m_delegate->paintHeader(&p, band, hdr, true);
    m_stickyRect = band;
    m_stickyGroup = hdr.data(rec::Group).toString();
}

void RecordListView::scrollContentsBy(int dx, int dy)
{
    QListView::scrollContentsBy(dx, dy);
    if (m_sticky)
        viewport()->update(); // the pinned header must not be blitted along with the rows
}

void RecordListView::mousePressEvent(QMouseEvent* e)
{
    if (e->button() == Qt::LeftButton) {
        const QPoint pos = e->position().toPoint();
        if (m_stickyRect.isValid() && m_stickyRect.contains(pos) && !m_stickyGroup.isEmpty()) {
            emit headerClicked(m_stickyGroup);
            e->accept();
            return;
        }
        const QModelIndex i = indexAt(pos);
        if (i.isValid() && i.data(rec::Header).toBool()) {
            emit headerClicked(i.data(rec::Group).toString());
            e->accept();
            return;
        }
    }
    QListView::mousePressEvent(e);
}

void RecordListView::mouseDoubleClickEvent(QMouseEvent* e)
{
    const QPoint pos = e->position().toPoint();
    if (m_stickyRect.contains(pos)) {
        e->accept();
        return;
    }
    const QModelIndex i = indexAt(pos);
    if (i.isValid() && i.data(rec::Header).toBool()) {
        e->accept();
        return;
    }
    if (selectionMode() == QAbstractItemView::MultiSelection && e->button() == Qt::LeftButton) {
        // Check mode: every click toggles its row, so a quick second click is a
        // second toggle — not an "activate" that swallows it and leaves the row
        // in the state the user just tried to undo.
        QMouseEvent press(QEvent::MouseButtonPress, e->position(), e->scenePosition(), e->globalPosition(),
                          e->button(), e->buttons(), e->modifiers(), e->pointingDevice());
        mousePressEvent(&press);
        e->accept();
        return;
    }
    QListView::mouseDoubleClickEvent(e);
}
