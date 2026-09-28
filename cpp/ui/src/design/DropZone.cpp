#include "design/DropZone.h"
#include "design/Icons.h"
#include "design/Theme.h"

#include <QDir>
#include <QDragEnterEvent>
#include <QDragLeaveEvent>
#include <QDragMoveEvent>
#include <QDropEvent>
#include <QEvent>
#include <QMimeData>
#include <QPainter>
#include <QPainterPath>
#include <QResizeEvent>
#include <QUrl>
#include <QWidget>

namespace {

class DropOverlay : public QWidget
{
public:
    DropOverlay(QWidget* parent, QString hint) : QWidget(parent), m_hint(std::move(hint))
    {
        setAttribute(Qt::WA_TransparentForMouseEvents);
        hide();
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        const QRectF r = QRectF(rect()).adjusted(4, 4, -4, -4);
        QPainterPath shape;
        shape.addRoundedRect(r, 16, 16);
        p.fillPath(shape, theme::tint(theme::bg(), 0.82));
        p.fillPath(shape, theme::tint(theme::accent(), 0.08));
        QPen dash(theme::accent(), 1.6, Qt::DashLine);
        dash.setDashPattern({5.0, 4.0});
        p.setPen(dash);
        p.setBrush(Qt::NoBrush);
        p.drawPath(shape);

        const QPointF c = r.center();
        AppIcon::draw(p, QStringLiteral("upload"), QRectF(c.x() - 16, c.y() - 34, 32, 32),
                      theme::accentSoft(), 2.0);
        QFont f = font();
        f.setPointSizeF(11.0);
        f.setWeight(QFont::DemiBold);
        p.setFont(f);
        p.setPen(theme::textPrimary());
        p.drawText(QRectF(r.left() + 16, c.y() + 6, r.width() - 32, 26), Qt::AlignCenter, m_hint);
    }

private:
    QString m_hint;
};

class DropFilter : public QObject
{
public:
    DropFilter(QWidget* target, const QString& hint, std::function<void(const QStringList&)> onDrop,
               std::function<bool(const QString&)> accept)
        : QObject(target), m_target(target), m_onDrop(std::move(onDrop)), m_accept(std::move(accept))
    {
        m_overlay = new DropOverlay(target, hint);
        target->setAcceptDrops(true);
        target->installEventFilter(this);
    }

protected:
    bool eventFilter(QObject* obj, QEvent* ev) override
    {
        if (obj != m_target)
            return QObject::eventFilter(obj, ev);
        switch (ev->type()) {
        case QEvent::DragEnter: {
            auto* de = static_cast<QDragEnterEvent*>(ev);
            if (!paths(de->mimeData()).isEmpty()) {
                de->acceptProposedAction();
                m_overlay->setGeometry(m_target->rect());
                m_overlay->show();
                m_overlay->raise();
            } else {
                de->ignore();
            }
            return true;
        }
        case QEvent::DragMove: {
            auto* dm = static_cast<QDragMoveEvent*>(ev);
            if (m_overlay->isVisible())
                dm->acceptProposedAction();
            else
                dm->ignore();
            return true;
        }
        case QEvent::DragLeave:
            m_overlay->hide();
            return true;
        case QEvent::Drop: {
            auto* d = static_cast<QDropEvent*>(ev);
            m_overlay->hide();
            const QStringList list = paths(d->mimeData());
            if (list.isEmpty()) {
                d->ignore();
                return true;
            }
            d->acceptProposedAction();
            if (m_onDrop)
                m_onDrop(list);
            return true;
        }
        case QEvent::Resize:
            if (m_overlay->isVisible())
                m_overlay->setGeometry(m_target->rect());
            break;
        default:
            break;
        }
        return QObject::eventFilter(obj, ev);
    }

private:
    QStringList paths(const QMimeData* md) const
    {
        QStringList out;
        if (!md || !md->hasUrls())
            return out;
        for (const QUrl& url : md->urls()) {
            if (!url.isLocalFile())
                continue;
            const QString p = QDir::toNativeSeparators(url.toLocalFile());
            if (p.isEmpty() || (m_accept && !m_accept(p)))
                continue;
            out << p;
        }
        return out;
    }

    QWidget* m_target;
    DropOverlay* m_overlay = nullptr;
    std::function<void(const QStringList&)> m_onDrop;
    std::function<bool(const QString&)> m_accept;
};

} // namespace

void ui::acceptFileDrops(QWidget* target, const QString& hint,
                         std::function<void(const QStringList&)> onDrop,
                         std::function<bool(const QString&)> accept)
{
    if (!target)
        return;
    new DropFilter(target, hint, std::move(onDrop), std::move(accept));
}
