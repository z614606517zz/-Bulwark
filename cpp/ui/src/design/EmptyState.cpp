#include "design/EmptyState.h"
#include "design/Components.h"
#include "design/IconTile.h"
#include "design/Theme.h"

#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>

namespace {

// A centred, wrapped line of text with a capped width. A plain QLabel is
// measured wrong here: the box layout asks for its height at the LAYOUT's
// width (one line fits), while the centring hands it only its own narrower
// hint width (two lines needed) — so the second line was clipped. Measure both
// at the capped width.
class CenteredText : public QLabel
{
public:
    CenteredText(const char* role, int maxWidth)
    {
        setProperty("role", role);
        setAlignment(Qt::AlignHCenter);
        setWordWrap(true);
        setMaximumWidth(maxWidth);
    }
    int heightForWidth(int w) const override { return QLabel::heightForWidth(qMin(w, maximumWidth())); }
    QSize sizeHint() const override
    {
        const int oneLine = fontMetrics().horizontalAdvance(text()) + 4;
        const int w = qMin(oneLine, maximumWidth());
        return {w, heightForWidth(w)};
    }
    QSize minimumSizeHint() const override { return {qMin(160, maximumWidth()), fontMetrics().height()}; }
};

} // namespace

EmptyState::EmptyState(QWidget* parent) : QWidget(parent)
{
    auto* v = new QVBoxLayout(this);
    v->setContentsMargins(24, 24, 24, 24);
    v->setSpacing(0);
    v->addStretch(3);

    m_tile = new IconTile(QStringLiteral("info"), theme::textMuted(), 52, 24);
    v->addWidget(m_tile, 0, Qt::AlignHCenter);
    v->addSpacing(16);

    m_title = new CenteredText("h2", 480);
    v->addWidget(m_title, 0, Qt::AlignHCenter);
    v->addSpacing(6);

    m_body = new CenteredText("secondary", 440);
    v->addWidget(m_body, 0, Qt::AlignHCenter);
    v->addSpacing(16);

    m_action = ui::button(QString(), "ghost");
    m_action->hide();
    connect(m_action, &QPushButton::clicked, this, [this] {
        if (m_fn)
            m_fn();
    });
    v->addWidget(m_action, 0, Qt::AlignHCenter);
    v->addStretch(4);
}

void EmptyState::setContent(const QString& icon, const QColor& color, const QString& title,
                            const QString& body)
{
    m_tile->set(icon, color);
    m_title->setText(title);
    m_body->setText(body);
    m_body->setVisible(!body.isEmpty());
    setAccessibleName(title);
    setAccessibleDescription(body);
}

void EmptyState::setAction(const QString& text, std::function<void()> fn, const char* variant)
{
    m_fn = std::move(fn);
    m_action->setText(text);
    ui::setVariant(m_action, variant);
    m_action->setVisible(!text.isEmpty());
}
