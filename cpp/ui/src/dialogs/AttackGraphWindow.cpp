#include "dialogs/AttackGraphWindow.h"
#include "dialogs/EventFormat.h"
#include "ipc/IpcClient.h"
#include "design/Backdrop.h"
#include "design/Components.h"
#include "design/Format.h"
#include "design/GlowCard.h"
#include "design/IconTile.h"
#include "design/Icons.h"
#include "design/Inspector.h"
#include "design/Theme.h"
#include "Nav.h"

#include <QEvent>
#include <QHBoxLayout>
#include <QLabel>
#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QPushButton>
#include <QScrollArea>
#include <QScrollBar>
#include <QSplitter>
#include <QToolButton>
#include <QVBoxLayout>
#include <QWheelEvent>

#include <algorithm>
#include <cmath>

using evtfmt::u;

namespace {

// 布局常量(逻辑坐标)。节点框故意做得够宽,因为标签是文件名/域名,太窄就全省略号了。
constexpr qreal kNodeW = 186;
constexpr qreal kNodeH = 56;
constexpr qreal kGapX = 34;
constexpr qreal kGapY = 84;
constexpr qreal kMargin = 40;
constexpr qreal kMinScale = 0.35;
constexpr qreal kMaxScale = 2.0;

QColor kindColor(bulwark::AttackNodeKind k)
{
    using K = bulwark::AttackNodeKind;
    switch (k) {
    case K::Process:       return theme::accent();
    case K::File:          return theme::olive(); // not accentAlt: that is the AI colour, and too close to violet
    case K::Registry:      return theme::violet();
    case K::Network:       return theme::sky();
    case K::Domain:        return theme::cyan();
    case K::Module:        return theme::amber();
    case K::Service:       return theme::purple();
    case K::ScheduledTask: return theme::pink();
    }
    return theme::accent();
}

QString kindLabel(bulwark::AttackNodeKind k)
{
    using K = bulwark::AttackNodeKind;
    switch (k) {
    case K::Process:       return u("进程");
    case K::File:          return u("文件");
    case K::Registry:      return u("注册表");
    case K::Network:       return u("远端地址");
    case K::Domain:        return u("域名");
    case K::Module:        return u("模块");
    case K::Service:       return u("服务");
    case K::ScheduledTask: return u("计划任务");
    }
    return u("实体");
}

QString kindIcon(bulwark::AttackNodeKind k)
{
    using K = bulwark::AttackNodeKind;
    switch (k) {
    case K::Process:       return QStringLiteral("target");
    case K::File:          return QStringLiteral("file");
    case K::Registry:      return QStringLiteral("sliders");
    case K::Network:       return QStringLiteral("globe");
    case K::Domain:        return QStringLiteral("globe");
    case K::Module:        return QStringLiteral("layers");
    case K::Service:       return QStringLiteral("server");
    case K::ScheduledTask: return QStringLiteral("clock");
    }
    return QStringLiteral("target");
}

QString dispositionText(const bulwark::AttackGraphEdge& e)
{
    using O = bulwark::EnforcementOutcome;
    switch (e.enforcement) {
    case O::KernelBlocked:     return u("内核前拦截");
    case O::Terminated:        return u("已结束进程");
    case O::ModuleBlacklisted: return u("已加入禁止加载");
    case O::ExecDenied:        return u("已禁止启动");
    case O::ActorAlreadyGone:  return u("主体已结束");
    case O::Failed:            return u("处置失败");
    case O::AlertedOnly:       return u("仅告警");
    case O::NotApplicable:     break;
    }
    switch (e.action) {
    case bulwark::VerdictAction::Block: return u("判定拦截");
    case bulwark::VerdictAction::Ask:   return u("已询问用户");
    case bulwark::VerdictAction::Allow: return u("放行");
    }
    return QString();
}

// 图上这条边算不算「这一步被真正掐断了」。口径:【主体被消灭】才算 ——
// ActorAlreadyGone 也算(那个进程确实已经不在了,只是杀它的是上一条事件的处置);
// ModuleBlacklisted / ExecDenied 【不算】,它们说的是「下一次会被拦」,这一步本身还是发生了。
// 与 AttackGraphBuilder::blockedForReal 必须保持同一口径(图的配色与统计各来自其中一处)。
bool reallyBlocked(const bulwark::AttackGraphEdge& e)
{
    return e.enforcement == bulwark::EnforcementOutcome::KernelBlocked
        || e.enforcement == bulwark::EnforcementOutcome::Terminated
        || e.enforcement == bulwark::EnforcementOutcome::ActorAlreadyGone;
}

QColor edgeColor(const bulwark::AttackGraphEdge& e)
{
    if (e.inferred)
        return theme::textDisabled();
    if (reallyBlocked(e))
        return theme::danger();
    if (e.riskScore >= 50 || e.hasThreatIndicator)
        return theme::warning();
    return theme::textMuted();
}

QString nodeText(const bulwark::AttackGraphNode& n)
{
    return n.label.isEmpty() ? kindLabel(n.kind) : n.label;
}

// Bottom-centre of the parent to top-centre of the child (the rare upward edge
// of a cycle runs top to bottom instead), as a vertical-tangent cubic.
QPainterPath edgePath(const QRectF& fb, const QRectF& tb)
{
    QPointF a(fb.center().x(), fb.bottom());
    QPointF b(tb.center().x(), tb.top());
    if (tb.top() < fb.top()) {
        a = QPointF(fb.center().x(), fb.top());
        b = QPointF(tb.center().x(), tb.bottom());
    }
    QPainterPath path(a);
    const qreal dy = (b.y() - a.y()) * 0.45;
    path.cubicTo(a + QPointF(0, dy), b - QPointF(0, dy), b);
    return path;
}

// Labels sit two thirds of the way down the curve: sibling edges leave their
// parent together, so at the midpoint their labels overlapped.
QPointF labelPoint(const QPainterPath& path) { return path.pointAtPercent(0.66); }

// "2026-09-27 16:25:33 → 16:38:33" (the date once when both ends share it).
QString span(const QDateTime& a, const QDateTime& b)
{
    if (!a.isValid())
        return QString();
    const QDateTime la = a.toLocalTime();
    const QDateTime lb = b.isValid() ? b.toLocalTime() : la;
    return QStringLiteral("%1 → %2").arg(la.toString(QStringLiteral("yyyy-MM-dd HH:mm:ss")),
                                         lb.toString(la.date() == lb.date() ? QStringLiteral("HH:mm:ss")
                                                                            : QStringLiteral("yyyy-MM-dd HH:mm:ss")));
}

// A small legend swatch: a node colour, or a line style.
class Swatch : public QWidget
{
public:
    enum class Kind { Node, Solid, Dashed };
    Swatch(Kind kind, const QColor& color) : m_kind(kind), m_color(color) { setFixedSize(22, 12); }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        if (m_kind == Kind::Node) {
            p.setPen(Qt::NoPen);
            p.setBrush(m_color);
            p.drawRoundedRect(QRectF(6, 1, 10, 10), 3, 3);
            return;
        }
        QPen pen(m_color, 1.6);
        if (m_kind == Kind::Dashed)
            pen.setStyle(Qt::DashLine);
        p.setPen(pen);
        p.drawLine(QPointF(1, 6), QPointF(21, 6));
    }

private:
    Kind m_kind;
    QColor m_color;
};

} // namespace

// ============================== 画布 ==============================

AttackGraphCanvas::AttackGraphCanvas(QWidget* parent) : QWidget(parent)
{
    setMouseTracking(true);
    setCursor(Qt::OpenHandCursor);
    setAccessibleName(u("攻击关系图"));
}

void AttackGraphCanvas::setGraph(const bulwark::AttackGraph& graph)
{
    m_graph = graph;
    m_indexById.clear();
    for (int i = 0; i < m_graph.nodes.size(); ++i)
        m_indexById.insert(m_graph.nodes[i].id, i);
    m_selectedNode = -1;
    m_selectedEdge = -1;
    relayout();
    update();
}

void AttackGraphCanvas::setMessage(const QString& text)
{
    m_message = text;
    update();
}

void AttackGraphCanvas::setScale(qreal s)
{
    const qreal clamped = std::clamp(s, kMinScale, kMaxScale);
    if (qFuzzyCompare(clamped, m_scale))
        return;
    m_scale = clamped;
    syncSize();
    update();
    emit scaleChanged(m_scale);
}

void AttackGraphCanvas::setViewportSize(const QSize& size)
{
    m_viewport = size;
    syncSize();
}

void AttackGraphCanvas::clearSelection()
{
    m_selectedNode = -1;
    m_selectedEdge = -1;
    update();
}

void AttackGraphCanvas::syncSize()
{
    const QSize graph(int(std::ceil(m_logicalSize.width() * m_scale)), int(std::ceil(m_logicalSize.height() * m_scale)));
    setFixedSize(graph.expandedTo(m_viewport));
}

QPointF AttackGraphCanvas::origin() const
{
    return {std::max(0.0, (width() - m_logicalSize.width() * m_scale) / 2.0),
            std::max(0.0, (height() - m_logicalSize.height() * m_scale) / 2.0)};
}

QPointF AttackGraphCanvas::toLogical(const QPointF& widgetPos) const
{
    const QPointF o = origin();
    return {(widgetPos.x() - o.x()) / m_scale, (widgetPos.y() - o.y()) / m_scale};
}

// 分层布局:层号(depth)由服务端按父子链算好,这里只在层内排位。
// 层内顺序:先进程(骨架),再实体节点,同类按风险、标签排 —— 保证同一张图两次打开长得一样。
void AttackGraphCanvas::relayout()
{
    m_boxes.assign(m_graph.nodes.size(), QRectF());
    if (m_graph.nodes.isEmpty()) {
        m_logicalSize = QSizeF(200, 120);
        syncSize();
        return;
    }

    int maxDepth = 0;
    for (const bulwark::AttackGraphNode& n : m_graph.nodes)
        maxDepth = std::max(maxDepth, n.depth);

    qreal widest = 0;
    for (int d = 0; d <= maxDepth; ++d) {
        QVector<int> row;
        for (int i = 0; i < m_graph.nodes.size(); ++i)
            if (m_graph.nodes[i].depth == d)
                row.append(i);
        std::sort(row.begin(), row.end(), [this](int a, int b) {
            const auto& na = m_graph.nodes[a];
            const auto& nb = m_graph.nodes[b];
            const bool pa = na.kind == bulwark::AttackNodeKind::Process;
            const bool pb = nb.kind == bulwark::AttackNodeKind::Process;
            if (pa != pb) return pa;
            if (na.riskScore != nb.riskScore) return na.riskScore > nb.riskScore;
            return na.label.compare(nb.label, Qt::CaseInsensitive) < 0;
        });
        const qreal rowW = row.size() * kNodeW + std::max<qreal>(0, row.size() - 1) * kGapX;
        widest = std::max(widest, rowW);
        for (int i = 0; i < row.size(); ++i) {
            const qreal x = kMargin + i * (kNodeW + kGapX);
            const qreal y = kMargin + d * (kNodeH + kGapY);
            m_boxes[row[i]] = QRectF(x, y, kNodeW, kNodeH);
        }
    }

    // 每层水平居中,图看起来才像一棵树而不是左对齐的表格。
    for (int d = 0; d <= maxDepth; ++d) {
        qreal minX = 1e9, maxX = -1e9;
        for (int i = 0; i < m_graph.nodes.size(); ++i) {
            if (m_graph.nodes[i].depth != d || m_boxes[i].isNull())
                continue;
            minX = std::min(minX, m_boxes[i].left());
            maxX = std::max(maxX, m_boxes[i].right());
        }
        if (maxX < minX)
            continue;
        const qreal shift = (widest - (maxX - minX)) / 2.0 + kMargin - minX;
        for (int i = 0; i < m_graph.nodes.size(); ++i)
            if (m_graph.nodes[i].depth == d && !m_boxes[i].isNull())
                m_boxes[i].translate(shift, 0);
    }

    m_logicalSize = QSizeF(widest + kMargin * 2, kMargin * 2 + (maxDepth + 1) * kNodeH + maxDepth * kGapY);
    syncSize();
}

int AttackGraphCanvas::nodeAt(const QPointF& logical) const
{
    for (int i = 0; i < m_boxes.size(); ++i)
        if (m_boxes[i].contains(logical))
            return i;
    return -1;
}

int AttackGraphCanvas::edgeAt(const QPointF& logical) const
{
    // 边的命中区:两端中点连线的中段附近(标签就画在那里)。
    for (int i = 0; i < m_graph.edges.size(); ++i) {
        const auto fromIt = m_indexById.constFind(m_graph.edges[i].fromId);
        const auto toIt = m_indexById.constFind(m_graph.edges[i].toId);
        if (fromIt == m_indexById.constEnd() || toIt == m_indexById.constEnd())
            continue;
        const QPointF mid = labelPoint(edgePath(m_boxes[fromIt.value()], m_boxes[toIt.value()]));
        if (QRectF(mid.x() - 70, mid.y() - 12, 140, 24).contains(logical))
            return i;
    }
    return -1;
}

void AttackGraphCanvas::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);
    p.fillRect(rect(), theme::canvasBrush());

    if (m_graph.nodes.isEmpty()) {
        p.setPen(theme::textMuted());
        p.drawText(rect(), Qt::AlignCenter, m_message.isEmpty() ? u("没有可展示的关联关系") : m_message);
        return;
    }

    p.translate(origin());
    p.scale(m_scale, m_scale);

    QFont edgeFont = p.font();
    edgeFont.setPointSizeF(8.0);

    // ---- 先画边:虚线 = 推导出来的关系(父子/服务启动),实线 = 真实观测到的行为事件。----
    for (int i = 0; i < m_graph.edges.size(); ++i) {
        const bulwark::AttackGraphEdge& e = m_graph.edges[i];
        const auto fromIt = m_indexById.constFind(e.fromId);
        const auto toIt = m_indexById.constFind(e.toId);
        if (fromIt == m_indexById.constEnd() || toIt == m_indexById.constEnd())
            continue;
        const QPainterPath path = edgePath(m_boxes[fromIt.value()], m_boxes[toIt.value()]);
        const QPointF b = path.currentPosition();

        const QColor c = edgeColor(e);
        QPen pen(c, i == m_selectedEdge ? 2.6 : 1.6);
        if (e.inferred)
            pen.setStyle(Qt::DashLine);
        p.setPen(pen);
        p.drawPath(path);

        // 箭头
        const QPointF dir = b - (path.pointAtPercent(0.92));
        const qreal len = std::hypot(dir.x(), dir.y());
        if (len > 0.1) {
            const QPointF n(dir.x() / len, dir.y() / len);
            const QPointF perp(-n.y(), n.x());
            QPolygonF head;
            head << b << (b - n * 9 + perp * 4.5) << (b - n * 9 - perp * 4.5);
            p.setBrush(c);
            p.setPen(Qt::NoPen);
            p.drawPolygon(head);
            p.setBrush(Qt::NoBrush);
        }

        // 标签:行为 + 处置。放在中点,带一层底色避免压在连线上看不清。
        QString text = e.label;
        if (!e.inferred) {
            const QString disp = dispositionText(e);
            if (!disp.isEmpty() && disp != u("放行"))
                text += QStringLiteral(" · ") + disp;
        }
        if (!text.isEmpty()) {
            p.setFont(edgeFont);
            const QPointF mid = labelPoint(path);
            const QRectF tr = QFontMetricsF(edgeFont).boundingRect(text).adjusted(-7, -3, 7, 3);
            const QRectF box = tr.translated(mid - QPointF(tr.width() / 2 + tr.left(), tr.height() / 2 + tr.top()));
            p.setPen(QPen(theme::blend(c, theme::bg(), 0.30), i == m_selectedEdge ? 1.6 : 1.0));
            p.setBrush(theme::blend(c, theme::bg(), 0.12));
            p.drawRoundedRect(box, 6, 6);
            p.setBrush(Qt::NoBrush);
            // 深色底上标签文字直接用连线色(各档都在 AA 以上);推导关系那一档太暗,改用 muted。
            p.setPen(e.inferred ? theme::textMuted() : c);
            p.drawText(box, Qt::AlignCenter, text);
        }
    }

    // ---- 再画节点 ----
    QFont titleFont = p.font();
    titleFont.setPointSizeF(9.5);
    titleFont.setBold(true);
    QFont subFont = p.font();
    subFont.setPointSizeF(8.0);

    for (int i = 0; i < m_graph.nodes.size(); ++i) {
        const bulwark::AttackGraphNode& n = m_graph.nodes[i];
        const QRectF& box = m_boxes[i];
        if (box.isNull())
            continue;

        const QColor accent = (n.kind == bulwark::AttackNodeKind::Process && n.riskScore > 0)
                                  ? evtfmt::riskColor(n.riskScore)
                                  : kindColor(n.kind);
        // 种子节点(用户点开的那条事件的主体)必须一眼能找到。
        const bool highlight = n.isSeed || i == m_selectedNode;
        p.setPen(QPen(i == m_selectedNode ? theme::accentSoft() : (highlight ? accent : theme::border()),
                      highlight ? 2.2 : 1.2));
        p.setBrush(n.blocked ? theme::blend(theme::danger(), theme::surface(), 0.08) : theme::surface());
        p.drawRoundedRect(box, 10, 10);

        // 左侧色条标明实体类别
        p.setPen(Qt::NoPen);
        p.setBrush(accent);
        p.drawRoundedRect(QRectF(box.left() + 1, box.top() + 8, 4, box.height() - 16), 2, 2);
        p.setBrush(Qt::NoBrush);

        const QRectF textRect = box.adjusted(14, 7, -10, -7);
        p.setFont(titleFont);
        p.setPen(theme::textPrimary());
        const QString title = QFontMetricsF(titleFont).elidedText(nodeText(n), Qt::ElideMiddle, textRect.width() - 4);
        p.drawText(QRectF(textRect.left(), textRect.top(), textRect.width(), 17), Qt::AlignLeft | Qt::AlignVCenter,
                   title);

        // 第二行:PID / 类别 + 启动来源(服务 / 计划任务)—— 这行才是溯源的价值所在。
        QStringList sub;
        if (n.kind == bulwark::AttackNodeKind::Process) {
            sub << (n.pid > 0 ? QStringLiteral("PID %1").arg(n.pid) : kindLabel(n.kind));
            if (!n.originLabel.isEmpty())
                sub << n.originLabel;
            else if (!n.signedActor && !n.path.isEmpty())
                sub << u("未签名");
        } else {
            sub << kindLabel(n.kind);
        }
        p.setFont(subFont);
        p.setPen(theme::textSecondary());
        const QString subText = QFontMetricsF(subFont).elidedText(sub.join(QStringLiteral("  ·  ")), Qt::ElideMiddle,
                                                                  textRect.width() - 4);
        p.drawText(QRectF(textRect.left(), textRect.top() + 18, textRect.width(), 15),
                   Qt::AlignLeft | Qt::AlignVCenter, subText);

        // 第三行:风险分 / 标记
        QStringList tags;
        if (n.isSeed) tags << u("本次事件");
        if (n.isRoot) tags << u("链首");
        if (n.blocked) tags << u("已拦截");
        if (n.riskScore > 0) tags << u("风险 %1").arg(n.riskScore);
        if (n.eventCount > 1) tags << u("%1 次行为").arg(n.eventCount);
        if (!tags.isEmpty()) {
            p.setPen(n.blocked ? theme::danger() : theme::textMuted());
            p.drawText(QRectF(textRect.left(), textRect.top() + 33, textRect.width(), 14),
                       Qt::AlignLeft | Qt::AlignVCenter,
                       QFontMetricsF(subFont).elidedText(tags.join(QStringLiteral("  ·  ")), Qt::ElideRight,
                                                         textRect.width() - 4));
        }
    }
}

void AttackGraphCanvas::mousePressEvent(QMouseEvent* e)
{
    if (e->button() != Qt::LeftButton) {
        QWidget::mousePressEvent(e);
        return;
    }
    const QPointF logical = toLogical(e->position());
    if (const int n = nodeAt(logical); n >= 0) {
        m_selectedNode = n;
        m_selectedEdge = -1;
        update();
        emit nodeSelected(n);
        return;
    }
    if (const int ed = edgeAt(logical); ed >= 0) {
        m_selectedEdge = ed;
        m_selectedNode = -1;
        update();
        emit edgeSelected(ed);
        return;
    }
    // Empty canvas: drag to pan; a click without a drag clears the selection.
    m_panning = true;
    m_panMoved = false;
    m_panLast = e->globalPosition().toPoint();
    setCursor(Qt::ClosedHandCursor);
}

void AttackGraphCanvas::mouseMoveEvent(QMouseEvent* e)
{
    if (m_panning) {
        const QPoint now = e->globalPosition().toPoint();
        const QPoint delta = now - m_panLast;
        m_panLast = now;
        if (!delta.isNull()) {
            m_panMoved = true;
            emit panRequested(-delta);
        }
        return;
    }
    const QPointF logical = toLogical(e->position());
    const bool over = nodeAt(logical) >= 0 || edgeAt(logical) >= 0;
    setCursor(over ? Qt::PointingHandCursor : Qt::OpenHandCursor);
}

void AttackGraphCanvas::mouseReleaseEvent(QMouseEvent* e)
{
    if (!m_panning) {
        QWidget::mouseReleaseEvent(e);
        return;
    }
    m_panning = false;
    setCursor(Qt::OpenHandCursor);
    if (!m_panMoved && (m_selectedNode >= 0 || m_selectedEdge >= 0)) {
        clearSelection();
        emit nodeSelected(-1);
    }
}

void AttackGraphCanvas::wheelEvent(QWheelEvent* e)
{
    if (!(e->modifiers() & Qt::ControlModifier)) {
        QWidget::wheelEvent(e); // 交给外层 QScrollArea 滚动
        return;
    }
    setScale(m_scale * (e->angleDelta().y() > 0 ? 1.12 : 1 / 1.12));
    e->accept();
}

// ============================== 窗口 ==============================

AttackGraphWindow::AttackGraphWindow(IpcClient* ipc, const QUuid& seedEventId, int rootPid, const QString& title,
                                     QWidget* parent)
    : QDialog(parent), m_ipc(ipc), m_seedEventId(seedEventId), m_rootPid(rootPid), m_title(title)
{
    setWindowTitle(title.isEmpty() ? u("攻击关系图") : u("攻击关系图 · %1").arg(title));
    setAccessibleName(windowTitle());
    Backdrop::install(this); // same work-area material as the main window
    resize(1220, 800);
    setMinimumSize(820, 520);
    setSizeGripEnabled(true);

    auto* outer = new QVBoxLayout(this);
    outer->setContentsMargins(20, 16, 20, 18);
    outer->setSpacing(12);

    // ---- header ----
    auto* head = new QHBoxLayout;
    head->setSpacing(14);
    head->addWidget(new IconTile(QStringLiteral("link"), theme::accent(), 42, 21), 0, Qt::AlignTop);
    auto* hc = new QVBoxLayout;
    hc->setSpacing(2);
    hc->addWidget(ui::label(title.isEmpty() ? u("攻击关系图") : title, "h2"));
    m_summary = ui::elided(u("正在关联事件…"), "secondary");
    hc->addWidget(m_summary);
    head->addLayout(hc, 1);
    outer->addLayout(head);

    // ---- canvas | inspector ----
    m_split = new QSplitter(Qt::Horizontal);
    m_split->setChildrenCollapsible(false);
    m_split->setHandleWidth(14);

    m_scroll = new QScrollArea;
    m_scroll->setWidgetResizable(false);
    m_scroll->setFrameShape(QFrame::NoFrame);
    m_scroll->setAlignment(Qt::AlignCenter);
    m_canvas = new AttackGraphCanvas;
    m_canvas->setMessage(u("正在关联事件…"));
    m_scroll->setWidget(m_canvas);
    m_scroll->installEventFilter(this);
    m_split->addWidget(m_scroll);

    m_inspector = new Inspector;
    m_inspector->setMinimumWidth(300);
    m_split->addWidget(m_inspector);
    m_split->setStretchFactor(0, 1);
    m_split->setStretchFactor(1, 0);
    m_split->setSizes({840, 360});
    outer->addWidget(m_split, 1);

    // ---- zoom capsule (floats over the canvas, bottom-left) ----
    auto* zoom = new GlowCard(m_scroll);
    zoom->setTone(GlowCard::Tone::Floating);
    zoom->setRadius(17);
    zoom->setFixedHeight(34);
    auto* zh = new QHBoxLayout(zoom);
    zh->setContentsMargins(6, 2, 6, 2);
    zh->setSpacing(2);
    auto* zoomOut = ui::iconButton(QStringLiteral("minus"), u("缩小 (Ctrl + 滚轮)"), theme::textSecondary(), 14);
    auto* zoomReset = new QToolButton;
    zoomReset->setAutoRaise(true);
    zoomReset->setCursor(Qt::PointingHandCursor);
    zoomReset->setText(QStringLiteral("100%"));
    zoomReset->setToolTip(u("恢复 100%"));
    zoomReset->setAccessibleName(u("缩放比例,点击恢复 100%"));
    zoomReset->setMinimumWidth(50);
    m_zoomReset = zoomReset;
    auto* zoomIn = ui::iconButton(QStringLiteral("plus"), u("放大 (Ctrl + 滚轮)"), theme::textSecondary(), 14);
    auto* fitBtn = ui::iconButton(QStringLiteral("maximize"), u("适应窗口"), theme::textSecondary(), 14);
    zh->addWidget(zoomOut);
    zh->addWidget(zoomReset);
    zh->addWidget(zoomIn);
    zh->addSpacing(2);
    zh->addWidget(fitBtn);
    m_zoomBar = zoom;
    connect(zoomOut, &QToolButton::clicked, this, [this] { m_canvas->setScale(m_canvas->scaleFactor() / 1.15); });
    connect(zoomIn, &QToolButton::clicked, this, [this] { m_canvas->setScale(m_canvas->scaleFactor() * 1.15); });
    connect(zoomReset, &QToolButton::clicked, this, [this] { m_canvas->setScale(1.0); });
    connect(fitBtn, &QToolButton::clicked, this, [this] { fit(); });
    connect(m_canvas, &AttackGraphCanvas::scaleChanged, this,
            [this](qreal s) { m_zoomReset->setText(QStringLiteral("%1%").arg(qRound(s * 100))); });

    // ---- legend (bottom-right; filled once the graph is known) ----
    auto* legend = new GlowCard(m_scroll);
    legend->setTone(GlowCard::Tone::Floating);
    legend->setRadius(12);
    legend->hide();
    m_legend = legend;

    connect(m_canvas, &AttackGraphCanvas::panRequested, this, [this](const QPoint& d) {
        m_scroll->horizontalScrollBar()->setValue(m_scroll->horizontalScrollBar()->value() + d.x());
        m_scroll->verticalScrollBar()->setValue(m_scroll->verticalScrollBar()->value() + d.y());
    });
    connect(m_canvas, &AttackGraphCanvas::nodeSelected, this, &AttackGraphWindow::showNodeDetail);
    connect(m_canvas, &AttackGraphCanvas::edgeSelected, this, &AttackGraphWindow::showEdgeDetail);
    connect(m_inspector, &Inspector::closeRequested, this, [this] {
        m_canvas->clearSelection();
        showOverview();
    });
    const auto fail = [this](const QString& why) {
        m_status = why;
        m_summary->setText(why);
        m_canvas->setMessage(why);
        showOverview();
    };

    // ---- 拉取 ----
    m_status = u("正在向服务请求这段时间里的关联事件…");
    showOverview();
    if (!m_ipc) {
        fail(u("未连接后台服务,无法构建攻击图。"));
        return;
    }
    connect(m_ipc, &IpcClient::attackGraphReceived, this,
            [this, fail](const bulwark::ipc::AttackGraphResponsePayload& p) {
        if (p.requestId != m_requestId)
            return; // 别的窗口发起的响应,与本窗口无关(服务端广播给所有界面)
        if (!p.success && p.graph.isEmpty()) {
            fail(p.message.isEmpty() ? u("未能构建攻击图") : p.message);
            return;
        }
        if (p.graph.isEmpty()) {
            fail(p.message.isEmpty() ? u("这段时间里没有与它关联的事件。") : p.message);
            return;
        }
        showGraph(p.graph);
    });
    if (!m_ipc->isConnected()) {
        fail(u("未连接后台服务,无法构建攻击图。"));
        return;
    }
    m_requestId = m_ipc->requestAttackGraph(m_seedEventId, m_rootPid, 3600);
}

bool AttackGraphWindow::eventFilter(QObject* watched, QEvent* e)
{
    if (watched == m_scroll && e->type() == QEvent::Resize) {
        m_canvas->setViewportSize(m_scroll->viewport()->size());
        placeOverlays();
        if (!m_fitted && !m_graph.isEmpty())
            fit();
    }
    return QDialog::eventFilter(watched, e);
}

void AttackGraphWindow::placeOverlays()
{
    const QRect vp = m_scroll->viewport()->geometry();
    m_zoomBar->adjustSize();
    m_zoomBar->move(vp.left() + 14, vp.bottom() - m_zoomBar->height() - 13);
    m_zoomBar->raise();
    if (m_legend->isVisible() || !m_graph.isEmpty()) {
        // Top-right: the layered graph is centred and its first layers are the
        // narrowest (the root), so that corner is the one least likely to hide a node.
        m_legend->adjustSize();
        m_legend->move(vp.right() - m_legend->width() - 13, vp.top() + 13);
        m_legend->raise();
    }
}

void AttackGraphWindow::fit()
{
    const QSizeF logical = m_canvas->logicalSize();
    const QSize vp = m_scroll->viewport()->size();
    if (logical.width() < 1 || logical.height() < 1 || vp.width() < 50 || vp.height() < 50)
        return;
    const qreal want = std::min((vp.width() - 24) / logical.width(), (vp.height() - 60) / logical.height());
    m_canvas->setScale(std::clamp(want, kMinScale, 1.0));
    m_fitted = true;
}

void AttackGraphWindow::showGraph(const bulwark::AttackGraph& g)
{
    m_graph = g;
    m_canvas->setGraph(g);
    m_canvas->setMessage(QString());

    QStringList parts;
    if (!g.summary.isEmpty())
        parts << g.summary;
    if (g.firstUtc.isValid() && g.lastUtc.isValid())
        parts << QStringLiteral("%1 → %2")
                     .arg(g.firstUtc.toLocalTime().toString(QStringLiteral("MM-dd HH:mm:ss")),
                          g.lastUtc.toLocalTime().toString(QStringLiteral("HH:mm:ss")));
    if (g.truncated)
        parts << u("事件过多,已截断");
    m_summary->setText(parts.join(u("  ·  ")));

    // Legend: only the entity kinds this graph actually has, plus the edge styles.
    Inspector::clearLayout(m_legend->layout());
    delete m_legend->layout();
    auto* lv = new QVBoxLayout(m_legend);
    lv->setContentsMargins(12, 9, 14, 10);
    lv->setSpacing(4);
    const auto line = [lv](QWidget* sw, const QString& text) {
        auto* row = new QHBoxLayout;
        row->setSpacing(6);
        row->addWidget(sw);
        row->addWidget(ui::label(text, "caption"));
        row->addStretch();
        lv->addLayout(row);
    };
    QList<bulwark::AttackNodeKind> kinds;
    for (const bulwark::AttackGraphNode& n : g.nodes)
        if (!kinds.contains(n.kind))
            kinds << n.kind;
    std::sort(kinds.begin(), kinds.end(), [](auto a, auto b) { return int(a) < int(b); });
    for (bulwark::AttackNodeKind k : kinds)
        line(new Swatch(Swatch::Kind::Node, kindColor(k)), kindLabel(k));
    line(new Swatch(Swatch::Kind::Solid, theme::textMuted()), u("观测到的行为"));
    line(new Swatch(Swatch::Kind::Solid, theme::danger()), u("已被拦截"));
    line(new Swatch(Swatch::Kind::Dashed, theme::textDisabled()), u("推导关系(父子 / 启动来源)"));
    m_legend->setVisible(!g.isEmpty());

    placeOverlays();
    m_fitted = false;
    fit();
    showOverview();
}

void AttackGraphWindow::showOverview()
{
    Inspector* in = m_inspector;
    in->setUpdatesEnabled(false);
    in->clear();
    const QColor tone = m_graph.maxRiskScore >= 50 ? evtfmt::riskColor(m_graph.maxRiskScore) : theme::accent();
    in->setHeader(QStringLiteral("link"), tone, u("整张图"),
                  m_graph.rootLabel.isEmpty() ? m_title : u("链首 %1").arg(m_graph.rootLabel));
    if (m_graph.isEmpty()) {
        in->addLead(m_status);
    } else {
        if (!m_graph.summary.isEmpty())
            in->addLead(m_graph.summary);
        QVBoxLayout* s = in->addSection(u("概况"));
        if (m_graph.firstUtc.isValid())
            in->addField(s, u("时间跨度"), span(m_graph.firstUtc, m_graph.lastUtc));
        in->addField(s, u("纳入事件"), QString::number(m_graph.eventCount));
        int processes = 0;
        for (const bulwark::AttackGraphNode& n : m_graph.nodes)
            if (n.kind == bulwark::AttackNodeKind::Process)
                ++processes;
        in->addField(s, u("节点"), u("%1 个进程 · %2 个其它实体").arg(processes).arg(m_graph.nodes.size() - processes));
        if (m_graph.maxRiskScore > 0)
            in->addField(s, u("最高风险"), QString::number(m_graph.maxRiskScore));
        if (!m_graph.techniques.isEmpty()) {
            QList<QPair<QString, QColor>> tech;
            for (const QString& t : m_graph.techniques)
                tech << qMakePair(t, theme::info());
            s = in->addSection(u("ATT&CK 技战术"));
            in->addChips(s, tech);
        }
        if (m_graph.truncated)
            in->setNote(u("这段时间的事件过多,图已按上限截断;更早或更边缘的关系可能没有画出来。"), theme::warning());
    }
    QVBoxLayout* how = in->addSection(u("怎么看"));
    in->addText(how, u("点击节点或连线查看详情;拖动空白处平移,Ctrl + 滚轮缩放。"));
    in->addText(how, u("图里的每一条关系都来自服务端的事件关联,界面不做任何推断。虚线是由进程父子链 / 启动来源"
                       "推导出的关系,不是一次被记录下来的行为。"),
                "muted");
    in->setUpdatesEnabled(true);
}

void AttackGraphWindow::showNodeDetail(int index)
{
    if (index < 0 || index >= m_graph.nodes.size()) {
        showOverview();
        return;
    }
    const bulwark::AttackGraphNode& n = m_graph.nodes[index];
    Inspector* in = m_inspector;
    in->setUpdatesEnabled(false);
    in->clear();
    const QColor accent = (n.kind == bulwark::AttackNodeKind::Process && n.riskScore > 0) ? evtfmt::riskColor(n.riskScore)
                                                                                         : kindColor(n.kind);
    in->setHeader(kindIcon(n.kind), accent, nodeText(n),
                  n.kind == bulwark::AttackNodeKind::Process && n.pid > 0
                      ? u("%1 · PID %2").arg(kindLabel(n.kind)).arg(n.pid)
                      : kindLabel(n.kind));
    QList<QPair<QString, QColor>> chips;
    if (n.isSeed) chips << qMakePair(u("本次事件"), theme::accentSoft());
    if (n.isRoot) chips << qMakePair(u("链首"), theme::info());
    if (n.blocked) chips << qMakePair(u("已拦截"), theme::danger());
    if (n.riskScore > 0) chips << qMakePair(u("风险 %1").arg(n.riskScore), evtfmt::riskColor(n.riskScore));
    if (!chips.isEmpty())
        in->addChips(nullptr, chips);

    const Inspector::FieldFlags monoCopy = Inspector::Mono | Inspector::Copy;
    if (n.kind == bulwark::AttackNodeKind::Process) {
        QVBoxLayout* s = in->addSection(u("进程"));
        in->addField(s, u("映像路径"), evtfmt::nativePath(n.path), monoCopy);
        in->addField(s, u("启动来源"), n.originLabel.isEmpty() ? u("未能判定(父进程为普通进程)") : n.originLabel);
        in->addField(s, u("数字签名"),
                     n.signedActor ? (n.publisher.isEmpty() ? u("有效") : u("有效 · ") + n.publisher) : u("无 / 无效"));
        if (!n.commandLine.isEmpty())
            in->addField(s, u("命令行"), n.commandLine, monoCopy);
        if (n.parentPid > 0)
            in->addField(s, u("父进程 PID"), QString::number(n.parentPid), Inspector::Mono);
    } else {
        QVBoxLayout* s = in->addSection(u("实体"));
        in->addField(s, u("目标"), n.detail.isEmpty() ? n.label : n.detail, monoCopy);
    }

    // The behaviours that touch this node, in time order (the graph's own edges).
    QList<int> touching;
    for (int i = 0; i < m_graph.edges.size(); ++i)
        if (m_graph.edges[i].fromId == n.id || m_graph.edges[i].toId == n.id)
            touching << i;
    std::sort(touching.begin(), touching.end(), [this](int a, int b) {
        return m_graph.edges[a].timestampUtc < m_graph.edges[b].timestampUtc;
    });
    QVBoxLayout* act = in->addSection(u("相关行为 · %1").arg(touching.size()));
    if (n.firstSeenUtc.isValid())
        in->addField(act, u("活动时间"), span(n.firstSeenUtc, n.lastSeenUtc));
    const auto labelOf = [this](const QString& id) -> QString {
        const auto it = m_graph.nodes.cend();
        for (auto i = m_graph.nodes.cbegin(); i != it; ++i)
            if (i->id == id)
                return nodeText(*i);
        return id;
    };
    constexpr int kMaxEdges = 12;
    for (int k = 0; k < touching.size() && k < kMaxEdges; ++k) {
        const bulwark::AttackGraphEdge& e = m_graph.edges[touching[k]];
        const bool out = e.fromId == n.id;
        QString line = out ? u("%1 → %2").arg(e.label, labelOf(e.toId)) : u("%1 ← %2").arg(e.label, labelOf(e.fromId));
        const QString disp = dispositionText(e);
        if (!e.inferred && !disp.isEmpty() && disp != u("放行"))
            line += u(" · ") + disp;
        in->addText(act, line, reallyBlocked(e) ? "title" : "secondary");
    }
    if (touching.size() > kMaxEdges)
        in->addText(act, u("… 另有 %1 条,点击连线逐条查看").arg(touching.size() - kMaxEdges), "muted");

    if (n.kind == bulwark::AttackNodeKind::Process && n.pid > 0) {
        const int pid = n.pid;
        in->addAction(QStringLiteral("activity"), u("在事件时间线中查看"), "ghost", [pid] {
            nav::go(QString::fromLatin1(nav::Timeline),
                    {{QStringLiteral("pid"), pid}, {QStringLiteral("range"), QStringLiteral("24h")}});
        });
    }
    in->setUpdatesEnabled(true);
}

void AttackGraphWindow::showEdgeDetail(int index)
{
    if (index < 0 || index >= m_graph.edges.size()) {
        showOverview();
        return;
    }
    const bulwark::AttackGraphEdge& e = m_graph.edges[index];
    Inspector* in = m_inspector;
    in->setUpdatesEnabled(false);
    in->clear();
    const QString disp = dispositionText(e);
    in->setHeader(evtfmt::typeGlyph(e.type), edgeColor(e) == theme::textDisabled() ? theme::textMuted() : edgeColor(e),
                  e.label.isEmpty() ? evtfmt::typeLabel(e.type) : e.label, evtfmt::typeLabel(e.type));
    QList<QPair<QString, QColor>> chips;
    if (!disp.isEmpty())
        chips << qMakePair(disp, reallyBlocked(e) ? theme::danger()
                                                   : (e.action == bulwark::VerdictAction::Allow ? theme::success()
                                                                                                : theme::warning()));
    if (e.inferred)
        chips << qMakePair(u("推导关系"), theme::textMuted());
    if (e.riskScore > 0)
        chips << qMakePair(u("风险 %1").arg(e.riskScore), evtfmt::riskColor(e.riskScore));
    for (const QString& t : e.techniques)
        chips << qMakePair(t, theme::info());
    if (!chips.isEmpty())
        in->addChips(nullptr, chips);

    const auto nodeDetail = [this](const QString& id) -> QString {
        for (const bulwark::AttackGraphNode& n : m_graph.nodes)
            if (n.id == id)
                return n.detail.isEmpty() ? (n.path.isEmpty() ? n.label : evtfmt::nativePath(n.path)) : n.detail;
        return id;
    };
    const Inspector::FieldFlags monoCopy = Inspector::Mono | Inspector::Copy;
    QVBoxLayout* s = in->addSection(u("行为"));
    in->addField(s, u("发起方"), nodeDetail(e.fromId), monoCopy);
    in->addField(s, u("作用对象"), nodeDetail(e.toId), monoCopy);
    if (e.timestampUtc.isValid())
        in->addField(s, u("时间"), fmt::absoluteTime(e.timestampUtc));
    if (!e.detail.isEmpty())
        in->addField(s, u("说明"), e.detail, Inspector::Mono);
    if (e.inferred)
        in->setNote(u("这条关系由进程父子链 / 启动来源推导得出,不是一次被记录下来的行为事件。"));
    in->setUpdatesEnabled(true);
}
