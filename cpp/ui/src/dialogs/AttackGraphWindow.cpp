#include "dialogs/AttackGraphWindow.h"
#include "dialogs/EventFormat.h"
#include "ipc/IpcClient.h"
#include "widgets/AppIcon.h"
#include "widgets/Cards.h"
#include "widgets/Ui.h"
#include "Theme.h"

#include <QApplication>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFileInfo>
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QPushButton>
#include <QScrollArea>
#include <QScrollBar>
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
constexpr qreal kMargin = 30;

QColor kindColor(bulwark::AttackNodeKind k)
{
    using K = bulwark::AttackNodeKind;
    switch (k) {
    case K::Process:       return theme::accent();
    case K::File:          return theme::accentAlt();
    case K::Registry:      return QColor("#8B5CF6");
    case K::Network:       return QColor("#0EA5E9");
    case K::Domain:        return QColor("#0891B2");
    case K::Module:        return QColor("#D97706");
    case K::Service:       return QColor("#7C3AED");
    case K::ScheduledTask: return QColor("#DB2777");
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
    case K::Module:        return QStringLiteral("link");
    case K::Service:       return QStringLiteral("power");
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

bool reallyBlocked(const bulwark::AttackGraphEdge& e)
{
    return e.enforcement == bulwark::EnforcementOutcome::KernelBlocked
        || e.enforcement == bulwark::EnforcementOutcome::Terminated;
}

QWidget* detailRow(const QString& caption, const QString& value, bool mono = false)
{
    auto* w = new QWidget;
    auto* h = new QHBoxLayout(w);
    h->setContentsMargins(0, 2, 0, 2);
    h->setSpacing(12);
    auto* cap = ui::label(caption, "caption");
    cap->setFixedWidth(84);
    h->addWidget(cap, 0, Qt::AlignTop);
    auto* val = ui::label(value.isEmpty() ? u("—") : value, mono ? "mono" : "secondary");
    val->setWordWrap(true);
    val->setTextInteractionFlags(Qt::TextSelectableByMouse);
    h->addWidget(val, 1);
    return w;
}

} // namespace

// ============================== 画布 ==============================

AttackGraphCanvas::AttackGraphCanvas(QWidget* parent) : QWidget(parent)
{
    setMouseTracking(true);
    setAttribute(Qt::WA_OpaquePaintEvent, false);
    setCursor(Qt::ArrowCursor);
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

void AttackGraphCanvas::setScale(qreal s)
{
    const qreal clamped = std::clamp(s, 0.45, 2.0);
    if (qFuzzyCompare(clamped, m_scale))
        return;
    m_scale = clamped;
    setFixedSize(QSize(int(m_logicalSize.width() * m_scale), int(m_logicalSize.height() * m_scale)));
    update();
}

// 分层布局:层号(depth)由服务端按父子链算好,这里只在层内排位。
// 层内顺序:先进程(骨架),再实体节点,同类按标签排 —— 保证同一张图两次打开长得一样。
void AttackGraphCanvas::relayout()
{
    m_boxes.assign(m_graph.nodes.size(), QRectF());
    if (m_graph.nodes.isEmpty()) {
        m_logicalSize = QSizeF(200, 120);
        setFixedSize(QSize(200, 120));
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

    m_logicalSize = QSizeF(widest + kMargin * 2,
                           kMargin * 2 + (maxDepth + 1) * kNodeH + maxDepth * kGapY);
    setFixedSize(QSize(int(m_logicalSize.width() * m_scale), int(m_logicalSize.height() * m_scale)));
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
        const QPointF a = QPointF(m_boxes[fromIt.value()].center().x(), m_boxes[fromIt.value()].bottom());
        const QPointF b = QPointF(m_boxes[toIt.value()].center().x(), m_boxes[toIt.value()].top());
        const QPointF mid((a.x() + b.x()) / 2, (a.y() + b.y()) / 2);
        if (QRectF(mid.x() - 70, mid.y() - 12, 140, 24).contains(logical))
            return i;
    }
    return -1;
}

void AttackGraphCanvas::paintEvent(QPaintEvent*)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);
    p.fillRect(rect(), theme::bg());
    p.scale(m_scale, m_scale);

    if (m_graph.nodes.isEmpty()) {
        p.setPen(theme::textMuted());
        p.drawText(QRectF(0, 0, m_logicalSize.width(), m_logicalSize.height()), Qt::AlignCenter,
                   u("没有可展示的关联关系"));
        return;
    }

    QFont edgeFont = p.font();
    edgeFont.setPointSizeF(8.0);

    // ---- 先画边:虚线 = 推导出来的关系(父子/服务启动),实线 = 真实观测到的行为事件。----
    for (int i = 0; i < m_graph.edges.size(); ++i) {
        const bulwark::AttackGraphEdge& e = m_graph.edges[i];
        const auto fromIt = m_indexById.constFind(e.fromId);
        const auto toIt = m_indexById.constFind(e.toId);
        if (fromIt == m_indexById.constEnd() || toIt == m_indexById.constEnd())
            continue;
        const QRectF& fb = m_boxes[fromIt.value()];
        const QRectF& tb = m_boxes[toIt.value()];
        QPointF a(fb.center().x(), fb.bottom());
        QPointF b(tb.center().x(), tb.top());
        if (tb.top() < fb.top()) { // 反向(极少数环形关系):从上边出、到下边进
            a = QPointF(fb.center().x(), fb.top());
            b = QPointF(tb.center().x(), tb.bottom());
        }

        QColor c = theme::borderStrong();
        if (e.inferred)
            c = theme::border();
        else if (reallyBlocked(e))
            c = theme::danger();
        else if (e.riskScore >= 50 || e.hasThreatIndicator)
            c = theme::warning();
        else
            c = theme::textMuted();

        QPen pen(c, i == m_selectedEdge ? 2.6 : 1.6);
        if (e.inferred)
            pen.setStyle(Qt::DashLine);
        p.setPen(pen);

        QPainterPath path(a);
        const qreal dy = (b.y() - a.y()) * 0.45;
        path.cubicTo(a + QPointF(0, dy), b - QPointF(0, dy), b);
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
            const QPointF mid((a.x() + b.x()) / 2, (a.y() + b.y()) / 2);
            const QRectF tr = QFontMetricsF(edgeFont).boundingRect(text).adjusted(-7, -3, 7, 3);
            QRectF box = tr.translated(mid - QPointF(tr.width() / 2 + tr.left(), tr.height() / 2 + tr.top()));
            p.setPen(Qt::NoPen);
            p.setBrush(theme::blend(c, theme::bg(), 0.12));
            p.drawRoundedRect(box, 6, 6);
            p.setBrush(Qt::NoBrush);
            p.setPen(c.darker(115));
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
        p.setPen(QPen(highlight ? accent : theme::border(), highlight ? 2.2 : 1.2));
        p.setBrush(n.blocked ? theme::blend(theme::danger(), theme::surface(), 0.08)
                             : theme::surface());
        p.drawRoundedRect(box, 10, 10);

        // 左侧色条标明实体类别
        p.setPen(Qt::NoPen);
        p.setBrush(accent);
        p.drawRoundedRect(QRectF(box.left() + 1, box.top() + 8, 4, box.height() - 16), 2, 2);
        p.setBrush(Qt::NoBrush);

        const QRectF textRect = box.adjusted(14, 7, -10, -7);
        p.setFont(titleFont);
        p.setPen(theme::textPrimary());
        const QString title = QFontMetricsF(titleFont).elidedText(
            n.label.isEmpty() ? kindLabel(n.kind) : n.label, Qt::ElideMiddle, textRect.width() - 4);
        p.drawText(QRectF(textRect.left(), textRect.top(), textRect.width(), 17),
                   Qt::AlignLeft | Qt::AlignVCenter, title);

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
        const QString subText = QFontMetricsF(subFont).elidedText(
            sub.join(QStringLiteral("  ·  ")), Qt::ElideMiddle, textRect.width() - 4);
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
                       QFontMetricsF(subFont).elidedText(tags.join(QStringLiteral("  ·  ")),
                                                         Qt::ElideRight, textRect.width() - 4));
        }
    }
}

void AttackGraphCanvas::mousePressEvent(QMouseEvent* e)
{
    const QPointF logical(e->position().x() / m_scale, e->position().y() / m_scale);
    const int n = nodeAt(logical);
    if (n >= 0) {
        m_selectedNode = n;
        m_selectedEdge = -1;
        update();
        emit nodeSelected(n);
        return;
    }
    const int ed = edgeAt(logical);
    if (ed >= 0) {
        m_selectedEdge = ed;
        m_selectedNode = -1;
        update();
        emit edgeSelected(ed);
        return;
    }
    m_selectedNode = -1;
    m_selectedEdge = -1;
    update();
    emit nodeSelected(-1);
}

void AttackGraphCanvas::mouseDoubleClickEvent(QMouseEvent* e) { mousePressEvent(e); }

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

AttackGraphWindow::AttackGraphWindow(IpcClient* ipc, const QUuid& seedEventId, int rootPid,
                                     const QString& title, QWidget* parent)
    : QDialog(parent), m_ipc(ipc), m_seedEventId(seedEventId), m_rootPid(rootPid)
{
    setWindowTitle(u("攻击关系图"));
    resize(1040, 760);
    setSizeGripEnabled(true);

    auto* outer = new QVBoxLayout(this);
    outer->setContentsMargins(0, 0, 0, 0);
    outer->setSpacing(0);

    // ---- 头部 ----
    auto* head = new QFrame;
    head->setObjectName(QStringLiteral("Topbar"));
    auto* hh = new QHBoxLayout(head);
    hh->setContentsMargins(20, 14, 20, 14);
    hh->setSpacing(14);
    hh->addWidget(ui::iconBadge("link", theme::accent(), 42, 22));
    auto* hcol = new QVBoxLayout;
    hcol->setSpacing(2);
    hcol->addWidget(ui::coloredText(title.isEmpty() ? u("攻击关系图") : title, 15, 700,
                                    theme::textPrimary()));
    m_summary = ui::label(u("正在关联事件…"), "secondary");
    hcol->addWidget(m_summary);
    hh->addLayout(hcol);
    hh->addStretch();

    auto* zoomOut = new QPushButton(QStringLiteral("−"));
    auto* zoomIn = new QPushButton(QStringLiteral("+"));
    auto* zoomFit = new QPushButton(u("适应"));
    for (QPushButton* b : { zoomOut, zoomIn, zoomFit }) {
        b->setProperty("variant", "ghost");
        b->setProperty("size", "sm");
        b->setCursor(Qt::PointingHandCursor);
        b->setFixedHeight(28);
        hh->addWidget(b);
    }
    zoomIn->setFixedWidth(34);
    zoomOut->setFixedWidth(34);
    outer->addWidget(head);

    // ---- 画布 ----
    m_scroll = new QScrollArea;
    m_scroll->setWidgetResizable(false);
    m_scroll->setFrameShape(QFrame::NoFrame);
    m_scroll->setAlignment(Qt::AlignCenter);
    m_canvas = new AttackGraphCanvas;
    m_scroll->setWidget(m_canvas);
    outer->addWidget(m_scroll, 1);

    connect(zoomIn, &QPushButton::clicked, this,
            [this] { m_canvas->setScale(m_canvas->scaleFactor() * 1.15); });
    connect(zoomOut, &QPushButton::clicked, this,
            [this] { m_canvas->setScale(m_canvas->scaleFactor() / 1.15); });
    connect(zoomFit, &QPushButton::clicked, this, [this] {
        const int w = m_canvas->width() > 0 ? m_canvas->width() : 1;
        const qreal want = qreal(m_scroll->viewport()->width() - 24) / (w / m_canvas->scaleFactor());
        m_canvas->setScale(want);
    });

    // ---- 详情面板 ----
    m_detailHost = ui::card();
    m_detailHost->setMinimumHeight(150);
    m_detailLayout = new QVBoxLayout(m_detailHost);
    m_detailLayout->setContentsMargins(18, 14, 18, 14);
    m_detailLayout->setSpacing(6);
    m_status = ui::label(u("点击节点或连线查看详情。按住 Ctrl + 滚轮可缩放。"), "muted");
    m_status->setWordWrap(true);
    m_detailLayout->addWidget(m_status);
    auto* detailWrap = new QWidget;
    auto* dwl = new QVBoxLayout(detailWrap);
    dwl->setContentsMargins(20, 12, 20, 12);
    dwl->addWidget(m_detailHost);
    outer->addWidget(detailWrap);

    auto* bar = new QHBoxLayout;
    bar->setContentsMargins(20, 0, 20, 16);
    bar->addStretch();
    auto* close = new QPushButton(u("关闭"));
    close->setProperty("variant", "primary");
    close->setCursor(Qt::PointingHandCursor);
    connect(close, &QPushButton::clicked, this, &QDialog::accept);
    bar->addWidget(close);
    outer->addLayout(bar);

    connect(m_canvas, &AttackGraphCanvas::nodeSelected, this, &AttackGraphWindow::showNodeDetail);
    connect(m_canvas, &AttackGraphCanvas::edgeSelected, this, &AttackGraphWindow::showEdgeDetail);

    // ---- 拉取 ----
    if (!m_ipc) {
        m_summary->setText(u("未连接服务,无法构建攻击图。"));
        return;
    }
    connect(m_ipc, &IpcClient::attackGraphReceived, this,
            [this](const bulwark::ipc::AttackGraphResponsePayload& p) {
                if (!m_requestId.isNull() && p.requestId != m_requestId)
                    return; // 别的窗口发起的响应,与本窗口无关
                if (!p.success && p.graph.isEmpty()) {
                    m_summary->setText(p.message.isEmpty() ? u("未能构建攻击图") : p.message);
                    return;
                }
                showGraph(p.graph);
            });
    if (!m_ipc->isConnected()) {
        m_summary->setText(u("未连接服务,无法构建攻击图。"));
        return;
    }
    m_requestId = m_ipc->requestAttackGraph(m_seedEventId, m_rootPid, 3600);
}

void AttackGraphWindow::showGraph(const bulwark::AttackGraph& g)
{
    m_graph = g;
    m_canvas->setGraph(g);

    QStringList parts;
    if (!g.summary.isEmpty()) parts << g.summary;
    if (g.firstUtc.isValid() && g.lastUtc.isValid())
        parts << QStringLiteral("%1 → %2")
                     .arg(g.firstUtc.toLocalTime().toString(QStringLiteral("MM-dd HH:mm:ss")),
                          g.lastUtc.toLocalTime().toString(QStringLiteral("HH:mm:ss")));
    if (!g.techniques.isEmpty())
        parts << g.techniques.mid(0, 6).join(QStringLiteral(" "));
    m_summary->setText(parts.join(u("  ·  ")));

    // 首屏自动适应宽度,免得一打开就要手动缩。
    const qreal logicalW = m_canvas->width() / m_canvas->scaleFactor();
    if (logicalW > 1) {
        const qreal want = qreal(m_scroll->viewport()->width() - 24) / logicalW;
        if (want < 1.0)
            m_canvas->setScale(want);
    }
}

void AttackGraphWindow::showNodeDetail(int index)
{
    // 清空旧内容(保留标题行的位置)。
    while (QLayoutItem* it = m_detailLayout->takeAt(0)) {
        if (QWidget* w = it->widget()) w->deleteLater();
        delete it;
    }
    if (index < 0 || index >= m_graph.nodes.size()) {
        m_status = ui::label(u("点击节点或连线查看详情。按住 Ctrl + 滚轮可缩放。"), "muted");
        m_detailLayout->addWidget(m_status);
        return;
    }
    const bulwark::AttackGraphNode& n = m_graph.nodes[index];

    auto* headRow = new QWidget;
    auto* hl = new QHBoxLayout(headRow);
    hl->setContentsMargins(0, 0, 0, 0);
    hl->setSpacing(8);
    hl->addWidget(ui::label(n.label.isEmpty() ? kindLabel(n.kind) : n.label, "h2"));
    hl->addWidget(ui::pill(kindLabel(n.kind), kindColor(n.kind)));
    if (n.riskScore > 0)
        hl->addWidget(ui::pill(u("风险 %1").arg(n.riskScore), evtfmt::riskColor(n.riskScore)));
    if (n.blocked)
        hl->addWidget(ui::pill(u("已拦截"), theme::danger()));
    hl->addStretch();
    m_detailLayout->addWidget(headRow);
    m_detailLayout->addWidget(ui::hDivider());

    if (n.kind == bulwark::AttackNodeKind::Process) {
        m_detailLayout->addWidget(detailRow(u("PID"),
                                           n.pid > 0 ? QString::number(n.pid) : QString()));
        m_detailLayout->addWidget(detailRow(u("映像路径"), n.path, true));
        m_detailLayout->addWidget(detailRow(
            u("启动来源"),
            n.originLabel.isEmpty() ? u("未能判定(父进程为普通进程)") : n.originLabel));
        m_detailLayout->addWidget(detailRow(
            u("数字签名"),
            n.signedActor ? (n.publisher.isEmpty() ? u("有效") : u("有效 · ") + n.publisher)
                          : u("无 / 无效")));
        if (!n.commandLine.isEmpty())
            m_detailLayout->addWidget(detailRow(u("命令行"), n.commandLine, true));
    } else {
        m_detailLayout->addWidget(detailRow(u("目标"), n.detail.isEmpty() ? n.label : n.detail, true));
    }
    if (n.firstSeenUtc.isValid())
        m_detailLayout->addWidget(detailRow(
            u("活动时间"),
            QStringLiteral("%1 → %2")
                .arg(n.firstSeenUtc.toLocalTime().toString(QStringLiteral("MM-dd HH:mm:ss")),
                     n.lastSeenUtc.isValid()
                         ? n.lastSeenUtc.toLocalTime().toString(QStringLiteral("HH:mm:ss"))
                         : QStringLiteral("—"))));
    m_detailLayout->addStretch();
}

void AttackGraphWindow::showEdgeDetail(int index)
{
    while (QLayoutItem* it = m_detailLayout->takeAt(0)) {
        if (QWidget* w = it->widget()) w->deleteLater();
        delete it;
    }
    if (index < 0 || index >= m_graph.edges.size())
        return;
    const bulwark::AttackGraphEdge& e = m_graph.edges[index];

    auto* headRow = new QWidget;
    auto* hl = new QHBoxLayout(headRow);
    hl->setContentsMargins(0, 0, 0, 0);
    hl->setSpacing(8);
    hl->addWidget(ui::label(evtfmt::typeLabel(e.type), "h2"));
    const QString disp = dispositionText(e);
    if (!disp.isEmpty())
        hl->addWidget(ui::pill(disp, reallyBlocked(e) ? theme::danger()
                                                      : (e.action == bulwark::VerdictAction::Allow
                                                             ? theme::success()
                                                             : theme::warning())));
    if (e.inferred)
        hl->addWidget(ui::pill(u("推导关系"), theme::textMuted()));
    hl->addStretch();
    m_detailLayout->addWidget(headRow);
    m_detailLayout->addWidget(ui::hDivider());

    const auto nodeLabel = [this](const QString& id) -> QString {
        for (const bulwark::AttackGraphNode& n : m_graph.nodes)
            if (n.id == id)
                return n.detail.isEmpty() ? n.label : n.detail;
        return id;
    };
    m_detailLayout->addWidget(detailRow(u("发起方"), nodeLabel(e.fromId), true));
    m_detailLayout->addWidget(detailRow(u("作用对象"), nodeLabel(e.toId), true));
    if (e.timestampUtc.isValid())
        m_detailLayout->addWidget(detailRow(
            u("时间"), e.timestampUtc.toLocalTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"))));
    if (!e.detail.isEmpty())
        m_detailLayout->addWidget(detailRow(u("说明"), e.detail, true));
    if (e.riskScore > 0)
        m_detailLayout->addWidget(detailRow(u("风险分"), QString::number(e.riskScore)));
    if (!e.techniques.isEmpty())
        m_detailLayout->addWidget(detailRow(u("ATT&CK"), e.techniques.join(QStringLiteral("  "))));
    if (e.inferred)
        m_detailLayout->addWidget(detailRow(
            u("备注"), u("这条关系由进程父子链 / 启动来源推导得出,不是一次被记录下来的行为事件。")));
    m_detailLayout->addStretch();
}
