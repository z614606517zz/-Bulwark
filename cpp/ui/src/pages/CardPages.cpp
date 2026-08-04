#include "pages/CardPages.h"
#include "ipc/IpcClient.h"
#include "dialogs/AiCleanupDialog.h"
#include "widgets/AppIcon.h"
#include "widgets/Cards.h"
#include "widgets/TableKit.h"
#include "widgets/ToggleSwitch.h"
#include "widgets/Ui.h"
#include "Theme.h"

#include "bulwark/models/RuntimeSettings.h"
#include "bulwark/models/VtScanRecord.h"

#include <QComboBox>
#include <QDialog>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QFrame>
#include <QGridLayout>
#include <QHash>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QScrollArea>
#include <QSpinBox>
#include <QTableWidget>
#include <QUuid>
#include <QVBoxLayout>
#include <QWidget>

#include <QFontMetrics>
#include <QPainter>
#include <QPainterPath>
#include <QPaintEvent>
#include <QResizeEvent>
#include <QVector>
#include <QWheelEvent>
#include <QTimer>
#include <functional>
#include <memory>

namespace {

QString u(const char* s) { return QString::fromUtf8(s); }

QVBoxLayout* section(QVBoxLayout* parent, const QString& title)
{
    auto* c = ui::card();
    auto* v = new QVBoxLayout(c);
    v->setContentsMargins(20, 18, 20, 18);
    v->setSpacing(8);
    v->addWidget(ui::label(title, "h2"));
    v->addWidget(ui::hDivider());
    v->addSpacing(2);
    parent->addWidget(c);
    return v;
}

// A settings row: title + description on the left, a toggle on the right.
// Returns the toggle so the caller can bind it to a RuntimeSettings field.
ToggleSwitch* settingRow(QVBoxLayout* box, const QString& title, const QString& desc, bool on)
{
    auto* w = new QWidget;
    auto* h = new QHBoxLayout(w);
    h->setContentsMargins(0, 6, 0, 6);
    auto* col = new QVBoxLayout;
    col->setSpacing(1);
    col->addWidget(ui::label(title, "title"));
    if (!desc.isEmpty())
        col->addWidget(ui::label(desc, "muted"));
    h->addLayout(col);
    h->addStretch();
    auto* tg = new ToggleSwitch(on);
    h->addWidget(tg);
    box->addWidget(w);
    return tg;
}

QLineEdit* fieldRow(QVBoxLayout* box, const QString& labelText, bool password)
{
    auto* w = new QWidget;
    auto* h = new QHBoxLayout(w);
    h->setContentsMargins(0, 6, 0, 6);
    h->setSpacing(12);
    auto* l = ui::label(labelText, "title");
    l->setFixedWidth(120);
    h->addWidget(l);
    auto* e = new QLineEdit;
    if (password)
        e->setEchoMode(QLineEdit::Password);
    h->addWidget(e, 1);
    box->addWidget(w);
    return e;
}

QString outcomeText(bulwark::VtScanOutcome o, QColor& c)
{
    using O = bulwark::VtScanOutcome;
    switch (o) {
    case O::Malicious:  c = theme::danger();  return u("恶意");
    case O::Suspicious: c = theme::warning(); return u("可疑");
    case O::Clean:      c = theme::success(); return u("干净");
    case O::Error:      c = theme::textMuted(); return u("失败");
    case O::Unknown:    c = theme::textMuted(); return u("未收录");
    default:            c = theme::info();    return u("进行中");
    }
}

// ── 关系图可视化(仿攻击链图:圆角节点卡片 + 三次贝塞尔连线,左→右分列)────────────
struct GraphNode {
    int column = 0;
    QString title;    // 主标题(加粗)
    QString subtitle; // 小字副标题(灰)
    QColor accent;    // 节点主色(左侧色条 + 圆点 + 边框着色)
    QRectF rect;      // 布局时计算
};
struct GraphEdge { int from = 0; int to = 0; QColor color; };

// 自绘节点图控件(无 Q_OBJECT,仅重写绘制/布局,无需 MOC)。放在 QScrollArea 里可滚动。
class BehaviorGraphView : public QWidget {
public:
    explicit BehaviorGraphView(QWidget* parent = nullptr) : QWidget(parent) { setMinimumHeight(240); }
    void setGraph(const QVector<GraphNode>& nodes, const QVector<GraphEdge>& edges) {
        nodes_ = nodes;
        edges_ = edges;
        relayout();
        update();
    }
    qreal zoom() const { return zoom_; }
    void setZoom(qreal z) {
        z = qBound<qreal>(0.4, z, 3.0);
        if (qFuzzyCompare(z, zoom_)) return;
        zoom_ = z;
        relayout();
        update();
        if (onZoom_) onZoom_(zoom_);
    }
    void fitTo(const QSize& viewport) { // 计算缩放使整图适应视口
        const QSizeF c = baseCanvas();
        if (c.width() <= 1 || c.height() <= 1 || viewport.width() < 10) return;
        setZoom(qMin(viewport.width() / c.width(), viewport.height() / c.height()));
    }
    void setZoomCallback(std::function<void(qreal)> cb) { onZoom_ = std::move(cb); }
protected:
    void resizeEvent(QResizeEvent*) override { relayout(); update(); }
    void wheelEvent(QWheelEvent* e) override {
        // 直接滚轮缩放(上滚放大 / 下滚缩小);放大后超出视口的部分用滚动条查看。
        setZoom(zoom_ * (e->angleDelta().y() > 0 ? 1.12 : 1.0 / 1.12));
        e->accept();
    }
    void paintEvent(QPaintEvent*) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        p.fillRect(rect(), theme::surface());
        p.scale(zoom_, zoom_); // 缩放:节点/连线均按基准坐标绘制,画笔整体缩放
        // 连线(在节点之下):右中点 -> 左中点的三次贝塞尔。
        for (const GraphEdge& e : edges_) {
            if (e.from < 0 || e.from >= nodes_.size() || e.to < 0 || e.to >= nodes_.size()) continue;
            const QRectF a = nodes_[e.from].rect, b = nodes_[e.to].rect;
            const QPointF p1(a.right(), a.center().y()), p2(b.left(), b.center().y());
            const qreal dx = qMax<qreal>(30.0, (p2.x() - p1.x()) * 0.5);
            QPainterPath path(p1);
            path.cubicTo(p1.x() + dx, p1.y(), p2.x() - dx, p2.y(), p2.x(), p2.y());
            QColor c = e.color; c.setAlpha(150);
            QPen pen(c); pen.setWidthF(1.6); pen.setCapStyle(Qt::RoundCap);
            p.setPen(pen); p.setBrush(Qt::NoBrush); p.drawPath(path);
        }
        // 节点卡片。
        QFont titleF = font(); titleF.setBold(true); titleF.setPointSizeF(9.0);
        QFont subF = font(); subF.setPointSizeF(7.6);
        const QFontMetrics fmT(titleF), fmS(subF);
        for (const GraphNode& n : nodes_) {
            QPainterPath card; card.addRoundedRect(n.rect, 9, 9);
            p.fillPath(card, QColor(255, 255, 255));
            QColor fill = n.accent; fill.setAlpha(20);
            p.fillPath(card, fill);
            QColor bc = n.accent; bc.setAlpha(115);
            QPen border(bc); border.setWidthF(1.2);
            p.setPen(border); p.setBrush(Qt::NoBrush); p.drawPath(card);
            QPainterPath bar; bar.addRoundedRect(QRectF(n.rect.left(), n.rect.top() + 6, 3.5, n.rect.height() - 12), 2, 2);
            p.fillPath(bar, n.accent);
            p.setBrush(n.accent); p.setPen(Qt::NoPen);
            p.drawEllipse(QPointF(n.rect.left() + 18, n.rect.center().y()), 3.6, 3.6);
            const qreal tx = n.rect.left() + 30, tw = n.rect.width() - 40;
            p.setFont(titleF); p.setPen(theme::textPrimary());
            const qreal ty = n.subtitle.isEmpty() ? n.rect.top() + 15 : n.rect.top() + 7;
            p.drawText(QRectF(tx, ty, tw, 16), Qt::AlignLeft | Qt::AlignVCenter,
                       fmT.elidedText(n.title, Qt::ElideMiddle, int(tw)));
            if (!n.subtitle.isEmpty()) {
                p.setFont(subF); p.setPen(theme::textMuted());
                p.drawText(QRectF(tx, n.rect.top() + 24, tw, 14), Qt::AlignLeft | Qt::AlignVCenter,
                           fmS.elidedText(n.subtitle, Qt::ElideRight, int(tw)));
            }
        }
    }
private:
    static constexpr qreal kNodeW = 178, kNodeH = 46, kColGap = 66, kRowGap = 15, kMarginX = 20, kMarginY = 20;
    QSizeF baseCanvas() const { // 基准(未缩放)画布尺寸
        if (nodes_.isEmpty()) return QSizeF(200, 200);
        int maxCol = 0;
        for (const GraphNode& n : nodes_) maxCol = qMax(maxCol, n.column);
        QVector<int> perCol(maxCol + 1, 0);
        for (const GraphNode& n : nodes_) perCol[n.column]++;
        int maxRows = 1;
        for (int c : perCol) maxRows = qMax(maxRows, c);
        return QSizeF(kMarginX * 2 + (maxCol + 1) * kNodeW + maxCol * kColGap,
                      kMarginY * 2 + maxRows * kNodeH + (maxRows - 1) * kRowGap);
    }
    void relayout() {
        if (nodes_.isEmpty()) { setMinimumSize(200, 200); return; }
        const QSizeF canvas = baseCanvas();
        setMinimumSize(int(canvas.width() * zoom_), int(canvas.height() * zoom_)); // 缩放后的实际占位
        int maxCol = 0;
        for (const GraphNode& n : nodes_) maxCol = qMax(maxCol, n.column);
        QVector<int> perCol(maxCol + 1, 0);
        for (const GraphNode& n : nodes_) perCol[n.column]++;
        // 居中所用逻辑高度:视口高度换算回基准坐标(缩放在 paintEvent 里统一施加)。
        const qreal logicalH = qMax<qreal>(canvas.height(), height() / qMax(zoom_, 0.01));
        QVector<int> placed(maxCol + 1, 0);
        for (GraphNode& n : nodes_) {
            const int cnt = perCol[n.column];
            const qreal colH = cnt * kNodeH + (cnt - 1) * kRowGap;
            const qreal startY = (logicalH - colH) / 2.0;
            const int i = placed[n.column]++;
            n.rect = QRectF(kMarginX + n.column * (kNodeW + kColGap), startY + i * (kNodeH + kRowGap), kNodeW, kNodeH);
        }
    }
    QVector<GraphNode> nodes_;
    QVector<GraphEdge> edges_;
    qreal zoom_ = 1.0;
    std::function<void(qreal)> onZoom_;
};

inline QColor cPurple() { return QColor(0x7C, 0x3A, 0xED); }
inline QColor cTeal()   { return QColor(0x0D, 0x94, 0x88); }

// 缩短注册表键用于节点标题(取末两段)。
QString shortRegKey(const QString& key) {
    QString k = key; k.replace(QLatin1Char('/'), QLatin1Char('\\'));
    const QStringList parts = k.split(QLatin1Char('\\'), Qt::SkipEmptyParts);
    if (parts.size() <= 2) return k;
    return QStringLiteral("…\\") + parts.mid(parts.size() - 2).join(QLatin1Char('\\'));
}

// 据扫描记录(+可选完整报告)构建行为关系图:文件 → VirusTotal 判定 → 行为/检出扇出 → 结论。
void buildBehaviorGraph(BehaviorGraphView* g, const bulwark::VtScanRecord& r,
                        const bulwark::ipc::VtDetailResponsePayload* d) {
    QVector<GraphNode> nodes;
    QVector<GraphEdge> edges;
    QColor vc;
    const QString verdict = outcomeText(r.outcome, vc);

    const QString fname = !r.fileName.isEmpty() ? r.fileName : QFileInfo(r.filePath).fileName();
    const int fileIdx = nodes.size();
    nodes.push_back({0, fname.isEmpty() ? u("未知文件") : fname, u("文件"), theme::info(), {}});

    const int hubIdx = nodes.size();
    const QString hubSub = r.totalEngines > 0 ? QStringLiteral("%1/%2 引擎判恶意").arg(r.malicious).arg(r.totalEngines)
                                              : (r.threatLabel.isEmpty() ? u("云端判定") : r.threatLabel);
    nodes.push_back({1, QStringLiteral("VirusTotal"), hubSub, theme::info(), {}});
    edges.push_back({fileIdx, hubIdx, theme::info()});

    QVector<int> fanIdx;
    auto addFan = [&](const QString& t, const QString& s, const QColor& c) {
        const int i = nodes.size();
        nodes.push_back({2, t.isEmpty() ? u("(未知)") : t, s, c, {}});
        edges.push_back({hubIdx, i, c});
        fanIdx.push_back(i);
    };
    if (d && d->success) {
        int n;
        n = 0; for (const QString& s : d->droppedFiles)     { if (n++ >= 5) break; addFan(s, u("释放文件"), theme::warning()); }
        n = 0; for (const QString& s : d->contactedIps)     { if (n++ >= 4) break; addFan(s, u("外联 IP"), cPurple()); }
        n = 0; for (const QString& s : d->contactedDomains) { if (n++ >= 4) break; addFan(s, u("外联域名"), cPurple()); }
        n = 0; for (const QString& s : d->registryKeys)     { if (n++ >= 3) break; addFan(shortRegKey(s), u("写注册表"), cTeal()); }
        n = 0;
        for (const QString& s : d->maliciousDetections) {
            if (n++ >= 6) break;
            const int colon = s.indexOf(QLatin1Char(':'));
            const QString eng = colon > 0 ? s.left(colon) : s;
            const QString rez = colon > 0 ? s.mid(colon + 1).trimmed() : QString();
            addFan(eng, rez.isEmpty() ? u("判为恶意") : rez, theme::danger());
        }
    }

    const int conclCol = fanIdx.isEmpty() ? 2 : 3;
    const int conclIdx = nodes.size();
    const QString conclSub = !r.threatLabel.isEmpty() ? r.threatLabel
                            : (r.uploaded ? u("已上传云端扫描") : u("云信誉判定"));
    nodes.push_back({conclCol, u("结论:") + verdict, conclSub, vc, {}});
    if (fanIdx.isEmpty())
        edges.push_back({hubIdx, conclIdx, vc});
    else
        for (int i : fanIdx) edges.push_back({i, conclIdx, vc});

    g->setGraph(nodes, edges);
}

// 云信誉查询历史「双击查看完整信息」的详情弹窗(独立第二窗口):以「行为关系图」呈现——
// 文件 → VirusTotal 判定 → 释放/外联/注册表/检出引擎扇出 → 结论;打开时按需联网补全。
void showVtRecordDetail(QWidget* parent, const bulwark::VtScanRecord& r,
                        IpcClient* ipc, QHash<QString, bulwark::ipc::VtDetailResponsePayload>* cache,
                        int autoCloseMs = 0)
{
    auto* dlg = new QDialog(parent);
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->setModal(false); // 独立第二窗口,不阻塞主界面
    const QString title = !r.fileName.isEmpty() ? r.fileName : QFileInfo(r.filePath).fileName();
    dlg->setWindowTitle(u("云信誉详情 · ") + (title.isEmpty() ? u("未知文件") : title));
    dlg->setMinimumWidth(560);
    dlg->setStyleSheet(QStringLiteral("QDialog{background:%1;}").arg(theme::surface().name()));

    auto* shell = new QVBoxLayout(dlg);
    shell->setContentsMargins(22, 20, 22, 20);
    shell->setSpacing(14);

    // 顶部:图标 + 文件名 + 路径/哈希 + 联网状态 + 结论 pill
    auto* head = new QHBoxLayout;
    head->setSpacing(12);
    head->addWidget(ui::iconBadge("cloud", theme::accent(), 40, 20), 0, Qt::AlignVCenter);
    auto* hcol = new QVBoxLayout;
    hcol->setSpacing(2);
    hcol->addWidget(ui::coloredText(title.isEmpty() ? u("未知文件") : title, 14, 700, theme::textPrimary()));
    auto* subPath = ui::elided(r.filePath.isEmpty() ? r.sha256 : r.filePath, "mono");
    subPath->setProperty("role", "muted");
    hcol->addWidget(subPath);
    head->addLayout(hcol, 1);
    auto* statusLbl = ui::label(QString(), "muted");
    head->addWidget(statusLbl, 0, Qt::AlignVCenter);
    QColor oc;
    const QString ot = outcomeText(r.outcome, oc);
    head->addWidget(ui::pill(ot, oc), 0, Qt::AlignVCenter);
    shell->addLayout(head);
    shell->addWidget(ui::hDivider());

    // 行为关系图(仿攻击链图):文件 → VirusTotal 判定 → 释放/外联/注册表/检出扇出 → 结论。可滚动。
    auto* graph = new BehaviorGraphView;
    auto* scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setWidget(graph);
    shell->addWidget(scroll, 1);

    // 初始只用记录本身画(文件 → 判定 → 结论);打开后异步拉完整报告补全行为/检出。
    buildBehaviorGraph(graph, r, nullptr);

    // 最新的完整报告(缓存命中或异步补全后更新),供「AI 清理」按钮据此构建清理画像。
    auto detail = std::make_shared<bulwark::ipc::VtDetailResponsePayload>();

    const QString shaKey = r.sha256.toLower();
    if (cache && cache->contains(shaKey)) {
        *detail = cache->value(shaKey);
        buildBehaviorGraph(graph, r, detail.get()); // 缓存命中:直接补全,不再联网
    } else if (ipc && r.isTerminal() && r.sha256.size() == 64) {
        statusLbl->setText(u("正在联网获取完整报告…"));
        QObject::connect(ipc, &IpcClient::vtDetailReceived, dlg,
                         [cache, graph, statusLbl, r, shaKey, detail](const bulwark::ipc::VtDetailResponsePayload& d) {
            if (d.sha256.toLower() != shaKey) return;
            if (cache) (*cache)[shaKey] = d;
            *detail = d;
            statusLbl->setText(d.success ? QString()
                                         : (d.message.isEmpty() ? u("未获取到完整报告") : d.message));
            buildBehaviorGraph(graph, r, detail.get());
        });
        ipc->vtDetail(r.sha256);
    }

    // 底部:缩放控件(−/百分比/+/适应)+ 全屏 + 关闭。缩放亦支持 Ctrl+滚轮。
    auto* footer = new QHBoxLayout;
    footer->setSpacing(8);
    footer->addWidget(ui::label(u("滚轮缩放"), "muted"));
    auto* zoomLbl = new QPushButton(QStringLiteral("100%"));
    auto* fitBtn  = new QPushButton(u("适应"));
    zoomLbl->setProperty("variant", "ghost");
    zoomLbl->setCursor(Qt::PointingHandCursor);
    zoomLbl->setFixedWidth(58);
    zoomLbl->setToolTip(u("点击恢复 100%"));
    fitBtn->setProperty("variant", "ghost");
    fitBtn->setCursor(Qt::PointingHandCursor);
    footer->addWidget(zoomLbl);
    footer->addWidget(fitBtn);
    footer->addStretch();
    // AI 清理:仅对判为恶意/可疑且有本机路径的文件提供——把行为画像(释放文件 / 外联 /
    // 注册表)交给大模型生成 PowerShell 清理方案,用户复核后一键(提权)执行。
    if (ipc && r.isTerminal() && !r.filePath.isEmpty()
        && (r.outcome == bulwark::VtScanOutcome::Malicious
            || r.outcome == bulwark::VtScanOutcome::Suspicious)) {
        auto* aiCleanBtn = new QPushButton(u("🤖 AI 清理"));
        aiCleanBtn->setProperty("variant", "danger");
        aiCleanBtn->setCursor(Qt::PointingHandCursor);
        aiCleanBtn->setMinimumWidth(96);
        aiCleanBtn->setToolTip(u("把该文件的行为画像交给大模型,由 AI 生成清理方案并可一键执行"));
        footer->addWidget(aiCleanBtn);
        QObject::connect(aiCleanBtn, &QPushButton::clicked, dlg, [dlg, ipc, r, detail] {
            bulwark::ipc::RemediationReportPayload rep;
            rep.actorPath   = r.filePath;
            rep.reason      = !r.threatLabel.isEmpty() ? r.threatLabel : u("云信誉判定为恶意 / 可疑");
            rep.intelSource = QStringLiteral("VirusTotal");
            if (detail->success) {
                rep.intelDroppedFiles     = detail->droppedFiles;
                rep.intelRegistryKeys     = detail->registryKeys;
                rep.intelContactedIps     = detail->contactedIps;
                rep.intelContactedDomains = detail->contactedDomains;
            }
            (new AiCleanupDialog(r, rep, ipc, ipc->aiScanner(), dlg))->show();
        });
    }
    auto* fullBtn = new QPushButton(u("最大化"));
    fullBtn->setProperty("variant", "ghost");
    fullBtn->setCursor(Qt::PointingHandCursor);
    fullBtn->setMinimumWidth(84);
    footer->addWidget(fullBtn);
    auto* closeBtn = new QPushButton(u("关闭"));
    closeBtn->setProperty("variant", "primary");
    closeBtn->setCursor(Qt::PointingHandCursor);
    closeBtn->setMinimumWidth(84);
    footer->addWidget(closeBtn);
    shell->addLayout(footer);

    graph->setZoomCallback([zoomLbl](qreal z) {
        zoomLbl->setText(QString::number(int(z * 100 + 0.5)) + QStringLiteral("%"));
    });
    QObject::connect(zoomLbl, &QPushButton::clicked, dlg, [graph] { graph->setZoom(1.0); });
    QObject::connect(fitBtn,  &QPushButton::clicked, dlg, [graph, scroll] { graph->fitTo(scroll->viewport()->size()); });
    QObject::connect(fullBtn, &QPushButton::clicked, dlg, [dlg, fullBtn] {
        // 用「最大化到工作区」而非无边框全屏:后者(尤其带父窗口的对话框)会被 Windows 任务栏
        // 盖住底部按钮;最大化只占用工作区(不含任务栏),按钮始终可见,视图同样铺满。
        if (dlg->isMaximized() || dlg->isFullScreen()) {
            dlg->showNormal();
            fullBtn->setText(u("最大化"));
        } else {
            dlg->showMaximized();
            fullBtn->setText(u("还原"));
        }
    });
    QObject::connect(closeBtn, &QPushButton::clicked, dlg, &QDialog::accept);

    dlg->resize(940, 560);
    dlg->show();

    // 自动弹出场景(查毒命中后):autoCloseMs 后自动关闭;用户提前关掉则计时器随对话框销毁作废。
    if (autoCloseMs > 0) {
        statusLbl->setText(u("· %1 秒后自动关闭").arg((autoCloseMs + 500) / 1000));
        QTimer::singleShot(autoCloseMs, dlg, [dlg] { dlg->close(); });
    }
}

} // namespace

// 供外部(查毒命中后自动弹出)调用:打开云信誉行为关系图详情窗口。autoCloseMs>0 时到时自动关闭。
void pages::showVtDetailWindow(QWidget* parent, const bulwark::VtScanRecord& r, IpcClient* ipc, int autoCloseMs)
{
    showVtRecordDetail(parent, r, ipc, nullptr, autoCloseMs);
}

// ── 云信誉:哈希查询 + 情报源状态(据设置)+ VT 查询历史(实时进度)──────────────
QWidget* pages::reputation(IpcClient* ipc)
{
    auto* page = new QWidget;
    auto* v = new QVBoxLayout(page);
    v->setContentsMargins(theme::metric::pagePad, 22, theme::metric::pagePad, theme::metric::pagePad);
    v->setSpacing(16);

    // Query card.
    auto* q = ui::card();
    auto* qv = new QVBoxLayout(q);
    qv->setContentsMargins(20, 18, 20, 18);
    qv->setSpacing(12);
    qv->addWidget(ui::label(u("哈希信誉查询"), "h2"));
    auto* qr = new QHBoxLayout;
    qr->setSpacing(10);
    auto* input = new QLineEdit;
    input->setPlaceholderText(u("输入文件路径或 SHA-256 哈希…"));
    auto* browse = ui::toolButton("file", u("浏览"), "ghost", theme::textSecondary());
    auto* query = ui::toolButton("search", u("查询"), "primary", theme::accentInk());
    qr->addWidget(input, 1);
    qr->addWidget(browse);
    qr->addWidget(query);
    qv->addLayout(qr);
    auto* qresult = ui::label(QString(), "muted");
    qresult->setWordWrap(true);
    qv->addWidget(qresult);
    v->addWidget(q);

    // Source status grid HIDDEN (portable build: no API keys exposed).
    // auto* sc = ui::card();
    // auto* scv = new QVBoxLayout(sc);
    // scv->setContentsMargins(20, 18, 20, 18);
    // scv->setSpacing(12);
    // scv->addWidget(ui::label(u("情报源状态"), "h2"));
    // auto* grid = new QGridLayout;
    // grid->setSpacing(12);
    // struct Src { const char* name; };
    // const Src ss[] = { {"VirusTotal"}, {"MalwareBazaar"}, {"AlienVault OTX"},
    //                    {"微步 ThreatBook"}, {"MetaDefender"}, {"Hybrid Analysis"} };
    auto* pills = new QHash<QString, QLabel*>; // keep for signal handler (no-op)
    // int idx = 0;
    // for (const auto& s : ss) {
    //     auto* cardw = ui::cardAlt();
    //     auto* h = new QHBoxLayout(cardw);
    //     h->setContentsMargins(14, 12, 14, 12);
    //     h->setSpacing(11);
    //     h->addWidget(ui::iconBadge("cloud", theme::textMuted(), 34, 18));
    //     h->addWidget(ui::label(u(s.name), "title"));
    //     h->addStretch();
    //     auto* pill = ui::pill(u("未配置"), theme::textMuted());
    //     pills->insert(QString::fromUtf8(s.name), pill);
    //     h->addWidget(pill);
    //     grid->addWidget(cardw, idx / 3, idx % 3);
    //     ++idx;
    // }
    // scv->addLayout(grid);
    // v->addWidget(sc);

    // History table.
    v->addWidget(ui::label(u("查询历史"), "h2"));
    auto* t = ui::table({u("文件"), u("SHA-256"), u("检出"), u("结论"), u("时间")});
    t->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    v->addWidget(t, 1);

    auto* rowById = new QHash<QUuid, int>;
    auto* recById = new QHash<QUuid, bulwark::VtScanRecord>; // 完整记录,供双击弹窗展示
    auto upsert = [t, rowById, recById](const bulwark::VtScanRecord& r) {
        (*recById)[r.id] = r; // 存/更新完整记录
        int row = rowById->value(r.id, -1);
        if (row < 0) { row = 0; t->insertRow(0);
            // shift existing indices
            for (auto it = rowById->begin(); it != rowById->end(); ++it) ++it.value();
            rowById->insert(r.id, 0);
        }
        auto* nameItem = ui::textItem(r.fileName.isEmpty() ? QFileInfo(r.filePath).fileName() : r.fileName);
        nameItem->setData(Qt::UserRole, r.id.toString()); // 行 -> 记录 id(双击时反查)
        t->setItem(row, 0, nameItem);
        t->setItem(row, 1, ui::textItem(r.sha256.left(16) + (r.sha256.size() > 16 ? QStringLiteral("…") : QString()), true, true));
        t->setItem(row, 2, ui::textItem(r.totalEngines > 0 ? QStringLiteral("%1 / %2").arg(r.malicious).arg(r.totalEngines) : u("—"), true));
        QColor oc; const QString ot = outcomeText(r.outcome, oc);
        ui::pillCell(t, row, 3, r.isTerminal() ? ot : (r.message.isEmpty() ? ot : r.message), oc);
        t->setItem(row, 4, ui::textItem(r.timestampUtc.toLocalTime().toString(QStringLiteral("HH:mm")), true, true));
    };

    QObject::connect(ipc, &IpcClient::vtHistoryReceived, page,
                     [t, rowById, recById, upsert](const QList<bulwark::VtScanRecord>& records) {
        t->setRowCount(0);
        rowById->clear();
        recById->clear();
        for (const auto& r : records) upsert(r);
    });
    // 双击任意行 -> 弹出第二窗口展示该条完整信息(并按需联网拉取 VT 完整报告)。
    auto* recDetailCache = new QHash<QString, bulwark::ipc::VtDetailResponsePayload>; // 按哈希缓存完整报告
    QObject::connect(t, &QTableWidget::cellDoubleClicked, page,
                     [t, recById, recDetailCache, page, ipc](int row, int /*col*/) {
        const QTableWidgetItem* item = t->item(row, 0);
        if (!item) return;
        const QUuid id(item->data(Qt::UserRole).toString());
        const auto it = recById->constFind(id);
        if (it != recById->constEnd())
            showVtRecordDetail(page, it.value(), ipc, recDetailCache);
    });
    QObject::connect(ipc, &IpcClient::vtScanUpdate, page, upsert);
    QObject::connect(ipc, &IpcClient::vtResponse, page,
                     [qresult](const bulwark::ipc::VtResponsePayload& resp) {
        qresult->setText((resp.success ? u("✓ ") : u("✕ ")) + resp.message);
    });
    QObject::connect(ipc, &IpcClient::settingsReceived, page,
                     [pills](const bulwark::RuntimeSettings& s) {
        auto set = [pills](const QString& name, bool on) {
            if (auto* p = pills->value(name, nullptr))
                ui::stylePill(p, on ? u("已启用") : u("未配置"), on ? theme::success() : theme::textMuted());
        };
        set(QStringLiteral("VirusTotal"), s.virusTotalEnabled);
        set(QStringLiteral("MalwareBazaar"), s.malwareBazaarEnabled);
        set(QStringLiteral("AlienVault OTX"), s.otxEnabled);
        set(QString::fromUtf8("微步 ThreatBook"), s.threatBookEnabled);
        set(QStringLiteral("MetaDefender"), s.metaDefenderEnabled);
        set(QStringLiteral("Hybrid Analysis"), s.hybridAnalysisEnabled);
    });

    auto runQuery = [ipc, input, qresult] {
        const QString text = input->text().trimmed();
        if (text.isEmpty()) return;
        bulwark::ipc::VtRequestPayload p;
        p.kind = bulwark::VtRequestKind::QueryFile;
        p.filePath = text;
        qresult->setText(u("查询中…"));
        ipc->vtQuery(p);
    };
    QObject::connect(query, &QPushButton::clicked, page, runQuery);
    QObject::connect(input, &QLineEdit::returnPressed, page, runQuery);
    QObject::connect(browse, &QPushButton::clicked, page, [input, page] {
        const QString f = QFileDialog::getOpenFileName(page, u("选择文件"));
        if (!f.isEmpty()) input->setText(QDir::toNativeSeparators(f));
    });
    QObject::connect(ipc, &IpcClient::connectionChanged, page, [ipc](bool c) {
        if (c) { ipc->requestVtHistory(); ipc->requestSettings(); }
    });
    if (ipc->isConnected()) { ipc->requestVtHistory(); ipc->requestSettings(); }
    QObject::connect(page, &QObject::destroyed, [pills, rowById, recById, recDetailCache] {
        delete pills; delete rowById; delete recById; delete recDetailCache;
    });
    return page;
}

// ── 设置:从服务加载运行时设置到各开关,保存时回写(未暴露字段原样保留)──────────────
QWidget* pages::settings(IpcClient* ipc)
{
    // 绑定的控件集合(堆分配,随页面销毁释放)。保存时以「最近一次收到的设置」为基,
    // 仅覆盖下方暴露的字段,避免抹掉 UI 未展示的配置(额度/事件源/AI 内容上限等)。
    struct Widgets {
        bulwark::RuntimeSettings last;
        bool loading{false}; // true while pushing service settings -> controls (suppresses auto-apply)
        ToggleSwitch *protection{}, *defaultBlock{}, *silent{}, *chainToast{};
        ToggleSwitch *proc{}, *file{}, *reg{}, *self{}, *net{}, *mem{};
        ToggleSwitch *trustSigned{}, *baseline{}, *canary{}, *userMon{}, *kernel{}, *grayAi{};
        ToggleSwitch *vt{}, *mb{}, *otx{}, *tb{}, *mdc{}, *ha{};
        ToggleSwitch *aiDouble{}, *aiSuspend{}, *aiBlockFail{};
        ToggleSwitch* cloudUpload{}; // 威胁情报共享(默认关)
        QSpinBox* timeout{};
        QLineEdit *vtKey{}, *mbKey{}, *otxKey{}, *tbKey{}, *mdcKey{}, *haKey{}; // 各情报源 API Key
        QLineEdit *aiBase{}, *aiKey{}, *aiModel{};
        QHash<QUuid, QLabel*> pendingTests; // 测试连接 requestId -> 对应源的状态标签
    };
    auto* wg = new Widgets;

    // 每个情报源的「测试连接 / 保存」按钮行。构建期就地生成(位置正确),clicked 接线延后到
    // apply 定义之后统一完成(apply / status 在下方才创建)。
    struct KeyActions { QString source; QPushButton* test; QPushButton* save; QLabel* status; };
    QList<KeyActions> keyActs;
    auto addKeyRow = [&keyActs](QVBoxLayout* box, const QString& source) {
        auto* row = new QWidget;
        auto* h = new QHBoxLayout(row);
        h->setContentsMargins(132, 0, 0, 4); // 与 fieldRow 输入框左对齐(label 120 + spacing 12)
        h->setSpacing(8);
        auto* test = new QPushButton(u("测试连接"));
        test->setProperty("variant", "ghost");
        test->setProperty("size", "sm");
        test->setCursor(Qt::PointingHandCursor);
        auto* save = new QPushButton(u("保存"));
        save->setProperty("variant", "primary");
        save->setProperty("size", "sm");
        save->setCursor(Qt::PointingHandCursor);
        auto* st = ui::label(QString(), "muted");
        st->setWordWrap(true);
        h->addWidget(test);
        h->addWidget(save);
        h->addWidget(st, 1);
        box->addWidget(row);
        keyActs.append({ source, test, save, st });
    };

    auto* page = new QWidget;
    auto* outer = new QVBoxLayout(page);
    outer->setContentsMargins(0, 0, 0, 0);
    auto* scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    outer->addWidget(scroll);
    auto* content = new QWidget;
    scroll->setWidget(content);
    auto* v = new QVBoxLayout(content);
    v->setContentsMargins(theme::metric::pagePad, 22, theme::metric::pagePad, theme::metric::pagePad);
    v->setSpacing(16);

    auto* s1 = section(v, u("防护总控"));
    wg->protection = settingRow(s1, u("实时防护"), u("监控并拦截敏感系统行为"), true);
    wg->defaultBlock = settingRow(s1, u("默认拦截未知行为"), u("灰区行为无匹配规则时默认拦截(更严格)"), false);
    wg->silent = settingRow(s1, u("静默模式"), u("不弹窗打扰,询问类自动放行,仅拦确定性高危"), false);
    // 紧跟静默模式之后,并在说明里点明「不受静默模式影响」—— 否则用户开了静默还看到弹窗
    // 会以为静默没生效。这两项的关系必须在界面上说清,不能只写在代码注释里。
    wg->chainToast = settingRow(s1, u("攻击链命中通知"),
                               u("右下角提示并自动消失,不受静默模式影响 —— 静默会把询问降级为放行,"
                                 "这条通知补的正是那种「命中了却无声」的情况"), true);
    {
        auto* w = new QWidget;
        auto* h = new QHBoxLayout(w);
        h->setContentsMargins(0, 6, 0, 6);
        auto* col = new QVBoxLayout;
        col->setSpacing(1);
        col->addWidget(ui::label(u("弹窗超时"), "title"));
        col->addWidget(ui::label(u("行为询问弹窗的自动处置倒计时"), "muted"));
        h->addLayout(col);
        h->addStretch();
        wg->timeout = new QSpinBox;
        wg->timeout->setRange(5, 300);
        wg->timeout->setValue(30);
        wg->timeout->setSuffix(u(" 秒"));
        wg->timeout->setFixedWidth(110);
        h->addWidget(wg->timeout);
        s1->addWidget(w);
    }

    auto* s2 = section(v, u("防护维度"));
    wg->proc = settingRow(s2, u("进程防护"), u("进程创建 / 远程线程注入"), true);
    wg->file = settingRow(s2, u("文件防护"), u("敏感文件写入 / 删除"), true);
    wg->reg = settingRow(s2, u("注册表防护"), u("启动项 / 敏感键值写入"), true);
    wg->self = settingRow(s2, u("自我保护"), u("防止防护组件被终止 / 卸载"), true);
    wg->net = settingRow(s2, u("网络防护"), u("可疑外联 / C2 通信"), true);
    wg->mem = settingRow(s2, u("内存防护"), u("反注入内存保护"), true);

    auto* s3 = section(v, u("决策与监控"));
    wg->trustSigned = settingRow(s3, u("信任已签名程序"), u("有效签名的程序默认放行、不弹询问(仅拦确定性恶意)"), true);
    wg->baseline = settingRow(s3, u("行为基线"), u("学习正常行为以降低误报"), true);
    wg->canary = settingRow(s3, u("勒索诱饵"), u("布放诱饵文件侦测勒索加密"), true);
    wg->userMon = settingRow(s3, u("用户态行为监控"), u("无驱动时的持久化 / 勒索监控"), true);
    wg->kernel = settingRow(s3, u("内核驱动"), u("加载 Bulwark.sys 实现事前拦截"), false);
    wg->grayAi = settingRow(s3, u("灰区 AI 会诊"), u("对双击/可疑程序额外调用大模型研判(需配置模型,默认关)"), false);

    auto* s4 = section(v, u("威胁情报源"));
    // 每个源:开关 + 其下 API Key 输入框(掩码)。留空则沿用服务端 appsettings.json / 内置默认;
    // 保存后立即热应用到对应客户端,无需改配置文件或重启。
    wg->vt = settingRow(s4, u("VirusTotal"), u("多引擎哈希信誉(内置默认 Key)"), false);
    wg->vtKey = fieldRow(s4, u("API Key"), true);
    addKeyRow(s4, QStringLiteral("VirusTotal"));
    wg->mb = settingRow(s4, u("MalwareBazaar"), u("恶意样本库"), false);
    wg->mbKey = fieldRow(s4, u("Auth-Key"), true);
    addKeyRow(s4, QStringLiteral("MalwareBazaar"));
    wg->otx = settingRow(s4, u("AlienVault OTX"), u("开放威胁情报"), false);
    wg->otxKey = fieldRow(s4, u("API Key"), true);
    addKeyRow(s4, QStringLiteral("OTX"));
    wg->tb = settingRow(s4, u("微步在线 ThreatBook"), u("文件 + IP 情报"), false);
    wg->tbKey = fieldRow(s4, u("API Key"), true);
    addKeyRow(s4, QStringLiteral("ThreatBook"));
    wg->mdc = settingRow(s4, u("MetaDefender"), u("多引擎扫描"), false);
    wg->mdcKey = fieldRow(s4, u("API Key"), true);
    addKeyRow(s4, QStringLiteral("MetaDefender"));
    wg->ha = settingRow(s4, u("Hybrid Analysis"), u("沙箱行为情报"), false);
    wg->haKey = fieldRow(s4, u("API Key"), true);
    addKeyRow(s4, QStringLiteral("HybridAnalysis"));

    auto* s5 = section(v, u("双击查杀 与 AI 研判"));
    wg->aiDouble = settingRow(s5, u("双击云查杀"), u("双击运行的程序自动做 VirusTotal 云端查毒"), true);
    wg->aiSuspend = settingRow(s5, u("查杀期间挂起"), u("查杀/研判完成前挂起目标进程"), true);
    wg->aiBlockFail = settingRow(s5, u("查杀失败即拦截"), u("云查杀/AI 无明确结论时从严拦截"), false);
    s5->addWidget(ui::hDivider());
    wg->aiBase = fieldRow(s5, u("接口地址"), false);
    wg->aiKey = fieldRow(s5, u("API Key"), true);
    wg->aiModel = fieldRow(s5, u("模型"), false);

    // 威胁情报共享(默认关)。开关下方用一段可换行的说明把「上传什么 / 不上传什么」讲清楚 ——
    // 这是用户决定要不要开启的唯一依据,不能只写一行含糊的描述。
    auto* s6 = section(v, u("威胁情报共享"));
    wg->cloudUpload = settingRow(s6, u("共享病毒信息与行为数据"),
                                 u("默认关闭。开启后每天凌晨自动上传,上传成功即删除本地暂存"), false);
    {
        auto* note = ui::label(
            u("只上传病毒信息与沙箱行为数据:病毒文件的 SHA-256、判定结果、引擎检出数、"
              "威胁名称,以及该病毒已知的释放物名称与哈希、注册表键、外联 IP 与域名、"
              "服务名、互斥体。\n"
              "不涉及任何个人隐私信息:不上传文件内容,不上传该文件在本机的路径与文件名,"
              "不上传计算机名、用户名或任何账号信息,也不附带任何机器标识。\n"
              "仅在云查杀判定为恶意或可疑时才收集;关闭开关会立即删除本地已暂存的全部数据。"),
            "muted");
        note->setWordWrap(true);
        s6->addWidget(note);
    }

    auto* bar = new QHBoxLayout;
    bar->addStretch();
    auto* status = ui::label(QString(), "muted");
    bar->addWidget(status);
    bar->addSpacing(10);
    auto* save = new QPushButton(u("保存设置"));
    save->setProperty("variant", "primary");
    save->setCursor(Qt::PointingHandCursor);
    bar->addWidget(save);
    v->addLayout(bar);
    v->addStretch();

    // Load: service settings -> controls.
    QObject::connect(ipc, &IpcClient::settingsReceived, page,
                     [wg, status](const bulwark::RuntimeSettings& s) {
        wg->loading = true; // suppress auto-apply while echoing service state into controls
        wg->last = s;
        wg->protection->setChecked(s.protectionEnabled);
        wg->defaultBlock->setChecked(s.defaultBlock);
        wg->silent->setChecked(s.silentMode);
    wg->chainToast->setChecked(s.attackChainToast);
        wg->timeout->setValue(s.promptTimeoutSeconds);
        wg->proc->setChecked(s.processProtection);
        wg->file->setChecked(s.fileProtection);
        wg->reg->setChecked(s.registryProtection);
        wg->self->setChecked(s.selfProtection);
        wg->net->setChecked(s.networkProtection);
        wg->mem->setChecked(s.memoryProtectionEnabled);
        wg->trustSigned->setChecked(s.trustSignedActors);
        wg->baseline->setChecked(s.behaviorBaselineEnabled);
        wg->canary->setChecked(s.ransomwareCanaryEnabled);
        wg->userMon->setChecked(s.userModeBehaviorMonitor);
        wg->kernel->setChecked(s.kernelDriverEnabled);
        wg->grayAi->setChecked(s.aiGrayZoneConsultEnabled);
        wg->vt->setChecked(s.virusTotalEnabled);
        wg->mb->setChecked(s.malwareBazaarEnabled);
        wg->otx->setChecked(s.otxEnabled);
        wg->tb->setChecked(s.threatBookEnabled);
        wg->mdc->setChecked(s.metaDefenderEnabled);
        wg->ha->setChecked(s.hybridAnalysisEnabled);
        wg->vtKey->setText(s.virusTotalApiKey);
        wg->mbKey->setText(s.malwareBazaarApiKey);
        wg->otxKey->setText(s.otxApiKey);
        wg->tbKey->setText(s.threatBookApiKey);
        wg->mdcKey->setText(s.metaDefenderApiKey);
        wg->haKey->setText(s.hybridAnalysisApiKey);
        wg->aiDouble->setChecked(s.aiScanDoubleClickEnabled);
        wg->aiSuspend->setChecked(s.aiScanSuspendDuringScan);
        wg->aiBlockFail->setChecked(s.aiScanBlockOnFailure);
        wg->cloudUpload->setChecked(s.cloudBehaviorUploadEnabled);
        wg->aiBase->setText(s.aiBaseUrl);
        wg->aiKey->setText(s.aiApiKey);
        wg->aiModel->setText(s.aiModel);
        wg->loading = false;
        status->setText(u("已从服务载入"));
    });

    // Gather current control state into a settings snapshot. Start from the last
    // service snapshot so fields the UI doesn't expose (quotas / event source /
    // AI content caps) are preserved rather than reset.
    auto collect = [wg]() -> bulwark::RuntimeSettings {
        bulwark::RuntimeSettings s = wg->last;
        s.protectionEnabled = wg->protection->isChecked();
        s.defaultBlock = wg->defaultBlock->isChecked();
        s.silentMode = wg->silent->isChecked();
    s.attackChainToast = wg->chainToast->isChecked();
        s.promptTimeoutSeconds = wg->timeout->value();
        s.processProtection = wg->proc->isChecked();
        s.fileProtection = wg->file->isChecked();
        s.registryProtection = wg->reg->isChecked();
        s.selfProtection = wg->self->isChecked();
        s.networkProtection = wg->net->isChecked();
        s.memoryProtectionEnabled = wg->mem->isChecked();
        s.trustSignedActors = wg->trustSigned->isChecked();
        s.behaviorBaselineEnabled = wg->baseline->isChecked();
        s.ransomwareCanaryEnabled = wg->canary->isChecked();
        s.userModeBehaviorMonitor = wg->userMon->isChecked();
        s.kernelDriverEnabled = wg->kernel->isChecked();
        s.aiGrayZoneConsultEnabled = wg->grayAi->isChecked();
        s.virusTotalEnabled = wg->vt->isChecked();
        s.malwareBazaarEnabled = wg->mb->isChecked();
        s.otxEnabled = wg->otx->isChecked();
        s.threatBookEnabled = wg->tb->isChecked();
        s.metaDefenderEnabled = wg->mdc->isChecked();
        s.hybridAnalysisEnabled = wg->ha->isChecked();
        s.virusTotalApiKey = wg->vtKey->text().trimmed();
        s.malwareBazaarApiKey = wg->mbKey->text().trimmed();
        s.otxApiKey = wg->otxKey->text().trimmed();
        s.threatBookApiKey = wg->tbKey->text().trimmed();
        s.metaDefenderApiKey = wg->mdcKey->text().trimmed();
        s.hybridAnalysisApiKey = wg->haKey->text().trimmed();
        s.aiScanDoubleClickEnabled = wg->aiDouble->isChecked();
        s.aiScanSuspendDuringScan = wg->aiSuspend->isChecked();
        s.aiScanBlockOnFailure = wg->aiBlockFail->isChecked();
        s.cloudBehaviorUploadEnabled = wg->cloudUpload->isChecked();
        s.aiBaseUrl = wg->aiBase->text().trimmed();
        s.aiApiKey = wg->aiKey->text().trimmed();
        s.aiModel = wg->aiModel->text().trimmed();
        return s;
    };

    // Apply immediately on any change — a toggle takes effect the moment it is
    // flipped, no separate save step. Guarded by wg->loading so the service echo
    // (settingsReceived -> setChecked) doesn't bounce straight back as an update.
    auto apply = [wg, ipc, status, collect] {
        if (wg->loading) return;
        const bulwark::RuntimeSettings s = collect();
        wg->last = s;
        ipc->updateSettings(s);
        status->setText(u("已应用"));
    };

    // Toggles + timeout apply on change; text fields apply when editing commits.
    for (ToggleSwitch* t : {wg->protection, wg->defaultBlock, wg->silent, wg->chainToast, wg->proc,
                            wg->file, wg->reg, wg->self, wg->net, wg->mem,
                            wg->trustSigned, wg->baseline, wg->canary, wg->userMon,
                            wg->kernel, wg->grayAi, wg->vt, wg->mb, wg->otx, wg->tb,
                            wg->mdc, wg->ha, wg->aiDouble, wg->aiSuspend, wg->aiBlockFail,
                            wg->cloudUpload})
        QObject::connect(t, &QAbstractButton::toggled, page, [apply](bool) { apply(); });
    QObject::connect(wg->timeout, qOverload<int>(&QSpinBox::valueChanged), page,
                     [apply](int) { apply(); });
    QObject::connect(wg->aiBase, &QLineEdit::editingFinished, page, [apply] { apply(); });
    QObject::connect(wg->aiKey, &QLineEdit::editingFinished, page, [apply] { apply(); });
    QObject::connect(wg->aiModel, &QLineEdit::editingFinished, page, [apply] { apply(); });

    // 情报源「保存 / 测试连接」按钮接线。保存=应用当前设置(含 Key,热生效+落盘)。测试=先应用
    // (确保服务端用最新 Key)再对该源发起 TestConnection;结果按 requestId 回填对应状态标签。
    for (const KeyActions& ka : keyActs) {
        QLabel* st = ka.status;
        const QString src = ka.source;
        QObject::connect(ka.save, &QPushButton::clicked, page, [apply, st] {
            apply();
            st->setStyleSheet(QStringLiteral("color:%1;").arg(theme::success().name()));
            st->setText(u("已保存"));
        });
        QObject::connect(ka.test, &QPushButton::clicked, page, [apply, ipc, wg, src, st] {
            apply(); // 先保存,确保服务端拿到最新 Key 再测试
            st->setStyleSheet(QStringLiteral("color:%1;").arg(theme::textMuted().name()));
            st->setText(u("测试中…"));
            bulwark::ipc::VtRequestPayload p;
            p.kind = bulwark::VtRequestKind::TestConnection;
            p.source = src;
            wg->pendingTests.insert(p.requestId, st);
            ipc->vtQuery(p);
        });
    }
    // 测试连接结果回填(按 requestId 匹配本页发起的测试;云信誉页的查询不在此表,自动忽略)。
    QObject::connect(ipc, &IpcClient::vtResponse, page, [wg](const bulwark::ipc::VtResponsePayload& resp) {
        auto it = wg->pendingTests.find(resp.requestId);
        if (it == wg->pendingTests.end())
            return;
        QLabel* st = it.value();
        wg->pendingTests.erase(it);
        st->setStyleSheet(QStringLiteral("color:%1;")
                              .arg((resp.success ? theme::success() : theme::danger()).name()));
        st->setText(resp.message.isEmpty() ? (resp.success ? u("连接成功") : u("连接失败")) : resp.message);
    });
    for (QLineEdit* k : {wg->vtKey, wg->mbKey, wg->otxKey, wg->tbKey, wg->mdcKey, wg->haKey})
        QObject::connect(k, &QLineEdit::editingFinished, page, [apply] { apply(); });

    // Keep the explicit button as a manual "apply now" (also flushes text fields).
    QObject::connect(save, &QPushButton::clicked, page, [apply] { apply(); });

    QObject::connect(ipc, &IpcClient::connectionChanged, page,
                     [ipc](bool c) { if (c) ipc->requestSettings(); });
    if (ipc->isConnected()) ipc->requestSettings();
    QObject::connect(page, &QObject::destroyed, [wg] { delete wg; });
    return page;
}

namespace {

// A stat card whose big value label is handed back for live updates.
QFrame* aiStat(const QString& icon, const QColor& color, const QString& name, QLabel*& out)
{
    auto* c = ui::card();
    c->setMinimumHeight(100);
    auto* v = new QVBoxLayout(c);
    v->setContentsMargins(18, 14, 18, 14);
    v->setSpacing(8);
    auto* top = new QHBoxLayout;
    top->addWidget(ui::iconBadge(icon, color, 36, 19));
    top->addStretch();
    v->addLayout(top);
    out = ui::coloredText(QStringLiteral("0"), 22, 800, theme::textPrimary());
    v->addWidget(out);
    v->addWidget(ui::label(name, "secondary"));
    return c;
}

} // namespace

// ── AI 研判:大模型接入状态(据设置)+ 手动扫描文件/文件夹 + 研判记录(实时)──────────
QWidget* pages::aiScan(IpcClient* ipc)
{
    auto* page = new QWidget;
    auto* v = new QVBoxLayout(page);
    v->setContentsMargins(theme::metric::pagePad, 22, theme::metric::pagePad, theme::metric::pagePad);
    v->setSpacing(16);

    // Connection + manual-scan card.
    auto* c = ui::card();
    c->setMinimumHeight(112);
    auto* h = new QHBoxLayout(c);
    h->setContentsMargins(24, 18, 24, 18);
    h->setSpacing(18);
    h->addWidget(ui::iconBadge("sparkles", theme::accentAlt(), 60, 32));
    auto* col = new QVBoxLayout;
    col->setSpacing(3);
    col->addWidget(ui::label(u("AI 行为研判"), "caption"));
    auto* statusText = ui::coloredText(u("未配置大模型"), 18, 800, theme::textMuted());
    col->addWidget(statusText);
    auto* modelText = ui::elided(u("在「设置 · AI 研判」填入接口地址 / API Key / 模型"), "secondary");
    col->addWidget(modelText);
    h->addLayout(col, 1);
    auto* scanFileBtn = ui::toolButton("file", u("扫描文件"), "primary", theme::accentInk());
    auto* scanDirBtn = ui::toolButton("file", u("扫描文件夹"), "ghost", theme::textSecondary());
    auto* btnCol = new QVBoxLayout;
    btnCol->setSpacing(8);
    btnCol->addWidget(scanFileBtn);
    btnCol->addWidget(scanDirBtn);
    h->addLayout(btnCol);
    v->addWidget(c);

    // Stats.
    QLabel *nToday = nullptr, *nMal = nullptr, *nTokens = nullptr;
    auto* stats = new QHBoxLayout;
    stats->setSpacing(16);
    stats->addWidget(aiStat("sparkles", theme::accentAlt(), u("研判总数"), nToday));
    stats->addWidget(aiStat("shield-x", theme::danger(), u("判定恶意"), nMal));
    stats->addWidget(aiStat("cpu", theme::accent(), u("消耗 Token"), nTokens));
    v->addLayout(stats);

    // Records (header row: title + 清空 button).
    auto* recHead = new QHBoxLayout;
    recHead->addWidget(ui::label(u("研判记录"), "h2"));
    recHead->addStretch();
    auto* clearAiBtn = ui::toolButton("trash", u("清空"), "ghost", theme::danger());
    recHead->addWidget(clearAiBtn);
    v->addLayout(recHead);
    auto* t = ui::table({u("时间"), u("文件"), u("结论"), u("置信度"), u("摘要")});
    t->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    v->addWidget(t, 1);
    QObject::connect(t, &QTableWidget::cellDoubleClicked, page, [t, page](int row, int) {
        auto* c0 = t->item(row, 0); // 双击查看研判溯源详情
        if (c0 && !c0->data(Qt::UserRole).toString().isEmpty())
            QMessageBox::information(page, u("AI 研判详情"), c0->data(Qt::UserRole).toString());
    });

    auto* counters = new int[3]{0, 0, 0}; // total / malicious / tokens
    // Shared row builder for both the live push and the persisted-history backfill.
    // atTop=true prepends (live scans, newest on top); atTop=false appends — the
    // backfill arrives newest-first, so appending keeps the table newest-on-top.
    auto addRow = [t, nToday, nMal, nTokens, counters](const AiScanResult& r, bool atTop) {
        const int row = atTop ? 0 : t->rowCount();
        t->insertRow(row);
        t->setItem(row, 0, ui::textItem(r.timestampUtc.toLocalTime().toString(QStringLiteral("HH:mm:ss")), true, true));
        t->setItem(row, 1, ui::textItem(r.fileName.isEmpty() ? QFileInfo(r.filePath).fileName() : r.fileName, false, true));
        QColor oc; QString ot;
        if (!r.available)     { ot = u("不可用"); oc = theme::textMuted(); }
        else if (r.malicious) { ot = u("恶意");   oc = theme::danger(); }
        else                  { ot = u("未见异常"); oc = theme::success(); }
        ui::pillCell(t, row, 2, ot, oc);
        t->setItem(row, 3, ui::textItem(r.available ? r.confidence : u("—"), true));
        t->setItem(row, 4, ui::textItem(r.summary, true));
        // 溯源详情:双击该行查看(时间线由 UserRole 携带)。
        if (auto* c0 = t->item(row, 0))
            c0->setData(Qt::UserRole,
                        u("文件:%1\n路径:%2\n结论:%3 · 置信度 %4\n用时 %5ms · Token %6 · 来源 %7\n\n研判摘要:\n%8")
                            .arg(r.fileName.isEmpty() ? QFileInfo(r.filePath).fileName() : r.fileName,
                                 r.filePath, ot, r.available ? r.confidence : u("—"))
                            .arg(r.elapsedMs).arg(r.tokens).arg(r.source, r.summary));
        counters[0]++;
        if (r.available && r.malicious) counters[1]++;
        counters[2] += r.tokens;
        nToday->setText(QString::number(counters[0]));
        nMal->setText(QString::number(counters[1]));
        nTokens->setText(QString::number(counters[2]));
    };
    QObject::connect(ipc, &IpcClient::aiScanRecord, page,
                     [addRow](const AiScanResult& r) { addRow(r, true); });
    // Backfill the persisted AI research history so the page isn't blank after a
    // restart (AI scans run UI-side, so this history is persisted UI-side too).
    for (const AiScanResult& r : ipc->aiScanHistory())
        addRow(r, false);
    // 清空研判记录:清 UI 侧落盘历史 + 清表 + 归零统计。
    QObject::connect(clearAiBtn, &QPushButton::clicked, page,
                     [ipc, page, t, counters, nToday, nMal, nTokens] {
        if (QMessageBox::question(page, u("清空研判记录"),
                u("确定清空全部 AI 研判记录吗?此操作不可恢复。")) != QMessageBox::Yes)
            return;
        ipc->clearAiScanHistory();
        t->setRowCount(0);
        counters[0] = counters[1] = counters[2] = 0;
        nToday->setText(QStringLiteral("0"));
        nMal->setText(QStringLiteral("0"));
        nTokens->setText(QStringLiteral("0"));
    });
    QObject::connect(page, &QObject::destroyed, [counters] { delete[] counters; });

    QObject::connect(scanFileBtn, &QPushButton::clicked, page, [ipc, page] {
        const QString f = QFileDialog::getOpenFileName(page, u("选择要研判的文件"));
        if (!f.isEmpty()) ipc->aiScanFile(QDir::toNativeSeparators(f));
    });
    QObject::connect(scanDirBtn, &QPushButton::clicked, page, [ipc, page] {
        const QString dir = QFileDialog::getExistingDirectory(page, u("选择要研判的文件夹"));
        if (dir.isEmpty()) return;
        // Cap the batch so a huge folder can't fire hundreds of model calls at once.
        const QStringList exts{QStringLiteral("exe"), QStringLiteral("dll"), QStringLiteral("scr"),
                               QStringLiteral("sys"), QStringLiteral("com")};
        QDir d(dir);
        int n = 0;
        for (const QFileInfo& fi : d.entryInfoList(QDir::Files)) {
            if (!exts.contains(fi.suffix().toLower())) continue;
            ipc->aiScanFile(fi.absoluteFilePath());
            if (++n >= 25) break;
        }
    });

    QObject::connect(ipc, &IpcClient::settingsReceived, page,
                     [statusText, modelText](const bulwark::RuntimeSettings& s) {
        if (s.aiConfigured()) {
            statusText->setText(u("大模型已接入"));
            statusText->setStyleSheet(QStringLiteral("font-size:18pt; font-weight:800; color:%1;")
                                          .arg(theme::success().name()));
            modelText->setText((s.aiModel.isEmpty() ? u("(默认模型)") : s.aiModel)
                               + u("  ·  ") + s.aiBaseUrl);
        } else {
            statusText->setText(u("未配置大模型"));
            statusText->setStyleSheet(QStringLiteral("font-size:18pt; font-weight:800; color:%1;")
                                          .arg(theme::textMuted().name()));
            modelText->setText(u("在「设置 · AI 研判」填入接口地址 / API Key / 模型"));
        }
    });
    QObject::connect(ipc, &IpcClient::connectionChanged, page,
                     [ipc](bool c) { if (c) ipc->requestSettings(); });
    if (ipc->isConnected()) ipc->requestSettings();
    return page;
}
