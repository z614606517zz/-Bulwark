// 云信誉 —— 查询一个文件的云端信誉(拖进来 / 选文件 / 输入 SHA-256),以及云查杀记录(实时进度)。
//
// 云查毒是分级链路:先问中央服务器「这个文件收录了吗」,没收录才动用本机密钥去查各情报源。
// 页面顶部把这条链路和它此刻的状态摆出来(部署策略「本机不动用第三方情报源」生效时如实写
// 「策略停用」)—— 否则用户看不出一条「未收录」到底是查过了没有,还是根本没去查。
//
// 按文件查询由服务端先算哈希再查;按 SHA-256 查询走完整报告接口(与记录详情同源),两者的
// 结果都在查询卡里逐条列出。
#include "pages/CardPages.h"
#include "pages/PageKit.h"
#include "dialogs/AiCleanupDialog.h"
#include "dialogs/EventFormat.h"
#include "design/Backdrop.h"
#include "design/Banner.h"
#include "design/Components.h"
#include "design/DropZone.h"
#include "design/Format.h"
#include "design/IconTile.h"
#include "design/Identity.h"
#include "design/Inspector.h"
#include "design/ListShell.h"
#include "design/Segmented.h"
#include "design/Theme.h"
#include "ipc/IpcClient.h"
#include "Nav.h"

#include "bulwark/models/RuntimeSettings.h"
#include "bulwark/models/VtScanRecord.h"

#include <QDialog>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QFontMetrics>
#include <QHash>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QPainter>
#include <QPainterPath>
#include <QPushButton>
#include <QRegularExpression>
#include <QResizeEvent>
#include <QScrollArea>
#include <QTimer>
#include <QVBoxLayout>
#include <QVector>
#include <QWheelEvent>

#include <algorithm>
#include <functional>
#include <memory>

using evtfmt::u;
using bulwark::VtScanRecord;

namespace {

QString outcomeText(bulwark::VtScanOutcome o, QColor& c)
{
    using O = bulwark::VtScanOutcome;
    switch (o) {
    case O::Malicious:  c = theme::danger();    return u("恶意");
    case O::Suspicious: c = theme::warning();   return u("可疑");
    case O::Clean:      c = theme::success();   return u("干净");
    case O::Error:      c = theme::textMuted(); return u("失败");
    case O::Unknown:    c = theme::textMuted(); return u("未收录");
    case O::Pending:    break;
    }
    c = theme::info();
    return u("进行中");
}

QString stageText(const VtScanRecord& r)
{
    using S = bulwark::VtScanStage;
    switch (r.stage) {
    case S::Queued:    return u("排队中");
    case S::Querying:  return u("查询中");
    case S::Uploading: return u("上传 %1%").arg(r.percent);
    case S::Analyzing: return u("分析中");
    case S::Completed:
    case S::Error:     break;
    }
    return QString();
}

QString fileNameOf(const VtScanRecord& r)
{
    if (!r.fileName.isEmpty())
        return r.fileName;
    const QString n = QFileInfo(r.filePath).fileName();
    return n.isEmpty() ? (r.sha256.isEmpty() ? u("未知文件") : r.sha256.left(16) + u("…")) : n;
}

// ── 行为关系图(文件 → 判定方 → 释放 / 外联 / 注册表 / 检出扇出 → 结论,左→右分列)─────────────
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
        p.fillRect(rect(), theme::canvasBrush());
        p.scale(zoom_, zoom_);
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
        QFont titleF = font(); titleF.setBold(true); titleF.setPointSizeF(9.0);
        QFont subF = font(); subF.setPointSizeF(7.6);
        const QFontMetrics fmT(titleF), fmS(subF);
        for (const GraphNode& n : nodes_) {
            QPainterPath card; card.addRoundedRect(n.rect, 9, 9);
            p.fillPath(card, theme::surface());
            QColor fill = n.accent; fill.setAlpha(26);
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
    QSizeF baseCanvas() const {
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
        setMinimumSize(int(canvas.width() * zoom_), int(canvas.height() * zoom_));
        int maxCol = 0;
        for (const GraphNode& n : nodes_) maxCol = qMax(maxCol, n.column);
        QVector<int> perCol(maxCol + 1, 0);
        for (const GraphNode& n : nodes_) perCol[n.column]++;
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

// 缩短注册表键用于节点标题(取末两段)。
QString shortRegKey(const QString& key) {
    QString k = key; k.replace(QLatin1Char('/'), QLatin1Char('\\'));
    const QStringList parts = k.split(QLatin1Char('\\'), Qt::SkipEmptyParts);
    if (parts.size() <= 2) return k;
    return QStringLiteral("…\\") + parts.mid(parts.size() - 2).join(QLatin1Char('\\'));
}

// 据扫描记录(+可选完整报告)构建行为关系图:文件 → 判定方 → 行为/检出扇出 → 结论。
void buildBehaviorGraph(BehaviorGraphView* g, const VtScanRecord& r, const bulwark::ipc::VtDetailResponsePayload* d) {
    QVector<GraphNode> nodes;
    QVector<GraphEdge> edges;
    QColor vc;
    const QString verdict = outcomeText(r.outcome, vc);

    const int fileIdx = int(nodes.size());
    nodes.push_back({0, fileNameOf(r), u("文件"), theme::info(), {}});

    const int hubIdx = int(nodes.size());
    const QString hubSub = r.totalEngines > 0 ? u("%1/%2 引擎判恶意").arg(r.malicious).arg(r.totalEngines)
                                              : (r.threatLabel.isEmpty() ? u("云端判定") : r.threatLabel);
    // 中枢节点写【实际给出结论的那一方】,不写死 "VirusTotal"(服务器命中或 MalwareBazaar 命中时那是错的)。
    // 「本机缓存·」前缀剥掉:节点讲的是「谁判的」,缓存只是那条结论的副本。
    QString hubName = r.intelSource.trimmed();
    if (hubName.startsWith(u("本机缓存·")))
        hubName = hubName.mid(5);
    if (hubName.isEmpty())
        hubName = QStringLiteral("VirusTotal");
    nodes.push_back({1, hubName, hubSub, theme::info(), {}});
    edges.push_back({fileIdx, hubIdx, theme::info()});

    QVector<int> fanIdx;
    auto addFan = [&](const QString& t, const QString& s, const QColor& c) {
        const int i = int(nodes.size());
        nodes.push_back({2, t.isEmpty() ? u("(未知)") : t, s, c, {}});
        edges.push_back({hubIdx, i, c});
        fanIdx.push_back(i);
    };
    if (d && d->success) {
        int n = 0;
        for (const QString& s : d->droppedFiles)     { if (n++ >= 5) break; addFan(s, u("释放文件"), theme::warning()); }
        n = 0;
        // Same kind colours as the attack graph (AttackGraphWindow kindColor): IP cyan, domain sky, registry violet.
        for (const QString& s : d->contactedIps)     { if (n++ >= 4) break; addFan(s, u("外联 IP"), theme::cyan()); }
        n = 0;
        for (const QString& s : d->contactedDomains) { if (n++ >= 4) break; addFan(s, u("外联域名"), theme::sky()); }
        n = 0;
        for (const QString& s : d->registryKeys)     { if (n++ >= 3) break; addFan(shortRegKey(s), u("写注册表"), theme::violet()); }
        n = 0;
        for (const QString& s : d->maliciousDetections) {
            if (n++ >= 6) break;
            const int colon = int(s.indexOf(QLatin1Char(':')));
            const QString eng = colon > 0 ? s.left(colon) : s;
            const QString rez = colon > 0 ? s.mid(colon + 1).trimmed() : QString();
            addFan(eng, rez.isEmpty() ? u("判为恶意") : rez, theme::danger());
        }
    }

    const int conclCol = fanIdx.isEmpty() ? 2 : 3;
    const int conclIdx = int(nodes.size());
    const QString conclSub = !r.threatLabel.isEmpty() ? r.threatLabel : (r.uploaded ? u("已上传云端扫描") : u("云信誉判定"));
    nodes.push_back({conclCol, u("结论:") + verdict, conclSub, vc, {}});
    if (fanIdx.isEmpty())
        edges.push_back({hubIdx, conclIdx, vc});
    else
        for (int i : fanIdx) edges.push_back({i, conclIdx, vc});

    g->setGraph(nodes, edges);
}

using DetailCache = QHash<QString, bulwark::ipc::VtDetailResponsePayload>;

// 云信誉记录详情(独立第二窗口):以「行为关系图」呈现;打开时按需联网补全完整报告。
void showVtRecordDetail(QWidget* parent, const VtScanRecord& r, IpcClient* ipc, std::shared_ptr<DetailCache> cache,
                        int autoCloseMs = 0)
{
    auto* dlg = new QDialog(parent);
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->setModal(false); // 独立第二窗口,不阻塞主界面
    Backdrop::install(dlg); // same work-area material as the main window
    const QString title = fileNameOf(r);
    dlg->setWindowTitle(u("云信誉详情 · ") + title);
    dlg->setAccessibleName(dlg->windowTitle());
    dlg->setMinimumWidth(560);

    auto* shell = new QVBoxLayout(dlg);
    shell->setContentsMargins(22, 20, 22, 18);
    shell->setSpacing(14);

    QColor oc;
    const QString ot = outcomeText(r.outcome, oc);
    auto* head = new QHBoxLayout;
    head->setSpacing(12);
    head->addWidget(new IconTile(QStringLiteral("cloud"), oc, 40, 20), 0, Qt::AlignVCenter);
    auto* hcol = new QVBoxLayout;
    hcol->setSpacing(2);
    hcol->addWidget(ui::label(title, "h2"));
    auto* subPath = ui::elided(r.filePath.isEmpty() ? r.sha256 : evtfmt::nativePath(r.filePath), "muted");
    subPath->setElideMode(Qt::ElideMiddle);
    hcol->addWidget(subPath);
    head->addLayout(hcol, 1);
    auto* statusLbl = ui::label(QString(), "muted");
    head->addWidget(statusLbl, 0, Qt::AlignVCenter);
    head->addWidget(ui::pill(ot, oc), 0, Qt::AlignVCenter);
    shell->addLayout(head);

    auto* graph = new BehaviorGraphView;
    auto* scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setWidget(graph);
    shell->addWidget(scroll, 1);

    // 初始只用记录本身画(文件 → 判定 → 结论);打开后异步拉完整报告补全行为/检出。
    buildBehaviorGraph(graph, r, nullptr);
    auto detail = std::make_shared<bulwark::ipc::VtDetailResponsePayload>();
    const QString shaKey = r.sha256.toLower();
    if (cache && cache->contains(shaKey)) {
        *detail = cache->value(shaKey);
        buildBehaviorGraph(graph, r, detail.get()); // 缓存命中:直接补全,不再联网
    } else if (ipc && ipc->isConnected() && r.isTerminal() && r.sha256.size() == 64) {
        statusLbl->setText(u("正在联网获取完整报告…"));
        QObject::connect(ipc, &IpcClient::vtDetailReceived, dlg,
                         [cache, graph, statusLbl, r, shaKey, detail](const bulwark::ipc::VtDetailResponsePayload& d) {
            if (d.sha256.toLower() != shaKey) return;
            if (cache) (*cache)[shaKey] = d;
            *detail = d;
            statusLbl->setText(d.success ? QString() : (d.message.isEmpty() ? u("未获取到完整报告") : d.message));
            buildBehaviorGraph(graph, r, detail.get());
        });
        ipc->vtDetail(r.sha256);
    }

    auto* footer = new QHBoxLayout;
    footer->setSpacing(8);
    auto* zoomLbl = ui::button(QStringLiteral("100%"), "ghost", QString(), true);
    zoomLbl->setMinimumWidth(64);
    zoomLbl->setToolTip(u("点击恢复 100% · 滚轮缩放"));
    auto* fitBtn = ui::button(u("适应"), "ghost", QStringLiteral("maximize"), true);
    footer->addWidget(zoomLbl);
    footer->addWidget(fitBtn);
    footer->addStretch();
    // AI 清理:仅对判为恶意/可疑且有本机路径的文件提供 —— 把行为画像交给大模型生成清理方案,
    // 用户逐行复核后(提权)执行。
    if (ipc && r.isTerminal() && !r.filePath.isEmpty()
        && (r.outcome == bulwark::VtScanOutcome::Malicious || r.outcome == bulwark::VtScanOutcome::Suspicious)) {
        auto* aiCleanBtn = ui::button(u("AI 清理…"), "danger", QStringLiteral("sparkles"));
        aiCleanBtn->setToolTip(u("把该文件的行为画像交给大模型,生成清理方案;复核后再决定是否执行"));
        footer->addWidget(aiCleanBtn);
        QObject::connect(aiCleanBtn, &QPushButton::clicked, dlg, [dlg, ipc, r, detail] {
            bulwark::ipc::RemediationReportPayload rep;
            rep.actorPath = r.filePath;
            rep.reason = !r.threatLabel.isEmpty() ? r.threatLabel : u("云信誉判定为恶意 / 可疑");
            rep.intelSource = r.intelSource.isEmpty() ? QStringLiteral("VirusTotal") : r.intelSource;
            if (detail->success) {
                rep.intelDroppedFiles = detail->droppedFiles;
                rep.intelRegistryKeys = detail->registryKeys;
                rep.intelContactedIps = detail->contactedIps;
                rep.intelContactedDomains = detail->contactedDomains;
            }
            (new AiCleanupDialog(r, rep, ipc, ipc->aiScanner(), dlg))->show();
        });
    }
    auto* fullBtn = ui::button(u("最大化"), "ghost");
    footer->addWidget(fullBtn);
    auto* closeBtn = ui::button(u("关闭"), "primary");
    closeBtn->setMinimumWidth(96);
    footer->addWidget(closeBtn);
    shell->addLayout(footer);

    graph->setZoomCallback([zoomLbl](qreal z) { zoomLbl->setText(QString::number(int(z * 100 + 0.5)) + QStringLiteral("%")); });
    QObject::connect(zoomLbl, &QPushButton::clicked, dlg, [graph] { graph->setZoom(1.0); });
    QObject::connect(fitBtn, &QPushButton::clicked, dlg, [graph, scroll] { graph->fitTo(scroll->viewport()->size()); });
    QObject::connect(fullBtn, &QPushButton::clicked, dlg, [dlg, fullBtn] {
        // 最大化到工作区(不含任务栏),而不是无边框全屏 —— 后者会把底部按钮压在任务栏下面。
        if (dlg->isMaximized() || dlg->isFullScreen()) {
            dlg->showNormal();
            fullBtn->setText(u("最大化"));
        } else {
            dlg->showMaximized();
            fullBtn->setText(u("还原"));
        }
    });
    QObject::connect(closeBtn, &QPushButton::clicked, dlg, &QDialog::accept);

    dlg->resize(960, 580);
    dlg->show();

    // 自动弹出场景(查毒命中后):到时自动关闭;用户提前关掉则计时器随对话框销毁作废。
    if (autoCloseMs > 0) {
        statusLbl->setText(u("%1 秒后自动关闭").arg((autoCloseMs + 500) / 1000));
        QTimer::singleShot(autoCloseMs, dlg, [dlg] { dlg->close(); });
    }
}

// ── list rows ────────────────────────────────────────────────────────────────
RecordView recordView(const VtScanRecord& r)
{
    RecordView v;
    QColor c;
    const QString ot = outcomeText(r.outcome, c);
    v.icon = QStringLiteral("cloud");
    v.iconColor = c;
    v.title = fileNameOf(r);
    v.subtitle = r.filePath.isEmpty() ? r.sha256 : evtfmt::nativePath(r.filePath);
    v.subtitleMono = true;
    if (!r.intelSource.isEmpty())
        v.chips << r.intelSource;
    if (!r.source.isEmpty())
        v.chips << r.source;
    if (r.totalEngines > 0) {
        v.score = QStringLiteral("%1/%2").arg(r.malicious).arg(r.totalEngines);
        v.scoreColor = c;
    }
    v.pill = r.isTerminal() ? ot : stageText(r);
    v.pillColor = c;
    v.time = r.timestampUtc;
    v.accent = r.outcome == bulwark::VtScanOutcome::Malicious ? theme::danger() : QColor();
    v.tooltip = r.message;
    v.haystack = QStringList{r.fileName, r.filePath, r.sha256, r.threatLabel, r.intelSource, r.source, ot}.join(QLatin1Char(' '));
    v.key = r.id.toString(QUuid::WithoutBraces);
    return v;
}

enum Seg { SegAll = 0, SegMal, SegSus, SegClean, SegNone };

bool isSha256(const QString& s)
{
    static const QRegularExpression re(QStringLiteral("^[0-9a-fA-F]{64}$"));
    return re.match(s).hasMatch();
}

// One result line in the query card.
QWidget* resultRow(const QString& name, const QString& verdict, const QColor& color, const QString& detail)
{
    auto* w = new QWidget;
    auto* h = new QHBoxLayout(w);
    h->setContentsMargins(0, 2, 0, 2);
    h->setSpacing(10);
    h->addWidget(ui::pill(verdict, color), 0, Qt::AlignVCenter);
    auto* n = ui::elided(name, "title");
    n->setElideMode(Qt::ElideMiddle);
    n->setMaximumWidth(280);
    h->addWidget(n, 0, Qt::AlignVCenter);
    auto* d = ui::elided(detail, "muted");
    h->addWidget(d, 1, Qt::AlignVCenter);
    return w;
}

} // namespace

// 供外部(查毒命中后自动弹出)调用:打开云信誉行为关系图详情窗口。autoCloseMs>0 时到时自动关闭。
void pages::showVtDetailWindow(QWidget* parent, const bulwark::VtScanRecord& r, IpcClient* ipc, int autoCloseMs)
{
    showVtRecordDetail(parent, r, ipc, nullptr, autoCloseMs);
}

QWidget* pages::reputation(IpcClient* ipc)
{
    auto* page = new RecordBrowser;
    page->setIdentity(identity::page(nav::Reputation));
    page->setLiveTop(true);
    page->searchBox()->setPlaceholderText(u("搜索文件名 / SHA-256 / 威胁名…"));
    page->setNoDataContent(QStringLiteral("cloud"), u("还没有云查杀记录"),
                           u("双击运行的程序会自动做云端查毒;也可以把文件拖到上方手动查询。"));
    auto store = std::make_shared<RecordStore<VtScanRecord>>(page->model(), &recordView);
    auto cache = std::make_shared<DetailCache>();

    // ---- query card -------------------------------------------------------------------------------------
    auto* card = ui::card();
    card->setGlow(page->identity(), QPointF(0.0, 0.0), 0.6, 0.08); // lit like the list below it
    auto* cv = new QVBoxLayout(card);
    cv->setContentsMargins(18, 14, 18, 14);
    cv->setSpacing(10);
    auto* head = new QHBoxLayout;
    head->setSpacing(12);
    head->addWidget(new IconTile(QStringLiteral("upload"), page->identity(), 36, 18), 0, Qt::AlignVCenter);
    auto* hc = new QVBoxLayout;
    hc->setSpacing(1);
    hc->addWidget(ui::label(u("查询文件的云信誉"), "title"));
    hc->addWidget(ui::label(u("把文件拖到这里,或输入文件路径 / SHA-256"), "muted"));
    head->addLayout(hc, 1);
    cv->addLayout(head);
    auto* inputRow = new QHBoxLayout;
    inputRow->setSpacing(8);
    auto* input = new QLineEdit;
    input->setPlaceholderText(u("文件路径或 SHA-256…"));
    input->setClearButtonEnabled(true);
    input->setAccessibleName(u("要查询的文件路径或 SHA-256"));
    inputRow->addWidget(input, 1);
    auto* browse = ui::button(u("选择文件…"), "ghost", QStringLiteral("folder"));
    auto* go = ui::button(u("查询"), "primary", QStringLiteral("search"));
    inputRow->addWidget(browse);
    inputRow->addWidget(go);
    cv->addLayout(inputRow);
    auto* results = new QWidget;
    auto* resultList = new QVBoxLayout(results);
    resultList->setContentsMargins(0, 0, 0, 0);
    resultList->setSpacing(2);
    results->hide();
    cv->addWidget(results);
    // 查询链路:先问中央服务器,未收录才动用本机密钥查各情报源。
    auto* chain = new QHBoxLayout;
    chain->setSpacing(8);
    chain->addWidget(ui::label(u("查询链路"), "caption"));
    auto* step1 = ui::pill(u("① 中央服务器 · —"), theme::textMuted());
    auto* arrow = ui::label(QStringLiteral("→"), "muted");
    auto* step2 = ui::pill(u("② 本机情报源 · —"), theme::textMuted());
    step1->setToolTip(u("先向中央服务器查询这个文件是否已收录"));
    step2->setToolTip(u("中央服务器未收录时,用本机配置的密钥查询各情报源"));
    chain->addWidget(step1);
    chain->addWidget(arrow);
    chain->addWidget(step2);
    chain->addStretch(1);
    cv->addLayout(chain);
    page->addTop(card);

    // ---- queries ------------------------------------------------------------------------------------------
    auto pendingFile = std::make_shared<QHash<QUuid, QString>>(); // requestId -> path
    auto pendingSha = std::make_shared<QString>();
    const auto addResult = [results, resultList](QWidget* row) {
        results->show();
        resultList->insertWidget(0, row);
        while (resultList->count() > 5) {
            QLayoutItem* it = resultList->takeAt(resultList->count() - 1);
            if (QWidget* w = it->widget()) {
                w->hide(); // out of the layout but still painted until the deferred delete runs
                w->deleteLater();
            }
            delete it;
        }
    };
    const auto queryOne = [page, ipc, pendingFile, pendingSha, addResult](const QString& raw) {
        const QString text = raw.trimmed();
        if (text.isEmpty())
            return;
        if (!ipc->isConnected()) {
            ui::notify(page, ui::Tone::Danger, u("未连接后台服务,无法查询。"));
            return;
        }
        if (isSha256(text)) {
            *pendingSha = text.toLower();
            addResult(resultRow(text.left(16) + u("…"), u("查询中"), theme::info(), u("按哈希获取完整报告")));
            ipc->vtDetail(text.toLower());
            return;
        }
        bulwark::ipc::VtRequestPayload p;
        p.kind = bulwark::VtRequestKind::QueryFile;
        p.filePath = QDir::toNativeSeparators(text);
        pendingFile->insert(p.requestId, p.filePath);
        addResult(resultRow(QFileInfo(p.filePath).fileName(), u("查询中"), theme::info(), u("服务端计算哈希并查询")));
        ipc->vtQuery(p);
    };
    QObject::connect(go, &QPushButton::clicked, page, [input, queryOne] { queryOne(input->text()); });
    QObject::connect(input, &QLineEdit::returnPressed, page, [input, queryOne] { queryOne(input->text()); });
    QObject::connect(browse, &QPushButton::clicked, page, [page, input, queryOne] {
        const QString f = QFileDialog::getOpenFileName(page, u("选择要查询的文件"));
        if (f.isEmpty())
            return;
        input->setText(QDir::toNativeSeparators(f));
        queryOne(input->text());
    });
    ui::acceptFileDrops(card, u("松开以查询云信誉"), [input, queryOne](const QStringList& paths) {
        int n = 0;
        for (const QString& p : paths) {
            if (n++ >= 10)
                break; // a drop of a whole folder shouldn't fire hundreds of lookups
            input->setText(QDir::toNativeSeparators(p));
            queryOne(p);
        }
    }, [](const QString& p) { return QFileInfo(p).isFile(); });

    QObject::connect(ipc, &IpcClient::vtResponse, page, [pendingFile, addResult](const bulwark::ipc::VtResponsePayload& r) {
        const auto it = pendingFile->constFind(r.requestId);
        if (it == pendingFile->constEnd())
            return; // 设置页的连接测试等,与本页无关
        const QString name = QFileInfo(it.value()).fileName();
        pendingFile->remove(r.requestId);
        if (!r.success || !r.reputation.has_value()) {
            addResult(resultRow(name, u("未获结论"), theme::textMuted(), r.message));
            return;
        }
        const bulwark::FileReputation& rep = *r.reputation;
        QString verdict = u("未收录");
        QColor c = theme::textMuted();
        switch (rep.verdict) {
        case bulwark::ReputationVerdict::Malicious:  verdict = u("恶意"); c = theme::danger(); break;
        case bulwark::ReputationVerdict::Suspicious: verdict = u("可疑"); c = theme::warning(); break;
        case bulwark::ReputationVerdict::Clean:      verdict = u("干净"); c = theme::success(); break;
        case bulwark::ReputationVerdict::Unknown:    break;
        }
        QStringList parts;
        if (rep.totalEngines > 0)
            parts << u("%1/%2 引擎检出").arg(rep.malicious).arg(rep.totalEngines);
        if (!rep.threatLabel.isEmpty())
            parts << rep.threatLabel;
        if (!rep.source.isEmpty())
            parts << u("来源 ") + rep.source;
        parts << rep.sha256.left(12) + u("…");
        addResult(resultRow(name, verdict, c, parts.join(u(" · "))));
    });
    QObject::connect(ipc, &IpcClient::vtDetailReceived, page,
                     [pendingSha, addResult, cache](const bulwark::ipc::VtDetailResponsePayload& d) {
        if (pendingSha->isEmpty() || d.sha256.toLower() != *pendingSha)
            return; // 详情窗口自己的请求
        pendingSha->clear();
        (*cache)[d.sha256.toLower()] = d;
        if (!d.success) {
            addResult(resultRow(d.sha256.left(16) + u("…"), u("未获结论"), theme::textMuted(), d.message));
            return;
        }
        const QColor c = d.malicious > 0 ? theme::danger() : theme::success();
        QStringList parts;
        if (d.totalEngines > 0)
            parts << u("%1/%2 引擎检出").arg(d.malicious).arg(d.totalEngines);
        if (!d.threatLabel.isEmpty())
            parts << d.threatLabel;
        if (!d.typeDescription.isEmpty())
            parts << d.typeDescription;
        addResult(resultRow(d.knownNames.isEmpty() ? d.sha256.left(16) + u("…") : d.knownNames.first(),
                            d.malicious > 0 ? u("恶意") : u("未见检出"), c, parts.join(u(" · "))));
    });
    QObject::connect(ipc, &IpcClient::settingsReceived, page, [step1, step2](const bulwark::RuntimeSettings& s) {
        ui::stylePill(step1, u("① 中央服务器 · 启用"), theme::success());
        int on = 0;
        for (bool b : {s.virusTotalEnabled, s.malwareBazaarEnabled, s.otxEnabled, s.threatBookEnabled,
                       s.metaDefenderEnabled, s.hybridAnalysisEnabled})
            on += b ? 1 : 0;
        if (s.cloudServerOnly)
            ui::stylePill(step2, u("② 本机情报源 · 策略停用"), theme::warning());
        else if (on > 0)
            ui::stylePill(step2, u("② 本机情报源 · %1 个已启用").arg(on), theme::success());
        else
            ui::stylePill(step2, u("② 本机情报源 · 未启用"), theme::textMuted());
    });

    // ---- history list ---------------------------------------------------------------------------------------
    Segmented* seg = page->segments();
    for (const char* t : {"全部", "恶意", "可疑", "干净", "未收录 / 失败"})
        seg->addSegment(u(t));
    seg->setAccent(SegMal, theme::danger());
    seg->setAccent(SegSus, theme::warning());
    page->setPredicate([store, seg](int row) {
        const VtScanRecord* r = store->itemAt(row);
        if (!r)
            return true;
        using O = bulwark::VtScanOutcome;
        switch (seg->currentIndex()) {
        case SegMal:   return r->outcome == O::Malicious;
        case SegSus:   return r->outcome == O::Suspicious;
        case SegClean: return r->outcome == O::Clean;
        case SegNone:  return r->outcome == O::Unknown || r->outcome == O::Error;
        default:       return true;
        }
    });
    page->setClearFilters([seg] { seg->setCurrentIndex(SegAll); });
    QObject::connect(seg, &Segmented::currentChanged, page, [page] { page->refilter(); });
    const auto updateCounts = [store, seg] {
        int n[5] = {0, 0, 0, 0, 0};
        for (const VtScanRecord& r : store->items()) {
            using O = bulwark::VtScanOutcome;
            ++n[SegAll];
            if (r.outcome == O::Malicious) ++n[SegMal];
            else if (r.outcome == O::Suspicious) ++n[SegSus];
            else if (r.outcome == O::Clean) ++n[SegClean];
            else if (r.outcome == O::Unknown || r.outcome == O::Error) ++n[SegNone];
        }
        for (int i = 0; i < 5; ++i)
            seg->setCount(i, n[i]);
    };

    page->setInspectorBuilder([store, ipc, cache, page](Inspector* in, int row) {
        const VtScanRecord* rp = store->itemAt(row);
        if (!rp)
            return;
        const VtScanRecord r = *rp;
        QColor c;
        const QString ot = outcomeText(r.outcome, c);
        in->setHeader(QStringLiteral("cloud"), c, fileNameOf(r),
                      r.isTerminal() ? ot : stageText(r));
        QString lead;
        using O = bulwark::VtScanOutcome;
        if (!r.isTerminal())
            lead = u("云查杀进行中:") + stageText(r) + u("。");
        else if (r.outcome == O::Malicious || r.outcome == O::Suspicious)
            lead = u("云端判定为%1").arg(ot)
                 + (r.totalEngines > 0 ? u(":%1/%2 个引擎检出").arg(r.malicious).arg(r.totalEngines) : QString())
                 + (r.threatLabel.isEmpty() ? QString() : u("(%1)").arg(r.threatLabel)) + u("。");
        else if (r.outcome == O::Clean)
            lead = u("云端没有发现问题") + (r.totalEngines > 0 ? u(":%1 个引擎均未检出。").arg(r.totalEngines) : u("。"));
        else if (r.outcome == O::Unknown)
            lead = u("云端没有这个文件的记录(未收录)。");
        else
            lead = u("这次查询没有完成:") + (r.message.isEmpty() ? u("原因未知。") : r.message);
        in->addLead(lead);
        QVBoxLayout* s = in->addSection(u("结论"));
        in->addField(s, r.isTerminal() ? u("判定") : u("状态"), r.isTerminal() ? ot : stageText(r));
        in->addField(s, u("检出"), r.totalEngines > 0 ? u("%1 / %2 个引擎").arg(r.malicious).arg(r.totalEngines) : QString());
        in->addField(s, u("威胁名"), r.threatLabel);
        in->addField(s, u("结论来源"), r.intelSource);
        in->addField(s, u("触发来源"), r.source);
        in->addField(s, u("上传扫描"), r.uploaded ? u("是(云端未收录,已上传)") : u("否"));
        if (!r.message.isEmpty())
            in->addField(s, u("说明"), r.message);
        s = in->addSection(u("文件"));
        in->addField(s, u("路径"), evtfmt::nativePath(r.filePath), Inspector::Mono | Inspector::Copy);
        in->addField(s, QStringLiteral("SHA-256"), r.sha256, Inspector::Mono | Inspector::Copy);
        in->addField(s, u("时间"), fmt::absoluteTime(r.timestampUtc));

        in->addAction(QStringLiteral("link"), u("行为关系图"), "ghost",
                      [page, r, ipc, cache] { showVtRecordDetail(page, r, ipc, cache); });
        if (r.isTerminal() && !r.filePath.isEmpty() && (r.outcome == O::Malicious || r.outcome == O::Suspicious))
            in->addAction(QStringLiteral("sparkles"), u("AI 清理…"), "danger", [page, r, ipc] {
                bulwark::ipc::RemediationReportPayload rep;
                rep.actorPath = r.filePath;
                rep.reason = !r.threatLabel.isEmpty() ? r.threatLabel : u("云信誉判定为恶意 / 可疑");
                rep.intelSource = r.intelSource;
                (new AiCleanupDialog(r, rep, ipc, ipc->aiScanner(), page->window()))->show();
            });
        auto* menu = new QMenu;
        if (!r.sha256.isEmpty())
            pagekit::menuAction(menu, QStringLiteral("copy"), u("复制 SHA-256"), in, [sha = r.sha256] {
                if (QClipboard* cb = QGuiApplication::clipboard())
                    cb->setText(sha);
            });
        in->addMenu(menu);
    });
    page->setActivateHandler([page, store, ipc, cache](int row) {
        if (const VtScanRecord* r = store->itemAt(row))
            showVtRecordDetail(page, *r, ipc, cache);
    });

    QObject::connect(ipc, &IpcClient::vtHistoryReceived, page, [page, store, updateCounts](const QList<VtScanRecord>& records) {
        QList<VtScanRecord> list = records;
        std::stable_sort(list.begin(), list.end(),
                         [](const VtScanRecord& a, const VtScanRecord& b) { return a.timestampUtc > b.timestampUtc; });
        store->reset(list);
        page->setLoading(false);
        updateCounts();
    });
    // 实时进度:同一条记录随阶段多次推送(以 id 关联),原地更新;新记录插到最上面。
    QObject::connect(ipc, &IpcClient::vtScanUpdate, page, [store, updateCounts](const VtScanRecord& r) {
        const QList<VtScanRecord>& items = store->items();
        for (int i = 0; i < items.size(); ++i)
            if (items[i].id == r.id) {
                store->update(i, r);
                updateCounts();
                return;
            }
        store->prepend(r);
        updateCounts();
    });
    pagekit::onConnected(page, ipc, page, 0, [page, ipc] {
        if (!ipc->isConnected())
            return;
        page->setLoading(true);
        ipc->requestVtHistory();
        ipc->requestSettings();
    });

    // nav::go("reputation", {sha256, path}):按哈希查(文件可能已不在原处,例如被隔离)。
    nav::onArrive(page, QString::fromLatin1(nav::Reputation), [input, queryOne](const QVariantMap& args) {
        const QString sha = args.value(QStringLiteral("sha256")).toString();
        const QString path = args.value(QStringLiteral("path")).toString();
        const QString q = !sha.isEmpty() ? sha : path;
        if (q.isEmpty())
            return;
        input->setText(q);
        queryOne(q);
    });
    updateCounts();
    return page;
}
