#include "dialogs/ScanProgressWindow.h"
#include "ai/AiScanner.h" // AiScanResult
#include "widgets/AppIcon.h"
#include "widgets/Cards.h"
#include "widgets/Ui.h"
#include "Theme.h"

#include "bulwark/models/SecurityEvent.h"

#include <QFileInfo>
#include <QGraphicsDropShadowEffect>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QHash>
#include <QLabel>
#include <QMouseEvent>
#include <QProgressBar>
#include <QPropertyAnimation>
#include <QQueue>
#include <QScreen>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>

namespace {

QString u(const char* s) { return QString::fromUtf8(s); }

constexpr int kEstimateSeconds = 120; // initial "预计等待" estimate (VT upload+analyze can take minutes)
constexpr int kMaxQueued = 12;
constexpr int kFallbackCloseMs = 330000; // hard close if no terminal update arrives (~5.5 min)

// Rounded progress bar with a themed chunk colour.
QString barStyle(const QColor& chunk)
{
    return QStringLiteral(
        "QProgressBar{background:%1; border:none; border-radius:4px; min-height:8px; max-height:8px;}"
        "QProgressBar::chunk{background:%2; border-radius:4px;}")
        .arg(theme::surfaceAlt().name(), chunk.name());
}

// Single-visible + queue registry, keyed by file path (see header).
QHash<QString, ScanProgressWindow*> g_byKey;
ScanProgressWindow* g_active = nullptr;
QQueue<ScanProgressWindow*> g_queue;

} // namespace

ScanProgressWindow::ScanProgressWindow(const QString& key, const QString& fileName)
    : QWidget(nullptr), m_key(key)
{
    // Frameless, on-top, never activates (won't steal focus from the user's work).
    setWindowFlags(Qt::FramelessWindowHint | Qt::Tool | Qt::WindowStaysOnTopHint);
    setAttribute(Qt::WA_TranslucentBackground);
    setAttribute(Qt::WA_ShowWithoutActivating);
    setFixedWidth(468);

    auto* shell = new QVBoxLayout(this);
    shell->setContentsMargins(18, 16, 18, 22); // room for the drop shadow

    auto* cardW = ui::card();
    auto* shadow = new QGraphicsDropShadowEffect(cardW);
    shadow->setBlurRadius(48);
    shadow->setOffset(0, 14);
    shadow->setColor(QColor(15, 23, 42, 105));
    cardW->setGraphicsEffect(shadow);
    shell->addWidget(cardW);

    auto* v = new QVBoxLayout(cardW);
    v->setContentsMargins(22, 20, 22, 20);
    v->setSpacing(14);

    // Row: state badge | (title + close, file name).
    m_row = new QHBoxLayout;
    m_row->setSpacing(14);
    m_badge = ui::iconBadge(QStringLiteral("cloud"), theme::accent(), 52, 26);
    m_row->addWidget(m_badge, 0, Qt::AlignTop);

    auto* col = new QVBoxLayout;
    col->setSpacing(4);

    auto* titleRow = new QHBoxLayout;
    titleRow->setSpacing(8);
    m_title = ui::coloredText(u("正在云端查毒…"), 14, 800, theme::textPrimary());
    // 标题允许换行:14pt 粗体下,固定 468 宽减去徽标/边距/关闭按钮后留给标题的横向空间有限,
    // 不换行的 QLabel 会被布局压窄并直接截字(「检测到威胁,已处置」尾字被切)。换行 + relayout
    // 保证完整显示;宁可多一行,也不要让用户看半句结论。
    m_title->setWordWrap(true);
    // 标题吃掉剩余横向空间(关闭按钮固定大小),故不再需要额外的 addStretch。
    titleRow->addWidget(m_title, 1);
    auto* closeBtn = new QToolButton;
    closeBtn->setIcon(AppIcon::icon(QStringLiteral("close"), theme::textMuted(), 16));
    closeBtn->setCursor(Qt::PointingHandCursor);
    closeBtn->setAutoRaise(true);
    closeBtn->setStyleSheet(QStringLiteral(
        "QToolButton{border:none;background:transparent;padding:2px;}"
        "QToolButton:hover{background:%1;border-radius:6px;}").arg(theme::surfaceAlt().name()));
    connect(closeBtn, &QToolButton::clicked, this, [this] { beginClose(); });
    titleRow->addWidget(closeBtn, 0, Qt::AlignTop);
    col->addLayout(titleRow);

    m_file = ui::elided(fileName, "secondary");
    col->addWidget(m_file);
    m_row->addLayout(col, 1);
    v->addLayout(m_row);

    // Progress bar (indeterminate until an upload % arrives).
    m_bar = new QProgressBar;
    m_bar->setTextVisible(false);
    m_bar->setRange(0, 0);
    m_bar->setStyleSheet(barStyle(theme::accent()));
    v->addWidget(m_bar);

    // Status row: stage message (left) + countdown (right).
    auto* statusRow = new QHBoxLayout;
    statusRow->setSpacing(10);
    // 占位文案必须与来源无关:真正的阶段文案由服务逐阶段推来(「正在查询中央服务器是否已收录…」
    // /「服务器未收录,正在查询 VirusTotal…」…),这里写死 VirusTotal 会在卡片刚建、第一条推送
    // 还没到的那一瞬间谎报查询对象 —— 而这张卡片唯一能说明「云查到底先问了谁」的就是这行字。
    m_status = ui::label(u("正在查询云端信誉…"), "muted");
    m_status->setWordWrap(true);
    statusRow->addWidget(m_status, 1);
    m_countdown = ui::coloredText(u("预计等待 ") + QString::number(kEstimateSeconds) + u(" 秒"),
                                  10, 600, theme::textMuted());
    statusRow->addWidget(m_countdown, 0, Qt::AlignRight | Qt::AlignVCenter);
    v->addLayout(statusRow);

    m_countdownTimer = new QTimer(this);
    m_countdownTimer->setInterval(1000);
    connect(m_countdownTimer, &QTimer::timeout, this, [this] {
        if (m_resultShown) { m_countdownTimer->stop(); return; }
        m_remaining = qMax(0, m_remaining - 1);
        m_countdown->setText(m_remaining > 0
                                 ? u("预计等待 ") + QString::number(m_remaining) + u(" 秒")
                                 : u("即将完成…"));
    });

    m_autoClose = new QTimer(this);
    m_autoClose->setSingleShot(true);
    connect(m_autoClose, &QTimer::timeout, this, [this] { beginClose(); });

    adjustSize();
}

QString ScanProgressWindow::keyFor(const QString& path, const QUuid& id)
{
    const QString p = path.trimmed();
    return !p.isEmpty() ? p.toLower() : (QStringLiteral("id:") + id.toString(QUuid::WithoutBraces));
}

ScanProgressWindow* ScanProgressWindow::obtain(const QString& key, const QString& fileName)
{
    const auto it = g_byKey.constFind(key);
    if (it != g_byKey.constEnd())
        return it.value(); // reuse the card for this file (VT + AI share it)

    auto* w = new ScanProgressWindow(key, fileName);
    g_byKey.insert(key, w);
    if (g_active == nullptr) {
        g_active = w;
        w->showCentered();
    } else {
        if (g_queue.size() >= kMaxQueued) {
            ScanProgressWindow* old = g_queue.dequeue();
            if (old) { g_byKey.remove(old->m_key); old->deleteLater(); }
        }
        g_queue.enqueue(w);
    }
    return w;
}

void ScanProgressWindow::promoteNext()
{
    if (g_active != nullptr)
        return;
    while (!g_queue.isEmpty()) {
        ScanProgressWindow* next = g_queue.dequeue();
        if (next) { g_active = next; next->showCentered(); return; }
    }
}

void ScanProgressWindow::showCentered()
{
    if (m_closing)
        return;
    refitHeight(); // 与 relayout() 用同一套高度计算,避免两处口径不一致
    recenter();
    setWindowOpacity(0.0);
    show();
    auto* fade = new QPropertyAnimation(this, "windowOpacity", this);
    fade->setDuration(200);
    fade->setStartValue(0.0);
    fade->setEndValue(1.0);
    fade->start(QAbstractAnimation::DeleteWhenStopped);
    startCountdown();
    // Hard fallback: close even if no terminal update ever arrives (service died, etc.).
    QTimer::singleShot(kFallbackCloseMs, this, [this] {
        if (!m_resultShown && !m_closing) beginClose();
    });
}

bool ScanProgressWindow::refitHeight()
{
    QLayout* l = layout();
    if (l)
        l->activate(); // 先把换行结果算进布局,再问高度
    // 固定宽度 + 自动换行的 QLabel:直接拿 sizeHint().height() 并不可靠 —— 换行标签在宽度
    // 确定前会低报所需高度,这正是「结论被裁掉」的根因之一。按当前宽度问 heightForWidth 才准,
    // 拿不到时才退回 sizeHint。
    int h = -1;
    if (l && l->hasHeightForWidth())
        h = l->totalHeightForWidth(width());
    if (h <= 0)
        h = sizeHint().height();
    if (h <= 0 || h == height())
        return false;
    resize(width(), h);
    return true;
}

void ScanProgressWindow::recenter()
{
    QScreen* scr = QGuiApplication::primaryScreen();
    const QRect area = scr ? scr->availableGeometry() : QRect(0, 0, 1920, 1080);
    move(area.center().x() - width() / 2, area.center().y() - height() / 2);
}

void ScanProgressWindow::relayout()
{
    if (m_closing)
        return;
    if (!refitHeight())
        return;          // 高度没变:不动窗口,免得每条进度更新都抖一下
    if (!isVisible())
        return;          // 还没显示:定位由 showCentered() 负责
    recenter();
}

void ScanProgressWindow::startCountdown()
{
    if (m_resultShown)
        return;
    m_countdownTimer->start();
}

void ScanProgressWindow::setBadge(const QString& iconName, const QColor& color)
{
    if (m_badge) {
        m_row->removeWidget(m_badge);
        m_badge->deleteLater();
    }
    m_badge = ui::iconBadge(iconName, color, 52, 26);
    m_row->insertWidget(0, m_badge, 0, Qt::AlignTop);
}

void ScanProgressWindow::applyVt(const bulwark::VtScanRecord& r)
{
    if (m_resultShown)
        return;

    if (!r.isTerminal()) {
        m_title->setText(u("正在云端查毒…"));
        if (!r.message.isEmpty())
            m_status->setText(r.message);
        if (r.stage == bulwark::VtScanStage::Uploading && r.percent > 0) {
            m_bar->setRange(0, 100);
            m_bar->setValue(r.percent);
            m_countdown->setText(u("上传中 ") + QString::number(r.percent) + u("%"));
        } else {
            m_bar->setRange(0, 0); // indeterminate
        }
        relayout(); // 各阶段提示长短不一(分级链路的「正在查询中央服务器…」等),跟着调整高度
        return;
    }

    // Terminal: map the outcome to a colour-coded result.
    const bool malicious = r.outcome == bulwark::VtScanOutcome::Malicious;
    const bool conclusive = r.outcome == bulwark::VtScanOutcome::Clean
                            || r.outcome == bulwark::VtScanOutcome::Suspicious
                            || r.outcome == bulwark::VtScanOutcome::Malicious;
    const QColor accent = malicious ? theme::danger() : conclusive ? theme::success() : theme::warning();
    const QString icon = malicious ? QStringLiteral("shield-x")
                         : conclusive ? QStringLiteral("check")
                                      : QStringLiteral("alert");
    const QString title = malicious ? u("检测到威胁,已处置")
                          : conclusive ? u("未发现风险,文件安全")
                                       : u("检测未完成");
    // 兜底文案(服务未附 message 时)。同样不点名 VirusTotal:结论可能来自中央服务器的收录、
    // 本机直连 VT,或其他情报源;有 intelSource 就如实标出是谁给的。
    QString status = r.message;
    if (status.isEmpty()) {
        const QString by = r.intelSource.trimmed().isEmpty()
                               ? u("云端多引擎")
                               : r.intelSource.trimmed();
        status = malicious ? (by + u(" 判定该文件为恶意,已结束进程并隔离。"))
                 : conclusive ? (by + u(" 未判定为恶意,文件可放心使用。"))
                              : u("云查毒未收录 / 无明确结论,已按放行处理。");
    }
    applyResult(accent, icon, title, status, malicious ? 10 : 6);
}

void ScanProgressWindow::applyResult(const QColor& accent, const QString& iconName,
                                     const QString& title, const QString& status, int autoCloseSecs)
{
    if (m_resultShown)
        return;
    m_resultShown = true;
    m_countdownTimer->stop();

    setBadge(iconName, accent);
    m_title->setText(title);
    m_title->setStyleSheet(QStringLiteral("font-size:14pt; font-weight:800; color:%1;").arg(accent.name()));
    m_bar->setRange(0, 100);
    m_bar->setValue(100);
    m_bar->setStyleSheet(barStyle(accent));
    m_status->setText(status);
    m_countdown->setVisible(false);
    // 结论文案通常比占位文案长(「恶意 · 18/66 · trojan.xxx · 来源 X」会换到第二行),
    // 且此时倒计时标签刚被隐藏 —— 两者都改变了所需高度,必须重算,否则卡片高度还停在
    // 建卡时那一行的尺寸,结论会被裁掉。
    relayout();

    m_autoClose->start(qMax(3, autoCloseSecs) * 1000);
}

void ScanProgressWindow::beginClose()
{
    if (m_closing)
        return;
    m_closing = true;
    m_countdownTimer->stop();
    m_autoClose->stop();

    // Detach from the registry immediately so a new scan for the same file starts fresh.
    if (g_byKey.value(m_key) == this)
        g_byKey.remove(m_key);
    const bool wasActive = (g_active == this);
    if (wasActive)
        g_active = nullptr;
    else
        g_queue.removeAll(this);

    auto* fade = new QPropertyAnimation(this, "windowOpacity", this);
    fade->setDuration(200);
    fade->setStartValue(windowOpacity());
    fade->setEndValue(0.0);
    connect(fade, &QPropertyAnimation::finished, this, [this, wasActive] {
        if (wasActive)
            promoteNext();
        deleteLater();
    });
    fade->start(QAbstractAnimation::DeleteWhenStopped);
}

void ScanProgressWindow::mousePressEvent(QMouseEvent* e)
{
    // Only dismiss on click once a result is shown (avoids closing mid-scan by accident).
    if (e->button() == Qt::LeftButton && m_resultShown)
        beginClose();
    QWidget::mousePressEvent(e);
}

// ---- static entry points -------------------------------------------------

void ScanProgressWindow::vtUpdate(const bulwark::VtScanRecord& record)
{
    const QString key = keyFor(record.filePath, record.id);
    const QString name = !record.fileName.isEmpty()
                             ? record.fileName
                             : QFileInfo(record.filePath).fileName();
    ScanProgressWindow* w = obtain(key, name.isEmpty() ? record.filePath : name);
    w->applyVt(record);
}

void ScanProgressWindow::aiStart(const bulwark::SecurityEvent& event)
{
    const QString key = keyFor(event.actorPath, event.id);
    const QString name = QFileInfo(event.actorPath).fileName();
    ScanProgressWindow* w = obtain(key, name.isEmpty() ? event.actorPath : name);
    if (!w->m_resultShown) {
        w->m_title->setText(u("AI 研判中…"));
        if (w->m_status->text().isEmpty() || w->m_status->text().startsWith(u("正在查询")))
            w->m_status->setText(u("大模型正在基于静态特征研判…"));
        w->m_bar->setRange(0, 0);
        w->relayout();
    }
}

void ScanProgressWindow::aiResult(const AiScanResult& result)
{
    // Only update an existing card (auto double-click scans). Manual scans are
    // shown in the AI research page, not this transient card.
    const QString key = keyFor(result.filePath, result.eventId);
    const auto it = g_byKey.constFind(key);
    if (it == g_byKey.constEnd())
        return;
    ScanProgressWindow* w = it.value();
    if (w->m_resultShown)
        return;

    const bool available = result.available;
    const bool malicious = available && (result.malicious
                                         || result.recommendation == bulwark::VerdictAction::Block);
    const QColor accent = malicious ? theme::danger() : available ? theme::success() : theme::warning();
    const QString icon = malicious ? QStringLiteral("shield-x")
                         : available ? QStringLiteral("check")
                                     : QStringLiteral("alert");
    const QString title = !available ? u("检测未完成")
                          : malicious ? u("检测到威胁,已处置")
                                      : u("未发现风险,文件安全");
    QString status = result.summary;
    if (status.isEmpty())
        status = !available ? u("AI 引擎不可用 / 超时,已按放行处理。")
                 : malicious ? u("AI 研判该文件具有恶意特征,已结束进程并隔离。")
                             : u("AI 研判未发现明显恶意特征,文件可放心使用。");
    w->applyResult(accent, icon, title, status, malicious ? 10 : 6);
}
