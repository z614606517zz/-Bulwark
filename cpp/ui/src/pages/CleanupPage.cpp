#include "pages/CleanupPage.h"
#include "ipc/IpcClient.h"
#include "widgets/TableKit.h"
#include "widgets/Ui.h"
#include "Theme.h"

#include <QComboBox>
#include <QDir>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLocale>
#include <QMessageBox>
#include <QProcess>
#include <QPushButton>
#include <QShowEvent>
#include <QTabWidget>
#include <QTableWidget>
#include <QTreeWidget>
#include <QVBoxLayout>

namespace {

QString u(const char* s) { return QString::fromUtf8(s); }

// 体积展示统一走这里。QLocale 的传统格式(KB/MB/GB,1024 进制)与资源管理器一致 ——
// 清理工具报的数跟系统属性页对不上会立刻让人怀疑它在虚报。
QString human(qint64 bytes) {
    if (bytes <= 0)
        return QStringLiteral("0 B");
    return QLocale().formattedDataSize(bytes, 2, QLocale::DataSizeTraditionalFormat);
}

QString riskLabel(bulwark::junk::Risk r) {
    return r == bulwark::junk::Risk::Safe ? u("可安全清理") : u("留意副作用");
}

QColor riskColor(bulwark::junk::Risk r) {
    return r == bulwark::junk::Risk::Safe ? theme::success() : theme::warning();
}

// 列序。第 0 列带复选框与类别名。
enum Col { ColName = 0, ColSize, ColFiles, ColRisk, ColNote, ColCount };

} // namespace

CleanupPage::CleanupPage(IpcClient* ipc, QWidget* parent)
    : QWidget(parent), m_ipc(ipc)
{
    // 两个标签共用一个导航项:它们回答的是同一个问题(磁盘空间去哪了),但办法不同 ——
    // 一个按类别清缓存,一个把最大的文件摊出来让用户自己决定。分成两个侧边栏项会让人
    // 以为是两件不相干的事。
    auto* outer = new QVBoxLayout(this);
    outer->setContentsMargins(0, 0, 0, 0);
    m_tabs = new QTabWidget;
    m_tabs->addTab(buildCategoryTab(), u("按类别清理"));
    m_tabs->addTab(buildLargeFileTab(), u("大文件"));
    outer->addWidget(m_tabs);

    connect(m_ipc, &IpcClient::junkScanReceived, this, &CleanupPage::applyScan);
    connect(m_ipc, &IpcClient::junkCleanDone, this, &CleanupPage::applyClean);
    connect(m_ipc, &IpcClient::largeFilesReceived, this, &CleanupPage::applyLargeFiles);
    connect(m_ipc, &IpcClient::junkProgress, this,
            [this](const bulwark::ipc::JunkProgressPayload& p) {
                // 只认自己发出去的那次请求的进度 —— 服务端是广播,多开一个界面时不该串。
                const bool mine = (p.requestId == m_pendingScan || p.requestId == m_pendingClean);
                const bool mineLarge = (p.requestId == m_pendingLarge);
                if (!mine && !mineLarge)
                    return;
                QString line;
                if (mineLarge) {
                    line = QStringLiteral("%1 (%2/%3):已检视 %4 个文件 · %5")
                               .arg(u("正在扫描"))
                               .arg(p.categoryIndex).arg(p.categoryTotal)
                               .arg(p.filesSoFar)
                               .arg(p.currentPath);
                    m_bigStatus->setText(line);
                    return;
                }
                const QString verb = p.cleaning ? u("正在清理") : u("正在扫描");
                line = QStringLiteral("%1 (%2/%3):%4")
                           .arg(verb).arg(p.categoryIndex).arg(p.categoryTotal)
                           .arg(p.categoryTitle);
                if (p.filesSoFar > 0)
                    line += QStringLiteral(" · %1 / %2 个文件")
                                .arg(human(p.bytesSoFar)).arg(p.filesSoFar);
                if (!p.currentPath.isEmpty())
                    line += QStringLiteral(" · %1").arg(p.currentPath);
                m_status->setText(line);
            });
    // 断链时把进行中的请求作废,免得重连后收到一份对不上的回执。
    connect(m_ipc, &IpcClient::connectionChanged, this, [this](bool up) {
        if (up)
            return;
        m_pendingScan = QUuid();
        m_pendingClean = QUuid();
        m_pendingLarge = QUuid();
        setBusy(false, QString());
        m_status->setText(u("与服务的连接已断开。"));
        m_bigScanBtn->setEnabled(true);
    });
}

QWidget* CleanupPage::buildCategoryTab()
{
    auto* page = new QWidget;
    auto* v = new QVBoxLayout(page);
    v->setContentsMargins(theme::metric::pagePad, 22, theme::metric::pagePad, theme::metric::pagePad);
    v->setSpacing(16);

    // ---- 顶部汇总卡:可释放空间 + 操作按钮 ----
    auto* head = ui::card();
    {
        auto* h = new QHBoxLayout(head);
        h->setContentsMargins(22, 18, 22, 18);
        h->setSpacing(18);

        auto* left = new QVBoxLayout;
        left->setSpacing(4);
        auto* cap = ui::label(u("可释放空间"), "muted");
        m_total = ui::label(QStringLiteral("—"));
        m_total->setStyleSheet(QStringLiteral("font-size:26pt; font-weight:700; color:%1;")
                                   .arg(theme::textPrimary().name()));
        m_selected = ui::label(u("尚未扫描"), "secondary");
        left->addWidget(cap);
        left->addWidget(m_total);
        left->addWidget(m_selected);
        h->addLayout(left);
        h->addStretch();

        auto* right = new QVBoxLayout;
        right->setSpacing(8);
        auto* btns = new QHBoxLayout;
        btns->setSpacing(10);
        m_scanBtn = ui::toolButton(QStringLiteral("refresh"), u("重新扫描"), "ghost",
                                   theme::textSecondary());
        m_cleanBtn = ui::toolButton(QStringLiteral("trash"), u("清理选中项"), "primary",
                                    theme::accentInk());
        m_cleanBtn->setEnabled(false);
        btns->addStretch();
        btns->addWidget(m_scanBtn);
        btns->addWidget(m_cleanBtn);
        right->addLayout(btns);
        m_policy = ui::label(QString(), "muted");
        m_policy->setAlignment(Qt::AlignRight);
        right->addWidget(m_policy);
        h->addLayout(right);
    }
    v->addWidget(head);

    // ---- 状态 / 进度一行 ----
    m_status = ui::label(u("点「重新扫描」开始检查可清理的内容。"), "secondary");
    v->addWidget(m_status);

    // ---- 类别树 ----
    m_tree = new QTreeWidget;
    m_tree->setColumnCount(ColCount);
    m_tree->setHeaderLabels({ u("类别"), u("大小"), u("文件数"), u("风险"), u("说明") });
    m_tree->setRootIsDecorated(true);
    m_tree->setAlternatingRowColors(true);
    m_tree->setSelectionMode(QAbstractItemView::NoSelection);
    m_tree->setFocusPolicy(Qt::NoFocus);
    m_tree->setUniformRowHeights(false);
    m_tree->header()->setSectionResizeMode(QHeaderView::Interactive);
    m_tree->header()->setStretchLastSection(true);
    m_tree->setColumnWidth(ColName, 260);
    m_tree->setColumnWidth(ColSize, 110);
    m_tree->setColumnWidth(ColFiles, 92);
    m_tree->setColumnWidth(ColRisk, 110);
    // 位置明细里可能出现「N 个子目录无权限读取」这种较长的说明,给说明列留足空间。
    m_tree->setColumnWidth(ColNote, 460);
    v->addWidget(m_tree, 1);

    // ---- 底部说明:把「我们不会碰什么」明确写出来 ----
    auto* foot = ui::label(
        u("清理范围固定在程序内部,不接受任何外部指定的路径。以下位置永远不会被触碰:"
          "文档 / 桌面 / 图片 / 视频 / 下载、系统关键目录、隔离区,以及你加入信任名单的位置。"
          "被占用的文件会跳过而不是强制删除。"),
        "muted");
    foot->setWordWrap(true);
    v->addWidget(foot);

    connect(m_scanBtn, &QPushButton::clicked, this, &CleanupPage::startScan);
    connect(m_cleanBtn, &QPushButton::clicked, this, &CleanupPage::startClean);

    // 勾选变化 -> 重算「已选中」与按钮可用性。
    connect(m_tree, &QTreeWidget::itemChanged, this, [this](QTreeWidgetItem* it, int col) {
        if (col == ColName && it && !it->parent())
            refreshTotals();
    });
    return page;
}

// ---------------------------- 大文件页 ----------------------------
//
// 这一页【没有删除按钮】,只有「打开所在位置」。它列出的是任意路径上的任意文件,给它配一个
// 删除按钮就等于把整条链路变成任意文件删除原语,与「按类别清理」那边「只收类别序号、绝不
// 收路径」的设计直接矛盾。让用户在资源管理器里自己处置,是刻意的边界。
QWidget* CleanupPage::buildLargeFileTab()
{
    auto* page = new QWidget;
    auto* v = new QVBoxLayout(page);
    v->setContentsMargins(theme::metric::pagePad, 22, theme::metric::pagePad, theme::metric::pagePad);
    v->setSpacing(14);

    auto* tb = new QHBoxLayout;
    tb->setSpacing(10);
    m_bigThreshold = new QComboBox;
    m_bigThreshold->addItem(u("大于 100 MB"), static_cast<qint64>(100) * 1024 * 1024);
    m_bigThreshold->addItem(u("大于 500 MB"), static_cast<qint64>(500) * 1024 * 1024);
    m_bigThreshold->addItem(u("大于 1 GB"), static_cast<qint64>(1024) * 1024 * 1024);
    m_bigThreshold->addItem(u("大于 50 MB"), static_cast<qint64>(50) * 1024 * 1024);
    m_bigThreshold->setFixedWidth(140);
    m_bigScanBtn = ui::toolButton(QStringLiteral("search"), u("查找大文件"), "primary",
                                  theme::accentInk());
    tb->addWidget(m_bigThreshold);
    tb->addWidget(m_bigScanBtn);
    tb->addStretch();
    m_bigStatus = ui::label(u("点「查找大文件」扫描本机固定磁盘。"), "secondary");
    tb->addWidget(m_bigStatus);
    v->addLayout(tb);

    m_bigTable = ui::table({ u("文件"), u("大小"), u("修改时间"), u("类型"), u("操作") });
    ui::columns(m_bigTable, QStringLiteral("largefiles"), {
        {460, 4, true},   // 路径(最长)
        {110, 0},         // 大小
        {150, 0},         // 修改时间
        { 90, 0},         // 类型
        {130, 0},         // 操作
    });
    v->addWidget(m_bigTable, 1);

    auto* foot = ui::label(
        u("本页只查看、不删除 —— 它列出的是磁盘上任意位置的文件,若在这里提供删除按钮,"
          "整个功能就变成了「按路径删任意文件」,与「按类别清理」只接受固定类别的设计相矛盾。"
          "请用「打开所在位置」在资源管理器里自行处置。休眠文件与页面文件请用系统方式调整"
          "(powercfg / 虚拟内存设置),直接删会破坏休眠与内存交换。"),
        "muted");
    foot->setWordWrap(true);
    v->addWidget(foot);

    connect(m_bigScanBtn, &QPushButton::clicked, this, &CleanupPage::startLargeScan);
    return page;
}

void CleanupPage::showEvent(QShowEvent* e)
{
    QWidget::showEvent(e);
    // 首次进入自动扫描一次。之后不再自动 —— 每次切页都扫一遍会让磁盘一直忙,
    // 而扫描结果几分钟内不会有实质变化。
    //
    // 大文件那一页【不】自动扫:它要遍历整块磁盘(几十秒、磁盘满负荷),用户只是切到这个
    // 页面看一眼时不该被迫付这个代价。等他明确点「查找大文件」。
    if (!m_scannedOnce && m_ipc && m_ipc->isConnected())
        startScan();
}

void CleanupPage::startLargeScan()
{
    if (!m_ipc->isConnected()) {
        m_bigStatus->setText(u("未连接服务,无法扫描。"));
        return;
    }
    if (!m_pendingLarge.isNull())
        return;                       // 已有一次在跑
    m_largeScannedOnce = true;
    const qint64 minBytes = m_bigThreshold->currentData().toLongLong();
    m_pendingLarge = m_ipc->requestLargeFiles(minBytes, 200);
    m_bigScanBtn->setEnabled(false);
    m_bigStatus->setText(u("正在扫描本机固定磁盘…"));
}

void CleanupPage::applyLargeFiles(const bulwark::ipc::LargeFileScanResponsePayload& p)
{
    if (!m_pendingLarge.isNull() && p.requestId != m_pendingLarge)
        return;
    m_pendingLarge = QUuid();
    m_bigScanBtn->setEnabled(true);

    m_bigTable->setRowCount(0);
    for (const bulwark::LargeFileEntry& f : p.files) {
        const int row = m_bigTable->rowCount();
        m_bigTable->insertRow(row);
        m_bigTable->setItem(row, 0, ui::textItem(f.path, false, true));
        m_bigTable->setItem(row, 1, ui::textItem(human(f.bytes)));
        m_bigTable->setItem(row, 2, ui::textItem(
            f.lastModifiedUtc.isValid()
                ? f.lastModifiedUtc.toLocalTime().toString(QStringLiteral("yyyy-MM-dd HH:mm"))
                : QStringLiteral("—"), true));
        m_bigTable->setItem(row, 3, ui::textItem(
            f.suffix.isEmpty() ? QStringLiteral("—") : f.suffix, true));

        // 唯一的操作:在资源管理器里定位到它。刻意没有「删除」。
        auto* open = new QPushButton(u("打开所在位置"));
        open->setProperty("variant", "ghost");
        open->setProperty("size", "sm");
        open->setCursor(Qt::PointingHandCursor);
        const QString target = f.path;
        connect(open, &QPushButton::clicked, this, [target] {
            // explorer /select 会打开父目录并把该文件选中。用 QProcess 而不是
            // QDesktopServices::openUrl:后者对「选中某个文件」无能为力,只能打开目录。
            QProcess::startDetached(QStringLiteral("explorer.exe"),
                                    { QStringLiteral("/select,") + QDir::toNativeSeparators(target) });
        });
        auto* cell = new QWidget;
        cell->setStyleSheet(QStringLiteral("background:transparent;"));
        auto* h = new QHBoxLayout(cell);
        h->setContentsMargins(8, 0, 8, 0);
        h->addWidget(open);
        h->addStretch();
        m_bigTable->setCellWidget(row, 4, cell);
    }

    QString status;
    if (!p.enabled) {
        status = u("服务端未启用大文件查找。");
    } else if (p.files.isEmpty()) {
        status = QStringLiteral("没有找到大于 %1 的文件。%2").arg(human(p.minBytes), p.message);
    } else {
        status = QStringLiteral("%1 个文件,合计 %2。%3")
                     .arg(p.files.size()).arg(human(p.totalBytes)).arg(p.message);
    }
    m_bigStatus->setText(status);
    m_bigStatus->setStyleSheet((p.unreadable > 0 || p.truncated)
        ? QStringLiteral("color:%1;").arg(theme::warning().name())
        : QString());
}

void CleanupPage::setBusy(bool busy, const QString& what)
{
    m_busy = busy;
    m_scanBtn->setEnabled(!busy);
    m_cleanBtn->setEnabled(!busy && !checkedCategories().isEmpty());
    if (busy && !what.isEmpty())
        m_status->setText(what);
}

void CleanupPage::startScan()
{
    if (!m_ipc->isConnected()) {
        m_status->setText(u("未连接服务,无法扫描。"));
        return;
    }
    if (m_busy)
        return;
    m_scannedOnce = true;
    m_pendingScan = m_ipc->requestJunkScan();
    setBusy(true, u("正在扫描…"));
}

QList<int> CleanupPage::checkedCategories() const
{
    QList<int> out;
    for (int i = 0; i < m_tree->topLevelItemCount(); ++i) {
        QTreeWidgetItem* it = m_tree->topLevelItem(i);
        if ((it->flags() & Qt::ItemIsUserCheckable) && it->checkState(ColName) == Qt::Checked)
            out << it->data(ColName, Qt::UserRole).toInt();
    }
    return out;
}

void CleanupPage::refreshTotals()
{
    const QList<int> picked = checkedCategories();
    qint64 pickedBytes = 0;
    int pickedFiles = 0;
    for (const bulwark::JunkCategoryResult& c : m_categories) {
        if (!picked.contains(static_cast<int>(c.category)))
            continue;
        pickedBytes += c.bytes;
        pickedFiles += c.fileCount;
    }
    m_selected->setText(picked.isEmpty()
        ? u("未选择任何类别")
        : QStringLiteral("已选 %1 类 · %2 · %3 个文件")
              .arg(picked.size()).arg(human(pickedBytes)).arg(pickedFiles));
    m_cleanBtn->setEnabled(!m_busy && !picked.isEmpty());
}

void CleanupPage::applyScan(const bulwark::ipc::JunkScanResponsePayload& p)
{
    if (!m_pendingScan.isNull() && p.requestId != m_pendingScan)
        return;                              // 不是我发的那次,忽略
    m_pendingScan = QUuid();
    setBusy(false, QString());

    m_categories = p.categories;
    // 重建树期间先断开 itemChanged,否则每插一行都会触发一次重算。
    const bool blocked = m_tree->blockSignals(true);
    m_tree->clear();

    for (const bulwark::JunkCategoryResult& c : p.categories) {
        auto* it = new QTreeWidgetItem(m_tree);
        it->setData(ColName, Qt::UserRole, static_cast<int>(c.category));
        it->setText(ColName, c.title);
        it->setText(ColSize, human(c.bytes));
        it->setText(ColFiles, c.fileCount > 0 ? QString::number(c.fileCount) : QStringLiteral("—"));
        it->setText(ColRisk, riskLabel(c.risk));
        it->setForeground(ColRisk, riskColor(c.risk));
        it->setText(ColNote, c.message.isEmpty() ? c.description : c.message);
        it->setToolTip(ColNote, c.description);

        // 只统计不清理的类别(旧版 Windows 残留)以及本机无内容的类别不给复选框 ——
        // 给一个勾上也没用的复选框,比不给更让人困惑。是否可清理由服务端直接下发
        // (c.cleanable),不靠界面去猜 message 里的措辞。
        if (c.cleanable) {
            it->setFlags(it->flags() | Qt::ItemIsUserCheckable);
            it->setCheckState(ColName, c.recommended ? Qt::Checked : Qt::Unchecked);
        } else {
            it->setFlags(it->flags() & ~Qt::ItemIsUserCheckable);
            it->setForeground(ColName, theme::textMuted());
        }

        // 子行:逐个位置的明细。让用户能看清「到底要删哪儿的东西」——
        // 一个只报总数、不肯说位置的清理工具不值得信任。
        for (const bulwark::JunkLocation& loc : c.locations) {
            auto* child = new QTreeWidgetItem(it);
            child->setText(ColName, loc.path);
            child->setForeground(ColName, theme::textSecondary());
            child->setText(ColSize, human(loc.bytes));
            child->setText(ColFiles, QString::number(loc.fileCount));
            QStringList bits;
            if (!loc.note.isEmpty())
                bits << loc.note;
            if (loc.skipped > 0)
                bits << QStringLiteral("%1 项跳过(占用中或未到保留时长)").arg(loc.skipped);
            // 读不进去的位置要显眼:它意味着这一行的数字偏小。用警示色,不要和普通备注混在一起。
            if (loc.unreadable > 0) {
                bits << QStringLiteral("%1 个子目录无权限读取,数字偏小").arg(loc.unreadable);
                child->setForeground(ColNote, theme::warning());
            } else {
                child->setForeground(ColNote, theme::textMuted());
            }
            child->setText(ColNote, bits.join(QStringLiteral(" · ")));
        }
    }
    m_tree->blockSignals(blocked);

    m_total->setText(human(p.totalBytes));
    // 保留时长 + 本次耗时都放在这里。把耗时显示出来是有意的:扫描只读目录元数据,上万个
    // 文件一秒出头是正常的,但「一下就完了」很容易让人以为没扫 —— 有了耗时与文件数,这个
    // 数字就能被核对,而不是只能被怀疑。
    QStringList policyBits;
    policyBits << (p.minAgeHours > 0
        ? QStringLiteral("只清理 %1 小时前的文件").arg(p.minAgeHours)
        : u("未设置保留时长"));
    if (p.elapsedMs > 0)
        policyBits << QStringLiteral("本次耗时 %1 秒").arg(p.elapsedMs / 1000.0, 0, 'f', 2);
    m_policy->setText(policyBits.join(QStringLiteral(" · ")));

    QString status = p.message;
    if (!p.enabled)
        status = u("服务端未启用磁盘垃圾清理(见 appsettings.json 的 DiskCleanup.Enabled)。");
    else if (p.truncated)
        status += u(" 部分位置文件过多,已达扫描上限,实际可释放空间可能更多。");
    m_status->setText(status);
    // 有读不进去的目录就把状态行标黄 —— 这条信息的意义是「上面那个数字偏小」,
    // 混在普通状态文字里等于没说。
    m_status->setStyleSheet(p.unreadable > 0
        ? QStringLiteral("color:%1;").arg(theme::warning().name())
        : QString());

    refreshTotals();
}

void CleanupPage::startClean()
{
    const QList<int> picked = checkedCategories();
    if (picked.isEmpty() || !m_ipc->isConnected())
        return;

    // 组织确认文案:列出要清的类别与体积,并把「留意副作用」的那几类单独拎出来。
    QStringList lines;
    QStringList cautions;
    qint64 bytes = 0;
    for (const bulwark::JunkCategoryResult& c : m_categories) {
        if (!picked.contains(static_cast<int>(c.category)))
            continue;
        bytes += c.bytes;
        lines << QStringLiteral("· %1 —— %2").arg(c.title, human(c.bytes));
        if (c.risk != bulwark::junk::Risk::Safe)
            cautions << QStringLiteral("· %1:%2").arg(c.title, c.description);
    }

    QString text = QStringLiteral("%1\n\n%2\n\n%3")
                       .arg(u("将清理以下内容,预计释放 ") + human(bytes) + QStringLiteral(":"))
                       .arg(lines.join(QLatin1Char('\n')))
                       .arg(u("删除【不可撤销】,文件不会进入回收站,也不会进入隔离区。"));
    if (!cautions.isEmpty()) {
        text += QStringLiteral("\n\n") + u("其中以下类别有可感知的副作用:") +
                QStringLiteral("\n") + cautions.join(QLatin1Char('\n'));
    }
    text += QStringLiteral("\n\n") + u("确定继续吗?");

    if (QMessageBox::warning(this, u("清理磁盘垃圾"), text,
                             QMessageBox::Yes | QMessageBox::Cancel,
                             QMessageBox::Cancel) != QMessageBox::Yes)
        return;

    m_pendingClean = m_ipc->requestJunkClean(picked);
    setBusy(true, u("正在清理…"));
}

void CleanupPage::applyClean(const bulwark::ipc::JunkCleanResponsePayload& p)
{
    if (!m_pendingClean.isNull() && p.requestId != m_pendingClean)
        return;
    m_pendingClean = QUuid();
    setBusy(false, QString());

    // 逐类别如实汇报,包括失败与跳过 —— 不允许把「跳过了 3000 个占用中的文件」说成完全成功。
    QStringList detail;
    for (const bulwark::JunkCleanOutcome& oc : p.outcomes) {
        detail << QStringLiteral("%1 %2 —— %3")
                      .arg(oc.success ? u("[已清理]") : u("[未清理]"), oc.title, oc.message);
    }
    const QString summary = QStringLiteral("%1\n\n%2")
                                .arg(p.message, detail.join(QLatin1Char('\n')));
    m_status->setText(p.message);
    if (p.success)
        QMessageBox::information(this, u("清理完成"), summary);
    else
        QMessageBox::warning(this, u("清理未完成"), summary);

    // 清完立刻重扫,让界面反映真实现状(而不是留着一份已经不存在的清单)。
    startScan();
}
