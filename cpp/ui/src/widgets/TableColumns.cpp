#include "widgets/TableColumns.h"

#include <QAction>
#include <QCoreApplication>
#include <QEvent>
#include <QFont>
#include <QFontMetrics>
#include <QHeaderView>
#include <QHelpEvent>
#include <QMenu>
#include <QModelIndex>
#include <QSettings>
#include <QStyledItemDelegate>
#include <QTableWidget>
#include <QTimer>
#include <QToolTip>
#include <QVariant>

#include <algorithm>
#include <utility>

namespace {

QString u(const char* s) { return QString::fromUtf8(s); }

// QSS 给单元格的左右内边距(6px 8px)+ 网格线余量。判断「文本是否被截断」时要扣掉,
// 否则刚刚好装下的文本也会被判成截断,每格都弹气泡。
constexpr int kCellPadding = 22;
constexpr int kMinSection  = 56;   // 可拖动的下限:比这更窄表头文字自己都放不下
constexpr int kSaveDelayMs = 500;  // 拖动是连续事件,防抖后再落盘

// 按列指定省略位置的代理。Qt 的省略模式是「按视图」而不是「按列」的,而路径列要中段省略
// (保住盘符与文件名)、备注/摘要一类的散文列要末尾省略 —— 只能靠代理逐列覆盖。
class ElideDelegate : public QStyledItemDelegate
{
public:
    ElideDelegate(QObject* parent, QList<bool> middle)
        : QStyledItemDelegate(parent), middle_(std::move(middle))
    {}

protected:
    void initStyleOption(QStyleOptionViewItem* option, const QModelIndex& index) const override
    {
        QStyledItemDelegate::initStyleOption(option, index);
        const int c = index.column();
        if (c >= 0 && c < middle_.size() && middle_[c])
            option->textElideMode = Qt::ElideMiddle;
    }

private:
    QList<bool> middle_;
};

// 装在表格上的列宽控制器:排布默认宽度、跟随窗口伸缩、记录用户拖动、补全被截断文本的提示。
// 生命周期挂在表格上(QObject 父子),页面销毁即随之销毁。
class ColumnLayout : public QObject
{
public:
    ColumnLayout(QTableWidget* t, QString key, QList<ui::ColSpec> spec)
        : QObject(t), table_(t), key_(std::move(key)), spec_(std::move(spec))
    {
        auto* hh = table_->horizontalHeader();
        hh->setSectionResizeMode(QHeaderView::Interactive); // 全列可拖(Stretch 是不能拖的)
        hh->setStretchLastSection(false);
        hh->setCascadingSectionResizes(false);              // 拖一列只改这一列,不连锁挤压邻居
        hh->setMinimumSectionSize(kMinSection);
        hh->setToolTip(u("拖动列边界可调整列宽 · 双击边界按内容自适应 · 右键可恢复默认"));
        table_->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);

        QList<bool> middle;
        middle.reserve(spec_.size());
        for (const ui::ColSpec& c : spec_)
            middle.append(c.pathLike);
        table_->setItemDelegate(new ElideDelegate(table_, std::move(middle)));

        saveTimer_ = new QTimer(this);
        saveTimer_->setSingleShot(true);
        saveTimer_->setInterval(kSaveDelayMs);
        connect(saveTimer_, &QTimer::timeout, this, [this] { save(); });
        // 退出前把还在防抖窗口里的那次拖动补写掉:否则「拖完就关窗」的列宽会丢。
        // 挂 aboutToQuit 而不是析构函数 —— 那时控件还活着,读列宽是安全的。
        connect(qApp, &QCoreApplication::aboutToQuit, this, [this] {
            if (saveTimer_->isActive()) {
                saveTimer_->stop();
                save();
            }
        });

        restore();
        apply();
        table_->viewport()->installEventFilter(this);

        // 用户拖动 -> 从此以用户的宽度为准,不再自动排布,并落盘记住。
        connect(hh, &QHeaderView::sectionResized, this, [this](int, int, int) {
            if (applying_)
                return;
            custom_ = true;
            saveTimer_->start();
        });

        // 表头右键给一条退路:拖乱了能一键回到默认。策略设在表头上,免得事件冒泡到表格,
        // 触发那边「右键某一行」的信任菜单。
        hh->setContextMenuPolicy(Qt::CustomContextMenu);
        connect(hh, &QWidget::customContextMenuRequested, this,
                [this, hh](const QPoint& p) { showMenu(hh->mapToGlobal(p)); });

        // 首帧布局:构造时表格还没进过布局,viewport 宽度尚不可信,等第一次布局后再排一次。
        QTimer::singleShot(0, this, [this] { apply(); });
    }

protected:
    bool eventFilter(QObject* watched, QEvent* ev) override
    {
        if (watched == table_->viewport()) {
            if (ev->type() == QEvent::Resize) {
                apply(); // 窗口/滚动条变化 -> 把新增宽度分给长文本列
            } else if (ev->type() == QEvent::ToolTip) {
                if (showElidedTip(static_cast<QHelpEvent*>(ev)))
                    return true;
            }
        }
        return QObject::eventFilter(watched, ev);
    }

private:
    QString settingsKey() const { return QStringLiteral("columnWidths/") + key_; }

    void save() const
    {
        QStringList widths;
        for (int i = 0; i < table_->columnCount(); ++i)
            widths << QString::number(table_->columnWidth(i));
        QSettings().setValue(settingsKey(), widths.join(QLatin1Char(',')));
    }

    // 读回用户上次拖出来的列宽。列数变了(版本升级增删列)就丢弃,免得宽度错位。
    void restore()
    {
        const QStringList widths =
            QSettings().value(settingsKey()).toString().split(QLatin1Char(','), Qt::SkipEmptyParts);
        if (widths.size() != table_->columnCount())
            return;
        applying_ = true;
        for (int i = 0; i < widths.size(); ++i) {
            const int w = widths[i].toInt();
            if (w >= kMinSection)
                table_->setColumnWidth(i, w);
        }
        applying_ = false;
        custom_ = true;
    }

    // 默认排布:各列先拿自己的默认宽度,可视区还有余量时按 grow 权重分给长文本列。
    // 余量为负(窗口窄)就保持默认宽度,让横向滚动条出现 —— 截断路径比滚动更难用。
    void apply()
    {
        if (applying_ || custom_)
            return;
        const int n = std::min<int>(table_->columnCount(), spec_.size());
        if (n <= 0)
            return;

        int base = 0;
        int weight = 0;
        for (int i = 0; i < n; ++i) {
            base += spec_[i].width;
            weight += spec_[i].grow;
        }

        QList<int> widths;
        widths.reserve(n);
        for (int i = 0; i < n; ++i)
            widths.append(spec_[i].width);

        const int extra = table_->viewport()->width() - base;
        if (extra > 0 && weight > 0) {
            int handed = 0;
            int last = -1;
            for (int i = 0; i < n; ++i) {
                if (spec_[i].grow <= 0)
                    continue;
                const int add = extra * spec_[i].grow / weight;
                widths[i] += add;
                handed += add;
                last = i;
            }
            if (last >= 0)
                widths[last] += extra - handed; // 整除的零头给最后一列,右侧不留缝
        }

        applying_ = true; // setColumnWidth 会回打 sectionResized / Resize,这里挡住递归
        for (int i = 0; i < n; ++i)
            table_->setColumnWidth(i, widths[i]);
        applying_ = false;
    }

    // 文本装不下的单元格,悬停给出完整内容。已自带 ToolTip 的单元格(页面显式设过)不抢。
    bool showElidedTip(QHelpEvent* he) const
    {
        const QModelIndex idx = table_->indexAt(he->pos());
        if (!idx.isValid() || !idx.data(Qt::ToolTipRole).toString().isEmpty())
            return false;
        const QString text = idx.data(Qt::DisplayRole).toString();
        if (text.isEmpty())
            return false;

        QFont f = table_->font();
        const QVariant fv = idx.data(Qt::FontRole); // 路径列用的是等宽字体,量度要按它算
        if (fv.canConvert<QFont>())
            f = qvariant_cast<QFont>(fv);
        if (QFontMetrics(f).horizontalAdvance(text) <= table_->columnWidth(idx.column()) - kCellPadding)
            return false;

        QToolTip::showText(he->globalPos(), text, table_->viewport());
        return true;
    }

    void showMenu(const QPoint& global)
    {
        QMenu m(table_);
        QAction* fit = m.addAction(u("按内容自适应列宽"));
        QAction* def = m.addAction(u("恢复默认列宽"));
        const QAction* chosen = m.exec(global);
        if (chosen == fit) {
            applying_ = true;
            table_->resizeColumnsToContents();
            applying_ = false;
            custom_ = true;
            saveTimer_->start();
        } else if (chosen == def) {
            custom_ = false;
            QSettings().remove(settingsKey());
            apply();
        }
    }

    QTableWidget* table_ = nullptr;
    QString key_;
    QList<ui::ColSpec> spec_;
    QTimer* saveTimer_ = nullptr;
    bool applying_ = false; // 正在由代码改列宽:别把它当成用户拖动
    bool custom_ = false;   // 用户拖过 / 自适应过:自动排布让位
};

} // namespace

void ui::columns(QTableWidget* table, const QString& key, const QList<ColSpec>& spec)
{
    if (!table)
        return;
    new ColumnLayout(table, key, spec); // 所有权交给 table(QObject 父子),随页面一起销毁
}
