#pragma once
#include <QWidget>
#include <QList>

#include "bulwark/ipc/Payloads.h"

class IpcClient;
class QComboBox;
class QLabel;
class QPushButton;
class QTreeWidget;
class QTreeWidgetItem;

// 「垃圾清理」页 —— 扫描出各类可清理内容的体积,用户勾选后执行清理。
//
// 之所以做成一个类(而不是 pages:: 下的工厂函数):这一页有真实的会话状态(上一次扫描结果、
// 勾选、进行中的请求 id、进度),用工厂函数就得把这些状态挂成一堆裸指针再在 destroyed 里删,
// 得不偿失。仪表盘页(DashboardPage)同样是类,不算破例。
//
// 设计上刻意做的两件事:
//   · 勾选项与体积【一律来自服务端的扫描结果】。界面不维护第二份「什么算垃圾」的清单,标题、
//     说明、风险档、是否建议勾选全部由服务端下发 —— 否则界面说的和真正执行删除的那一侧迟早
//     会不一致,而这里不一致的代价是用户以为删的是缓存、实际删的是别的东西。
//   · 高风险类别(回收站 / 预读取 / 最近使用记录 / 本产品自身日志)默认不勾,并在确认框里
//     单独列出来。清理工具最容易招人恨的就是「我只是点了个清理,它把我的东西删了」。
class QTableWidget;
class QTabWidget;

class CleanupPage : public QWidget {
    Q_OBJECT
public:
    explicit CleanupPage(IpcClient* ipc, QWidget* parent = nullptr);

protected:
    // 首次进入本页时自动扫描一次(与常见清理工具一致)。扫描是重 I/O,所以【只做一次】,
    // 之后由用户点「重新扫描」—— 每次切页都扫一遍会让磁盘一直忙。
    void showEvent(QShowEvent* e) override;

private:
    QWidget* buildCategoryTab();
    QWidget* buildLargeFileTab();

    void startScan();
    void startClean();
    void applyScan(const bulwark::ipc::JunkScanResponsePayload& p);
    void applyClean(const bulwark::ipc::JunkCleanResponsePayload& p);
    void refreshTotals();
    void setBusy(bool busy, const QString& what);
    QList<int> checkedCategories() const;

    void startLargeScan();
    void applyLargeFiles(const bulwark::ipc::LargeFileScanResponsePayload& p);

    IpcClient*   m_ipc = nullptr;
    QTabWidget*  m_tabs = nullptr;
    QTreeWidget* m_tree = nullptr;
    QLabel*      m_total = nullptr;      // 大号「可释放空间」
    QLabel*      m_selected = nullptr;   // 「已选中 X」
    QLabel*      m_status = nullptr;     // 状态 / 进度一行
    QLabel*      m_policy = nullptr;     // 当前生效的保留时长等
    QPushButton* m_scanBtn = nullptr;
    QPushButton* m_cleanBtn = nullptr;

    // 大文件页。刻意【没有删除按钮】—— 只有「打开所在位置」,理由见 LargeFileEntry 的说明。
    QTableWidget* m_bigTable = nullptr;
    QLabel*       m_bigStatus = nullptr;
    QPushButton*  m_bigScanBtn = nullptr;
    QComboBox*    m_bigThreshold = nullptr;
    QUuid         m_pendingLarge;
    bool          m_largeScannedOnce = false;

    bool  m_scannedOnce = false;
    bool  m_busy = false;
    QUuid m_pendingScan;
    QUuid m_pendingClean;
    // 上一次扫描的类别结果,按树的顶层顺序排列。清理时要用它拿到 category 序号与标题。
    QList<bulwark::JunkCategoryResult> m_categories;
};
