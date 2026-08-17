#pragma once
#include <QList>
#include <QString>

class QTableWidget;

// 列宽管理 —— 解决「路径列被截断、看不全」这个老问题。
//
// 此前所有列都是 QHeaderView::Stretch:列宽 = 可视宽度 / 列数,平分。进程管理 8 列、
// 攻击链 9 列时每列只剩 ~110px,连 "C:\Windows\System32\svchost.exe" 都装不下,而且
// Stretch 的列【不能拖】—— 用户既看不全也改不了。
//
// 这里改成:每列一个按真实内容量身定的默认宽度 + 权重分配剩余空间 + 全列可拖 + 记住用户的拖动。
namespace ui {

// 一列的宽度规格。
struct ColSpec {
    int  width;              // 默认像素宽(按该列真实内容长度定,不再平分)
    int  grow     = 0;       // 权重:窗口变宽后多出来的横向空间按权重分给 grow>0 的列
    bool pathLike = false;   // 该列是路径/命令一类:省略号打在【中段】,保住盘符与文件名
};

// 给表格装上「可拖动 + 记得住」的列宽:
//   · 所有列改成 QHeaderView::Interactive —— 可拖列边界,双击边界按内容自适应;
//   · 用户没动过时按 ColSpec 排布,窗口变宽多出来的宽度按 grow 权重分给长文本列;
//   · 用户一旦手动拖过就完全交给用户,并把列宽记入 QSettings,下次启动照旧;
//   · 表头右键:按内容自适应 / 恢复默认列宽;
//   · 文本被截断的单元格,悬停显示完整内容(长路径不拖也能看全)。
// 总宽超过可视区时出现横向滚动条 —— 路径宁可滚,不要截断。
//
// key 是持久化用的稳定标识(一个页面一个,改名等于丢掉用户已保存的列宽)。
void columns(QTableWidget* table, const QString& key, const QList<ColSpec>& spec);

} // namespace ui
