#pragma once
#include <QDialog>
#include <QHash>
#include <QPointF>
#include <QRectF>
#include <QUuid>
#include <QWidget>

#include "bulwark/models/AttackGraph.h"

class IpcClient;
class QLabel;
class QScrollArea;
class QVBoxLayout;

// 攻击图画布:把服务端算好的节点/边画成一张分层有向图。
//
// 只负责画。布局、着色、命中测试都在这里,但【关联关系一概不推断】—— 节点、边、层号、风险分
// 全部来自服务端 AttackGraphBuilder 的结果。这样界面上看到的因果与引擎实际依据的因果永远一致,
// 不会出现「图上连着、日志里对不上」这种排查事故时最要命的偏差。
class AttackGraphCanvas : public QWidget
{
    Q_OBJECT
public:
    explicit AttackGraphCanvas(QWidget* parent = nullptr);

    void setGraph(const bulwark::AttackGraph& graph);
    void setScale(qreal s);
    qreal scaleFactor() const { return m_scale; }

signals:
    // 选中一个节点(index 为 graph.nodes 下标;-1 = 取消选中)。
    void nodeSelected(int index);
    // 选中一条边(index 为 graph.edges 下标)。
    void edgeSelected(int index);

protected:
    void paintEvent(QPaintEvent* e) override;
    void mousePressEvent(QMouseEvent* e) override;
    void mouseDoubleClickEvent(QMouseEvent* e) override;
    void wheelEvent(QWheelEvent* e) override;

private:
    void relayout();
    int nodeAt(const QPointF& logical) const;
    int edgeAt(const QPointF& logical) const;

    bulwark::AttackGraph m_graph;
    QHash<QString, int> m_indexById;
    QVector<QRectF> m_boxes;      // 逻辑坐标(未缩放)下每个节点的矩形
    QSizeF m_logicalSize{ 100, 100 };
    qreal m_scale = 1.0;
    int m_selectedNode = -1;
    int m_selectedEdge = -1;
};

// 攻击图窗口:请求 -> 等待 -> 绘制 -> 点节点/边看详情。
// 由「拦截记录 / 活动日志 / 事件时间线」的行右键或攻击时间线窗口里的按钮打开。
class AttackGraphWindow : public QDialog
{
    Q_OBJECT
public:
    // seedEventId 为准;rootPid 仅在没有事件 id(例如从进程管理页展开)时作为兜底种子。
    AttackGraphWindow(IpcClient* ipc, const QUuid& seedEventId, int rootPid,
                      const QString& title, QWidget* parent = nullptr);

private:
    void showGraph(const bulwark::AttackGraph& g);
    void showNodeDetail(int index);
    void showEdgeDetail(int index);

    IpcClient* m_ipc = nullptr;
    QUuid m_seedEventId;
    QUuid m_requestId;   // 只认自己那份响应
    int m_rootPid = 0;
    AttackGraphCanvas* m_canvas = nullptr;
    QScrollArea* m_scroll = nullptr;
    QLabel* m_status = nullptr;
    QLabel* m_summary = nullptr;
    QWidget* m_detailHost = nullptr;
    QVBoxLayout* m_detailLayout = nullptr;
    bulwark::AttackGraph m_graph;
};
