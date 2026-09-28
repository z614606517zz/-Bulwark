#pragma once
#include <QDialog>
#include <QHash>
#include <QPoint>
#include <QPointF>
#include <QRectF>
#include <QUuid>
#include <QWidget>

#include "bulwark/models/AttackGraph.h"

class ElidingLabel;
class Inspector;
class IpcClient;
class QScrollArea;
class QSplitter;
class QToolButton;

// 攻击图画布:把服务端算好的节点/边画成一张分层有向图。
//
// 只负责画。布局、着色、命中测试都在这里,但【关联关系一概不推断】—— 节点、边、层号、风险分
// 全部来自服务端 AttackGraphBuilder 的结果。这样界面上看到的因果与引擎实际依据的因果永远一致,
// 不会出现「图上连着、日志里对不上」这种排查事故时最要命的偏差。
//
// The canvas is at least as large as its viewport (the dotted canvas fills the
// window; a small graph sits centred), can be dragged to pan, and zooms with
// Ctrl + wheel or the window's zoom capsule.
class AttackGraphCanvas : public QWidget
{
    Q_OBJECT
public:
    explicit AttackGraphCanvas(QWidget* parent = nullptr);

    void setGraph(const bulwark::AttackGraph& graph);
    void setMessage(const QString& text); // shown while there is no graph (loading / failure)
    void setScale(qreal s);
    qreal scaleFactor() const { return m_scale; }
    QSizeF logicalSize() const { return m_logicalSize; }
    void setViewportSize(const QSize& size);
    void clearSelection();

signals:
    // 选中一个节点(index 为 graph.nodes 下标;-1 = 取消选中)。
    void nodeSelected(int index);
    // 选中一条边(index 为 graph.edges 下标)。
    void edgeSelected(int index);
    void scaleChanged(qreal scale);
    void panRequested(const QPoint& delta);

protected:
    void paintEvent(QPaintEvent* e) override;
    void mousePressEvent(QMouseEvent* e) override;
    void mouseMoveEvent(QMouseEvent* e) override;
    void mouseReleaseEvent(QMouseEvent* e) override;
    void wheelEvent(QWheelEvent* e) override;

private:
    void relayout();
    void syncSize();
    QPointF origin() const;              // where the scaled graph starts inside the canvas
    QPointF toLogical(const QPointF& widgetPos) const;
    int nodeAt(const QPointF& logical) const;
    int edgeAt(const QPointF& logical) const;

    bulwark::AttackGraph m_graph;
    QHash<QString, int> m_indexById;
    QVector<QRectF> m_boxes;      // 逻辑坐标(未缩放)下每个节点的矩形
    QSizeF m_logicalSize{ 100, 100 };
    QSize m_viewport;
    QString m_message;
    qreal m_scale = 1.0;
    int m_selectedNode = -1;
    int m_selectedEdge = -1;
    bool m_panning = false;
    bool m_panMoved = false;
    QPoint m_panLast;
};

// 攻击图窗口:请求 -> 等待 -> 绘制 -> 点节点/边在右侧检查器里看详情。
// 由事件记录 / 事件时间线的检查器与右键菜单、攻击时间线窗口、进程管理页打开(非模态)。
class AttackGraphWindow : public QDialog
{
    Q_OBJECT
public:
    // seedEventId 为准;rootPid 仅在没有事件 id(例如从进程管理页展开)时作为兜底种子。
    AttackGraphWindow(IpcClient* ipc, const QUuid& seedEventId, int rootPid,
                      const QString& title, QWidget* parent = nullptr);

protected:
    bool eventFilter(QObject* watched, QEvent* e) override;

private:
    void showGraph(const bulwark::AttackGraph& g);
    void showOverview();
    void showNodeDetail(int index);
    void showEdgeDetail(int index);
    void placeOverlays();
    void fit();

    IpcClient* m_ipc = nullptr;
    QUuid m_seedEventId;
    QUuid m_requestId;   // 只认自己那份响应
    int m_rootPid = 0;
    QString m_title;
    AttackGraphCanvas* m_canvas = nullptr;
    QScrollArea* m_scroll = nullptr;
    QSplitter* m_split = nullptr;
    Inspector* m_inspector = nullptr;
    ElidingLabel* m_summary = nullptr;
    QWidget* m_zoomBar = nullptr;
    QToolButton* m_zoomReset = nullptr;
    QWidget* m_legend = nullptr;
    QString m_status;    // what the overview says while there is no graph
    bool m_fitted = false;
    bulwark::AttackGraph m_graph;
};
