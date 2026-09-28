#pragma once
#include <QList>
#include <QStringList>
#include <QWidget>

// A horizontal stage indicator: numbered nodes joined by a line, a label under
// each. Used where a process has real, ordered stages the user waits through —
// cloud scan (查询 → 上传 → 分析 → 结论), online update (检查 → 下载校验 → 安装 →
// 完成), the AI cleanup wizard. States are painted with glyph + colour + label
// weight, and announced through the accessible description.
class Stepper : public QWidget
{
public:
    enum class State { Pending, Active, Done, Error, Skipped };

    explicit Stepper(const QStringList& labels, QWidget* parent = nullptr);

    int count() const { return int(m_labels.size()); }
    void setLabel(int step, const QString& label);
    void setState(int step, State s);
    State state(int step) const;
    // Steps before `current` Done, `current` = `currentState`, later ones Pending.
    void setProgress(int current, State currentState = State::Active);

    QSize sizeHint() const override;
    QSize minimumSizeHint() const override;

protected:
    void paintEvent(QPaintEvent*) override;

private:
    void syncAccessible();

    QStringList m_labels;
    QList<State> m_states;
};
