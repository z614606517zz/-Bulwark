#pragma once
#include <QDateTime>
#include <QTimeZone>
#include <atomic>

// 引擎与模型层统一的「现在」。
//
// ============================ 为什么需要这层间接 ============================
//
// 决策管线里有若干判定依赖墙上时钟,而非事件自带的时间戳:
//   · DefenseRule::matches   —— 规则是否已到期
//   · TrustPolicy::isHealthySigned / ThreatDetector —— 「首见 + 证书剩余 <= 186 天」软信号
//   · ProcessChainTracker    —— dropper 检测(「最近落地的可执行文件」时间窗)
//   · BaselineAnalyzer       —— 学习期判定
//
// 后果:同一条事件在不同时刻求值会得到【不同裁决】。这让「用一份语料固定住 12 步管线的
// 行为」这件事无法成立 —— 而那是回归测试能抓到「改动静默改掉了别的裁决」的前提
// (见 cpp/tests/SnapshotTool.cpp)。
//
// 于是把「现在」收敛成这一个可注入的入口:生产路径行为完全不变(仍是真实 UTC),
// 测试路径把它钉死,使同一份语料在任何时刻、任何机器上都得到逐条相同的裁决。
//
// 注意:四个有状态时序监视器(勒索 / 信标 / 外联速率 / 基线)本来就优先用 e.timestampUtc,
// 只在事件缺时间戳时才退回这里 —— 所以带时间戳的语料对它们天然可复现。
//
// 线程模型:读侧无锁(relaxed 原子读,生产路径每次判定一次)。写侧仅测试在回放前调用一次。

namespace bulwark {

namespace clock_detail {

// 0 = 使用真实时钟;非 0 = 被钉死的 UTC 毫秒时间戳。
// 函数内静态 + inline:跨翻译单元保证唯一实例,故本文件可以是纯头文件,无需改 CMake。
inline std::atomic<qint64> &fixedNowMs()
{
    static std::atomic<qint64> v{ 0 };
    return v;
}

} // namespace clock_detail

// 统一的「现在」(UTC)。生产路径等价于 QDateTime::currentDateTimeUtc()。
inline QDateTime nowUtc()
{
    const qint64 fixed = clock_detail::fixedNowMs().load(std::memory_order_relaxed);
    if (fixed != 0)
        return QDateTime::fromMSecsSinceEpoch(fixed, QTimeZone::UTC);
    return QDateTime::currentDateTimeUtc();
}

// 仅供测试:钉死「现在」。传入无效 QDateTime 则恢复真实时钟。
inline void setFixedNowUtcForTest(const QDateTime &fixed)
{
    clock_detail::fixedNowMs().store(fixed.isValid() ? fixed.toMSecsSinceEpoch() : 0,
                                     std::memory_order_relaxed);
}

// 当前是否处于「时钟已钉死」状态(诊断 / 断言用)。
inline bool isNowUtcFixedForTest()
{
    return clock_detail::fixedNowMs().load(std::memory_order_relaxed) != 0;
}

} // namespace bulwark
