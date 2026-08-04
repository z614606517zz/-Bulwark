#pragma once
#include "bulwark/service/Logger.h"
#include "bulwark/service/ThreatIntelContribStore.h"

#include <QString>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>

namespace bulwark::service {

// 威胁情报共享的夜间上传器。
//
// 每天凌晨(默认 3:00,带 0~5 分钟错峰抖动)把 ThreatIntelContribStore 里攒下的
// 「病毒信息 + 行为数据」批量 POST 到中央服务器 /v1/intel/contribute;每批上传成功后
// 立即从本地暂存里删掉这一批,失败则原样留着等下一晚重试。
//
// 默认整条链路关闭:enabled_ 由 RuntimeSettings::cloudBehaviorUploadEnabled 驱动,
// 用户不开就永远既不收集也不上传。开关是热的 —— setEnabled(false) 立即生效,且由宿主
// 顺带清空本地暂存(见 main.cpp 的 settingsUpdated)。
//
// 线程模型沿用 AttackChainFeed:独立 std::thread + condition_variable 可中断睡眠,
// stop() 唤醒并 join。上传在该线程内同步做,不碰 Qt 对象、不需要编组回主线程。
class ThreatIntelUploader {
public:
    // baseUrl / token 与中央信誉代理同源(同一台服务器);baseUrl 为空则本类永不启用。
    ThreatIntelUploader(ThreatIntelContribStore* store, QString baseUrl, QString token,
                        int uploadHour, int timeoutSeconds);
    ~ThreatIntelUploader();

    ThreatIntelUploader(const ThreatIntelUploader&) = delete;
    ThreatIntelUploader& operator=(const ThreatIntelUploader&) = delete;

    void setEnabled(bool on) { enabled_.store(on); }
    bool isEnabled() const { return enabled_.load(); }

    void start();
    void stop();

    // 立即上传一次(供手动触发 / 自检)。返回成功上传的记录条数。
    // 未启用 / 无端点 / 队列为空 -> 返回 0。阻塞调用方线程。
    int uploadNow();

private:
    void loop();
    bool sleepInterruptible(int seconds);
    int secondsUntilDailyHour(int hour) const;

    ThreatIntelContribStore* store_;
    QString baseUrl_;   // 已去尾斜杠
    QString maskedUrl_; // 日志用掩码形式,绝不记录明文端点
    QString token_;
    int uploadHour_;
    int timeoutSecs_;

    std::atomic<bool> enabled_{false};
    std::atomic<bool> running_{false};
    // 服务器不认这个接口(404/405/501):记下来,不再每晚白发一次。
    std::atomic<bool> unsupported_{false};
    std::thread worker_;
    std::mutex mx_;
    std::condition_variable cv_;
    Logger log_{QStringLiteral("IntelUpload")};
};

} // namespace bulwark::service
