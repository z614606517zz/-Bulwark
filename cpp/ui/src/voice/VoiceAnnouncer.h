#pragma once
#include <QHash>
#include <QObject>
#include <QString>

#include "bulwark/models/Enums.h"   // EnforcementOutcome(按值传参,不能只前置声明)

class QTimer;

// 语音播报「威胁拦截结果」。
//
// 只念一类东西:拦截通知的【真实处置结果】。询问弹窗、放行、攻击链命中、云查杀进度、更新提示……一律不念。
// 措辞与右下角拦截通知同一口径:没拦下时绝不说「已拦截」,而是说「未能拦截,请手动处理」。
//
// 喂给它的是 ToastNotifier【去重与限流合并之后】真正弹出的拦截通知(blockPresented /
// blockBatchPresented),所以耳朵听到的与眼睛看到的一一对应:通知压掉的重复不会被念,
// 通知合并成的摘要也只念一句。
//
// 念一句要两三秒,比通知弹得慢。正在念时新到的结果先攒着,念完后:攒了一条就念原句,攒了多条就念一句
// 汇总(「又拦截了 N 项」「其中 M 项未能拦截」)。待念的永远只有一句 —— 拦截风暴时不会连念几分钟。
//
// 【同一威胁只念一次】通知那层的去重窗口是 10 秒(看一眼就过去的东西,过 10 秒再提醒一次是合理的);
// 声音不是:一段三秒多、打断当前工作、且内容逐字相同的播报,重复出现就只是噪音。所以这里另记一份
// 「已念过」的账,同一威胁在本次界面运行期间不再念第二遍 —— 每隔半分钟重试一次的样本,只会听到一次。
// 记账的键是【主体 + 要念的那句话】,于是处置结果变了就算新消息:先「已拦截」后「未能拦截,请手动处理」
// 照样会念出来。被这层压掉的只是声音,拦截通知、拦截记录与日志一条都不少。
//
// 开关在「设置 > 防护总控 > 语音播报拦截结果」,默认关。这是纯界面行为,服务端既不需要知道也不参与,
// 所以存在当前 Windows 用户的 QSettings 里而不进 RuntimeSettings:连不上后台服务时照样能改,
// 也不会因为服务版本旧、不认识这个键而「拨了开关又弹回去」。
//
// 语音走 Windows 自带的 SAPI(本机的 Qt 没有 TextToSpeech 模块,这样也不必多带 DLL)。优先用中文语音;
// 本机一个中文语音都没有时照样会念,但 status() 如实报告,设置页据此提示用户去添加语音。
// 引擎在第一次开启时才初始化:默认关的用户不为 SAPI 付任何启动开销。
class VoiceAnnouncer : public QObject
{
    Q_OBJECT
public:
    enum class Status {
        Idle,           // 未开启,或刚开启、引擎还没初始化
        Ready,          // 中文语音就绪
        NoChineseVoice, // 引擎可用,但本机没有中文语音:念出来多半没声音或只剩英文字母
        Unavailable,    // SAPI 初始化失败,无法播报
    };

    // 进程内唯一实例:主窗口往里喂拦截通知、设置页拨开关,用的是同一个。
    static VoiceAnnouncer* instance();
    ~VoiceAnnouncer() override;

    bool isEnabled() const { return m_enabled; }
    // 写入 QSettings。关掉时立即截断正在念的那一句,并丢弃攒着的。
    void setEnabled(bool on);
    Status status() const { return m_enabled ? m_engineStatus : Status::Idle; }

    // 一条单独弹出的拦截通知。actorPath = 发起行为的程序;enforcement = 服务端处置之后的真实结果。
    void announceBlock(const QString& actorPath, bulwark::EnforcementOutcome enforcement);
    // 一条限流合并出来的摘要通知。blocked = 真拦下的数目;unenforced = 裁决拦截、实际没拦下的数目。
    void announceBatch(int blocked, int unenforced);

signals:
    void statusChanged();

private:
    explicit VoiceAnnouncer(QObject* parent);

    // 这条威胁是否已经念过(念过就不再念,见类说明)。没念过则就地记账。
    bool alreadySpoken(const QString& actorPath, const QString& sentence);
    void enqueue(const QString& sentence, int blocked, int unenforced);
    bool ensureEngine();   // 懒初始化 SAPI;失败后不在每条拦截上反复重试(用户重新打开开关时再试)
    void speak(const QString& sentence);
    void poll();           // 念完了没有;念完就把攒着的念出来
    bool flushPending();
    void stopSpeaking();   // 截断正在念的 + 丢弃攒着的
    void shutdown();       // 退出前释放 COM 对象(aboutToQuit)
    void setEngineStatus(Status s);

    struct Impl;           // SAPI 的 COM 指针只出现在 .cpp 里,头文件不拖进 windows.h
    Impl* d = nullptr;

    bool m_enabled = false;
    bool m_engineTried = false;
    bool m_shutDown = false;
    Status m_engineStatus = Status::Idle;

    bool m_busy = false;
    qint64 m_busySinceMs = 0;
    QString m_current;     // 正在念的那一句(SAPI 异步念期间保证字符串一直活着)

    // 念的时候攒下的结果。
    int m_pendingItems = 0;
    int m_pendingBlocked = 0;
    int m_pendingUnenforced = 0;
    QString m_pendingSentence; // 只攒了一条时念它的原句

    // 已播报过的威胁:键(主体 + 那句话)-> 首次播报时刻。关掉开关不清空 —— 关了又开不该让
    // 之前念过的一批重新念一遍。
    QHash<QString, qint64> m_spoken;

    QTimer* m_poll = nullptr;
};
