#include "voice/VoiceAnnouncer.h"
// 「算不算需要用户自己动手」这条界线必须与右下角通知逐字一致,所以共用 EventFormat 里的那个
// 判据,而不是在这里再手写一份 —— 两处各写一份的结果就是它们迟早说两套话。
#include "dialogs/EventFormat.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QFileInfo>
#include <QPointer>
#include <QRegularExpression>
#include <QSettings>
#include <QStringList>
#include <QTimer>
#include <QtGlobal>

#include <algorithm>

#ifdef Q_OS_WIN
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#  include <sapi.h>
#  include <wrl/client.h>
#endif

namespace {

QString u(const char* s) { return QString::fromUtf8(s); }

const char kSettingKey[] = "ui/voiceAnnounceBlocks";

constexpr int kPollMs = 200;
// 一句播报正常两三秒就念完。念了这么久还没完,多半是音频设备卡住了:截断它,别让后面的结果永远排不上。
constexpr qint64 kStuckMs = 30000;
// 名字超过这个长度(多半是随机串 / 哈希 / 带版本号的安装包名),逐个字母念出来只是噪音,干脆不念名字。
constexpr int kMaxSpokenNameLen = 24;
// 「已念过」账本的上限(键数)。只在超限时丢最早的四分之一,见 alreadySpoken()。
constexpr int kMaxSpokenKeys = 2048;

// 念给人听的程序名:去掉扩展名(「点 exe」念出来是噪音),分隔符换成停顿。
QString spokenProgram(const QString& actorPath)
{
    static const QRegularExpression separators(QStringLiteral("[._\\-]+"));
    QString name = QFileInfo(actorPath).completeBaseName();
    name.replace(separators, QStringLiteral(" "));
    name = name.simplified();
    return name.size() > kMaxSpokenNameLen ? QString() : name;
}

// 与 ToastNotifier::showBlock 同一口径:抬头「已拦截危险行为 / 检测到危险行为,未能拦截 / …处置未成功」,
// 再加上处置 pill 的「已结束进程 / 已禁止加载」。没拦下的一律带上「请手动处理」—— 那是用户此刻唯一该做的事。
QString blockSentence(const QString& actorPath, bulwark::EnforcementOutcome enforcement)
{
    using EO = bulwark::EnforcementOutcome;
    const QString who = spokenProgram(actorPath);
    const QString what = who.isEmpty() ? u("危险行为") : u(" %1 的危险行为").arg(who);
    switch (enforcement) {
    case EO::AlertedOnly:       return u("检测到%1,未能拦截,请手动处理").arg(what);
    case EO::Failed:            return u("检测到%1,处置未成功,请手动处理").arg(what);
    case EO::Terminated:        return u("已拦截%1,并结束了该进程").arg(what);
    case EO::ModuleBlacklisted: return u("已拦截%1,相关模块已禁止加载").arg(what);
    case EO::ExecDenied:        return u("已拦截%1,并已禁止它再次启动").arg(what);
    // 不说「已拦截」:那次拦截是上一条通知报过的,这里只说清这条动作的归属,
    // 也绝不说「请手动处理」—— 那个进程已经不在了,没有可处理的东西。
    case EO::ActorAlreadyGone:  return u("检测到%1,发起进程此前已被结束").arg(what);
    case EO::KernelBlocked:
    case EO::NotApplicable:     break; // NotApplicable:老服务不带处置字段,与通知同样按已拦截兜底
    }
    return u("已拦截%1").arg(what);
}

// 摘要。followUp = 念上一句时又攒下的:用「又」开头,听起来是接着说,而不像是在重复上一句。
// 与通知摘要同一条规矩:只要有没拦下的,就说出各是多少并提示手动处理,绝不用一句「已拦截」盖过去。
QString batchSentence(int blocked, int unenforced, bool followUp)
{
    const int total = blocked + unenforced;
    if (unenforced <= 0)
        return followUp ? u("又拦截了 %1 项危险行为").arg(blocked)
                        : u("短时间内共拦截 %1 项危险行为").arg(blocked);
    if (blocked <= 0)
        return followUp ? u("又有 %1 项危险行为未能拦截,请手动处理").arg(unenforced)
                        : u("短时间内有 %1 项危险行为未能拦截,请手动处理").arg(unenforced);
    return followUp ? u("又有 %1 项危险行为,其中 %2 项未能拦截,请手动处理").arg(total).arg(unenforced)
                    : u("短时间内共 %1 项危险行为,其中 %2 项未能拦截,请手动处理").arg(total).arg(unenforced);
}

#ifdef Q_OS_WIN
using Microsoft::WRL::ComPtr;

// 语音 token 的 Attributes\Language 是十六进制 LCID 列表("804"、"804;409")。主语言是中文即算,
// 简体 / 繁体 / 港澳台都能念简体字。
bool isChineseVoice(ISpObjectToken* token)
{
    ComPtr<ISpDataKey> attrs;
    if (!token || FAILED(token->OpenKey(L"Attributes", attrs.GetAddressOf())) || !attrs)
        return false;
    LPWSTR raw = nullptr;
    if (FAILED(attrs->GetStringValue(L"Language", &raw)) || !raw)
        return false;
    const QString langs = QString::fromWCharArray(raw);
    ::CoTaskMemFree(raw);
    for (const QString& part : langs.split(QLatin1Char(';'), Qt::SkipEmptyParts)) {
        bool ok = false;
        const uint lcid = part.trimmed().toUInt(&ok, 16);
        if (ok && PRIMARYLANGID(static_cast<WORD>(lcid)) == LANG_CHINESE)
            return true;
    }
    return false;
}

// 用户在系统里选的默认语音本身就是中文 -> 不动它。否则依次在「经典 SAPI 语音库 -> Windows 10/11 的 OneCore
// 语音库」里找简体、繁体中文语音。OneCore 那一处必须找:「设置 > 时间和语言 > 语音」里添加的语音只登记在
// 那里,不去找的话,英文版 Windows 装了中文语音也照样念不出中文。
bool selectChineseVoice(ISpVoice* voice)
{
    ComPtr<ISpObjectToken> current;
    if (SUCCEEDED(voice->GetVoice(current.GetAddressOf())) && isChineseVoice(current.Get()))
        return true;

    const wchar_t* const categories[] = {
        SPCAT_VOICES,
        L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Speech_OneCore\\Voices",
    };
    const wchar_t* const languages[] = {L"Language=804", L"Language=404"}; // 简体中文、繁体中文
    for (const wchar_t* category : categories) {
        ComPtr<ISpObjectTokenCategory> cat;
        if (FAILED(::CoCreateInstance(__uuidof(SpObjectTokenCategory), nullptr, CLSCTX_ALL,
                                      IID_PPV_ARGS(cat.GetAddressOf())))
            || FAILED(cat->SetId(category, FALSE)))
            continue;
        for (const wchar_t* language : languages) {
            ComPtr<IEnumSpObjectTokens> tokens;
            if (FAILED(cat->EnumTokens(language, nullptr, tokens.GetAddressOf())) || !tokens)
                continue;
            for (;;) {
                ComPtr<ISpObjectToken> token;
                ULONG fetched = 0;
                if (tokens->Next(1, token.GetAddressOf(), &fetched) != S_OK || fetched != 1 || !token)
                    break;
                if (SUCCEEDED(voice->SetVoice(token.Get())))
                    return true; // 个别 OneCore 语音经典接口装不上:换下一个
            }
        }
    }
    return false;
}
#endif // Q_OS_WIN

} // namespace

struct VoiceAnnouncer::Impl {
#ifdef Q_OS_WIN
    ComPtr<ISpVoice> voice;
    bool comInit = false; // 本对象的 CoInitializeEx 成功过,需要配对 CoUninitialize
#endif
};

VoiceAnnouncer* VoiceAnnouncer::instance()
{
    static QPointer<VoiceAnnouncer> s;
    if (!s)
        s = new VoiceAnnouncer(QCoreApplication::instance());
    return s;
}

VoiceAnnouncer::VoiceAnnouncer(QObject* parent) : QObject(parent), d(new Impl)
{
    m_enabled = QSettings().value(QLatin1String(kSettingKey), false).toBool();

    m_poll = new QTimer(this);
    m_poll->setInterval(kPollMs);
    connect(m_poll, &QTimer::timeout, this, &VoiceAnnouncer::poll);

    // 在 QApplication 析构之前放掉 COM 对象:Qt 平台插件会在那时 OleUninitialize,晚于它再 Release 不安全。
    if (QCoreApplication* app = QCoreApplication::instance())
        connect(app, &QCoreApplication::aboutToQuit, this, &VoiceAnnouncer::shutdown);

    // 上次就开着的:下一轮事件循环把引擎备好,第一条拦截不必等 SAPI 冷启动,设置页也能尽早拿到真实状态。
    if (m_enabled)
        QTimer::singleShot(0, this, [this] {
            if (m_enabled)
                ensureEngine();
        });
}

VoiceAnnouncer::~VoiceAnnouncer()
{
    shutdown();
    delete d;
}

void VoiceAnnouncer::setEnabled(bool on)
{
    if (on == m_enabled)
        return;
    m_enabled = on;
    QSettings().setValue(QLatin1String(kSettingKey), on);
    if (on) {
        m_engineTried = false; // 用户重新打开:上次初始化失败的话再试一次
        ensureEngine();
    } else {
        stopSpeaking();
    }
    emit statusChanged(); // status() 随开关变化(关着一律 Idle)
}

void VoiceAnnouncer::announceBlock(const QString& actorPath, bulwark::EnforcementOutcome enforcement)
{
    // 先确认「这条真的会被念出来」再记账。开关关着、或者引擎根本用不了的时候就记下「已念过」,
    // 等于把一条从没出过声的播报永久吞掉 —— 用户之后打开开关、或装好中文语音,也再也听不到它。
    if (!m_enabled || !ensureEngine())
        return;
    const QString sentence = blockSentence(actorPath, enforcement);
    if (alreadySpoken(actorPath, sentence))
        return;
    // 与通知同一条界线(evtfmt::needsManualAction):只有真的什么都没拦住才计入「未能拦截」,
    // 否则摘要那句「其中 N 项未能拦截,请手动处理」会把已经处置好的也数进去。
    const bool unenforced = evtfmt::needsManualAction(enforcement);
    enqueue(sentence, unenforced ? 0 : 1, unenforced ? 1 : 0);
}

// 同一威胁只念一次(见头文件里的说明)。键 = 主体 + 要念的那句话:处置结果变了,句子就变了,
// 于是算新消息、照样会念。
bool VoiceAnnouncer::alreadySpoken(const QString& actorPath, const QString& sentence)
{
    const QString key = actorPath + QLatin1Char('|') + sentence;
    if (m_spoken.contains(key))
        return true;
    // 有界维护:同一次界面运行里出现几千个【互不相同】的威胁已属异常,真到了就按最早的先丢。
    // 代价是被丢掉的那条日后可能再念一次 —— 比无上限增长要好,也比清空整张表温和。
    if (m_spoken.size() >= kMaxSpokenKeys) {
        QList<qint64> stamps = m_spoken.values();
        std::nth_element(stamps.begin(), stamps.begin() + stamps.size() / 4, stamps.end());
        const qint64 cutoff = stamps.at(stamps.size() / 4);
        for (auto it = m_spoken.begin(); it != m_spoken.end();) {
            if (it.value() <= cutoff)
                it = m_spoken.erase(it);
            else
                ++it;
        }
    }
    m_spoken.insert(key, QDateTime::currentMSecsSinceEpoch());
    return false;
}

void VoiceAnnouncer::announceBatch(int blocked, int unenforced)
{
    blocked = qMax(0, blocked);
    unenforced = qMax(0, unenforced);
    if (blocked + unenforced <= 0)
        return;
    enqueue(batchSentence(blocked, unenforced, /*followUp=*/false), blocked, unenforced);
}

void VoiceAnnouncer::enqueue(const QString& sentence, int blocked, int unenforced)
{
    if (!m_enabled || !ensureEngine())
        return;
    if (!m_busy) {
        speak(sentence);
        return;
    }
    ++m_pendingItems;
    m_pendingBlocked += blocked;
    m_pendingUnenforced += unenforced;
    m_pendingSentence = sentence;
}

bool VoiceAnnouncer::ensureEngine()
{
    if (m_shutDown)
        return false;
#ifdef Q_OS_WIN
    if (d->voice)
        return true;
    if (m_engineTried)
        return false;
    m_engineTried = true;

    // Qt 的 GUI 线程已是 STA(平台插件调过 OleInitialize),这里只是多加一次引用(S_FALSE),由 shutdown()
    // 配对释放。线程若已是 MTA(RPC_E_CHANGED_MODE),SAPI 照样能用,只是这次不能配对 CoUninitialize。
    const HRESULT init = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(init) && init != RPC_E_CHANGED_MODE) {
        qWarning("VoiceAnnouncer: CoInitializeEx failed (0x%08lx)", static_cast<unsigned long>(init));
        setEngineStatus(Status::Unavailable);
        return false;
    }
    d->comInit = SUCCEEDED(init);

    const HRESULT hr = ::CoCreateInstance(__uuidof(SpVoice), nullptr, CLSCTX_ALL,
                                          IID_PPV_ARGS(d->voice.GetAddressOf()));
    if (FAILED(hr) || !d->voice) {
        qWarning("VoiceAnnouncer: cannot create SAPI SpVoice (0x%08lx)", static_cast<unsigned long>(hr));
        d->voice.Reset();
        if (d->comInit) {
            ::CoUninitialize();
            d->comInit = false;
        }
        setEngineStatus(Status::Unavailable);
        return false;
    }
    // 不订阅任何 SAPI 事件:念完没有靠 SpeakCompleteEvent 查,事件没人取就只会在队列里越攒越多。
    d->voice->SetInterest(0, 0);
    setEngineStatus(selectChineseVoice(d->voice.Get()) ? Status::Ready : Status::NoChineseVoice);
    return true;
#else
    m_engineTried = true;
    setEngineStatus(Status::Unavailable);
    return false;
#endif
}

void VoiceAnnouncer::speak(const QString& sentence)
{
#ifdef Q_OS_WIN
    if (!d->voice)
        return;
    m_current = sentence;
    // SPF_IS_NOT_XML:句子里的程序名由样本自己决定,绝不能被当成 SAPI XML 解析(音量 / 静音 / 改读音标签)。
    const HRESULT hr = d->voice->Speak(reinterpret_cast<LPCWSTR>(m_current.utf16()),
                                       static_cast<DWORD>(SPF_ASYNC | SPF_IS_NOT_XML), nullptr);
    if (FAILED(hr)) {
        qWarning("VoiceAnnouncer: Speak failed (0x%08lx)", static_cast<unsigned long>(hr));
        m_current.clear();
        return;
    }
    m_busy = true;
    m_busySinceMs = QDateTime::currentMSecsSinceEpoch();
    m_poll->start();
#else
    Q_UNUSED(sentence);
#endif
}

void VoiceAnnouncer::poll()
{
#ifdef Q_OS_WIN
    if (d->voice && m_busy) {
        // 念完的信号是 voice 自带的事件句柄(归 voice 所有,不关闭)。用 0 超时的 WaitForSingleObject 查,
        // 而不是 WaitUntilDone:后者在 STA 线程上可能顺手泵消息,在这个定时器槽里重入 Qt 的事件分发。
        const HANDLE doneEvent = d->voice->SpeakCompleteEvent();
        const bool done = !doneEvent || ::WaitForSingleObject(doneEvent, 0) == WAIT_OBJECT_0;
        if (!done && QDateTime::currentMSecsSinceEpoch() - m_busySinceMs < kStuckMs)
            return;
        if (!done)
            d->voice->Speak(nullptr, SPF_PURGEBEFORESPEAK, nullptr);
    }
#endif
    m_busy = false;
    m_current.clear();
    if (!flushPending())
        m_poll->stop();
}

bool VoiceAnnouncer::flushPending()
{
    if (m_pendingItems <= 0)
        return false;
    const QString sentence = m_pendingItems == 1
                                 ? m_pendingSentence
                                 : batchSentence(m_pendingBlocked, m_pendingUnenforced, /*followUp=*/true);
    m_pendingItems = 0;
    m_pendingBlocked = 0;
    m_pendingUnenforced = 0;
    m_pendingSentence.clear();
    speak(sentence);
    return m_busy;
}

void VoiceAnnouncer::stopSpeaking()
{
    m_pendingItems = 0;
    m_pendingBlocked = 0;
    m_pendingUnenforced = 0;
    m_pendingSentence.clear();
#ifdef Q_OS_WIN
    if (d->voice && m_busy)
        d->voice->Speak(nullptr, SPF_PURGEBEFORESPEAK, nullptr); // 截断正在念的那一句
#endif
    m_busy = false;
    m_current.clear();
    if (m_poll)
        m_poll->stop();
}

void VoiceAnnouncer::shutdown()
{
    if (m_shutDown)
        return;
    m_shutDown = true;
    stopSpeaking();
#ifdef Q_OS_WIN
    d->voice.Reset();
    if (d->comInit) {
        ::CoUninitialize();
        d->comInit = false;
    }
#endif
}

void VoiceAnnouncer::setEngineStatus(Status s)
{
    if (m_engineStatus == s)
        return;
    m_engineStatus = s;
    if (m_enabled)
        emit statusChanged();
}
