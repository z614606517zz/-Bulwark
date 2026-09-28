// 设置 —— 两栏:左侧分类,右侧分组卡片(滚动时左侧跟随高亮)。
//
// 改动即时生效,没有「保存」按钮:开关一拨就发给服务,文本框在编辑完成时发。界面只在服务
// 回推的设置到达后才说「已保存 ✓」—— 没等到就如实说没等到。
//
// 在收到服务的第一份设置之前(以及断开连接之后),全部控件禁用:此刻显示的不是真实状态,
// 让用户去拨一个不知道真假的开关,等于让他改一份他看不见的配置。
//
// 两个开关关闭前先确认:实时防护(关掉后系统不受保护)与自我保护(关掉后防护组件可被结束)。
// 它们始终可以由用户关闭 —— 这是用户可控的安全工具,只是关之前要让人看清后果。
#include "pages/CardPages.h"
#include "pages/PageKit.h"
#include "dialogs/EventFormat.h"
#include "dialogs/UpdateDialog.h"
#include "bulwark/Version.h"
#include "bulwark/models/RuntimeSettings.h"
#include "design/Banner.h"
#include "design/Components.h"
#include "design/Confirm.h"
#include "design/GlowCard.h"
#include "design/IconTile.h"
#include "design/Identity.h"
#include "design/Motion.h"
#include "design/NavButton.h"
#include "design/StatusStrip.h"
#include "design/Theme.h"
#include "design/ToggleSwitch.h"
#include "ipc/IpcClient.h"
#include "Nav.h"

#include <QButtonGroup>
#include <QGridLayout>
#include <QHash>
#include <QLabel>
#include <QLineEdit>
#include <QPropertyAnimation>
#include <QPushButton>
#include <QScrollArea>
#include <QScrollBar>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>

#include <algorithm>
#include <iterator>
#include <memory>

using evtfmt::u;
using bulwark::RuntimeSettings;

namespace {

struct ToggleBind {
    ToggleSwitch* sw = nullptr;
    bool RuntimeSettings::*field = nullptr;
};
struct TextBind {
    QLineEdit* edit = nullptr;
    QString RuntimeSettings::*field = nullptr;
};
struct IntelSource {
    const char* name;      // display name
    const char* desc;
    const char* testKey;   // VtRequestPayload::source
    const char* keyLabel;
    bool RuntimeSettings::*enabled;
    QString RuntimeSettings::*key;
};
const IntelSource kSources[] = {
    {"VirusTotal", "多引擎哈希信誉(内置默认 Key)", "VirusTotal", "API Key", &RuntimeSettings::virusTotalEnabled,
     &RuntimeSettings::virusTotalApiKey},
    {"MalwareBazaar", "恶意样本库", "MalwareBazaar", "Auth-Key", &RuntimeSettings::malwareBazaarEnabled,
     &RuntimeSettings::malwareBazaarApiKey},
    {"AlienVault OTX", "开放威胁情报", "OTX", "API Key", &RuntimeSettings::otxEnabled, &RuntimeSettings::otxApiKey},
    {"微步在线 ThreatBook", "文件 + IP 情报", "ThreatBook", "API Key", &RuntimeSettings::threatBookEnabled,
     &RuntimeSettings::threatBookApiKey},
    {"MetaDefender", "多引擎扫描", "MetaDefender", "API Key", &RuntimeSettings::metaDefenderEnabled,
     &RuntimeSettings::metaDefenderApiKey},
    {"Hybrid Analysis", "沙箱行为情报", "HybridAnalysis", "API Key", &RuntimeSettings::hybridAnalysisEnabled,
     &RuntimeSettings::hybridAnalysisApiKey},
};

struct State {
    RuntimeSettings last;
    bool have = false;       // a snapshot from the service has arrived
    bool loading = false;    // echoing a snapshot into the controls (don't send it back)
    bool connected = false;
    bool pendingSave = false;
    int saveSeq = 0;
    QList<ToggleBind> toggles;
    QList<TextBind> texts;
    QSpinBox* timeout = nullptr;
    QList<QWidget*> controls;          // usable only while the state is known
    QList<ToggleSwitch*> intelToggles; // additionally locked by the server-only policy
    QList<QWidget*> intelEditors;
    QList<QLabel*> intelPills;
    QLabel* intelPolicy = nullptr;
    QHash<QUuid, QLabel*> pendingTests;
    QLabel* saveState = nullptr;
    StatusStrip* strip = nullptr;
    QLabel* aiState = nullptr;
};

// A titled section card in the hue of what the section configures
// (identity::settingsSection): its tile, a faint light from its top-left corner,
// and its entry in the category column. Returns the layout to fill.
QVBoxLayout* sectionCard(QWidget** cardOut, const QString& icon, const QColor& hue, const QString& title,
                         const QString& lead = QString())
{
    GlowCard* c = ui::card();
    c->setGlow(hue, QPointF(0.0, 0.0), 0.45, 0.06);
    auto* v = new QVBoxLayout(c);
    v->setContentsMargins(22, 18, 22, 18);
    v->setSpacing(4);
    auto* head = new QHBoxLayout;
    head->setSpacing(10);
    head->addWidget(new IconTile(icon, hue, 30, 15), 0, Qt::AlignVCenter);
    head->addWidget(ui::label(title, "h2"), 1, Qt::AlignVCenter);
    v->addLayout(head);
    if (!lead.isEmpty()) {
        auto* l = ui::label(lead, "muted");
        l->setWordWrap(true);
        l->setContentsMargins(40, 0, 0, 0);
        v->addWidget(l);
    }
    v->addSpacing(6);
    *cardOut = c;
    return v;
}

// title + description on the left, `control` on the right; a hairline above
// every row but the first.
QWidget* settingRow(QVBoxLayout* box, const QString& title, const QString& desc, QWidget* control, bool first = false)
{
    if (!first)
        box->addWidget(ui::hDivider());
    auto* w = new QWidget;
    auto* h = new QHBoxLayout(w);
    h->setContentsMargins(0, 10, 0, 10);
    h->setSpacing(16);
    auto* col = new QVBoxLayout;
    col->setSpacing(2);
    col->addWidget(ui::label(title, "title"));
    if (!desc.isEmpty()) {
        auto* d = ui::label(desc, "muted");
        d->setWordWrap(true);
        col->addWidget(d);
    }
    h->addLayout(col, 1);
    h->addWidget(control, 0, Qt::AlignVCenter);
    box->addWidget(w);
    return w;
}

} // namespace

QWidget* pages::settings(IpcClient* ipc)
{
    auto st = std::make_shared<State>();
    auto* page = new QWidget;
    auto* outer = new QVBoxLayout(page);
    outer->setContentsMargins(theme::metric::pagePad, 12, theme::metric::pagePad, 0);
    outer->setSpacing(12);

    st->strip = new StatusStrip;
    outer->addWidget(st->strip);

    auto* cols = new QHBoxLayout;
    cols->setSpacing(18);
    outer->addLayout(cols, 1);

    // ---- left: categories -----------------------------------------------------------------------
    auto* navHost = new QWidget;
    navHost->setFixedWidth(196);
    auto* navCol = new QVBoxLayout(navHost);
    navCol->setContentsMargins(0, 2, 0, 0);
    navCol->setSpacing(2);
    auto* group = new QButtonGroup(page);
    group->setExclusive(true);
    cols->addWidget(navHost, 0);

    // ---- right: section cards ----------------------------------------------------------------------
    auto* scroll = new QScrollArea;
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scroll->viewport()->setAutoFillBackground(false);
    auto* content = new QWidget;
    auto* v = new QVBoxLayout(content);
    v->setContentsMargins(0, 0, 8, theme::metric::pagePad);
    v->setSpacing(16);
    cols->addWidget(scroll, 1);

    struct Sec {
        QString key;
        QWidget* card;
        NavButton* nav;
    };
    auto sections = std::make_shared<QList<Sec>>();
    const auto addSection = [&](const QString& key, const QString& icon, const QString& title, const QString& lead) {
        const QColor hue = identity::settingsSection(key);
        QWidget* card = nullptr;
        QVBoxLayout* box = sectionCard(&card, icon, hue, title, lead);
        v->addWidget(card);
        auto* nb = new NavButton(icon, title);
        nb->setIdentity(hue);
        nb->setCheckable(true);
        group->addButton(nb);
        navCol->addWidget(nb);
        sections->append({key, card, nb});
        return box;
    };
    const auto toggle = [st](bool on, bool RuntimeSettings::*field) {
        auto* sw = new ToggleSwitch(on);
        st->toggles.append({sw, field});
        st->controls << sw;
        return sw;
    };

    // 1 防护总控
    QVBoxLayout* s = addSection(QStringLiteral("protection"), QStringLiteral("shield"), u("防护总控"), QString());
    ToggleSwitch* protection = toggle(true, &RuntimeSettings::protectionEnabled);
    settingRow(s, u("实时防护"), u("监控并拦截敏感系统行为。关闭后系统不受本软件保护(界面关闭不等于防护关闭)。"),
               protection, true);
    settingRow(s, u("默认拦截未知行为"), u("灰区行为无匹配规则时默认拦截(更严格)"),
               toggle(false, &RuntimeSettings::defaultBlock));
    settingRow(s, u("静默模式"), u("不弹窗打扰,询问类自动放行,仅拦确定性高危"), toggle(false, &RuntimeSettings::silentMode));
    // 紧跟静默模式之后,并在说明里点明「不受静默模式影响」—— 否则用户开了静默还看到通知
    // 会以为静默没生效。这两项的关系必须在界面上说清。
    settingRow(s, u("攻击链命中通知"),
               u("右下角提示并自动消失,不受静默模式影响 —— 静默会把询问降级为放行,这条通知补的正是那种"
                 "「命中了却无声」的情况"),
               toggle(true, &RuntimeSettings::attackChainToast));
    st->timeout = new QSpinBox;
    st->timeout->setRange(5, 300);
    st->timeout->setValue(30);
    st->timeout->setSuffix(u(" 秒"));
    st->timeout->setFixedWidth(116);
    st->timeout->setAccessibleName(u("弹窗超时"));
    st->controls << st->timeout;
    settingRow(s, u("弹窗超时"), u("行为询问弹窗的自动处置倒计时"), st->timeout);

    // 2 防护维度 — 2 × 3 tiles
    s = addSection(QStringLiteral("dims"), QStringLiteral("layers"), u("防护维度"),
                   u("每个维度独立开关;关闭某一维度,只停这一类行为的监控与拦截。"));
    {
        // Each dimension wears the hue of the behaviour family it watches — the
        // hue those events carry in 事件记录 (design/Identity.h). Process creation
        // itself is left uncoloured in lists, so the process dimension takes the
        // injection it also watches; memory protection guards loaded code.
        struct Dim {
            const char* icon;
            const char* name;
            const char* desc;
            bool RuntimeSettings::*field;
            identity::Kind kind;
        };
        using K = identity::Kind;
        const Dim dims[] = {
            {"activity", "进程防护", "进程创建 / 远程线程注入", &RuntimeSettings::processProtection, K::Injection},
            {"file", "文件防护", "敏感文件写入 / 删除", &RuntimeSettings::fileProtection, K::File},
            {"sliders", "注册表防护", "启动项 / 敏感键值写入", &RuntimeSettings::registryProtection, K::Registry},
            {"shield", "自我保护", "防止防护组件被结束 / 卸载", &RuntimeSettings::selfProtection, K::Protection},
            {"globe", "网络防护", "可疑外联 / C2 通信", &RuntimeSettings::networkProtection, K::Network},
            {"cpu", "内存防护", "反注入内存保护", &RuntimeSettings::memoryProtectionEnabled, K::Module},
        };
        auto* grid = new QGridLayout;
        grid->setHorizontalSpacing(12);
        grid->setVerticalSpacing(12);
        int i = 0;
        for (const Dim& d : dims) {
            const QColor hue = identity::kind(d.kind);
            GlowCard* tile = ui::cardAlt();
            tile->setGlow(hue, QPointF(0.0, 0.0), 0.8, 0.05);
            auto* th = new QHBoxLayout(tile);
            th->setContentsMargins(14, 12, 14, 12);
            th->setSpacing(12);
            th->addWidget(new IconTile(QString::fromLatin1(d.icon), hue, 34, 17), 0, Qt::AlignTop);
            auto* tc = new QVBoxLayout;
            tc->setSpacing(2);
            tc->addWidget(ui::label(u(d.name), "title"));
            auto* dd = ui::label(u(d.desc), "muted");
            dd->setWordWrap(true);
            tc->addWidget(dd);
            th->addLayout(tc, 1);
            ToggleSwitch* sw = toggle(true, d.field);
            sw->setAccessibleName(u(d.name));
            th->addWidget(sw, 0, Qt::AlignTop);
            grid->addWidget(tile, i / 2, i % 2);
            ++i;
        }
        s->addLayout(grid);
    }
    ToggleSwitch* selfProtection = nullptr;
    for (const ToggleBind& b : st->toggles)
        if (b.field == &RuntimeSettings::selfProtection)
            selfProtection = b.sw;

    // 3 决策与监控
    s = addSection(QStringLiteral("decision"), QStringLiteral("sliders"), u("决策与监控"), QString());
    settingRow(s, u("信任已签名程序"), u("有效签名的程序默认放行、不弹询问(仅拦确定性恶意)"),
               toggle(true, &RuntimeSettings::trustSignedActors), true);
    settingRow(s, u("行为基线"), u("学习正常行为以降低误报"), toggle(true, &RuntimeSettings::behaviorBaselineEnabled));
    settingRow(s, u("勒索诱饵"), u("布放诱饵文件侦测勒索加密"), toggle(true, &RuntimeSettings::ransomwareCanaryEnabled));
    settingRow(s, u("用户态行为监控"), u("无驱动时的持久化 / 勒索监控"),
               toggle(true, &RuntimeSettings::userModeBehaviorMonitor));
    settingRow(s, u("内核驱动"), u("加载 Bulwark.sys 实现事前拦截"), toggle(false, &RuntimeSettings::kernelDriverEnabled));
    settingRow(s, u("灰区 AI 会诊"), u("对双击 / 可疑程序额外调用大模型研判(需配置模型,默认关)"),
               toggle(false, &RuntimeSettings::aiGrayZoneConsultEnabled));

    // 4 威胁情报源 — a card per source; 「配置」 opens its key + connection test
    s = addSection(QStringLiteral("intel"), QStringLiteral("cloud"), u("威胁情报源"),
                   u("Key 留空则沿用服务端 appsettings.json / 内置默认;保存后立即热应用,无需重启。"));
    // 部署策略「本机不动用任何第三方情报源」生效时,下面这些开关在服务端一律按关处理。那就必须在这里
    // 说出来并把它们禁掉 —— 一个看着可点、点了却毫无效果的开关,是最难排查的一类「设置不生效」。
    st->intelPolicy = ui::label(
        u("当前部署策略:本机不动用任何第三方情报源 —— 云端只向中央服务器查询「该文件是否已收录」,不用本机密钥"
          "直连下列情报源、不上传文件。因此下列开关与 Key 暂不生效(策略在服务端 appsettings.json 的 "
          "ReputationProxy.ServerOnly)。"),
        "secondary");
    st->intelPolicy->setWordWrap(true);
    st->intelPolicy->setStyleSheet(QStringLiteral("color:%1;").arg(theme::warning().name()));
    st->intelPolicy->hide();
    s->addWidget(st->intelPolicy);
    struct TestRow {
        QPushButton* button;
        QLabel* result;
        QString source;
    };
    auto tests = std::make_shared<QList<TestRow>>();
    int sourceIndex = 0;
    for (const IntelSource& src : kSources) {
        // Peers without a kind of their own: a fixed walk through the identity hues,
        // so neighbouring sources never share one and each keeps its colour.
        const QColor hue = identity::sequence(sourceIndex++);
        auto* card = ui::cardAlt();
        auto* cv = new QVBoxLayout(card);
        cv->setContentsMargins(14, 10, 14, 10);
        cv->setSpacing(8);
        auto* top = new QHBoxLayout;
        top->setSpacing(12);
        top->addWidget(new IconTile(QStringLiteral("cloud"), hue, 30, 15), 0, Qt::AlignVCenter);
        auto* tc = new QVBoxLayout;
        tc->setSpacing(1);
        tc->addWidget(ui::label(u(src.name), "title"));
        tc->addWidget(ui::label(u(src.desc), "muted"));
        top->addLayout(tc, 1);
        auto* pill = ui::pill(u("—"), theme::textMuted());
        st->intelPills << pill;
        top->addWidget(pill, 0, Qt::AlignVCenter);
        auto* config = ui::button(u("配置"), "ghost", QStringLiteral("chevron-down"), true);
        config->setCheckable(true);
        top->addWidget(config, 0, Qt::AlignVCenter);
        ToggleSwitch* sw = toggle(false, src.enabled);
        sw->setAccessibleName(u(src.name));
        st->intelToggles << sw;
        top->addWidget(sw, 0, Qt::AlignVCenter);
        cv->addLayout(top);

        auto* detail = new QWidget;
        auto* dh = new QHBoxLayout(detail);
        dh->setContentsMargins(42, 0, 0, 4);
        dh->setSpacing(8);
        dh->addWidget(ui::label(u(src.keyLabel), "caption"));
        auto* key = new QLineEdit;
        key->setEchoMode(QLineEdit::Password);
        key->setPlaceholderText(u("留空 = 沿用服务端配置"));
        key->setAccessibleName(u(src.name) + u(" ") + u(src.keyLabel));
        dh->addWidget(key, 1);
        auto* test = ui::button(u("测试连接"), "ghost", QString(), true);
        dh->addWidget(test);
        auto* result = ui::label(QString(), "muted");
        result->setWordWrap(true);
        result->setMinimumWidth(120);
        dh->addWidget(result);
        detail->hide();
        cv->addWidget(detail);
        s->addWidget(card);
        st->texts.append({key, src.key});
        st->controls << key << test << config;
        st->intelEditors << key << test;

        QObject::connect(config, &QPushButton::toggled, detail, [detail, config](bool open) {
            detail->setVisible(open);
            config->setIcon(AppIcon::icon(open ? QStringLiteral("chevron-up") : QStringLiteral("chevron-down"),
                                          theme::textSecondary(), 16));
        });
        tests->append({test, result, QString::fromLatin1(src.testKey)});
    }

    // 5 云查杀与 AI
    s = addSection(QStringLiteral("ai"), QStringLiteral("sparkles"), u("云查杀与 AI"), QString());
    // 不写死 VirusTotal:云查毒是分级链路(中央服务器是否已收录 -> 本机密钥查各情报源 -> 上传)。
    settingRow(s, u("双击云查杀"), u("双击运行的程序自动做云端查毒"), toggle(true, &RuntimeSettings::aiScanDoubleClickEnabled),
               true);
    settingRow(s, u("查杀期间挂起"), u("查杀 / 研判完成前挂起目标进程"),
               toggle(true, &RuntimeSettings::aiScanSuspendDuringScan));
    settingRow(s, u("查杀失败即拦截"), u("云查杀 / AI 无明确结论时从严拦截"),
               toggle(false, &RuntimeSettings::aiScanBlockOnFailure));
    s->addWidget(ui::hDivider());
    {
        auto* aiHead = new QHBoxLayout;
        aiHead->setContentsMargins(0, 10, 0, 2);
        aiHead->addWidget(ui::label(u("大模型接入"), "title"));
        aiHead->addStretch();
        st->aiState = ui::pill(u("未配置"), theme::textMuted());
        aiHead->addWidget(st->aiState);
        s->addLayout(aiHead);
        auto* note = ui::label(u("AI 研判、AI 生成规则与 AI 清理都用这里的接口。API Key 只保存在本机服务端。"), "muted");
        note->setWordWrap(true);
        s->addWidget(note);
        auto* form = new QGridLayout;
        form->setContentsMargins(0, 6, 0, 4);
        form->setHorizontalSpacing(12);
        form->setVerticalSpacing(8);
        const struct {
            const char* label;
            const char* placeholder;
            QString RuntimeSettings::*field;
            bool secret;
        } fields[] = {
            {"接口地址", "https://api.example.com/v1", &RuntimeSettings::aiBaseUrl, false},
            {"API Key", "sk-…", &RuntimeSettings::aiApiKey, true},
            {"模型", "留空 = 服务端默认模型", &RuntimeSettings::aiModel, false},
        };
        int r = 0;
        for (const auto& f : fields) {
            form->addWidget(ui::label(u(f.label), "caption"), r, 0);
            auto* e = new QLineEdit;
            e->setPlaceholderText(u(f.placeholder));
            e->setAccessibleName(u(f.label));
            if (f.secret)
                e->setEchoMode(QLineEdit::Password);
            form->addWidget(e, r, 1);
            st->texts.append({e, f.field});
            st->controls << e;
            ++r;
        }
        form->setColumnStretch(1, 1);
        s->addLayout(form);
    }

    // 6 威胁情报共享(默认关)。「上传什么 / 不上传什么」必须讲清楚 —— 这是用户决定要不要开的唯一依据。
    s = addSection(QStringLiteral("share"), QStringLiteral("upload"), u("威胁情报共享"), QString());
    settingRow(s, u("共享病毒信息与行为数据"), u("默认关闭。开启后每天凌晨自动上传,上传成功即删除本地暂存"),
               toggle(false, &RuntimeSettings::cloudBehaviorUploadEnabled), true);
    {
        auto* note = ui::label(
            u("只上传病毒信息与沙箱行为数据:病毒文件的 SHA-256、判定结果、引擎检出数、威胁名称,以及该病毒已知的"
              "释放物名称与哈希、注册表键、外联 IP 与域名、服务名、互斥体。\n"
              "不涉及任何个人隐私信息:不上传文件内容,不上传该文件在本机的路径与文件名,不上传计算机名、用户名或"
              "任何账号信息,也不附带任何机器标识。\n"
              "仅在云查杀判定为恶意或可疑时才收集;关闭开关会立即删除本地已暂存的全部数据。"),
            "muted");
        note->setWordWrap(true);
        note->setContentsMargins(0, 4, 0, 0);
        s->addWidget(note);
    }

    // 7 关于与更新
    s = addSection(QStringLiteral("about"), QStringLiteral("info"), u("关于与更新"), QString());
    {
        auto* check = ui::button(u("检查更新"), "primary", QString(), true);
        settingRow(s, u("检查更新"),
                   u("向服务器查询新版本;下载后会校验大小、SHA-256 与数字签名,签名者不符一律拒绝安装"), check, true);
        settingRow(s, u("当前版本"), QString(), ui::label(bulwark::version::displayString(), "secondary"));
        QObject::connect(check, &QPushButton::clicked, page, [ipc, page] {
            UpdateDialog dlg(ipc, page);
            dlg.exec();
        });
    }
    v->addStretch(1);
    navCol->addStretch(1);
    scroll->setWidget(content);
    content->setAutoFillBackground(false);

    // ---- category nav <-> scroll position ---------------------------------------------------------------
    auto spyLock = std::make_shared<bool>(false);
    const auto scrollTo = [scroll, spyLock](QWidget* card) {
        QScrollBar* sb = scroll->verticalScrollBar();
        const int target = std::min(sb->maximum(), std::max(0, card->y() - 4));
        *spyLock = true;
        if (const int ms = motion::duration(220); ms > 0) {
            auto* a = new QPropertyAnimation(sb, "value", sb);
            a->setDuration(ms);
            a->setEasingCurve(QEasingCurve::OutCubic);
            a->setStartValue(sb->value());
            a->setEndValue(target);
            QObject::connect(a, &QPropertyAnimation::finished, sb, [spyLock] { *spyLock = false; });
            a->start(QAbstractAnimation::DeleteWhenStopped);
        } else {
            sb->setValue(target);
            *spyLock = false;
        }
    };
    for (const Sec& sec : std::as_const(*sections))
        QObject::connect(sec.nav, &QAbstractButton::clicked, page,
                         [scrollTo, card = sec.card] { scrollTo(card); });
    QObject::connect(scroll->verticalScrollBar(), &QScrollBar::valueChanged, page, [sections, spyLock, scroll](int value) {
        if (*spyLock || sections->isEmpty())
            return;
        const Sec* current = &sections->first();
        for (const Sec& sec : std::as_const(*sections))
            if (sec.card->y() <= value + 48)
                current = &sec;
        if (value >= scroll->verticalScrollBar()->maximum() - 2)
            current = &sections->last(); // the last card may never reach the top
        current->nav->setChecked(true);
    });
    sections->first().nav->setChecked(true);

    // ---- header: save state ------------------------------------------------------------------------------
    QHBoxLayout* actions = pagekit::headerActions(page);
    st->saveState = ui::label(QString(), "secondary");
    actions->addWidget(st->saveState);

    // ---- state -> controls ---------------------------------------------------------------------------------
    const auto syncEnabled = [st] {
        const bool usable = st->have && st->connected;
        for (QWidget* w : std::as_const(st->controls))
            w->setEnabled(usable);
        const bool serverOnly = st->last.cloudServerOnly;
        if (usable && serverOnly) {
            for (ToggleSwitch* t : std::as_const(st->intelToggles))
                t->setEnabled(false);
            for (QWidget* w : std::as_const(st->intelEditors))
                w->setEnabled(false);
        }
        st->intelPolicy->setVisible(st->have && serverOnly);
        if (!st->connected)
            st->strip->setState(QStringLiteral("server"), theme::textMuted(), u("未连接后台服务"),
                                st->have ? u("下面显示的是上次读到的设置,连接恢复前不能修改。")
                                         : u("连接后台服务后才能读取和修改设置。"));
        else if (!st->have)
            st->strip->setState(QStringLiteral("refresh"), theme::accent(), u("正在读取服务端设置…"),
                                u("读到之前控件保持禁用,免得改动一份看不见的配置。"));
        st->strip->setVisible(!usable);
    };
    const auto load = [st, syncEnabled](const RuntimeSettings& s2) {
        st->loading = true;
        st->last = s2;
        st->have = true;
        for (const ToggleBind& b : std::as_const(st->toggles))
            b.sw->setChecked(s2.*(b.field));
        for (const TextBind& b : std::as_const(st->texts))
            if (!b.edit->hasFocus()) // don't yank text out from under the cursor
                b.edit->setText(s2.*(b.field));
        {
            const QSignalBlocker block(st->timeout);
            st->timeout->setValue(s2.promptTimeoutSeconds);
        }
        for (int i = 0; i < st->intelPills.size() && i < int(std::size(kSources)); ++i) {
            const bool on = s2.*(kSources[i].enabled);
            ui::stylePill(st->intelPills[i],
                          s2.cloudServerOnly ? u("策略停用") : (on ? u("已启用") : u("未启用")),
                          s2.cloudServerOnly ? theme::warning() : (on ? theme::success() : theme::textMuted()));
        }
        ui::stylePill(st->aiState, s2.aiConfigured() ? u("已配置") : u("未配置"),
                      s2.aiConfigured() ? theme::success() : theme::textMuted());
        st->loading = false;
        syncEnabled();
    };

    // ---- controls -> service ---------------------------------------------------------------------------------
    const auto collect = [st]() -> RuntimeSettings {
        RuntimeSettings s2 = st->last; // fields the UI doesn't expose are preserved, not reset
        for (const ToggleBind& b : std::as_const(st->toggles))
            s2.*(b.field) = b.sw->isChecked();
        for (const TextBind& b : std::as_const(st->texts))
            s2.*(b.field) = b.edit->text().trimmed();
        s2.promptTimeoutSeconds = st->timeout->value();
        return s2;
    };
    const auto apply = [st, ipc, collect, page] {
        if (st->loading || !st->have)
            return;
        if (!ipc->isConnected()) {
            ui::notify(page, ui::Tone::Danger, u("未连接后台服务,改动没有保存。"));
            return;
        }
        const RuntimeSettings s2 = collect();
        st->last = s2;
        st->pendingSave = true;
        const int seq = ++st->saveSeq;
        st->saveState->setStyleSheet(QString());
        st->saveState->setText(u("正在保存…"));
        ipc->updateSettings(s2);
        QTimer::singleShot(6000, st->saveState, [st, seq] {
            if (!st->pendingSave || st->saveSeq != seq)
                return;
            st->pendingSave = false;
            st->saveState->setStyleSheet(QStringLiteral("color:%1;").arg(theme::warning().name()));
            st->saveState->setText(u("没有收到服务确认"));
        });
    };

    for (const ToggleBind& b : std::as_const(st->toggles)) {
        ToggleSwitch* sw = b.sw;
        const bool guarded = sw == protection || sw == selfProtection;
        QObject::connect(sw, &QAbstractButton::toggled, page, [st, sw, guarded, protection, page, apply](bool on) {
            if (st->loading)
                return;
            if (guarded && !on) {
                ui::ConfirmSpec c;
                if (sw == protection) {
                    c.risk = ui::Risk::Danger;
                    c.title = u("关闭实时防护");
                    c.summary = u("关闭后,本软件不再监控和拦截任何行为,系统此刻不受保护。");
                    c.consequences << u("已有的规则、信任名单与隔离区都保留,重新打开即恢复")
                                   << u("只是想少被打扰,可以改用「静默模式」");
                    c.confirmText = u("关闭实时防护");
                } else {
                    c.risk = ui::Risk::Caution;
                    c.title = u("关闭自我保护");
                    c.summary = u("关闭后,防护组件可以被其它程序结束或卸载 —— 恶意程序常先做这一步。");
                    c.consequences << u("需要卸载或排查本软件时再关,完成后记得打开");
                    c.confirmText = u("关闭自我保护");
                }
                if (!ui::confirm(page, c)) {
                    st->loading = true; // put it back without sending anything
                    sw->setChecked(true);
                    st->loading = false;
                    return;
                }
            }
            apply();
        });
    }
    // Arrow clicks and typing both change the value; send once it settles.
    auto* timeoutDebounce = new QTimer(page);
    timeoutDebounce->setSingleShot(true);
    timeoutDebounce->setInterval(450);
    QObject::connect(timeoutDebounce, &QTimer::timeout, page, [apply] { apply(); });
    QObject::connect(st->timeout, &QSpinBox::valueChanged, page, [timeoutDebounce] { timeoutDebounce->start(); });

    // 情报源「测试连接」:先把当前 Key 发给服务(热生效),再对该源发起 TestConnection;
    // 结果按 requestId 回填这一行。
    for (const TestRow& t : std::as_const(*tests))
        QObject::connect(t.button, &QPushButton::clicked, page, [st, ipc, apply, t] {
            if (!ipc->isConnected()) {
                t.result->setText(u("未连接后台服务"));
                return;
            }
            apply();
            t.result->setStyleSheet(QStringLiteral("color:%1;").arg(theme::textMuted().name()));
            t.result->setText(u("测试中…"));
            bulwark::ipc::VtRequestPayload p;
            p.kind = bulwark::VtRequestKind::TestConnection;
            p.source = t.source;
            st->pendingTests.insert(p.requestId, t.result);
            ipc->vtQuery(p);
        });
    for (const TextBind& b : std::as_const(st->texts))
        QObject::connect(b.edit, &QLineEdit::editingFinished, page, [st, apply, edit = b.edit, field = b.field] {
            if (st->have && st->last.*field == edit->text().trimmed())
                return; // focus left an unchanged field: nothing to save
            apply();
        });

    QObject::connect(ipc, &IpcClient::settingsReceived, page, [st, load](const RuntimeSettings& s2) {
        load(s2);
        if (st->pendingSave) {
            st->pendingSave = false;
            st->saveState->setStyleSheet(QStringLiteral("color:%1;").arg(theme::success().name()));
            st->saveState->setText(u("已保存 ✓"));
            const int seq = st->saveSeq;
            QTimer::singleShot(2500, st->saveState, [st, seq] {
                if (st->saveSeq == seq && !st->pendingSave)
                    st->saveState->clear();
            });
        }
    });
    // 测试连接结果回填(按 requestId 匹配本页发起的测试;云信誉页的查询不在此表,自动忽略)。
    QObject::connect(ipc, &IpcClient::vtResponse, page, [st](const bulwark::ipc::VtResponsePayload& r) {
        const auto it = st->pendingTests.find(r.requestId);
        if (it == st->pendingTests.end())
            return;
        QLabel* result = it.value();
        st->pendingTests.erase(it);
        result->setStyleSheet(QStringLiteral("color:%1;").arg((r.success ? theme::success() : theme::danger()).name()));
        result->setText(r.message.isEmpty() ? (r.success ? u("连接成功") : u("连接失败")) : r.message);
    });
    QObject::connect(ipc, &IpcClient::connectionChanged, page, [st, ipc, syncEnabled](bool c) {
        st->connected = c;
        syncEnabled();
        if (c)
            ipc->requestSettings();
    });
    st->connected = ipc->isConnected();
    syncEnabled();
    if (st->connected)
        ipc->requestSettings();

    // ---- navigation: nav::go("settings", {section}) ------------------------------------------------------------
    nav::onArrive(page, QString::fromLatin1(nav::Settings), [sections, scrollTo](const QVariantMap& args) {
        const QString key = args.value(QStringLiteral("section")).toString();
        for (const Sec& sec : std::as_const(*sections))
            if (sec.key == key) {
                sec.nav->setChecked(true);
                QTimer::singleShot(0, sec.card, [scrollTo, card = sec.card] { scrollTo(card); });
            }
    });
    return page;
}
