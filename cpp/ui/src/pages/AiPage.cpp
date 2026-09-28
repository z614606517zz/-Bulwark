// AI 研判 —— 大模型接入状态 + 手动研判文件 / 文件夹 + 研判记录(实时,落盘可回填)。
//
// 研判在界面进程里调用大模型(AiScanner),记录也由界面侧落盘,所以重启后这页从本机历史回填。
// 一次拖进一个大文件夹不该同时触发上百次模型调用:文件夹只取顶层的可执行文件,每次最多 25 个,
// 超出的如实告诉用户。
#include "pages/CardPages.h"
#include "pages/PageKit.h"
#include "dialogs/EventFormat.h"
#include "design/Banner.h"
#include "design/Confirm.h"
#include "design/DropZone.h"
#include "design/Format.h"
#include "design/Identity.h"
#include "design/Inspector.h"
#include "design/ListShell.h"
#include "design/Segmented.h"
#include "design/StatusStrip.h"
#include "design/Theme.h"
#include "ipc/IpcClient.h"
#include "Nav.h"

#include "bulwark/models/RuntimeSettings.h"

#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QLocale>
#include <QMenu>
#include <QPushButton>

#include <memory>

using evtfmt::u;

namespace {

constexpr int kBatchCap = 25;
enum Seg { SegAll = 0, SegMal, SegOk, SegNa };

evtfmt::Badge verdictOf(const AiScanResult& r)
{
    if (!r.available)
        return {u("不可用"), theme::textMuted()};
    if (r.malicious)
        return {u("恶意"), theme::danger()};
    return {u("未见异常"), theme::success()};
}

QString nameOf(const AiScanResult& r)
{
    return r.fileName.isEmpty() ? QFileInfo(r.filePath).fileName() : r.fileName;
}

RecordView resultView(const AiScanResult& r)
{
    RecordView v;
    const evtfmt::Badge b = verdictOf(r);
    v.icon = QStringLiteral("sparkles");
    v.iconColor = b.color;
    v.title = nameOf(r).isEmpty() ? u("未知文件") : nameOf(r);
    v.subtitle = r.summary.simplified().isEmpty() ? evtfmt::nativePath(r.filePath) : r.summary.simplified();
    if (r.available && !r.confidence.isEmpty())
        v.chips << u("置信度 ") + r.confidence;
    if (!r.source.isEmpty())
        v.chips << r.source;
    v.pill = b.text;
    v.pillColor = b.color;
    v.time = r.timestampUtc;
    v.accent = r.available && r.malicious ? theme::danger() : QColor();
    v.tooltip = evtfmt::nativePath(r.filePath);
    v.haystack = QStringList{r.fileName, r.filePath, r.summary, r.confidence, r.source, b.text}.join(QLatin1Char(' '));
    v.key = QStringLiteral("%1|%2").arg(r.timestampUtc.toMSecsSinceEpoch()).arg(r.filePath);
    return v;
}

// Files as given; folders contribute their top-level executables. Capped.
QStringList expand(const QStringList& paths, int* skipped)
{
    static const QStringList exts{QStringLiteral("exe"), QStringLiteral("dll"), QStringLiteral("scr"),
                                  QStringLiteral("sys"), QStringLiteral("com")};
    QStringList out;
    int total = 0;
    for (const QString& p : paths) {
        const QFileInfo fi(p);
        if (fi.isFile()) {
            ++total;
            if (out.size() < kBatchCap)
                out << fi.absoluteFilePath();
            continue;
        }
        if (!fi.isDir())
            continue;
        for (const QFileInfo& f : QDir(p).entryInfoList(QDir::Files)) {
            if (!exts.contains(f.suffix().toLower()))
                continue;
            ++total;
            if (out.size() < kBatchCap)
                out << f.absoluteFilePath();
        }
    }
    *skipped = total - int(out.size());
    return out;
}

} // namespace

QWidget* pages::aiScan(IpcClient* ipc)
{
    auto* page = new RecordBrowser;
    page->setIdentity(identity::page(nav::Ai));
    page->setLiveTop(true);
    page->setNeedsConnection(false); // 研判记录在界面侧落盘:没连上服务也能看
    page->searchBox()->setPlaceholderText(u("搜索文件 / 摘要…"));
    auto store = std::make_shared<RecordStore<AiScanResult>>(page->model(), &resultView);
    auto configured = std::make_shared<bool>(false);

    // ---- model status -------------------------------------------------------------------------------------
    auto* strip = new StatusStrip;
    auto* toSettings = ui::button(u("去设置"), "ghost", QStringLiteral("settings"), true);
    strip->addTrailing(toSettings);
    page->addTop(strip);
    QObject::connect(toSettings, &QPushButton::clicked, page, [] {
        nav::go(QString::fromLatin1(nav::Settings), {{QStringLiteral("section"), QStringLiteral("ai")}});
    });
    auto model = std::make_shared<QString>();
    const auto syncStrip = [strip, store, configured, model] {
        int mal = 0;
        qint64 tokens = 0;
        for (const AiScanResult& r : store->items()) {
            if (r.available && r.malicious)
                ++mal;
            tokens += r.tokens;
        }
        const QString meta = store->isEmpty() ? QString()
                                              : u("研判 %1 次 · 判定恶意 %2 · Token %3")
                                                    .arg(store->size())
                                                    .arg(mal)
                                                    .arg(QLocale().toString(tokens));
        if (*configured)
            strip->setState(QStringLiteral("sparkles"), theme::success(), u("大模型已接入"), *model, meta);
        else
            strip->setState(QStringLiteral("sparkles"), theme::textMuted(), u("未配置大模型"),
                            u("在「设置 → 云查杀与 AI」填入接口地址 / API Key / 模型后,才能研判。"), meta);
    };
    syncStrip();

    const auto scan = [page, ipc, configured](const QStringList& paths) {
        int skipped = 0;
        const QStringList files = expand(paths, &skipped);
        if (files.isEmpty()) {
            ui::notify(page, ui::Tone::Warning, u("没有找到可研判的可执行文件(exe / dll / scr / sys / com)。"));
            return;
        }
        if (!*configured) {
            if (Banner* b = ui::notify(page, ui::Tone::Warning, u("还没有配置大模型,研判会返回「不可用」。")))
                b->setAction(u("去设置"), [] {
                    nav::go(QString::fromLatin1(nav::Settings), {{QStringLiteral("section"), QStringLiteral("ai")}});
                });
        }
        for (const QString& f : files)
            ipc->aiScanFile(QDir::toNativeSeparators(f));
        QString text = u("已提交 %1 个文件给 AI 研判,结果会陆续出现在列表里。").arg(files.size());
        if (skipped > 0)
            text += u("另有 %1 个没有提交:一次最多 %2 个,免得同时触发大量模型调用。").arg(skipped).arg(kBatchCap);
        ui::notify(page, skipped > 0 ? ui::Tone::Warning : ui::Tone::Info, text);
    };
    page->setNoDataContent(QStringLiteral("sparkles"), u("还没有研判记录"),
                           u("把文件或文件夹拖到这里,AI 会根据静态特征给出研判;双击查杀触发的研判也会记在这里。"),
                           u("研判文件…"), [page, scan] {
                               const QStringList f = QFileDialog::getOpenFileNames(page, u("选择要研判的文件"));
                               if (!f.isEmpty())
                                   scan(f);
                           });

    // ---- header -----------------------------------------------------------------------------------------------
    QHBoxLayout* actions = pagekit::headerActions(page);
    QObject::connect(pagekit::headerButton(actions, QStringLiteral("folder"), u("研判文件夹…")), &QPushButton::clicked,
                     page, [page, scan] {
                         const QString d = QFileDialog::getExistingDirectory(page, u("选择要研判的文件夹"));
                         if (!d.isEmpty())
                             scan({d});
                     });
    QObject::connect(pagekit::headerButton(actions, QStringLiteral("file"), u("研判文件…"), "primary"),
                     &QPushButton::clicked, page, [page, scan] {
                         const QStringList f = QFileDialog::getOpenFileNames(page, u("选择要研判的文件"));
                         if (!f.isEmpty())
                             scan(f);
                     });
    QMenu* more = pagekit::headerMenu(actions);
    pagekit::menuAction(more, QStringLiteral("trash"), u("清空研判记录…"), page, [page, ipc, store, syncStrip] {
        ui::ConfirmSpec c;
        c.risk = ui::Risk::Danger;
        c.title = u("清空 AI 研判记录");
        c.summary = u("将清空这台电脑上保存的全部 AI 研判记录。");
        c.consequences << u("只影响这一页的历史,不影响规则、信任名单或隔离区") << u("此操作不可撤销");
        c.confirmText = u("清空");
        if (!ui::confirm(page, c))
            return;
        ipc->clearAiScanHistory();
        store->reset({});
        syncStrip();
        ui::notify(page, ui::Tone::Success, u("AI 研判记录已清空。"));
    });
    ui::acceptFileDrops(page, u("松开以交给 AI 研判"), [scan](const QStringList& paths) { scan(paths); });

    // ---- list ------------------------------------------------------------------------------------------------------
    Segmented* seg = page->segments();
    for (const char* t : {"全部", "恶意", "未见异常", "不可用"})
        seg->addSegment(u(t));
    seg->setAccent(SegMal, theme::danger());
    page->setPredicate([store, seg](int row) {
        const AiScanResult* r = store->itemAt(row);
        if (!r)
            return true;
        switch (seg->currentIndex()) {
        case SegMal: return r->available && r->malicious;
        case SegOk:  return r->available && !r->malicious;
        case SegNa:  return !r->available;
        default:     return true;
        }
    });
    page->setClearFilters([seg] { seg->setCurrentIndex(SegAll); });
    QObject::connect(seg, &Segmented::currentChanged, page, [page] { page->refilter(); });
    const auto updateCounts = [store, seg, syncStrip] {
        int n[4] = {0, 0, 0, 0};
        for (const AiScanResult& r : store->items()) {
            ++n[SegAll];
            if (!r.available) ++n[SegNa];
            else if (r.malicious) ++n[SegMal];
            else ++n[SegOk];
        }
        for (int i = 0; i < 4; ++i)
            seg->setCount(i, n[i]);
        syncStrip();
    };

    page->setInspectorBuilder([store](Inspector* in, int row) {
        const AiScanResult* rp = store->itemAt(row);
        if (!rp)
            return;
        const AiScanResult r = *rp;
        const evtfmt::Badge b = verdictOf(r);
        in->setHeader(QStringLiteral("sparkles"), b.color, nameOf(r).isEmpty() ? u("未知文件") : nameOf(r),
                      b.text + (r.available && !r.confidence.isEmpty() ? u(" · 置信度 ") + r.confidence : QString()));
        in->addLead(!r.available ? u("这次研判没有得到可用结论,文件没有被判定为恶意或安全。")
                    : r.malicious ? u("大模型判定这个文件为恶意。")
                                  : u("大模型没有发现恶意特征。"));
        if (r.available)
            in->addText(nullptr, u("AI 研判基于静态特征,是参考意见;真正的拦截由行为规则与威胁检测在事件发生时决定。"), "muted");
        // 不可用时 summary 装的是失败原因(未配置 / 请求失败 / 返回为空),不能当成研判摘要展示。
        QVBoxLayout* s = in->addSection(r.available ? u("研判摘要") : u("没有结论的原因"));
        in->addText(s, !r.summary.isEmpty() ? r.summary : r.available ? u("—") : u("原因未知。"), "secondary");
        s = in->addSection(u("详情"));
        in->addField(s, u("文件"), evtfmt::nativePath(r.filePath), Inspector::Mono | Inspector::Copy);
        in->addField(s, u("建议"), r.available ? evtfmt::verdict(r.recommendation).text : QString());
        in->addField(s, u("来源"), r.source);
        in->addField(s, u("用时"), r.elapsedMs > 0 ? u("%1 秒").arg(QString::number(r.elapsedMs / 1000.0, 'f', 1)) : QString());
        in->addField(s, u("Token"), r.tokens > 0 ? QLocale().toString(r.tokens) : QString());
        in->addField(s, u("时间"), fmt::absoluteTime(r.timestampUtc));
        if (!r.filePath.isEmpty())
            in->addAction(QStringLiteral("cloud"), u("查询云信誉"), "ghost", [path = evtfmt::nativePath(r.filePath)] {
                nav::go(QString::fromLatin1(nav::Reputation), {{QStringLiteral("path"), path}});
            });
        auto* menu = new QMenu;
        pagekit::menuAction(menu, QStringLiteral("copy"), r.available ? u("复制研判摘要") : u("复制失败原因"), in, [text = r.summary] {
            if (QClipboard* cb = QGuiApplication::clipboard())
                cb->setText(text);
        });
        in->addMenu(menu);
    });

    // ---- data ------------------------------------------------------------------------------------------------------
    store->reset(ipc->aiScanHistory()); // 最新在前,界面侧落盘
    QObject::connect(ipc, &IpcClient::aiScanRecord, page, [store, updateCounts](const AiScanResult& r) {
        store->prepend(r);
        updateCounts();
    });
    QObject::connect(ipc, &IpcClient::settingsReceived, page,
                     [configured, model, syncStrip](const bulwark::RuntimeSettings& s) {
        *configured = s.aiConfigured();
        *model = (s.aiModel.isEmpty() ? u("(默认模型)") : s.aiModel) + (s.aiBaseUrl.isEmpty() ? QString() : u(" · ") + s.aiBaseUrl);
        syncStrip();
    });
    pagekit::onConnected(page, ipc, page, 0, [ipc] {
        if (ipc->isConnected())
            ipc->requestSettings();
    });
    updateCounts();
    return page;
}
