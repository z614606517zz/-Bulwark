#include "bulwark/service/IpcServer.h"
#include "bulwark/service/Logger.h"
#include "bulwark/service/IpcClientAuth.h"

#include "bulwark/ipc/IpcMessageType.h"
#include "bulwark/ipc/Payloads.h"
#include "bulwark/ipc/PipeNames.h"

#include <QLocalServer>
#include <QLocalSocket>

namespace bulwark::service {
using namespace bulwark::ipc;

namespace {
Logger& log() { static Logger l(QStringLiteral("IpcServer")); return l; }
}

IpcServer::IpcServer(QObject* parent) : QObject(parent) {
    server_ = new QLocalServer(this);
    //
    // 允许其它用户会话的 UI 连接(服务以 SYSTEM 运行,UI 以普通用户运行)。
    //
    // 【为什么不收窄这个 DACL】QLocalServer 只暴露 User/Group/Other/World 四档粗粒度选项,
    // 没有「Authenticated Users」或自定义 SD 的入口;而收到 User|Group 就只剩服务自身的
    // SYSTEM 账户可连,普通用户的 UI 直接连不上。要真正做细粒度 SD 就得放弃 QLocalServer
    // 自己管命名管道,代价远大于收益 —— 因为按本产品的威胁模型,「谁能连」本来就不该是
    // 安全边界:一个允许普通用户连的管道,和一个允许所有人连的管道,对本地攻击者是等价的。
    //
    // 真正的边界是 onNewConnection 里的 IpcClientAuth:连进来之后必须证明自己是「本产品
    // 安装目录下的 bulwark_ui.exe」才会被放进 buffers_,否则立刻断开且收不到任何广播。
    // 这也是为什么这里保留 WorldAccessOption 是安全的 —— 不要把它当成遗漏改掉。
    //
    server_->setSocketOptions(QLocalServer::WorldAccessOption);
    connect(server_, &QLocalServer::newConnection, this, &IpcServer::onNewConnection);
}

bool IpcServer::start() {
    const QString name = controlPipe();
    QLocalServer::removeServer(name); // 清理可能的陈旧监听
    if (!server_->listen(name)) {
        log().error(QStringLiteral("监听控制管道失败: %1 (%2)").arg(name, server_->errorString()));
        return false;
    }
    log().info(QStringLiteral("IPC 服务器已监听 %1").arg(name));
    return true;
}

void IpcServer::stop() {
    for (auto it = buffers_.constBegin(); it != buffers_.constEnd(); ++it)
        it.key()->disconnectFromServer();
    buffers_.clear();
    if (server_) server_->close();
}

void IpcServer::onNewConnection() {
    while (QLocalSocket* sock = server_->nextPendingConnection()) {
        //
        // ===== 客户端认证:必须在把 socket 放进 buffers_ 之前完成 =====
        //
        // 管道上能下发的都是最高权限动作(关总开关 / 加白任意路径 / 结束任意进程树 / 还原隔离区),
        // 而 DACL 必须放开到普通用户(UI 以普通用户、可能在另一会话运行),所以连接权限本身不是
        // 安全边界 —— 边界在这里。见 IpcClientAuth.h 的完整说明。
        //
        // 顺序很关键:未通过认证的连接【绝不能】进入 buffers_。broadcast() 是按 buffers_ 遍历的,
        // 一旦入表,该客户端立刻开始收到全部弹窗、拦截通知与事件日志 —— 那本身就是一次完整的
        // 安全遥测泄露,即便它一条命令都发不出去。
        //
        const IpcClientAuth::Result auth = IpcClientAuth::authenticate(sock->socketDescriptor());
        if (!auth.ok) {
            log().warning(QStringLiteral("已拒绝未授权的控制管道连接:%1").arg(auth.reason));
            ++rejectedConnections_;
            sock->disconnectFromServer();
            sock->deleteLater();
            continue;
        }

        buffers_.insert(sock, QByteArray());
        connect(sock, &QLocalSocket::readyRead, this, &IpcServer::onReadyRead);
        connect(sock, &QLocalSocket::disconnected, this, &IpcServer::onDisconnected);
        log().info(QStringLiteral("UI 客户端已连接(%1,当前 %2)").arg(auth.reason).arg(buffers_.size()));
        emit clientCountChanged(buffers_.size());
    }
}

void IpcServer::onReadyRead() {
    auto* sock = qobject_cast<QLocalSocket*>(sender());
    if (!sock || !buffers_.contains(sock)) return;
    QByteArray& buf = buffers_[sock];
    buf += sock->readAll();
    int nl;
    while ((nl = buf.indexOf('\n')) >= 0) {
        const QByteArray lineBytes = buf.left(nl);
        buf.remove(0, nl + 1);
        const QString line = QString::fromUtf8(lineBytes).trimmed();
        if (!line.isEmpty()) handleLine(sock, line);
    }
}

void IpcServer::onDisconnected() {
    auto* sock = qobject_cast<QLocalSocket*>(sender());
    if (!sock) return;
    buffers_.remove(sock);
    sock->deleteLater();
    log().info(QStringLiteral("UI 客户端断开(当前 %1)").arg(buffers_.size()));
    emit clientCountChanged(buffers_.size());
}

void IpcServer::handleLine(QLocalSocket* /*sock*/, const QString& line) {
    const auto msg = IpcMessage::deserialize(line);
    if (!msg) return;

    // 处理器异常绝不能中断读取循环(否则管道断开,UI 表现为"保存无效")。
    try {
        switch (msg->type) {
            case IpcMessageType::Hello: {
                const HelloPayload h = HelloPayload::fromJson(msg->payloadObject());
                emit helloReceived(h.processId, h.role);
                if (uiProcessConnected && h.processId > 0) uiProcessConnected(h.processId);
                break;
            }
            case IpcMessageType::PromptResponse: {
                const PromptResponsePayload p = PromptResponsePayload::fromJson(msg->payloadObject());
                emit promptResponse(p.eventId, p.action, p.remember, p.scope);
                break;
            }
            case IpcMessageType::AiScanResponse: {
                emit aiScanResponse(AiScanResponsePayload::fromJson(msg->payloadObject()));
                break;
            }

            // ---- 规则管理 ----
            case IpcMessageType::RulesRequest:
                sendRules();
                break;
            case IpcMessageType::DeleteRule: {
                const auto p = DeleteRulePayload::fromJson(msg->payloadObject());
                if (ruleDeleteRequested) ruleDeleteRequested(p.ruleId);
                sendRules();
                break;
            }
            case IpcMessageType::AddRule: {
                const auto p = AddRulePayload::fromJson(msg->payloadObject());
                if (ruleAddRequested) ruleAddRequested(p);
                sendRules();
                break;
            }

            // ---- 运行时设置 ----
            case IpcMessageType::SettingsRequest:
                sendSettings();
                break;
            case IpcMessageType::SettingsUpdate: {
                const auto s = bulwark::RuntimeSettings::fromJson(msg->payloadObject());
                if (settingsUpdated) settingsUpdated(s);
                sendSettings();
                break;
            }

            // ---- 文件信任 ----
            case IpcMessageType::TrustListRequest:
                sendTrustList();
                break;
            case IpcMessageType::AddTrust: {
                const auto p = AddTrustPayload::fromJson(msg->payloadObject());
                if (trustAddRequested && !p.actorPath.trimmed().isEmpty()) trustAddRequested(p);
                sendTrustList();
                break;
            }
            case IpcMessageType::RemoveTrust: {
                const auto p = RemoveTrustPayload::fromJson(msg->payloadObject());
                if (trustRemoveRequested) trustRemoveRequested(p.ruleId);
                sendTrustList();
                break;
            }

            // ---- 威胁情报 / VirusTotal ----
            case IpcMessageType::VtQueryRequest: {
                const auto req = VtRequestPayload::fromJson(msg->payloadObject());
                VtResponsePayload resp = vtRequested
                    ? vtRequested(req)
                    : VtResponsePayload{req.requestId, false, QStringLiteral("服务未启用威胁情报"), std::nullopt, std::nullopt};
                resp.requestId = req.requestId;
                broadcast(IpcMessage::from(IpcMessageType::VtQueryResponse, resp));
                break;
            }
            // ---- 云信誉详情:按需拉取某哈希的 VT 完整报告(异步,响应经 sendVtDetail 回推)----
            case IpcMessageType::VtDetailRequest: {
                const auto req = VtRequestPayload::fromJson(msg->payloadObject());
                if (vtDetailRequested)
                    vtDetailRequested(req.requestId, req.filePath); // filePath 携带 sha256
                break;
            }
            case IpcMessageType::VtHistoryRequest: {
                const auto payload = vtHistoryRequested ? vtHistoryRequested() : VtHistoryResponsePayload{};
                broadcast(IpcMessage::from(IpcMessageType::VtHistoryResponse, payload));
                break;
            }

            // ---- 隔离区 ----
            case IpcMessageType::QuarantineListRequest:
                sendQuarantineList();
                break;
            case IpcMessageType::QuarantineRestore: {
                const auto p = QuarantineActionPayload::fromJson(msg->payloadObject());
                QuarantineActionResultPayload r = quarantineRestoreRequested
                    ? quarantineRestoreRequested(p.id)
                    : QuarantineActionResultPayload{p.id, false, QStringLiteral("服务未启用隔离区"), };
                broadcast(IpcMessage::from(IpcMessageType::QuarantineActionResult, r));
                sendQuarantineList();
                break;
            }
            case IpcMessageType::QuarantineDelete: {
                const auto p = QuarantineActionPayload::fromJson(msg->payloadObject());
                QuarantineActionResultPayload r = quarantineDeleteRequested
                    ? quarantineDeleteRequested(p.id)
                    : QuarantineActionResultPayload{p.id, false, QStringLiteral("服务未启用隔离区"), };
                broadcast(IpcMessage::from(IpcMessageType::QuarantineActionResult, r));
                sendQuarantineList();
                break;
            }
            case IpcMessageType::ManualQuarantineRequest: {
                const auto req = ManualQuarantinePayload::fromJson(msg->payloadObject());
                ManualQuarantineResultPayload resp;
                resp.requestId = req.requestId;
                if (manualQuarantineRequested) {
                    const auto [ok, message] = manualQuarantineRequested(req.path);
                    resp.success = ok;
                    resp.message = message;
                } else {
                    resp.success = false;
                    resp.message = QStringLiteral("当前环境不支持隔离");
                }
                broadcast(IpcMessage::from(IpcMessageType::ManualQuarantineResponse, resp));
                break;
            }

            // ---- 持久化审计 ----
            // ---- 自启动项清理(此前协议留了消息号,但两端都没有实现)----
            case IpcMessageType::PersistenceCleanupRequest: {
                const auto req = PersistenceCleanupRequestPayload::fromJson(msg->payloadObject());
                PersistenceCleanupResultPayload res;
                if (persistenceCleanupRequested) {
                    res = persistenceCleanupRequested(req);
                } else {
                    res.success = false;
                    res.message = QStringLiteral("服务未启用自启动项清理");
                }
                res.requestId = req.requestId;
                res.entryId = req.entry.id;
                broadcast(IpcMessage::from(IpcMessageType::PersistenceCleanupResponse, res));
                break;
            }

            case IpcMessageType::PersistenceListRequest: {
                PersistenceListResponsePayload payload = persistenceListRequested
                    ? persistenceListRequested()
                    : PersistenceListResponsePayload{QDateTime::currentDateTimeUtc(), {}, QStringLiteral("服务未启用持久化扫描")};
                broadcast(IpcMessage::from(IpcMessageType::PersistenceListResponse, payload));
                break;
            }

            // ---- 结构化事件历史(活动日志/拦截记录打开时回填最近 N 条)----
            case IpcMessageType::EventHistoryRequest: {
                const EventHistoryResponsePayload payload =
                    eventHistoryRequested ? eventHistoryRequested() : EventHistoryResponsePayload{};
                broadcast(IpcMessage::from(IpcMessageType::EventHistoryResponse, payload));
                break;
            }

            // ---- 清空事件历史:清后回推(已空的)历史,所有 UI 的活动日志/拦截记录同步清空 ----
            case IpcMessageType::EventHistoryClearRequest: {
                if (eventHistoryClearRequested) eventHistoryClearRequested();
                const EventHistoryResponsePayload payload =
                    eventHistoryRequested ? eventHistoryRequested() : EventHistoryResponsePayload{};
                broadcast(IpcMessage::from(IpcMessageType::EventHistoryResponse, payload));
                break;
            }

            // ---- 攻击链组合引擎:表状态 + 命中记录 ----
            case IpcMessageType::AttackChainRequest:
                sendAttackChain();
                break;
            // 清空命中记录:清后回推(已空的)记录,UI 无需再请求(同事件历史的约定)。
            case IpcMessageType::AttackChainClearRequest: {
                if (attackChainClearRequested) attackChainClearRequested();
                sendAttackChain();
                break;
            }

            // ---- 在线更新:异步 —— 宿主后台走网络,算完经 sendUpdateCheck / 进度 / 结果回推 ----
            // 未绑定回调时【立刻】回一条 ok=false 的结论,而不是什么都不发:后者会让弹窗
            // 一直停在「正在检查…」,用户无从判断是服务没这个功能还是网络卡住了。
            case IpcMessageType::UpdateCheckRequest: {
                if (updateCheckRequested) {
                    updateCheckRequested();
                } else {
                    UpdateCheckResponsePayload res;
                    res.ok = false;
                    res.error = QString::fromUtf8("本服务未启用在线更新功能。");
                    sendUpdateCheck(res);
                }
                break;
            }
            case IpcMessageType::UpdateDownloadRequest: {
                if (updateDownloadRequested) {
                    updateDownloadRequested();
                } else {
                    UpdateDownloadResponsePayload res;
                    res.ok = false;
                    res.error = QString::fromUtf8("本服务未启用在线更新功能。");
                    sendUpdateDownloadResult(res);
                }
                break;
            }
            case IpcMessageType::UpdateApplyRequest: {
                if (updateApplyRequested) {
                    updateApplyRequested();
                } else {
                    // 未绑定时【立刻】回一条失败结论,不能什么都不发 —— 后者会让界面
                    // 一直停在「正在安装」,而用户无从判断是没这功能还是卡住了。
                    UpdateApplyResponsePayload res;
                    res.ok = false;
                    res.needsRestart = false;
                    res.error = QString::fromUtf8("本服务未启用在线更新功能。");
                    sendUpdateApplyResult(res);
                }
                break;
            }

            // ---- 磁盘垃圾清理:异步 —— 宿主后台遍历,算完经 sendJunkScan / sendJunkClean 回推。
            //      未绑定回调时【立刻】回一条 enabled=false / success=false 的结论,而不是什么都
            //      不发 —— 后者会让界面一直停在「正在扫描…」,用户无从判断是没这功能还是卡住了。
            case IpcMessageType::JunkScanRequest: {
                const auto req = JunkScanRequestPayload::fromJson(msg->payloadObject());
                if (junkScanRequested) {
                    junkScanRequested(req);
                } else {
                    JunkScanResponsePayload res;
                    res.requestId = req.requestId;
                    res.enabled = false;
                    res.message = QString::fromUtf8("本服务未启用磁盘垃圾清理。");
                    sendJunkScan(res);
                }
                break;
            }
            case IpcMessageType::JunkCleanRequest: {
                const auto req = JunkCleanRequestPayload::fromJson(msg->payloadObject());
                if (junkCleanRequested) {
                    junkCleanRequested(req);
                } else {
                    JunkCleanResponsePayload res;
                    res.requestId = req.requestId;
                    res.success = false;
                    res.message = QString::fromUtf8("本服务未启用磁盘垃圾清理。");
                    sendJunkClean(res);
                }
                break;
            }
            case IpcMessageType::LargeFileScanRequest: {
                const auto req = LargeFileScanRequestPayload::fromJson(msg->payloadObject());
                if (largeFileScanRequested) {
                    largeFileScanRequested(req);
                } else {
                    LargeFileScanResponsePayload res;
                    res.requestId = req.requestId;
                    res.enabled = false;
                    res.message = QString::fromUtf8("本服务未启用大文件查找。");
                    sendLargeFileScan(res);
                }
                break;
            }

            // ---- 事件时间线(取证回溯):异步 —— 宿主后台扫历史,算完经 sendTimeline 回推 ----
            case IpcMessageType::EventTimelineRequest: {
                const auto req = TimelineRequestPayload::fromJson(msg->payloadObject());
                if (timelineRequested) {
                    timelineRequested(req);
                } else {
                    TimelineResponsePayload res;
                    res.requestId = req.requestId;
                    res.message = QStringLiteral("服务未启用事件时间线");
                    broadcast(IpcMessage::from(IpcMessageType::EventTimelineResponse, res));
                }
                break;
            }

            // ---- 攻击图:同样异步(要取时间窗内全部事件再关联)----
            case IpcMessageType::AttackGraphRequest: {
                const auto req = AttackGraphRequestPayload::fromJson(msg->payloadObject());
                if (attackGraphRequested) {
                    attackGraphRequested(req);
                } else {
                    AttackGraphResponsePayload res;
                    res.requestId = req.requestId;
                    res.message = QStringLiteral("服务未启用攻击图");
                    broadcast(IpcMessage::from(IpcMessageType::AttackGraphResponse, res));
                }
                break;
            }

            // ---- 进程管理:列表异步(首次快照要验签),处置同步 ----
            case IpcMessageType::ProcessListRequest: {
                const auto req = ProcessListRequestPayload::fromJson(msg->payloadObject());
                if (processListRequested) {
                    processListRequested(req);
                } else {
                    ProcessListResponsePayload res;
                    res.requestId = req.requestId;
                    res.message = QStringLiteral("服务未启用进程管理");
                    broadcast(IpcMessage::from(IpcMessageType::ProcessListResponse, res));
                }
                break;
            }
            case IpcMessageType::ProcessActionRequest: {
                const auto req = ProcessActionRequestPayload::fromJson(msg->payloadObject());
                ProcessActionResultPayload res;
                if (processActionRequested) {
                    res = processActionRequested(req);
                } else {
                    res.success = false;
                    res.message = QStringLiteral("服务未启用进程管理");
                }
                res.requestId = req.requestId;
                res.kind = req.kind;
                res.pid = req.pid;
                broadcast(IpcMessage::from(IpcMessageType::ProcessActionResponse, res));
                break;
            }

            // ---- 情报订阅(ThreatFox) ----
            case IpcMessageType::IntelRefreshRequest: {
                const auto req = IntelRefreshRequestPayload::fromJson(msg->payloadObject());
                IntelRefreshResultPayload result = intelRefreshRequested
                    ? intelRefreshRequested(req)
                    : IntelRefreshResultPayload{req.requestId, false, 0, 0, {}, {}, QStringLiteral("情报刷新未启用")};
                result.requestId = req.requestId;
                broadcast(IpcMessage::from(IpcMessageType::IntelRefreshResponse, result));
                break;
            }
            case IpcMessageType::IntelApplyRequest: {
                const auto req = IntelApplyRequestPayload::fromJson(msg->payloadObject());
                IntelRefreshResultPayload result = intelApplyRequested
                    ? intelApplyRequested(req)
                    : IntelRefreshResultPayload{req.requestId, false, 0, 0, {}, {}, QStringLiteral("情报采纳未启用")};
                result.requestId = req.requestId;
                broadcast(IpcMessage::from(IpcMessageType::IntelApplyResponse, result));
                break;
            }

            default:
                break; // 未处理的类型静默忽略(响应类消息由本端发出,不应回收)
        }
    } catch (const std::exception& ex) {
        log().warning(QStringLiteral("处理 UI 消息出错(已忽略): %1").arg(QString::fromUtf8(ex.what())));
    } catch (...) {
        log().warning(QStringLiteral("处理 UI 消息出现未知异常(已忽略)。"));
    }
}

void IpcServer::broadcast(const IpcMessage& msg) {
    const QByteArray bytes = (msg.serialize() + QLatin1Char('\n')).toUtf8();
    for (auto it = buffers_.constBegin(); it != buffers_.constEnd(); ++it) {
        QLocalSocket* sock = it.key();
        if (sock->state() == QLocalSocket::ConnectedState) {
            sock->write(bytes);
            sock->flush();
        }
    }
}

// ---- 推送 ----
void IpcServer::sendPrompt(const bulwark::SecurityEvent& e) {
    broadcast(IpcMessage::create(IpcMessageType::PromptRequest, e.toJson()));
}

void IpcServer::sendBlock(const bulwark::SecurityEvent& e) {
    broadcast(IpcMessage::create(IpcMessageType::BlockNotification, e.toJson()));
}

void IpcServer::sendAttackChainHit(const bulwark::ipc::AttackChainHitPayload& hit) {
    broadcast(IpcMessage::from(IpcMessageType::AttackChainHitNotification, hit));
}

void IpcServer::sendLog(const QString& line) {
    broadcast(IpcMessage::createRaw(IpcMessageType::LogEntry, line));
}

void IpcServer::sendEventLog(const bulwark::SecurityEvent& e,
                             bulwark::VerdictAction action, bulwark::VerdictSource source,
                             bulwark::EnforcementOutcome enforcement) {
    EventLogPayload p;
    p.event = e;
    p.action = action;
    p.source = source;
    p.enforcement = enforcement;
    broadcast(IpcMessage::from(IpcMessageType::EventLogEntry, p));
}

void IpcServer::sendRemediationReport(const RemediationReportPayload& report) {
    broadcast(IpcMessage::from(IpcMessageType::RemediationReport, report));
}

void IpcServer::sendVtScanUpdate(const bulwark::VtScanRecord& record) {
    broadcast(IpcMessage::create(IpcMessageType::VtScanUpdate, record.toJson()));
}

void IpcServer::sendVtDetail(const bulwark::ipc::VtDetailResponsePayload& detail) {
    broadcast(IpcMessage::from(IpcMessageType::VtDetailResponse, detail));
}

void IpcServer::requestAiScan(const bulwark::SecurityEvent& e) {
    broadcast(IpcMessage::create(IpcMessageType::AiScanRequest, e.toJson()));
}

void IpcServer::sendTimeline(const TimelineResponsePayload& payload) {
    broadcast(IpcMessage::from(IpcMessageType::EventTimelineResponse, payload));
}

void IpcServer::sendAttackGraph(const AttackGraphResponsePayload& payload) {
    broadcast(IpcMessage::from(IpcMessageType::AttackGraphResponse, payload));
}

void IpcServer::sendProcessList(const ProcessListResponsePayload& payload) {
    broadcast(IpcMessage::from(IpcMessageType::ProcessListResponse, payload));
}

// ---- 快照推送 ----
void IpcServer::sendRules() {
    RulesResponsePayload payload;
    if (rulesRequested) payload.rules = rulesRequested();
    broadcast(IpcMessage::from(IpcMessageType::RulesResponse, payload));
}

void IpcServer::sendSettings() {
    const bulwark::RuntimeSettings settings = settingsRequested ? settingsRequested() : bulwark::RuntimeSettings{};
    broadcast(IpcMessage::from(IpcMessageType::SettingsResponse, settings));
}

void IpcServer::sendTrustList() {
    TrustListResponsePayload payload;
    if (trustListRequested) payload.entries = trustListRequested();
    broadcast(IpcMessage::from(IpcMessageType::TrustListResponse, payload));
}

void IpcServer::sendQuarantineList() {
    const QuarantineListResponsePayload payload =
        quarantineListRequested ? quarantineListRequested() : QuarantineListResponsePayload{};
    broadcast(IpcMessage::from(IpcMessageType::QuarantineListResponse, payload));
}

void IpcServer::sendUpdateCheck(const UpdateCheckResponsePayload& payload) {
    broadcast(IpcMessage::from(IpcMessageType::UpdateCheckResponse, payload));
}

void IpcServer::sendUpdateProgress(const UpdateProgressPayload& payload) {
    broadcast(IpcMessage::from(IpcMessageType::UpdateProgressNotification, payload));
}

void IpcServer::sendUpdateDownloadResult(const UpdateDownloadResponsePayload& p) {
    broadcast(IpcMessage::from(IpcMessageType::UpdateDownloadResponse, p));
}

void IpcServer::sendUpdateApplyResult(const UpdateApplyResponsePayload& p) {
    broadcast(IpcMessage::from(IpcMessageType::UpdateApplyResponse, p));
}

void IpcServer::sendJunkScan(const JunkScanResponsePayload& payload) {
    broadcast(IpcMessage::from(IpcMessageType::JunkScanResponse, payload));
}

void IpcServer::sendJunkClean(const JunkCleanResponsePayload& payload) {
    broadcast(IpcMessage::from(IpcMessageType::JunkCleanResponse, payload));
}

void IpcServer::sendJunkProgress(const JunkProgressPayload& payload) {
    broadcast(IpcMessage::from(IpcMessageType::JunkProgressNotification, payload));
}

void IpcServer::sendLargeFileScan(const LargeFileScanResponsePayload& payload) {
    broadcast(IpcMessage::from(IpcMessageType::LargeFileScanResponse, payload));
}

// 未绑定回调时回一个 enabled=false 的空负载 —— UI 据此显示「引擎未启用」而不是空白页。
void IpcServer::sendAttackChain() {
    const AttackChainResponsePayload payload =
        attackChainRequested ? attackChainRequested() : AttackChainResponsePayload{};
    broadcast(IpcMessage::from(IpcMessageType::AttackChainResponse, payload));
}

} // namespace bulwark::service
