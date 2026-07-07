#include "bulwark/service/EventSource.h"

#include <QTimer>
#include <QVector>

namespace bulwark::service {

namespace {
// 代表性样本(与 .NET SimulatedEventSource.Samples 对应)。
QVector<bulwark::SecurityEvent> buildSamples() {
    QVector<bulwark::SecurityEvent> s;
    auto make = [](bulwark::EventType type, int pid, const char* path, bool signed_,
                   const char* target, const char* detail) {
        bulwark::SecurityEvent e;
        e.type = type;
        e.actorPid = pid;
        e.actorPath = QString::fromUtf8(path);
        e.actorSigned = signed_;
        e.target = QString::fromUtf8(target);
        e.detail = QString::fromUtf8(detail);
        return e;
    };
    s << make(bulwark::EventType::ProcessCreate, 4321, "C:\\Users\\Public\\unknown.exe", false,
              "C:\\Windows\\System32\\cmd.exe", "\xe5\xb0\x9d\xe8\xaf\x95\xe5\x90\xaf\xe5\x8a\xa8\xe5\x91\xbd\xe4\xbb\xa4\xe8\xa1\x8c");
    s << make(bulwark::EventType::RegistryWrite, 4321, "C:\\Users\\Public\\unknown.exe", false,
              "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor",
              "\xe5\x86\x99\xe5\x85\xa5\xe5\xbc\x80\xe6\x9c\xba\xe5\x90\xaf\xe5\x8a\xa8\xe9\xa1\xb9");
    s << make(bulwark::EventType::RemoteThread, 4321, "C:\\Users\\Public\\unknown.exe", false,
              "C:\\Windows\\explorer.exe",
              "\xe5\x90\x91 explorer \xe6\xb3\xa8\xe5\x85\xa5\xe8\xbf\x9c\xe7\xa8\x8b\xe7\xba\xbf\xe7\xa8\x8b");
    s << make(bulwark::EventType::FileWrite, 8800, "C:\\Program Files\\Editor\\editor.exe", true,
              "C:\\Users\\Me\\Documents\\note.txt",
              "\xe4\xbf\x9d\xe5\xad\x98\xe6\x96\x87\xe6\xa1\xa3");
    s << make(bulwark::EventType::NetworkConnect, 4321, "C:\\Users\\Public\\unknown.exe", false,
              "203.0.113.66:443",
              "\xe5\xa4\x96\xe8\x81\x94\xe5\x8f\xaf\xe7\x96\x91\xe5\x9c\xb0\xe5\x9d\x80");
    // DNS 查询(疑似 DGA):随机度高的域名,供 DgaDomainAnalyzer 演示评分。
    s << make(bulwark::EventType::DnsQuery, 4321, "C:\\Users\\Public\\unknown.exe", false,
              "kq3v9zx7bqp1w8rt.com",
              "DNS \xe6\x9f\xa5\xe8\xaf\xa2\xef\xbc\x88\xe7\x96\x91\xe4\xbc\xbc DGA\xef\xbc\x89");
    // 删除重要文件:未签名主体删除文档,演示文件删除维度。
    s << make(bulwark::EventType::FileDelete, 4321, "C:\\Users\\Public\\unknown.exe", false,
              "C:\\Users\\Me\\Documents\\backup.db",
              "\xe5\x88\xa0\xe9\x99\xa4\xe9\x87\x8d\xe8\xa6\x81\xe6\x96\x87\xe4\xbb\xb6");
    return s;
}
const QVector<bulwark::SecurityEvent>& samples() {
    static const QVector<bulwark::SecurityEvent> s = buildSamples();
    return s;
}
} // namespace

SimulatedEventSource::SimulatedEventSource(QObject* parent) : EventSource(parent) {
    timer_ = new QTimer(this);
    timer_->setInterval(8000); // 每 8 秒一条
    connect(timer_, &QTimer::timeout, this, &SimulatedEventSource::tick);
}

void SimulatedEventSource::start() { timer_->start(); }
void SimulatedEventSource::stop() { timer_->stop(); }

void SimulatedEventSource::tick() {
    const auto& all = samples();
    if (all.isEmpty()) return;
    const bulwark::SecurityEvent& sample = all.at(index_++ % all.size());

    // 克隆出新事件(新 Id / 时间戳),避免复用同一实例。
    bulwark::SecurityEvent e;
    e.type = sample.type;
    e.actorPid = sample.actorPid;
    e.actorPath = sample.actorPath;
    e.actorSigned = sample.actorSigned;
    e.actorHash = sample.actorHash;
    e.commandLine = sample.commandLine;
    e.target = sample.target;
    e.detail = sample.detail;
    emit eventProduced(e);
}

} // namespace bulwark::service
