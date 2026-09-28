#pragma once
#include <QObject>
#include <QString>
#include <QVariantMap>

#include <functional>

// In-app navigation between pages, with arguments.
//
// Pages are built by factory functions and don't know the shell; the shell
// doesn't know what a page can be asked to show. This hub sits between them:
//   nav::go("events", {{"segment", "block"}})      — any widget asks to go somewhere
//   MainWindow switches pages, then delivers the args
//   nav::onArrive(page, "events", fn)             — the page applies them
//
// Stable page keys (never the nav label, which may change):
namespace nav {
inline constexpr const char* Dashboard   = "dashboard";
inline constexpr const char* Events      = "events";
inline constexpr const char* Timeline    = "timeline";
inline constexpr const char* Chain       = "chain";
inline constexpr const char* Processes   = "processes";
inline constexpr const char* Rules       = "rules";
inline constexpr const char* Trust       = "trust";
inline constexpr const char* Quarantine  = "quarantine";
inline constexpr const char* Persistence = "persistence";
inline constexpr const char* Reputation  = "reputation";
inline constexpr const char* Ai          = "ai";
inline constexpr const char* Settings    = "settings";
} // namespace nav

class NavHub : public QObject
{
    Q_OBJECT
public:
    static NavHub* instance();

    void request(const QString& key, const QVariantMap& args) { emit requested(key, args); }
    void deliver(const QString& key, const QVariantMap& args) { emit delivered(key, args); }
    void setBadge(const QString& key, int count) { emit badgeChanged(key, count); }

signals:
    void requested(const QString& key, const QVariantMap& args);
    void delivered(const QString& key, const QVariantMap& args);
    void badgeChanged(const QString& key, int count);

private:
    using QObject::QObject;
};

namespace nav {

// Ask the shell to show page `key` and hand it `args`.
inline void go(const QString& key, const QVariantMap& args = {})
{
    NavHub::instance()->request(key, args);
}

// Run `fn(args)` whenever navigation to `key` delivers arguments; `context`
// scopes the connection (the page).
inline void onArrive(QObject* context, const QString& key, std::function<void(const QVariantMap&)> fn)
{
    QObject::connect(NavHub::instance(), &NavHub::delivered, context,
                     [key, fn = std::move(fn)](const QString& k, const QVariantMap& args) {
                         if (k == key && fn)
                             fn(args);
                     });
}

} // namespace nav
