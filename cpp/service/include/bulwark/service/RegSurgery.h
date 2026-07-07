#pragma once
#include <QString>

// 注册表「手术刀」:对被 ACL 锁死的持久化键值,先取得所有权 + 授予管理员完全控制,
// 再强制删除(用于清除顽固后门自启动项)。Windows 专用(advapi32)。
// 注:原 C++ 头已丢失,此处按 RegSurgery.cpp 用法重建。
namespace bulwark::service {

enum class RegHive { LocalMachine, CurrentUser, ClassesRoot, Users, CurrentConfig };
enum class RegView { Default, Registry32, Registry64 };

namespace RegSurgery {

// 强制删除某个注册表值(取得所有权 -> 授权 -> 删除)。缺失视为成功。
bool forceDeleteValue(RegHive hive, const QString& subKey, const QString& valueName,
                      RegView view = RegView::Default);

// 强制删除某个子键树。缺失视为成功。
bool forceDeleteSubKeyTree(RegHive hive, const QString& parentSubKey, const QString& childName,
                           RegView view = RegView::Default);

} // namespace RegSurgery
} // namespace bulwark::service
