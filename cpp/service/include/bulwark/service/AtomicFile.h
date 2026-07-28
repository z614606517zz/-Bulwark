#pragma once
#include "bulwark/service/Logger.h"

#include <QByteArray>
#include <QFile>
#include <QSaveFile>
#include <QString>

// 原子落盘助手。
//
// 为什么需要它:规则库 / 运行时设置原来都是「open(Truncate) -> write -> close」直接就地覆写。
// 这一路只要中途出事(进程被杀、崩溃、掉电、磁盘满),盘上留下的就是一个截断甚至空的文件 ——
// 下次启动解析失败就退回默认值,于是**用户的全部加白与设置静默消失**。对安全产品来说这是
// 最不能接受的一类数据丢失:用户以为加过白,重启后又开始被拦。
//
// QSaveFile 正是这个模式的正解:先写同目录临时文件,commit() 时 flush + 原子改名;任何一步
// 失败都保证**原文件保持不动**(宁可这次没存上,也不要留下半个文件)。
//
// 兜底:%ProgramData%\Bulwark 处于内核 SelfGuard 保护下(只放行本产品自身进程写/删/改名)。
// 万一改名这一步被拒,就退回旧的就地覆写并记一条警告 —— 至少不比改动前更差。
namespace bulwark::service {

inline bool writeFileAtomically(const QString& path, const QByteArray& bytes,
                                const QString& whatForLog = QString()) {
    {
        QSaveFile sf(path);
        if (sf.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
            if (sf.write(bytes) == bytes.size() && sf.commit())
                return true;
            sf.cancelWriting(); // 原文件保持不动
        }
    }

    // 退路:就地覆写(非原子)。仅在原子路径不可用时才走,并如实记录。
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate))
        return false;                       // 环境性失败(权限/占用):内存态仍有效,本次不落盘
    const bool ok = (f.write(bytes) == bytes.size());
    f.flush();
    f.close();
    if (!ok)
        f.remove();                         // 半个文件比没有文件更危险,直接删掉
    Logger(QStringLiteral("bulwark.service.Store"))
        .warning(QStringLiteral("原子写入不可用,已退回就地覆写%1(ok=%2):%3")
                     .arg(whatForLog.isEmpty() ? QString() : QStringLiteral("(") + whatForLog + QStringLiteral(")"))
                     .arg(ok ? 1 : 0)
                     .arg(path));
    return ok;
}

} // namespace bulwark::service
