#pragma once
#include <QByteArray>
#include <QString>

namespace bulwark::service::occupied {

//
// 「文件读不了 / 删不掉」时的用户态阶梯。
//
// ============================ 先把两种失败分清楚 ============================
// 隔离失败在日志里长得一样,但根因是两个,能用的手段也完全不同。这一点原计划写错了
//(计划里写的是「用 SeBackupPrivilege 读被占用文件」),实测纠正如下:
//
//  · ERROR_SHARING_VIOLATION(32)—— 别的进程正以冲突的共享模式握着这个文件。
//    共享访问由 I/O 管理器在每次打开时检查,【没有任何特权能让用户态豁免】。
//    实测:同一文件被 share-mode-0 持有时,普通打开 winerr=32,
//    加 SeBackupPrivilege + FILE_FLAG_BACKUP_SEMANTICS 之后【仍然是 32】。
//    内核可以豁免(IO_IGNORE_SHARE_ACCESS_CHECK,即驱动的 readLockedFile 走的那条),
//    用户态不行。所以对 32 号错误,本文件里的备份语义那两个函数是无用的 —— 别指望它们。
//
//  · ERROR_ACCESS_DENIED(5)—— 文件的 DACL 不让我们读/删。这才是备份语义解决的那个。
//    实测:对一个 deny Everyone:(R) 的文件,普通打开 winerr=5;
//    启用 SeBackupPrivilege 后以 FILE_FLAG_BACKUP_SEMANTICS 打开【成功】。
//    勒索软件给自己的投放物收紧 ACL 是真实存在的手法,与「文件被占用」是两回事。
//
// 结论:备份语义是一根【只对 5 号错误有效】的梯级。把它当成「读被占用文件的办法」会造出
// 一根永远不会成功的梯级,那比没有更糟 —— 日志会显示试过了,读的人以为这条路走过了。
//
// ============================ 对 32 号错误,用户态还剩什么 ============================
//  1. 放开我们自己的独占锁再重试(UserModeExecBlock::suspendForRemediation,已在 1.1 接上);
//  2. 让占用者松手 —— 先查出占用者是谁,若正是我们本来就要结束的恶意进程,结束它再重试;
//  3. 复制占用者自己的句柄(DuplicateHandle)—— 可行但要枚举系统句柄表且会动对方的文件指针,
//     风险与收益不成比例,本阶段不做;
//  4. 计划重启删除(已有)。
// 本文件提供第 2 步需要的那个事实:describeHolders()。
//
// ============================ 为什么「谁占着」这件事值得单独做 ============================
// 今天隔离失败只会留下一句「未清理」,不说是谁挡的。对用户与对排查都等于没有信息。
// Restart Manager(RstrtMgr)能给出占用者的 PID、映像名、类型(服务/控制台/窗口程序)。
// 实测:自持 share-mode-0 时 RmGetList 返回 needed=1,取回的记录正是本进程
//(pid 与 getpid() 一致,name=Python,type=Critical)。
// 这条信息进了日志,「为什么没清掉」就从猜变成了可读。
//
// 诚实局限:RstrtMgr 看得见的是它能识别的那类句柄,不保证枚举出全部持有者;查不到时返回空串,
// 调用方据此说「未能确定占用者」,而不是说「没有占用者」。
//

// 进程级启用 SeBackupPrivilege / SeRestorePrivilege(幂等,只做一次并记一次日志)。
// 返回是否至少成功启用了 SeBackupPrivilege。两个特权默认是「持有但未启用」,
// 不显式启用则备份语义无效 —— 这一点很容易漏,漏了的表现是「加了 flag 却还是 5」。
bool enableBackupPrivileges();

// 以备份语义读出整个文件(绕 DACL,不绕共享冲突)。why 回填失败原因供日志。
// 上限 512MB,与驱动侧 kernelReadFile 同一口径,防异常大文件占满内存。
bool readWithBackupSemantics(const QString& path, QByteArray& out, QString& why);

// 以备份语义删除文件(绕 DACL,不绕共享冲突)。why 回填失败原因供日志。
bool deleteWithBackupSemantics(const QString& path, QString& why);

// 列出占用该文件的进程,返回给人读的一行(如 "pid=123 chrome.exe(MainWindow)")。
// 查不到 / 查不了时返回空串 —— 调用方须表述为「未能确定占用者」。
QString describeHolders(const QString& path);

} // namespace bulwark::service::occupied
