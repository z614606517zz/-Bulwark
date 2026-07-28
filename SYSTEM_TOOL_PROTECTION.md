# 系统工具保护白名单

## 🛡️ 保护机制

Bulwark 在清理恶意文件时，会**绝对保护**以下系统工具，确保即使它们被 VirusTotal 或威胁情报报告为"释放文件"，也**永远不会被删除**。

## 📋 保护列表（21个系统工具）

### Shell 工具
- `cmd.exe` - Windows 命令提示符
- `powershell.exe` - Windows PowerShell
- `pwsh.exe` - PowerShell Core

### 核心系统工具
- `conhost.exe` - 控制台窗口宿主
- `taskmgr.exe` - 任务管理器
- `regedit.exe` - 注册表编辑器
- `notepad.exe` - 记事本
- `explorer.exe` - Windows 资源管理器
- `rundll32.exe` - DLL 调用工具

### 脚本宿主
- `mshta.exe` - HTML 应用程序宿主
- `wscript.exe` - Windows Script Host
- `cscript.exe` - 控制台脚本宿主

### 管理工具
- `reg.exe` - 注册表命令行工具
- `sc.exe` - 服务控制工具
- `net.exe` - 网络管理工具
- `netsh.exe` - 网络配置工具

### 系统服务进程
- `svchost.exe` - 服务宿主进程
- `services.exe` - 服务控制管理器
- `lsass.exe` - 本地安全认证子系统

### 关键系统进程
- `winlogon.exe` - Windows 登录进程
- `csrss.exe` - 客户端/服务器运行时子系统
- `smss.exe` - 会话管理器子系统

### 桌面与运行时
- `wininit.exe` - Windows 初始化进程
- `dwm.exe` - 桌面窗口管理器
- `taskhostw.exe` - 任务宿主窗口
- `msiexec.exe` - Windows 安装程序
- `dllhost.exe` - COM 代理宿主
- `runtimebroker.exe` - 运行时代理

---

## 🔍 为什么需要这个白名单？

### 真实场景
用户报告：Visual Studio 2022 的开发工具快捷方式（Developer Command Prompt、PowerShell 等）被 Bulwark 清理，导致无法使用开发工具。

### 原因分析
1. 这些快捷方式的**目标路径**指向 `cmd.exe` 或 `powershell.exe`
2. 如果某个恶意样本的 VT 报告中包含这些系统工具（作为"释放文件"或"创建进程"）
3. Bulwark 的威胁清理会将它们加入清理候选列表
4. 即使它们在 System32 目录（受保护区），快捷方式路径匹配仍可能导致误删

### 解决方案
在 `isSafeToRemove()` 函数的**第一优先级**检查系统工具白名单：
```cpp
bool isSafeToRemove(const QString& path, bool bypassSignatureGuard, QString& reason) {
    // 1) 系统可执行文件白名单 - 绝对不能删（即使被 VT 报告为释放物）
    if (isSystemExecutable(path)) { 
        reason = u("系统关键工具,绝对保护"); 
        return false; 
    }
    // ... 其他检查
}
```

---

## 🎯 实现细节

### 代码位置
`cpp/service/src/ThreatRemediator.cpp`

### 白名单定义
```cpp
const char* const kSystemExecutables[] = {
    "cmd.exe", "powershell.exe", "pwsh.exe",
    "conhost.exe", "taskmgr.exe", "regedit.exe",
    // ... 共 21 个
};
```

### 检查函数
```cpp
bool isSystemExecutable(const QString& path) {
    const QFileInfo fi(path);
    const QString fname = fi.fileName().toLower();
    for (const char* sysExe : kSystemExecutables)
        if (fname == QLatin1String(sysExe)) return true;
    return false;
}
```

### 优先级
**最高优先级** - 在所有其他检查（系统目录、签名、落地区）之前执行。

---

## 📊 清理决策流程（v2.0.3）

```
文件清理候选: example.exe
    ↓
1. 是否为系统工具? (cmd.exe/powershell.exe 等)
   ├─ 是 → ❌ 跳过 "系统关键工具,绝对保护"
   └─ 否 → 继续
    ↓
2. 是否在系统/安装目录? (System32/Program Files)
   ├─ 是 → ❌ 跳过 "位于系统/安装目录,保护不动"
   └─ 否 → 继续
    ↓
3. 是否在用户可写落地区? (Temp/AppData/Downloads 等)
   ├─ 否 → ❌ 跳过 "不在用户可写落地区,谨慎起见不清理"
   └─ 是 → 继续
    ↓
4. 是否需要绕过签名保护?
   ├─ 主体签名异常 → 绕过
   ├─ 哈希精确匹配 → 绕过
   └─ VT 确认释放物 → 绕过
    ↓
5. 是否带可信签名?
   ├─ 是 + 未绕过 → ❌ 跳过 "带可信数字签名,保护不动"
   └─ 否 或 已绕过 → ✅ 隔离
```

---

## 🧪 测试验证

### 测试场景 1: 恶意样本调用 cmd.exe
```
样本行为: 创建子进程 C:\Windows\System32\cmd.exe
VT 报告: droppedFilePaths 包含 "cmd.exe"
预期结果: ✅ cmd.exe 不会被清理
实际结果: ✅ 跳过 "系统关键工具,绝对保护"
```

### 测试场景 2: VS 开发工具快捷方式
```
快捷方式: Developer Command Prompt.lnk
目标路径: %comspec% /k "vcvarsall.bat"
%comspec% 解析为: C:\Windows\System32\cmd.exe
预期结果: ✅ 快捷方式和 cmd.exe 都不会被清理
实际结果: ✅ 通过系统工具白名单保护
```

### 测试场景 3: 恶意 cmd.exe 副本
```
文件路径: C:\Users\admin\AppData\Local\Temp\cmd.exe
文件来源: 恶意软件复制的 cmd.exe
预期结果: ⚠️ 这不是真正的 cmd.exe，应该被清理
实际结果: ⚠️ 会被白名单保护（按文件名判断）
```

> **注意**: 当前实现**只检查文件名**，不检查路径。这意味着 `C:\Temp\cmd.exe`（恶意副本）也会被保护。
> 这是保守策略：宁可漏过恶意副本，也不能误删真正的系统工具。

---

## 🔧 未来改进

### 可能的增强方案
1. **路径 + 文件名双重检查**
   ```cpp
   bool isSystemExecutable(const QString& path) {
       const QString lower = path.toLower();
       // 必须在系统目录 + 文件名匹配
       if (!lower.contains("\\windows\\system32\\") && 
           !lower.contains("\\windows\\syswow64\\"))
           return false;
       // ... 文件名检查
   }
   ```

2. **数字签名验证**
   ```cpp
   // 只保护 Microsoft 签名的系统工具
   if (isSystemExecutable(fname) && isMicrosoftSigned(path))
       return true;
   ```

3. **哈希白名单**
   ```cpp
   // 维护真实系统工具的 SHA-256 列表
   const QSet<QString> trustedHashes = { /* ... */ };
   if (trustedHashes.contains(computeSha256(path)))
       return true;
   ```

### 当前策略理由
- **简单可靠** - 文件名检查不会失败
- **零误删风险** - 宁可保守，不能破坏系统
- **性能友好** - 不需要签名验证或哈希计算

---

## 📝 维护指南

### 如何添加新的系统工具
1. 编辑 `cpp/service/src/ThreatRemediator.cpp`
2. 在 `kSystemExecutables` 数组中添加文件名（小写）
3. 重新编译 `bulwark_service.exe`

### 如何验证保护生效
```powershell
# 查看跳过日志
Get-Content "C:\ProgramData\Bulwark\service.log" | 
    Select-String "系统关键工具,绝对保护"

# 应该看到类似输出:
# [INFO] 威胁清理:跳过 C:\Windows\System32\cmd.exe, 原因: 系统关键工具,绝对保护
```

---

## ⚠️ 安全注意事项

1. **不要从白名单移除工具** - 可能导致系统不可用
2. **谨慎添加第三方工具** - 只保护真正的系统工具
3. **定期审查白名单** - Windows 更新可能引入新的系统工具
4. **不要禁用此保护** - 这是核心安全机制

---

## 📚 相关文档

- `CHANGELOG.md` - v2.0.3 更新记录
- `V2.0.2_TEST_GUIDE.md` - 测试指南
- `PROACTIVE_DEFENSE.md` - 主动防护技术文档
- `ThreatRemediator.cpp` - 威胁清理实现代码
