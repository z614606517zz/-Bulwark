# Bulwark 实时防护与威胁清理 - 当前状态

## ✅ 已实现的功能

### 1. 自动威胁清理（一次性清理）

当检测到恶意样本时，系统**自动执行一次性清理**，包括：

#### 📁 文件清理
```cpp
RemediationReport remediate(
    const SecurityEvent& malicious,
    const QList<ChainEventInfo>& footprint,
    const ThreatBehaviorProfile& profile)
```

**清理范围**：
- ✅ **恶意主体文件** - 样本本身
- ✅ **进程树释放的文件** - footprint 中的 FileWrite/FileDelete 事件
- ✅ **VT 行为报告的释放文件** - `profile.droppedFilePaths` 翻译到本机用户目录
- ✅ **哈希确认的恶意文件** - `profile.locatedLocalPaths` (精确匹配，绕过签名保护)

**安全护栏**：
- 仅清理用户可写落地区（Temp/Downloads/Desktop/AppData/Public/ProgramData）
- 保护系统目录（System32/SysWOW64/WinSxS/Program Files）
- 保护已签名文件（除非哈希确认恶意 - BYOVD 场景）
- 可逆隔离（非永久删除，可还原）

#### 📝 注册表持久化清理
- ✅ **自启动项** (Run/RunOnce) - 检查是否指向恶意文件，是则删除
- ✅ **映像劫持** (IFEO Debugger) - 检查是否劫持到恶意文件
- ✅ **Windows 服务** - 检查 ImagePath/ServiceDll 是否指向恶意文件
- ✅ **Winlogon 持久化** - Shell/Userinit/TaskMan 等
- ✅ **AppInit_DLLs** - 检查是否注入恶意 DLL
- ✅ **计划任务** - 调用 `schtasks /delete`
- ✅ **启动文件夹** - 隔离 Startup 文件夹中的恶意文件

#### 🛡️ 持久化反重建
- ✅ **内核注册表硬拦** - 清理的自启动项立即加入内核硬拦列表
- ✅ **防守护进程秒级重建** - 补上"清理→恶意软件重写"的竞态窗口

---

### 2. 实时主动防护（持续拦截）

当检测到恶意样本并获取行为报告后，**自动生成拦截规则**，实时防护同族样本：

#### 🚫 自动生成的规则类型

| 类型 | 事件类型 | 动作 | 数据源 | 生效时机 | 状态 |
|------|---------|------|--------|----------|------|
| 1️⃣ 释放文件哈希 | ProcessCreate | Block | droppedFileHashes | 运行前拦截 | ✅ 已实现 |
| 2️⃣ C2 外联 IP | NetworkConnect | Block | contactedIps | 连接时拦截 | ✅ 已实现 |
| 3️⃣ C2 外联域名 | DnsQuery | Block | contactedDomains | DNS 解析时拦截 | ✅ 已实现（新增）|
| 4️⃣ 释放文件名 | FileWrite | Ask | droppedFileNames | 文件落地时询问 | ✅ 已实现 |

#### 规则特性
- ✅ **自动去重** - 避免重复规则累积
- ✅ **持久化** - 保存到 `rules.json`，重启保留
- ✅ **域名白名单** - 自动排除 microsoft/google/amazon/cloudflare 等合法域名
- ✅ **数量限制** - 域名最多 50 条，文件名最多 20 条

---

## ❌ 缺失的功能（你提到的需求）

### 1. 实时内存清理
**当前状态**: ❌ 未实现

**需求描述**: 
- 检测到恶意进程时，扫描其内存空间
- 识别并清除恶意注入的代码/DLL
- 修复被篡改的内存区域

**技术难度**: ⭐⭐⭐⭐⭐ （极高）
- 需要内核驱动支持
- 进程内存保护机制
- 可能导致目标进程崩溃

---

### 2. 实时注册表监控拦截
**当前状态**: ⚠️ 部分实现

**已有功能**:
- ✅ 清理已存在的恶意注册表项（一次性）
- ✅ 内核硬拦防重建（对已清理的项）

**缺失功能**:
- ❌ **主动拦截规则** - 根据 VT 行为报告的 `registryKeysSet` 生成注册表写入拦截规则
- ❌ **实时监控** - 恶意软件尝试写入 VT 报告中的注册表键时直接拦截

**实现方案**:
```cpp
// 在 buildRulesFromProfile 中添加
for (const QString& regKey : p.registryKeysSet) {
    bulwark::DefenseRule r;
    r.type = bulwark::EventType::RegistrySetValue;
    r.targetPattern = regKey;
    r.action = VerdictAction::Block;
    r.note = tag + " 已知恶意注册表持久化项:" + regKey;
    rules.append(r);
}
```

---

### 3. 实时文件释放拦截
**当前状态**: ⚠️ 部分实现

**已有功能**:
- ✅ 释放文件名监控（Ask 询问，非 Block）
- ✅ 释放文件哈希拦截（精确哈希运行前拦截）

**缺失功能**:
- ❌ **路径模式拦截** - 根据 VT 报告的 `droppedFilePaths` 生成路径模式规则
  - 例如：VT 报告显示释放到 `%TEMP%\evil.exe`
  - 应生成规则：任何进程写入 `*\Temp\evil.exe` → Block

**实现方案**:
```cpp
// 在 buildRulesFromProfile 中添加
for (const QString& vtPath : p.droppedFilePaths) {
    QString pattern = translateVtPathToPattern(vtPath);
    bulwark::DefenseRule r;
    r.type = bulwark::EventType::FileWrite;
    r.targetPattern = pattern;  // 例如 "*\AppData\Local\Temp\evil.exe"
    r.action = VerdictAction::Block;  // 改为 Block 而非 Ask
    r.note = tag + " 已知恶意释放路径:" + pattern;
    rules.append(r);
}
```

---

### 4. 进程名拦截规则
**当前状态**: ❌ 未实现

**数据源**: `profile.processNames` - VT 报告的"创建进程"涉及的可执行名

**需求描述**:
- 恶意样本会启动特定名称的子进程（如 `cmd.exe`, `powershell.exe` 加恶意参数）
- 应根据进程名生成拦截规则

**实现方案**:
```cpp
for (const QString& procName : p.processNames) {
    bulwark::DefenseRule r;
    r.type = bulwark::EventType::ProcessCreate;
    r.actorPattern = "*\\" + procName;  // 任意路径下的同名进程
    r.action = VerdictAction::Ask;  // 询问而非硬拦（避免误报）
    r.note = tag + " 已知恶意样本启动的进程:" + procName;
    rules.append(r);
}
```

---

### 5. 服务名拦截
**当前状态**: ❌ 未实现

**数据源**: `profile.serviceNames` - VT 报告的"创建/启动服务"

**需求描述**:
- 恶意样本会创建特定名称的服务
- 应拦截创建同名服务的尝试

**技术限制**: 
- Bulwark 当前无 `ServiceCreate` 事件类型
- 需要扩展事件源支持服务创建监控

---

## 📊 功能对比表

| 功能 | 一次性清理 | 实时防护 | 状态 |
|------|-----------|----------|------|
| **文件** |
| - 恶意主体隔离 | ✅ | ✅ (哈希) | 完整 |
| - 释放文件隔离 | ✅ | ✅ (哈希) | 完整 |
| - 释放路径拦截 | ⚠️ | ⚠️ (仅询问) | 需增强 |
| **注册表** |
| - 清理持久化项 | ✅ | ❌ | 缺主动拦截 |
| - 防重建硬拦 | ✅ | N/A | 完整 |
| - VT 键预防性拦截 | ❌ | ❌ | 未实现 |
| **网络** |
| - C2 IP 拦截 | N/A | ✅ | 完整 |
| - C2 域名拦截 | N/A | ✅ | 完整（新增）|
| **进程** |
| - 结束恶意进程树 | ✅ | N/A | 完整 |
| - 进程名监控 | ❌ | ❌ | 未实现 |
| **内存** |
| - 内存清理/修复 | ❌ | ❌ | 未实现 |
| **服务** |
| - 删除恶意服务 | ✅ | ❌ | 缺主动拦截 |

---

## 🎯 实现优先级建议

### 🔥 高优先级（立即可实现）

#### 1. 注册表写入拦截规则
**工作量**: ⭐ 小（30 分钟）
**影响**: ⭐⭐⭐⭐ 大（阻止持久化重建）

```cpp
// 在 Worker.cpp buildRulesFromProfile 中添加
// 4) 注册表持久化键 -> 禁止写入
int regRules = 0;
for (const QString& regKey : p.registryKeysSet) {
    if (regRules >= 30) break;  // 限制 30 条
    if (regKey.size() < 10) continue;
    
    bulwark::DefenseRule r;
    r.type = bulwark::EventType::RegistrySetValue;
    r.targetPattern = regKey;
    r.action = VerdictAction::Block;
    r.note = tag + QStringLiteral(" 已知恶意注册表持久化,禁止写入:") + regKey;
    rules.append(r);
    ++regRules;
}
```

#### 2. 释放路径硬拦截（升级为 Block）
**工作量**: ⭐ 小（15 分钟）
**影响**: ⭐⭐⭐ 中（更强的预防）

```cpp
// 修改现有的文件名规则为路径模式 + Block
for (const QString& vtPath : p.droppedFilePaths) {
    if (pathRules >= 20) break;
    QString pattern = extractPathPattern(vtPath);  // 提取路径模式
    
    bulwark::DefenseRule r;
    r.type = bulwark::EventType::FileWrite;
    r.targetPattern = pattern;
    r.action = VerdictAction::Block;  // 改为硬拦截
    r.note = tag + QStringLiteral(" 已知恶意释放路径,禁止写入:") + pattern;
    rules.append(r);
    ++pathRules;
}
```

---

### 🔶 中优先级（需要适度开发）

#### 3. 进程名监控规则
**工作量**: ⭐⭐ 中（1 小时）
**影响**: ⭐⭐⭐ 中（识别子进程模式）

#### 4. 增强文件清理 - 扫描更多落地区
**工作量**: ⭐⭐ 中（2 小时）
**影响**: ⭐⭐ 小（更彻底的清理）

---

### 🔵 低优先级（技术复杂度高）

#### 5. 内存清理/修复
**工作量**: ⭐⭐⭐⭐⭐ 极大（数周）
**影响**: ⭐⭐⭐⭐ 大
**建议**: 暂不实现（风险高，收益相对较低）

#### 6. 服务创建拦截
**工作量**: ⭐⭐⭐ 大（需扩展事件源）
**影响**: ⭐⭐ 小

---

## 📝 实现计划

### 第一步：增强规则生成（30 分钟）
```bash
# 修改文件
cpp/service/src/Worker.cpp - buildRulesFromProfile()

# 新增规则类型
1. 注册表写入拦截
2. 释放路径硬拦截（可选）
```

### 第二步：测试验证（15 分钟）
1. 编译新版本
2. 双击恶意样本触发扫描
3. 检查日志：
   ```
   情报行为画像[VirusTotal]:
   释放文件 5、注册表 3、外联IP 2、域名 1;
   已注入主动拦截规则 11 条（含 3 条注册表拦截）。
   ```
4. 验证规则生效：
   - 尝试写入 VT 报告的注册表键 → 应被拦截
   - 查看 `rules.json` 确认规则存在

### 第三步：文档更新（10 分钟）
更新 `PROACTIVE_DEFENSE.md` 增加注册表拦截说明

---

## 🔍 当前系统工作流程（完整版）

```
双击恶意样本
    ↓
VT 扫描 → 判定恶意
    ↓
【阶段1: 获取情报】
    ├─ 基础扫描结果 (malicious/suspicious)
    └─ 行为报告 (behaviour_summary)
        ├─ droppedFileHashes
        ├─ droppedFilePaths
        ├─ droppedFileNames
        ├─ contactedIps
        ├─ contactedDomains
        ├─ registryKeysSet      ← 当前未生成规则
        ├─ processNames         ← 当前未生成规则
        ├─ serviceNames         ← 当前未生成规则
        └─ mutexes             ← 仅展示，不生成规则
    ↓
【阶段2: 一次性清理】（confirmReputationMaliciousAsync）
    ├─ 结束恶意进程树
    ├─ 隔离恶意文件
    │   ├─ 主体文件
    │   ├─ footprint 释放文件
    │   ├─ VT 报告翻译的本机路径
    │   └─ 哈希精确定位的文件
    ├─ 清理注册表持久化
    │   ├─ Run/RunOnce
    │   ├─ IFEO Debugger
    │   ├─ Services
    │   ├─ Winlogon
    │   ├─ AppInit_DLLs
    │   └─ 计划任务/启动文件夹
    └─ 内核硬拦防重建
    ↓
【阶段3: 生成防护规则】（buildRulesFromProfile）
    ├─ ✅ 释放文件哈希 → ProcessCreate Block
    ├─ ✅ C2 IP → NetworkConnect Block
    ├─ ✅ C2 域名 → DnsQuery Block （新增）
    ├─ ✅ 释放文件名 → FileWrite Ask
    ├─ ❌ 注册表键 → RegistrySetValue Block （缺失）
    ├─ ❌ 进程名 → ProcessCreate Ask （缺失）
    └─ ❌ 服务名 → ServiceCreate Block （缺失，事件源不支持）
    ↓
【阶段4: 规则注入】（setIntelRuleInjector）
    ├─ 去重检查
    ├─ 加入引擎
    ├─ 持久化到 rules.json
    └─ 记录日志
    ↓
【阶段5: 实时防护】
    └─ 后续同族样本/行为 → 实时拦截
```

---

## 总结

### ✅ 系统已经实现的核心能力
1. **自动威胁清理** - 文件+注册表+持久化，完整且成熟
2. **实时主动防护** - 哈希+IP+域名，覆盖最关键的 IOC
3. **防重建机制** - 内核硬拦，防守护进程秒级重建

### ⚠️ 需要增强的部分
1. **注册表拦截规则** - 技术简单，影响大，建议立即实现
2. **释放路径硬拦** - 可选，增强预防能力
3. **进程名监控** - 识别子进程模式，价值中等

### ❌ 不建议实现的部分
1. **内存清理** - 技术复杂度极高，风险大
2. **服务创建拦截** - 需要扩展基础设施，收益相对较低

---

**下一步**: 需要我立即实现"注册表拦截规则"吗？只需 30 分钟。
