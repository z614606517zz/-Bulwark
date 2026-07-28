# Bulwark 主动防护 - 实时 IOC 规则生成

## 功能概述

Bulwark 具备**基于行为情报的实时主动防护**能力：当检测到恶意样本时，自动从 VirusTotal 沙箱报告中提取 IOC（失陷指标），生成拦截规则，**在同族样本、释放物、C2通信再次出现时实时拦截**。

## 工作流程

```
双击恶意样本
    ↓
上传 VT 扫描 → 判定恶意
    ↓
获取行为报告 (behaviour_summary)
    ↓
提取 IOC:
  • droppedFileHashes - 释放文件哈希
  • contactedIps - 外联 IP
  • contactedDomains - 外联域名
  • droppedFileNames - 释放文件名
    ↓
生成防护规则 (buildRulesFromProfile)
    ↓
去重 + 注入引擎 + 持久化
    ↓
✓ 实时拦截生效
```

## 生成的规则类型

### 1. 释放文件哈希拦截（硬拦截）
- **类型**: `ProcessCreate`
- **动作**: `Block` (硬拦截，不可绕过)
- **匹配**: SHA-256 哈希精确匹配
- **说明**: 同族样本释放的恶意载荷，运行时直接拦截
- **示例**: `[情报-行为] 已知恶意释放物,禁止运行(sha256 a1b2c3d4...)`

### 2. C2 外联 IP 拦截（硬拦截）
- **类型**: `NetworkConnect`
- **动作**: `Block`
- **匹配**: IP地址 + 通配端口 `192.168.1.1:*`
- **说明**: 阻断恶意样本的命令控制通信
- **示例**: `[情报-行为] 已知 C2 外联地址,禁止外联:192.168.1.100`

### 3. C2 外联域名拦截（DNS 阶段拦截）**[新增]**
- **类型**: `DnsQuery`
- **动作**: `Block`
- **匹配**: 域名精确匹配
- **说明**: 在 DNS 解析阶段就拦截，比 IP 拦截更早
- **过滤**: 自动排除合法 CDN/云服务商（microsoft/google/amazon/cloudflare等）
- **数量限制**: 最多 50 条（避免误报）
- **示例**: `[情报-行为] 已知 C2 域名,禁止解析:evil-c2.example.com`

### 4. 释放文件名监控（软提示）
- **类型**: `FileWrite`
- **动作**: `Ask` (询问用户)
- **匹配**: 文件名通配 `*\malware.exe`
- **说明**: 当同名文件落地时弹窗询问（避免硬拦误报）
- **数量限制**: 最多 20 条
- **示例**: `[情报-行为] 已知恶意释放文件名:payload.dll`

### 5. 注册表写入拦截（硬拦截）**[新增 v2.0.1]**
- **类型**: `RegistrySetValue`
- **动作**: `Block`
- **匹配**: 注册表键路径精确匹配
- **说明**: 阻止恶意软件写入 VT 报告中的注册表键（自启动/劫持/持久化）
- **过滤**: 自动排除系统关键路径（如 `\Windows\`）
- **数量限制**: 最多 30 条
- **示例**: `[情报-行为] 已知恶意注册表持久化,禁止写入:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Evil`

## 代码实现

### 关键函数

#### `buildRulesFromProfile()` - 规则生成器
**位置**: `cpp/service/src/Worker.cpp`

```cpp
QVector<bulwark::DefenseRule> buildRulesFromProfile(
    const bulwark::ThreatBehaviorProfile& p,
    const QString& tag) {
    
    // 1. 释放文件哈希 → Block
    for (const QString& h : p.droppedFileHashes) { ... }
    
    // 2. C2 IP → Block
    for (const QString& ioc : p.contactedIps) { ... }
    
    // 2b. C2 域名 → Block (DNS)  [v2.0.1]
    for (const QString& domain : p.contactedDomains) { ... }
    
    // 3. 释放文件名 → Ask
    for (const QString& name : p.droppedFileNames) { ... }
    
    // 4. 注册表持久化键 → Block  [v2.0.1]
    for (const QString& regKey : p.registryKeysSet) { ... }
}
```

#### `setIntelRuleInjector()` - 规则注入器
**位置**: `cpp/service/src/main.cpp`

```cpp
worker.setIntelRuleInjector(
    [&engine, &ruleStore, &log](const QVector<bulwark::DefenseRule>& newRules) -> int {
        // 去重检查
        auto duplicate = [&existing](const bulwark::DefenseRule& nr) { ... };
        
        // 逐条添加
        for (const bulwark::DefenseRule& r : newRules) {
            if (duplicate(r)) continue;
            engine.addRule(r);
            ++added;
        }
        
        // 持久化
        if (added > 0) {
            ruleStore.save(engine.getRules());
            log.info("新增主动拦截规则 X 条");
        }
    });
```

## 触发条件

主动防护在以下情况自动触发：

1. **双击扫描** - 用户从 explorer.exe 双击启动可疑程序
2. **释放载荷** - 未签名 + 首见 + 可疑目录运行
3. **写出即执行** - 文件写入后 5 分钟内被执行
4. **外部信誉** - ReputationManager 判定恶意

## 规则管理

### 持久化
- **存储**: `C:\ProgramData\Bulwark\rules.json`
- **格式**: JSON 数组，包含所有用户规则、信任规则、情报规则
- **生命周期**: 跨重启保留，除非用户手动删除

### 去重机制
规则注入前自动去重，基于：
- `type` - 事件类型
- `action` - 动作
- `targetPattern` - 目标模式
- `actorHashes` - 哈希集合

### 查看规则
1. UI → 规则管理 → 筛选 `[情报-行为]`
2. 日志: `C:\ProgramData\Bulwark\service.log`
   ```
   情报行为规则:据确认恶意样本的行为画像新增主动拦截规则 X 条。
   情报行为画像[VirusTotal]:释放文件 5、注册表 3、外联IP 2、域名 1;已注入主动拦截规则 8 条。
   ```

## 日志验证

### 行为报告获取成功
```log
[Worker] 情报行为画像[VirusTotal]:释放文件 12、注册表 5、外联IP 3、域名 2;
         已注入主动拦截规则 17 条。
```

### 规则生效拦截
```log
[Worker] 命中情报规则:[情报-行为] 已知恶意释放物,禁止运行(sha256 a1b2c3d4...)
[Worker] 拦截: C:\Users\Public\payload.exe (PID 1234) → 规则拦截
```

## 配置要求

### 必需配置
1. ✅ `settings.json` → `virusTotalEnabled: true`
2. ✅ `settings.json` → `aiScanDoubleClickEnabled: true`
3. ✅ `appsettings.json` → `VirusTotal.Enabled: true`
4. ✅ `appsettings.json` → `VirusTotal.ApiKey: "your-key"` (或使用内置 Key)

### 可选配置
- `ReputationProxy.Enabled: true` - 优先走中央服务器（哈希查询）
- `EventSource: "Driver"` - 内核驱动模式（真正的运行前拦截）

## 测试验证

### 1. 准备测试样本
找一个 VT 已收录的恶意样本（或自己上传一个）

### 2. 双击触发扫描
从 explorer.exe 双击样本 → 等待 VT 扫描完成

### 3. 检查日志
```powershell
Get-Content "C:\ProgramData\Bulwark\service.log" -Tail 50 | Select-String -Pattern "情报|IOC|规则"
```

### 4. 验证规则生效
- 方式1: UI → 规则管理 → 查看 `[情报-行为]` 规则
- 方式2: 再次尝试运行同族样本 → 应被直接拦截
- 方式3: 查看规则文件:
  ```powershell
  Get-Content "C:\ProgramData\Bulwark\rules.json" | ConvertFrom-Json | 
    Where-Object { $_.note -like "*情报*" }
  ```

## 性能与安全

### 性能优化
- **去重**: 避免重复规则累积
- **数量限制**: 
  - 域名规则最多 50 条
  - 文件名规则最多 20 条
- **后台执行**: 行为报告拉取在后台线程，不阻塞主线程

### 安全考虑
- **域名白名单**: 自动排除合法云服务商域名
- **软拦截**: 文件名规则使用 `Ask` 而非 `Block`，避免误报
- **哈希精确**: 释放文件必须哈希匹配，不仅依赖文件名

## 已知限制

1. **依赖 VT 沙箱** - 样本必须在 VT 成功运行才有行为报告
2. **网络类型限制** - 当前只支持 TCP/IP 外联，不支持 UDP
3. **注册表规则未实现** - `registryKeysSet` 暂未生成拦截规则（仅用于清理）
4. **进程名规则未实现** - `processNames` 暂未生成规则

## 版本历史

### v2.0.1 (2026-07-28)
- ✅ 新增：C2 域名 DNS 阶段拦截
- ✅ 新增：注册表写入拦截规则（阻止恶意持久化重建）
- ✅ 优化：域名白名单过滤（microsoft/google/amazon等）
- ✅ 优化：注册表规则过滤系统关键路径
- ✅ 限制：域名规则最多 50 条，注册表规则最多 30 条

### v2.0.0
- ✅ 初始实现：释放文件哈希拦截
- ✅ 初始实现：C2 IP 拦截
- ✅ 初始实现：释放文件名监控

## 相关文件

- `cpp/service/src/Worker.cpp` - 核心逻辑
- `cpp/service/src/main.cpp` - 规则注入器配置
- `cpp/shared/include/bulwark/models/ThreatBehaviorProfile.h` - 行为画像结构
- `cpp/service/src/reputation/VirusTotalClient.cpp` - 行为报告解析
- `C:\ProgramData\Bulwark\rules.json` - 规则持久化文件
- `C:\ProgramData\Bulwark\service.log` - 服务日志

## 故障排查

### 问题：规则没有生成
**检查**:
1. 日志中是否有 `情报行为画像` 字样？
2. VT 扫描是否成功？(`vt_diag.log`)
3. 样本是否被判定为恶意？
4. 行为报告是否为空？（某些样本 VT 沙箱未成功运行）

### 问题：规则生成了但没有拦截
**检查**:
1. 规则是否在 `C:\ProgramData\Bulwark\rules.json` 中？
2. 事件类型是否匹配？（ProcessCreate / NetworkConnect / DnsQuery）
3. 是否被信任规则覆盖？（信任优先级高于拦截）
4. 内核驱动是否连接？（`EventSource: "Driver"` 才能真正前拦）

### 问题：大量误报
**调整**:
1. 域名规则改为 `Ask` 而非 `Block`
2. 增加白名单过滤条件
3. 降低规则数量上限

## 后续计划

- [ ] 实现注册表持久化拦截规则
- [ ] 实现进程名匹配规则
- [ ] 支持 UDP 外联拦截
- [ ] 规则有效期（TTL）自动过期
- [ ] 规则命中率统计
- [ ] 误报反馈机制

---

**注**: 主动防护是 Bulwark 的核心差异化能力，它将"事后清理"升级为"实时拦截"，真正做到**一次感染，全网免疫**。
