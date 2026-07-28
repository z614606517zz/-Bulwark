# Bulwark 实时防护测试指南

## 快速验证新增功能

### ✅ 已实现的增强（v2.0.1）

1. **C2 域名 DNS 拦截**
2. **注册表写入拦截规则**

---

## 测试步骤

### 1. 启动新版本

```powershell
# 关闭旧版 UI（会自动卸载驱动和服务）
# 以管理员身份启动新版本
d:\新建文件夹 (3)\cpp\dist\bulwark_ui.exe
```

**预期结果**:
- UI 启动
- 托盘图标出现
- 服务自动启动
- 驱动自动加载（如果 `EventSource: "Driver"`）

---

### 2. 准备测试样本

**选项 A: 使用真实恶意样本**
- 从沙箱环境获取一个 VT 已收录的恶意样本
- ⚠️ 注意：在隔离环境中操作

**选项 B: 使用测试样本（推荐）**
- 自己编译一个无害的测试程序
- 上传到 VT 让它在沙箱运行
- 等待行为报告生成（约 1-5 分钟）

---

### 3. 触发扫描

从 `explorer.exe` 双击测试样本

**预期行为**:
1. UI 显示"正在扫描..."
2. 后台上传到 VT（如果未收录）
3. 等待沙箱分析完成
4. 判定为恶意 → 自动清理 + 生成规则

---

### 4. 检查日志

```powershell
# 查看服务日志
Get-Content "C:\ProgramData\Bulwark\service.log" -Tail 50 | 
  Select-String -Pattern "情报|域名|注册表|规则"
```

**预期日志**:
```
[Worker] 情报行为画像[VirusTotal]:
  释放文件 5、注册表 3、外联IP 2、域名 1;
  已注入主动拦截规则 11 条。

[Worker] 情报行为规则:据确认恶意样本的行为画像新增主动拦截规则 11 条。
```

---

### 5. 验证规则生成

#### 方式1: 查看 UI
1. 打开 UI
2. 进入"规则管理"
3. 搜索 `[情报-行为]`
4. 应该看到新增的规则：
   - 释放文件哈希规则（ProcessCreate → Block）
   - C2 IP 规则（NetworkConnect → Block）
   - C2 域名规则（DnsQuery → Block）← 新增
   - 注册表规则（RegistrySetValue → Block）← 新增
   - 文件名规则（FileWrite → Ask）

#### 方式2: 查看规则文件
```powershell
$rules = Get-Content "C:\ProgramData\Bulwark\rules.json" | ConvertFrom-Json
$intelRules = $rules | Where-Object { $_.note -like "*情报-行为*" }

Write-Host "情报规则总数: $($intelRules.Count)"
Write-Host "域名规则: $(($intelRules | Where-Object { $_.type -eq 'DnsQuery' }).Count)"
Write-Host "注册表规则: $(($intelRules | Where-Object { $_.type -eq 'RegistrySetValue' }).Count)"
```

---

### 6. 测试规则生效

#### 测试域名拦截
```powershell
# 如果 VT 报告中有恶意域名 evil.example.com
nslookup evil.example.com
```

**预期结果**: DNS 查询被拦截，日志显示：
```
[Worker] 命中情报规则:[情报-行为] 已知 C2 域名,禁止解析:evil.example.com
[Worker] 拦截: DNS 查询 evil.example.com → 规则拦截
```

#### 测试注册表拦截
如果 VT 报告中有注册表键 `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Evil`：

```powershell
# 尝试写入（会被拦截）
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Evil" -Value "C:\test.exe"
```

**预期结果**: 写入被拦截，日志显示：
```
[Worker] 命中情报规则:[情报-行为] 已知恶意注册表持久化,禁止写入:...
[Worker] 拦截: 注册表写入 HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Evil → 规则拦截
```

---

### 7. 检查 VT 诊断日志

```powershell
Get-Content "C:\ProgramData\Bulwark\vt_diag.log" -Tail 20
```

**预期内容**:
```
00:14:27 query a1b2c3d4 => OK v3 21/68
00:14:32 behaviour a1b2c3d4 => OK 释放文件5 哈希3 注册表3 IP2 域名1 服务0
```

---

### 8. 检查清理报告

UI 应该显示"足迹清理报告"，包含：

✅ **已隔离文件**:
- 恶意主体: `C:\Users\...\sample.exe`
- 释放文件: `C:\Users\...\AppData\Local\Temp\payload.dll`

✅ **已删除注册表项**:
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Malware`
- `HKLM\SYSTEM\CurrentControlSet\Services\EvilService`

✅ **已生成规则**:
- 5 个哈希拦截
- 2 个 IP 拦截
- 1 个域名拦截 ← 新增
- 2 个注册表拦截 ← 新增
- 3 个文件名监控

⚠️ **未能清理**（如果有）:
- `C:\Program Files\LegitApp\signed.dll` (位于安装目录,保护不动)

---

## 问题排查

### 问题1: 没有生成域名/注册表规则

**原因**: VT 行为报告中可能没有这些数据

**检查**:
```powershell
# 查看 VT 返回的行为报告
Get-Content "C:\ProgramData\Bulwark\vt_diag.log" | Select-String "behaviour"
```

如果显示 `释放文件0 ... 域名0 注册表0`，说明 VT 沙箱没有成功运行样本或未观察到这些行为。

**解决方案**:
- 使用其他恶意样本测试
- 确保样本能在 VT 沙箱成功运行

---

### 问题2: 规则生成了但没有拦截

**检查1**: 规则是否真的存在？
```powershell
Get-Content "C:\ProgramData\Bulwark\rules.json" | ConvertFrom-Json | 
  Where-Object { $_.note -like "*域名*" -or $_.note -like "*注册表*" }
```

**检查2**: 事件类型是否匹配？
- 域名规则只拦截 `DnsQuery` 事件
- 注册表规则只拦截 `RegistrySetValue` 事件

**检查3**: 是否被信任规则覆盖？
信任规则优先级高于拦截规则。检查是否有覆盖的信任规则。

**检查4**: 驱动是否连接？
```powershell
# 查看驱动状态
sc query Bulwark
```

如果驱动未运行，切换到驱动模式：
1. 编辑 `appsettings.json`
2. 设置 `"EventSource": "Driver"`
3. 重启 UI

---

### 问题3: 大量误报

**症状**: 合法软件被拦截

**原因**: VT 报告中包含了合法行为

**解决方案**:

1. **域名误报** - 增加白名单：
   ```cpp
   // Worker.cpp buildRulesFromProfile 中添加
   if (d.contains("yourlegitdomain.com")) continue;
   ```

2. **注册表误报** - 增加过滤：
   ```cpp
   // 增加键名长度限制
   if (key.size() < 20) continue;  // 改为 20
   ```

3. **手动删除误报规则**:
   - UI → 规则管理 → 找到误报规则 → 删除

---

## 性能验证

### 规则数量检查
```powershell
$rules = Get-Content "C:\ProgramData\Bulwark\rules.json" | ConvertFrom-Json
Write-Host "总规则数: $($rules.Count)"
Write-Host "情报规则数: $(($rules | Where-Object { $_.note -like '*情报*' }).Count)"
```

**预期**: 
- 情报规则应该合理增长（每个样本 5-20 条）
- 总规则数不应超过 1000 条（有去重机制）

### 内存/CPU 检查
```powershell
Get-Process bulwark_service | Select-Object Name, CPU, WorkingSet64
```

**预期**:
- 内存: < 100MB
- CPU: 正常情况下 < 5%

---

## 测试矩阵

| 功能 | 测试方法 | 预期结果 | 状态 |
|------|---------|----------|------|
| 域名拦截规则生成 | 双击样本 → 检查规则 | 生成 DnsQuery 规则 | ⬜ |
| 域名拦截生效 | nslookup 恶意域名 | 被拦截 | ⬜ |
| 注册表拦截规则生成 | 双击样本 → 检查规则 | 生成 RegistrySetValue 规则 | ⬜ |
| 注册表拦截生效 | Set-ItemProperty 恶意键 | 被拦截 | ⬜ |
| 域名白名单过滤 | VT 报告含 google.com | 不生成规则 | ⬜ |
| 注册表路径过滤 | VT 报告含 \Windows\ | 不生成规则 | ⬜ |
| 规则持久化 | 重启 UI | 规则仍存在 | ⬜ |
| 规则去重 | 重复扫描同一样本 | 不重复生成规则 | ⬜ |

---

## 下一步

测试完成后，如果发现问题：

1. **收集日志**:
   ```powershell
   Copy-Item "C:\ProgramData\Bulwark\service.log" ".\service_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
   Copy-Item "C:\ProgramData\Bulwark\vt_diag.log" ".\vt_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
   ```

2. **检查规则文件**:
   ```powershell
   Copy-Item "C:\ProgramData\Bulwark\rules.json" ".\rules_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
   ```

3. **报告问题** - 附上日志和规则文件

---

## 高级测试

### 模拟同族样本攻击

1. 获取样本 A 的行为报告
2. 手动创建样本 B，复制样本 A 的行为：
   - 释放同名文件
   - 写入同样的注册表键
   - 连接同样的 C2 域名
3. 运行样本 B

**预期结果**: 样本 B 被规则拦截，不需要再次上传 VT

### 压力测试

1. 连续扫描 10 个不同的恶意样本
2. 观察规则数量增长
3. 检查去重是否工作
4. 验证性能是否下降

**预期**:
- 规则增长合理（50-150 条）
- 无明显性能下降
- 内存稳定

---

**祝测试顺利！** 🎉
