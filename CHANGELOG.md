# 更新记录 (Changelog)

本文件记录磐垒主动防御 (Bulwark) 的主要变更。

## [未发布] - 2026-07-02

### 新增
- **银狐微信/QQ 群控防护(批次 14c)** `Bulwark.Core/Engine/DefaultRules.cs`
  新增 `AddImHarvestAndFrameworkRules`,补齐"银狐控制微信/QQ 群发"链路:
  - 具名群控/hook 模块 DLL 落地与加载(`wxhook`、`WeChatSDK`、`vchat`、
    `WeChatRobotCE`、`wxbotpp`、`WeChatManager`、企业微信 `WeWorkHook`/`wework_api`、
    `wxDump`、`QQHook`)→ **Block**;
  - 微信数据库解密/导出工具命令行(`PyWxDump`、`SharpWxDump`、`wxdump`、
    `WeChatMsg`,群发目标采集前置步骤)→ **Ask**;
  - 补充注入落点:`WeChatOCR.exe`、`WeChatUtility.exe`、`WXWorkWeb.exe`
    (仅未签名注入方命中)→ **Ask**;
  - 企业微信安装目录植入接口 DLL(`WXWork\*\wwapi*.dll`)→ **Ask**。
  - 设计取舍:**不对微信本体正常写库(`MicroMsg.db`/`MSG*.db`)下 FileWrite 规则**,
    避免海量误报,只锁定正常环境不出现的具名外挂特征。
- **规则单元测试** `Bulwark.Core.Tests/SilverFoxImRulesTests.cs`
  把真实内置规则集加载进 `RuleEngine`,以具体事件跑完整决策链验证上述裁决(全部通过)。
- **无害行为测试脚本** `tools/银狐防护测试.ps1`
  复现群控可观测特征(落 `wxhook.dll`、含 `PyWxDump`/`wcferry` 的命令行、向 IM 目录写 DLL)
  用于实机验证监控层+拦截是否生效。脚本不含任何真实群发/窃密逻辑,并自动清理。

### 安全 / 配置
- **停止跟踪 `Bulwark.Service/appsettings.json`**(其中含真实情报源 API 密钥),
  加入 `.gitignore`,改用 **`Bulwark.Service/appsettings.example.json`** 模板(密钥留空)。
  首次使用请复制该模板为 `appsettings.json` 并按下表填入自己的密钥。
- `.gitignore` 补充忽略:`bin_verify_svc/`、`__*.txt`、`ui_out.txt`、`ui_err.txt`、`query` 等调试残留。

---

## 情报源 API 获取地址

各情报源密钥填入 `appsettings.json` 对应节点(`Bulwark:<源>:ApiKey` 或 `AuthKey`)。
以下均为官方申请页面,**请勿将真实密钥提交到仓库**。

| 情报源 | 配置节点 | 申请/获取地址 |
|--------|----------|---------------|
| VirusTotal | `VirusTotal:ApiKey` | https://www.virustotal.com/gui/my-apikey (注册后在个人资料页获取) |
| MalwareBazaar (abuse.ch) | `MalwareBazaar:AuthKey` | https://auth.abuse.ch/ (注册 abuse.ch 账号后生成 Auth-Key) |
| AlienVault OTX | `Otx:ApiKey` | https://otx.alienvault.com/api (登录后在 API 页获取 OTX Key) |
| 微步在线 ThreatBook | `ThreatBook:ApiKey` | https://x.threatbook.com/ (社区版 API Key,个人中心获取) |
| OPSWAT MetaDefender | `MetaDefender:ApiKey` | https://metadefender.opswat.com/ (经 https://id.opswat.com/ 注册获取) |
| Hybrid Analysis (CrowdStrike) | `HybridAnalysis:ApiKey` | https://www.hybrid-analysis.com/apikeys/info (注册后在 API keys 页获取) |
| ThreatFox (abuse.ch) | `ThreatFoxFeed:AuthKey` | https://auth.abuse.ch/ (与 MalwareBazaar 共用 abuse.ch Auth-Key) |

> 提示:各源均可通过 `appsettings.json` 中对应的 `Enabled` 开关单独启停;
> `RequestsPerMinute` / `RequestsPerDay` 为本地限速,请按各源免费额度调整。
