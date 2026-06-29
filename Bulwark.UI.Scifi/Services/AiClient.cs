using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Bulwark.Core.Ipc;
using Bulwark.Core.Models;

namespace Bulwark.UI.Services;

/// <summary>
/// UI 侧大模型客户端(OpenAI 兼容协议)。负责:
/// 1. AI 病毒扫描(双击启动的程序)
/// 2. AI 规则生成(根据拦截事件自动推荐防御规则)
/// 
/// 使用 System.Net.Http.HttpClient,无需额外 NuGet 包。
/// </summary>
public sealed class AiClient : IDisposable
{
    private readonly HttpClient _http;

    /// <summary>月度 Credits 预算护栏:接近额度自动停止调用大模型(fail-open)。</summary>
    private readonly CreditBudget _budget = new();

    /// <summary>预算护栏(供 UI 读取用量快照)。</summary>
    public CreditBudget Budget => _budget;

    static AiClient()
    {
        // 全局级别禁用证书校验(兜底)。
        ServicePointManager.ServerCertificateValidationCallback = (_, _, _, _) => true;
    }

    public AiClient()
    {
        // 使用 WinHttpHandler —— 和 PowerShell/系统浏览器走完全相同的 WinHTTP 栈，
        // 彻底避免 SChannel "安全包不存在" 问题。
        var handler = new System.Net.Http.WinHttpHandler
        {
            ServerCertificateValidationCallback = (_, _, _, _) => true,
            WindowsProxyUsePolicy = System.Net.Http.WindowsProxyUsePolicy.UseWinHttpProxy,
            DefaultProxyCredentials = System.Net.CredentialCache.DefaultCredentials
        };
        _http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(300) };
    }

    // 默认值(与 opencode.json 一致)—— 内置开箱即用,无需用户配置。
    // 用户在设置页填入了自己的 Key 后,以用户配置优先。
    private const string DefaultBaseUrl = "https://token-plan-sgp.xiaomimimo.com/v1";
    private const string DefaultModel = "mimo-v2.5-pro";

    // 内置默认 Key 不再硬编码到源码(避免随仓库泄露)。
    // 优先从环境变量 BULWARK_AI_APIKEY 读取;未设置则为空(用户可在设置页自行填入)。
    private static readonly string DefaultApiKey =
        Environment.GetEnvironmentVariable("BULWARK_AI_APIKEY")?.Trim() is { Length: > 0 } envKey
            ? envKey
            : string.Empty;

    /// <summary>
    /// 已退役的内置 Key 列表。之前的内置默认 Key 可能被持久化进 settings.json(AiApiKey),
    /// 换新 Key 后这些旧值应视为「未配置」,自动回退到当前内置 Key,避免旧 Key 残留导致额度/鉴权问题。
    /// 注:不再在源码内嵌任何明文 Key(避免随仓库泄露)。
    /// </summary>
    private static readonly string[] RetiredKeys = Array.Empty<string>();

    /// <summary>判断给定 Key 是否为已退役的旧内置 Key(应被视为未配置)。</summary>
    public static bool IsRetiredKey(string? key)
        => !string.IsNullOrWhiteSpace(key)
           && Array.Exists(RetiredKeys, k => string.Equals(k, key!.Trim(), StringComparison.Ordinal));

    /// <summary>内置默认 API 基址(供 UI 设置页展示)。</summary>
    public static string BuiltInBaseUrl => DefaultBaseUrl;
    /// <summary>内置默认模型名(供 UI 设置页展示)。</summary>
    public static string BuiltInModel => DefaultModel;
    /// <summary>内置默认 API Key(供 UI 设置页展示)。</summary>
    public static string BuiltInApiKey => DefaultApiKey;

    private string _baseUrl = DefaultBaseUrl;
    private string _apiKey = DefaultApiKey;
    private string _model = DefaultModel;

    /// <summary>已确认配置的 Key 无效、改走内置 Key。避免每次研判都先用坏 Key 失败一趟。</summary>
    private bool _preferBuiltIn;

    /// <summary>当前文件扫描内容提取上限(由 Configure 从运行时设置同步)。</summary>
    public FileInspector.ScanOptions FileScanOptions { get; private set; } = FileInspector.ScanOptions.Default;

    /// <summary>是否已配置(至少有 API Key)。内置默认 Key 故始终为 true,除非用户主动清空。</summary>
    public bool IsConfigured => !string.IsNullOrWhiteSpace(_apiKey);

    /// <summary>用运行时设置更新 AI 配置。任一字段为空时回退到内置默认值。</summary>
    public void Configure(RuntimeSettings s)
    {
        // 退役的旧内置 Key 视为未配置,自动回退当前内置 Key(换 Key 后旧持久化值自愈)。
        var configured = IsRetiredKey(s.AiApiKey) ? string.Empty : s.AiApiKey;
        var newKey = string.IsNullOrWhiteSpace(configured) ? DefaultApiKey : configured;
        // Key 变更时重置"偏好内置"标记,给新 Key 一次机会。
        if (!string.Equals(newKey, _apiKey, StringComparison.Ordinal)) _preferBuiltIn = false;

        _baseUrl = string.IsNullOrWhiteSpace(s.AiBaseUrl) ? DefaultBaseUrl : s.AiBaseUrl.TrimEnd('/');
        _apiKey = newKey;
        _model = string.IsNullOrWhiteSpace(s.AiModel) ? DefaultModel : s.AiModel;
        FileScanOptions = FileInspector.ScanOptions.FromSettings(
            s.AiScanScriptTextLimitKb, s.AiScanBinarySampleLimitMb, s.AiScanMaxStrings);
        _budget.Configure(s.AiCreditGuardEnabled, s.AiMonthlyCreditBudget);
    }

    // ========== AI 病毒扫描 ==========

    /// <summary>
    /// 对一个安全事件调用大模型做病毒研判。返回 AiScanResponsePayload。
    /// 未配置/超时/异常时返回 Available=false（调用方 fail-open）。
    /// </summary>
    public async Task<AiScanResponsePayload> ScanAsync(SecurityEvent e)
    {
        if (!IsConfigured)
            return new AiScanResponsePayload { EventId = e.Id, Available = false };

        try
        {
            // 主路径:真正读取主体文件的实际内容(PE 结构/脚本源码/可打印字符串/可疑 API/熵),
            // 交由 AI 做静态恶意代码分析 —— 结论基于"文件本身是什么",而非拦截/进程行为元数据。
            if (!string.IsNullOrEmpty(e.ActorPath) && System.IO.File.Exists(e.ActorPath))
            {
                FileInspector.FileSnapshot? snapshot = null;
                try { snapshot = await Task.Run(() => FileInspector.Inspect(e.ActorPath, FileScanOptions)); }
                catch { snapshot = null; }

                if (snapshot is not null && snapshot.Error is null)
                {
                    var verdict = await ScanFileAsync(snapshot);
                    if (verdict.Available)
                    {
                        return new AiScanResponsePayload
                        {
                            EventId = e.Id,
                            Available = true,
                            // 仅"恶意"才拦截;"可疑/干净"放行(低误报原则)。
                            Recommendation = verdict.Verdict == AiVerdict.Malicious
                                ? VerdictAction.Block : VerdictAction.Allow,
                            Confidence = verdict.Confidence,
                            Summary = BuildSummary(verdict)
                        };
                    }
                }
            }

            // 退化路径:文件不可读(已删除/占用/无权限)时,才退回到行为研判。
            var prompt = BuildScanPrompt(e, null);
            var reply = await ChatAsync(prompt,
                "你是一个专业的 Windows 安全分析师。主体文件不可读,只能依据进程行为判断其是否为恶意软件,以 JSON 回复。",
                "病毒研判");
            return ParseScanResponse(reply, e.Id);
        }
        catch
        {
            return new AiScanResponsePayload { EventId = e.Id, Available = false };
        }
    }

    /// <summary>把文件研判结论组织成一句给用户看的话(含 verdict 文案 + 关键证据)。</summary>
    private static string BuildSummary(AiFileVerdict v)
    {
        var head = v.Verdict switch
        {
            AiVerdict.Malicious => "恶意",
            AiVerdict.Suspicious => "可疑",
            _ => "未发现恶意"
        };
        if (!string.IsNullOrWhiteSpace(v.Summary)) return $"[{head}] {v.Summary}";
        if (v.Reasons.Count > 0) return $"[{head}] {string.Join("；", v.Reasons)}";
        return $"基于文件内容分析:{head}。";
    }

    private static string BuildScanPrompt(SecurityEvent e, FileInspector.FileSnapshot? snapshot = null)
    {
        var sb = new StringBuilder();
        sb.AppendLine("请分析以下 Windows 进程行为,判断其是否为恶意软件。");
        sb.AppendLine();
        sb.AppendLine($"事件类型: {e.Type}");
        sb.AppendLine($"主体路径: {e.ActorPath}");
        sb.AppendLine($"PID: {e.ActorPid}");
        sb.AppendLine($"命令行: {e.CommandLine ?? "(无)"}");
        sb.AppendLine($"父进程: {e.ParentPath} (PID={e.ParentPid})");
        sb.AppendLine($"操作目标: {e.Target}");
        sb.AppendLine($"签名: {(e.ActorSigned ? $"已签名({e.ActorPublisher})" : "未签名")}");
        sb.AppendLine($"本机首见: {(e.IsFirstSeen ? "是" : "否")}");
        sb.AppendLine($"文件大小: {e.ActorFileSize} 字节");
        if (e.RiskReasons.Count > 0)
            sb.AppendLine($"风险标签: {string.Join(", ", e.RiskReasons)}");

        // ATT&CK 命中的技战术(结构化标签,便于模型对齐已知攻击手法)
        if (e.Techniques is { Count: > 0 })
            sb.AppendLine($"命中 ATT&CK 技战术: {string.Join(", ", e.Techniques)}");

        // 结构化证据链(决策时间线):比扁平风险标签更可解释 —— 含来源分析器、类别、分值贡献。
        if (e.EvidenceChain is { Count: > 0 })
        {
            sb.AppendLine();
            sb.AppendLine("证据链(磐垒各分析器的判定依据,类别 软信号/硬指标/互证/信任/规则):");
            foreach (var ev in e.EvidenceChain)
            {
                if (ev.Kind == EvidenceKind.Decision) continue; // 最终裁决是结论,不作为研判输入
                string score = ev.ScoreDelta != 0 ? $" [{ev.ScoreDelta:+0;-0}分]" : string.Empty;
                string tech = string.IsNullOrEmpty(ev.Technique) ? string.Empty : $" ({ev.Technique})";
                sb.AppendLine($"  - [{KindLabel(ev.Kind)}] {ev.Source}: {ev.Description}{tech}{score}");
            }
        }

        if (e.ChainContext is { Count: > 0 })
        {
            sb.AppendLine();
            sb.AppendLine("进程链上下文(按时间升序):");
            foreach (var c in e.ChainContext)
                sb.AppendLine($"  [{c.Type}] {System.IO.Path.GetFileName(c.ActorPath)}(pid={c.ActorPid}) -> {c.Target}");
        }

        // 文件实际内容特征(若可读)。
        if (snapshot is not null && snapshot.Error is null)
            AppendContentFeatures(sb, snapshot);

        sb.AppendLine();
        sb.AppendLine("请结合【进程行为 + 文件内容特征】综合判断。要求:");
        sb.AppendLine("· 结论必须基于确定性的恶意行为证据;未签名、运行目录、本机首见、熵值偏高等仅是弱信号,单独不能判恶意;");
        sb.AppendLine("· 用词准确确定,与判定一致,判恶意时禁止使用『疑似/可能/或许』等不确定措辞,证据不足就判为不恶意;");
        sb.AppendLine("· summary 用一句话给出可复核的具体理由。");
        sb.AppendLine("以如下 JSON 格式回复(不要包含其他文字)：");
        sb.AppendLine("{\"malicious\": true/false, \"confidence\": \"高/中/低\", \"summary\": \"基于具体证据的确定性结论(不得含疑似/可能等措辞)\"}");
        return sb.ToString();
    }

    /// <summary>把文件的内容静态特征(可疑API/脚本源码/二进制字符串/熵)追加到 prompt。供行为研判与文件研判共用。</summary>
    private static void AppendContentFeatures(StringBuilder sb, FileInspector.FileSnapshot s)
    {
        sb.AppendLine();
        sb.AppendLine($"== 文件内容特征 == (类型: {(s.IsPe ? "PE 可执行" : s.IsTextScript ? "文本/脚本" : "其他二进制")}, 魔数: {s.MagicHex ?? "?"})");

        if (s.SuspiciousIndicators.Count > 0)
            sb.AppendLine($"命中的可疑 API/关键词: {string.Join(", ", s.SuspiciousIndicators)}");

        if (s.IsTextScript && !string.IsNullOrWhiteSpace(s.ScriptText))
        {
            sb.AppendLine("脚本/文本源码(请逐行审计其行为):");
            sb.AppendLine("```");
            sb.AppendLine(s.ScriptText);
            sb.AppendLine("```");
        }
        else if (s.Strings.Count > 0)
        {
            sb.AppendLine($"二进制可打印字符串(共{s.Strings.Count}条,香农熵={s.Entropy:F2}/8):");
            var joined = string.Join('\n', s.Strings);
            if (joined.Length > 1_200_000) joined = joined[..1_200_000] + "\n...(已截断)...";
            sb.AppendLine(joined);
            if (s.Entropy >= 7.2)
                sb.AppendLine("(提示:熵值偏高,可能加壳/加密)");
        }
    }

    private static AiScanResponsePayload ParseScanResponse(string? reply, Guid eventId)
    {
        if (string.IsNullOrWhiteSpace(reply))
            return new AiScanResponsePayload { EventId = eventId, Available = false };

        try
        {
            // 提取 JSON 部分（模型可能返回 markdown code fence）
            var json = ExtractJson(reply);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            bool malicious = root.TryGetProperty("malicious", out var m) && m.GetBoolean();
            string? confidence = root.TryGetProperty("confidence", out var c) ? c.GetString() : null;
            string? summary = root.TryGetProperty("summary", out var s) ? s.GetString() : null;

            // 准确性闸门:判恶意却又含『疑似/可能』等不确定措辞,属自相矛盾的不自洽结论。
            // 不拿这种含糊结论去拦截/结束进程,降级为放行,确保拦截只发生在确定性恶意上。
            if (malicious && IsHedged(summary, new List<string>()))
            {
                malicious = false;
                summary = "(磐垒校正:模型结论含不确定措辞,证据不足以确诊恶意,不予拦截)" +
                          (string.IsNullOrWhiteSpace(summary) ? string.Empty : " 原文:" + summary);
            }

            return new AiScanResponsePayload
            {
                EventId = eventId,
                Available = true,
                Recommendation = malicious ? VerdictAction.Block : VerdictAction.Allow,
                Confidence = confidence,
                Summary = summary
            };
        }
        catch
        {
            return new AiScanResponsePayload { EventId = eventId, Available = false };
        }
    }

    // ========== AI 规则生成 ==========

    /// <summary>
    /// 根据用户用自然语言给出的「要求/条件」,请求大模型生成对应的防御规则建议。
    /// 例如:「禁止 wscript 创建子进程」「只允许 chrome 联网」。返回建议规则列表(供用户确认后添加)。
    /// </summary>
    public async Task<List<AiRuleSuggestion>> GenerateRulesFromRequirementAsync(
        string requirement, CancellationToken token = default)
    {
        if (!IsConfigured || string.IsNullOrWhiteSpace(requirement))
            return new List<AiRuleSuggestion>();

        try
        {
            var prompt = BuildRuleGenFromRequirementPrompt(requirement);
            var reply = await ChatAsync(prompt,
                "你是 Bulwark 主动防御系统的安全规则专家。根据用户用自然语言描述的要求或条件,生成精确的防御规则。以 JSON 数组回复。",
                "规则生成",
                token);
            return ParseRuleSuggestions(reply);
        }
        catch
        {
            return new List<AiRuleSuggestion>();
        }
    }

    private static string BuildRuleGenFromRequirementPrompt(string requirement)
    {
        var sb = new StringBuilder();
        sb.AppendLine("用户希望新增防御规则,用自然语言描述的要求/条件如下:");
        sb.AppendLine();
        sb.AppendLine(requirement.Trim());
        sb.AppendLine();
        sb.AppendLine("请把上述要求转换为 1~5 条精确、可执行的防御规则。");
        sb.AppendLine("说明:");
        sb.AppendLine("· actorPattern/targetPattern 用通配符 *,尽量精确匹配用户意图,不要过度宽泛而误伤正常程序;");
        sb.AppendLine("· 用户未明确指定的字段填 null;动作只能是 Block 或 Allow;");
        sb.AppendLine("· 若要求含糊无法形成有效规则,返回空数组 []。");
        sb.AppendLine("每条规则以如下 JSON 格式提供(整体用数组包裹):");
        sb.AppendLine("[{");
        sb.AppendLine("  \"actorPattern\": \"主体匹配模式(通配符*)\",");
        sb.AppendLine("  \"type\": \"事件类型(ProcessCreate/FileWrite/RegistryWrite/NetworkConnect/...或null)\",");
        sb.AppendLine("  \"targetPattern\": \"目标匹配模式(通配符*,可null)\",");
        sb.AppendLine("  \"commandLinePattern\": \"命令行匹配模式(可null)\",");
        sb.AppendLine("  \"action\": \"Block 或 Allow\",");
        sb.AppendLine("  \"reason\": \"一句话说明此规则如何满足用户要求\"");
        sb.AppendLine("}]");
        return sb.ToString();
    }

    private static List<AiRuleSuggestion> ParseRuleSuggestions(string? reply)
    {
        var result = new List<AiRuleSuggestion>();
        if (string.IsNullOrWhiteSpace(reply)) return result;

        try
        {
            var json = ExtractJson(reply);
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return result;

            foreach (var item in doc.RootElement.EnumerateArray())
            {
                var suggestion = new AiRuleSuggestion
                {
                    ActorPattern = item.TryGetProperty("actorPattern", out var ap) ? ap.GetString() : null,
                    TypeStr = item.TryGetProperty("type", out var t) ? t.GetString() : null,
                    TargetPattern = item.TryGetProperty("targetPattern", out var tp) ? tp.GetString() : null,
                    CommandLinePattern = item.TryGetProperty("commandLinePattern", out var cl) ? cl.GetString() : null,
                    ActionStr = item.TryGetProperty("action", out var a) ? a.GetString() : "Block",
                    Reason = item.TryGetProperty("reason", out var r) ? r.GetString() : null
                };
                result.Add(suggestion);
            }
        }
        catch { /* 解析失败忽略 */ }
        return result;
    }

    // ========== HTTP 底层 ==========

    private async Task<string?> ChatAsync(string userMessage, string systemMessage, string category, CancellationToken token = default)
    {
        // 预算护栏:调用大模型【之前】先估算本次开销,若本月额度即将耗尽则直接跳过(返回 null),
        // 各调用方据此 fail-open(走本地引擎,不调模型),硬性防止刷爆套餐 Credits。
        // 输出按 max_tokens 上限(1024)保守计入估算。
        long estCredits = CreditBudget.EstimateCredits(userMessage + systemMessage, 1024);
        if (!_budget.CanAfford(estCredits))
        {
            var (used, limit, _) = _budget.Snapshot();
            BudgetExhausted?.Invoke(used, limit);
            return null;
        }

        const int MaxAttempts = 3;
        int delayMs = 800;
        for (int attempt = 1; ; attempt++)
        {
            try
            {
                return await ChatWithKeyFallbackAsync(userMessage, systemMessage, category, token);
            }
            catch (Exception ex) when (attempt < MaxAttempts && !token.IsCancellationRequested && IsTransient(ex))
            {
                // 瞬时错误(超时/空响应/429/5xx):指数退避后重试。
                try { await Task.Delay(delayMs, token); } catch { }
                delayMs *= 2;
            }
        }
    }

    /// <summary>是否为可重试的瞬时错误(鉴权/内容风控等不重试)。</summary>
    private static bool IsTransient(Exception ex)
    {
        if (ex is OperationCanceledException || ex is System.Net.Http.HttpRequestException) return true;
        var m = (ex.Message ?? string.Empty).ToLowerInvariant();
        return m.Contains("空响应")
            || m.Contains("缺少 choices")
            || m.Contains("timeout") || m.Contains("timed out")
            || m.Contains("429") || m.Contains("rate limit")
            || m.Contains("500") || m.Contains("502") || m.Contains("503") || m.Contains("504")
            || m.Contains("temporar") || m.Contains("overload") || m.Contains("busy");
    }

    private async Task<string?> ChatWithKeyFallbackAsync(string userMessage, string systemMessage, string category, CancellationToken token = default)
    {
        // 已知配置的 Key 无效(之前回退成功过)时,直接用内置 Key,避免每次都先失败一趟。
        var primaryKey = (_preferBuiltIn && UsingCustomKeyOnBuiltInEndpoint()) ? DefaultApiKey : _apiKey;
        try
        {
            return await ChatOnceAsync(userMessage, systemMessage, primaryKey, category, token);
        }
        catch (InvalidOperationException ex)
            when (primaryKey != DefaultApiKey && UsingCustomKeyOnBuiltInEndpoint() && IsAuthError(ex.Message))
        {
            // 用户自定义 Key 在内置端点上鉴权失败(如 Invalid API Key)。
            // 1) 立即回退到内置有效 Key 重试一次(本次请求不失败)。
            var reply = await ChatOnceAsync(userMessage, systemMessage, DefaultApiKey, category, token);
            // 2) 记住坏 Key,本会话后续直接走内置;并通知上层把坏 Key 清除并持久化(永久自愈)。
            if (!_preferBuiltIn)
            {
                _preferBuiltIn = true;
                try { BadUserKeyDetected?.Invoke(); } catch { /* 通知失败不影响研判 */ }
            }
            return reply;
        }
    }

    /// <summary>
    /// 检测到"持久化的自定义 Key 无效、已回退内置 Key"时触发(每会话至多一次)。
    /// 上层据此把无效 Key 从设置中清除并持久化,实现永久自愈。
    /// </summary>
    public event Action? BadUserKeyDetected;

    /// <summary>本月 Credits 额度即将耗尽、本次调用被护栏跳过时触发(已用, 额度)。供 UI 提示。</summary>
    public event Action<long, long>? BudgetExhausted;

    /// <summary>当前是否"用着自定义 Key,但端点仍是内置端点"——只有这种情况下回退内置 Key 才有意义。</summary>
    private bool UsingCustomKeyOnBuiltInEndpoint()
        => !string.Equals(_apiKey, DefaultApiKey, StringComparison.Ordinal)
           && string.Equals(_baseUrl, DefaultBaseUrl, StringComparison.OrdinalIgnoreCase);

    /// <summary>粗略识别鉴权类错误(用于决定是否回退内置 Key)。</summary>
    private static bool IsAuthError(string? msg)
    {
        if (string.IsNullOrEmpty(msg)) return false;
        var m = msg.ToLowerInvariant();
        return m.Contains("invalid api key")
            || m.Contains("invalid_api_key")
            || m.Contains("unauthorized")
            || m.Contains("authentication")
            || m.Contains("api key")
            || m.Contains("401")
            || m.Contains("403");
    }

    /// <summary>单次对话请求(指定使用的 API Key)。失败时抛出可读异常,供上层决定是否回退。</summary>
    private async Task<string?> ChatOnceAsync(string userMessage, string systemMessage, string apiKey, string category, CancellationToken token = default)
    {
        var url = $"{_baseUrl}/chat/completions";
        var body = new
        {
            model = _model,
            messages = new object[]
            {
                new { role = "system", content = systemMessage },
                new { role = "user", content = userMessage }
            },
            temperature = 0.1,
            max_tokens = 1024
        };

        var jsonBody = JsonSerializer.Serialize(body);
        var respJson = await PostJsonAsync(url, jsonBody, apiKey, token);
        if (string.IsNullOrWhiteSpace(respJson))
            throw new InvalidOperationException("服务器返回空响应(可能是网络被拦截、代理异常或 curl/HttpClient 均失败)。");

        using var doc = JsonDocument.Parse(respJson);
        var root = doc.RootElement;

        // 接口返回错误体(额度耗尽/鉴权失败/模型不存在等):把真实原因抛出,而不是静默当作"无内容"。
        if (root.TryGetProperty("error", out var errEl))
        {
            string? errMsg = errEl.ValueKind == JsonValueKind.Object && errEl.TryGetProperty("message", out var em)
                ? em.GetString()
                : errEl.ToString();
            throw new InvalidOperationException($"接口返回错误: {errMsg}");
        }

        if (!root.TryGetProperty("choices", out var choices) || choices.GetArrayLength() == 0)
        {
            var raw = respJson.Length > 300 ? respJson[..300] + "…" : respJson;
            throw new InvalidOperationException($"响应缺少 choices 字段。原始响应: {raw}");
        }

        var message = choices[0].GetProperty("message");
        string? content = message.TryGetProperty("content", out var c) ? c.GetString() : null;
        // 推理模型(如 mimo)在 content 为空时,answer 可能只在 reasoning_content 里 —— 回退取用。
        if (string.IsNullOrWhiteSpace(content)
            && message.TryGetProperty("reasoning_content", out var rc))
            content = rc.GetString();

        // 计入 Credits 用量:优先用接口返回的真实 usage(prompt/completion tokens);
        // 缺失时按字符数粗估兜底。按 mimo-v2.5-pro 价(输入 300 / 输出 600 Credits/token)。
        long credits;
        if (root.TryGetProperty("usage", out var usage) && usage.ValueKind == JsonValueKind.Object)
        {
            long pt = usage.TryGetProperty("prompt_tokens", out var p) && p.TryGetInt64(out var pv) ? pv : 0;
            long ct = usage.TryGetProperty("completion_tokens", out var ce) && ce.TryGetInt64(out var cv) ? cv : 0;
            credits = pt * CreditBudget.InputCreditsPerToken + ct * CreditBudget.OutputCreditsPerToken;
        }
        else
        {
            credits = 0;
        }
        if (credits <= 0)
        {
            // 兜底估算:输入=用户+系统消息,输出=返回内容。
            credits = CreditBudget.EstimateTokens(userMessage) * CreditBudget.InputCreditsPerToken
                      + CreditBudget.EstimateTokens(systemMessage) * CreditBudget.InputCreditsPerToken
                      + CreditBudget.EstimateTokens(content) * CreditBudget.OutputCreditsPerToken;
        }
        _budget.Record(category, credits);

        return content;
    }

    /// <summary>
    /// 发送 JSON POST 请求并返回响应体。
    /// 优先使用系统自带 curl.exe 子进程(走系统网络栈,规避部分环境下 .NET
    /// 进程 SChannel/SSPI "要求的安全包不存在" 的问题);curl 不可用时回退 HttpClient。
    /// </summary>
    private async Task<string?> PostJsonAsync(string url, string jsonBody, string apiKey, CancellationToken token)
    {
        // 1) 优先 curl.exe(Windows 10 1803+ 内置)
        try
        {
            var viaCurl = await PostViaCurlAsync(url, jsonBody, apiKey, token);
            if (viaCurl is not null) return viaCurl;
        }
        catch { /* curl 不可用,回退 HttpClient */ }

        // 2) 回退:.NET HttpClient
        using var req = new HttpRequestMessage(HttpMethod.Post, url);
        req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", apiKey);
        req.Content = new StringContent(jsonBody, Encoding.UTF8, "application/json");

        using var resp = await _http.SendAsync(req, token);
        // 即使非 2xx 也读取响应体并返回 —— 让上层能识别 "Invalid API Key" 等错误并决定是否回退。
        var respBody = await resp.Content.ReadAsStringAsync(token);
        return string.IsNullOrWhiteSpace(respBody) ? null : respBody;
    }

    /// <summary>
    /// 通过 curl.exe 子进程发送 POST 请求。body 经临时文件传递(避免命令行转义/长度限制)。
    /// 返回响应体字符串;curl 不存在或进程异常时抛出供上层回退。
    /// </summary>
    private async Task<string?> PostViaCurlAsync(string url, string jsonBody, string apiKey, CancellationToken token)
    {
        // 把 body 写入临时文件,用 --data-binary @file 传递。
        var tempFile = System.IO.Path.GetTempFileName();
        try
        {
            await System.IO.File.WriteAllTextAsync(tempFile, jsonBody, new UTF8Encoding(false), token);

            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "curl.exe",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8
            };
            psi.ArgumentList.Add("-s");                 // 静默
            psi.ArgumentList.Add("-k");                 // 跳过证书校验(与 .NET 端策略一致)
            psi.ArgumentList.Add("--max-time");
            psi.ArgumentList.Add("300");
            psi.ArgumentList.Add("-X");
            psi.ArgumentList.Add("POST");
            psi.ArgumentList.Add("-H");
            psi.ArgumentList.Add($"Authorization: Bearer {apiKey}");
            psi.ArgumentList.Add("-H");
            psi.ArgumentList.Add("Content-Type: application/json");
            psi.ArgumentList.Add("--data-binary");
            psi.ArgumentList.Add($"@{tempFile}");
            psi.ArgumentList.Add(url);

            using var proc = new System.Diagnostics.Process { StartInfo = psi };
            if (!proc.Start())
                throw new InvalidOperationException("无法启动 curl.exe");

            var stdoutTask = proc.StandardOutput.ReadToEndAsync(token);
            await proc.WaitForExitAsync(token);
            var stdout = await stdoutTask;

            // curl 退出码非 0 视为失败,回退 HttpClient。
            if (proc.ExitCode != 0)
                throw new InvalidOperationException($"curl 退出码 {proc.ExitCode}");

            return stdout;
        }
        finally
        {
            try { System.IO.File.Delete(tempFile); } catch { /* 忽略 */ }
        }
    }

    // ========== AI 行为解释(用于拦截通知 / 裁决弹窗的「AI 安全助手」) ==========

    /// <summary>
    /// 让大模型用 2~3 句中文解释一个安全事件的风险与意图(给普通用户看)。
    /// 未配置/失败/超时返回 null,调用方据此隐藏 AI 区或显示降级文案。
    /// </summary>
    public async Task<string?> ExplainEventAsync(SecurityEvent e, CancellationToken token = default)
    {
        if (!IsConfigured) return null;

        try
        {
            var prompt = BuildScanPrompt(e)
                + "\n\n(本程序已被安全软件拦截/处置。)请不要输出 JSON,直接用 2~3 句简洁中文,"
                + "向普通用户解释这个行为为什么危险、攻击者可能的意图。";
            var reply = await ChatAsync(prompt,
                "你是 Bulwark 主动防御系统里的「AI 安全助手」。用通俗、简短的中文向普通用户解释被拦截行为的风险,不要用 Markdown,不要超过 3 句。",
                "拦截解释",
                token);
            return string.IsNullOrWhiteSpace(reply) ? null : reply.Trim();
        }
        catch
        {
            return null;
        }
    }

    /// <summary>测试 AI 连接是否可用。</summary>
    public async Task<(bool ok, string message)> TestConnectionAsync(CancellationToken token = default)
    {
        if (!IsConfigured)
            return (false, "未配置 API Key");

        try
        {
            var reply = await ChatAsync("你好,请回复\"连接正常\"四个字。",
                "你是 Bulwark 安全助手。", "连接测试", token);
            return string.IsNullOrWhiteSpace(reply)
                ? (false, $"模型未返回有效内容(URL={_baseUrl}, Model={_model})")
                : (true, $"模型响应正常: {reply.Trim()[..Math.Min(reply.Trim().Length, 30)]}");
        }
        catch (Exception ex)
        {
            var inner = ex.InnerException?.Message ?? "";
            var inner2 = ex.InnerException?.InnerException?.Message ?? "";
            return (false, $"连接失败: {ex.Message}" +
                (string.IsNullOrEmpty(inner) ? "" : $"\n内层: {inner}") +
                (string.IsNullOrEmpty(inner2) ? "" : $"\n根因: {inner2}"));
        }
    }

    // ========== 文件 AI 病毒扫描(用户主动选文件/文件夹) ==========

    /// <summary>对一个静态文件做 AI 病毒研判。返回 AiFileVerdict;未配置/失败返回 Available=false。</summary>
    public async Task<AiFileVerdict> ScanFileAsync(FileInspector.FileSnapshot snapshot, CancellationToken token = default, string category = "病毒研判")
    {
        if (!IsConfigured)
            return new AiFileVerdict { Path = snapshot.Path, Available = false };

        try
        {
            var prompt = BuildFileScanPrompt(snapshot);
            DumpPrompt(snapshot.Path, prompt); // 调试:落盘本次发给模型的完整提示词,供核验"文件信息确实已发送"
            var reply = await ChatAsync(prompt,
                "你是 Bulwark 杀毒引擎的 AI 静态分析模块。你会拿到文件的真实内容特征(脚本源码 / 二进制可打印字符串 / 命中的可疑 API / 熵值 / 签名等)。" +
                "请只依据【实际内容证据】判定,引用你真正看到的具体内容作为依据;严禁仅凭未签名、文件位置、本机首见、熵高、文件名等元数据就判为恶意。" +
                "结论用词必须准确确定、与 verdict 一致,判恶意时禁止使用『疑似/可能/或许』等措辞。仅以 JSON 回复,不要任何额外文字。",
                category,
                token);
            return ParseFileVerdict(reply, snapshot);
        }
        catch (Exception ex)
        {
            return new AiFileVerdict { Path = snapshot.Path, Available = false, Error = ex.Message };
        }
    }

    /// <summary>
    /// 把最近一次发给模型的提示词落盘(%TEMP%\bulwark_ai_lastprompt.txt),用于核验文件内容确实被发送。
    /// 默认关闭(正式版不写盘);设置环境变量 BULWARK_AI_DUMP_PROMPT=1 后开启,便于排查。
    /// </summary>
    private static void DumpPrompt(string filePath, string prompt)
    {
        if (!string.Equals(Environment.GetEnvironmentVariable("BULWARK_AI_DUMP_PROMPT"), "1", StringComparison.Ordinal))
            return;
        try
        {
            var dump = $"==== {DateTime.Now:yyyy-MM-dd HH:mm:ss} 发送给模型的提示词 ===="
                + $"\n目标文件: {filePath}\n提示词字符数: {prompt.Length}\n{new string('-', 60)}\n{prompt}\n";
            System.IO.File.WriteAllText(
                System.IO.Path.Combine(System.IO.Path.GetTempPath(), "bulwark_ai_lastprompt.txt"),
                dump, new UTF8Encoding(false));
        }
        catch { /* 调试转储失败不影响研判 */ }
    }

    private static string BuildFileScanPrompt(FileInspector.FileSnapshot s)
    {
        var sb = new StringBuilder();
        sb.AppendLine("你是一个静态恶意代码分析引擎。请直接分析以下 Windows 文件的【实际内容/静态特征】来判断它是否为恶意软件,而不是只看元数据。");
        sb.AppendLine();
        sb.AppendLine("== 基本信息 ==");
        sb.AppendLine($"路径: {s.Path}");
        sb.AppendLine($"扩展名: {s.Extension ?? "(无)"}");
        sb.AppendLine($"大小: {FormatSize(s.Size)} ({s.Size} 字节)");
        sb.AppendLine($"SHA-256: {s.Sha256 ?? "(未计算)"}");
        sb.AppendLine($"文件魔数(头16字节hex): {s.MagicHex ?? "(无)"}");
        sb.AppendLine($"类型: {(s.IsPe ? "PE 可执行" : s.IsTextScript ? "文本/脚本" : "其他二进制")}");
        sb.AppendLine($"签名: {(s.Signed ? $"已签名,发行商={s.Publisher}" : "未签名")}");
        if (!string.IsNullOrEmpty(s.FileDescription)) sb.AppendLine($"FileDescription: {s.FileDescription}");
        if (!string.IsNullOrEmpty(s.CompanyName)) sb.AppendLine($"CompanyName: {s.CompanyName}");
        if (!string.IsNullOrEmpty(s.ProductName)) sb.AppendLine($"ProductName: {s.ProductName}");
        if (!string.IsNullOrEmpty(s.OriginalFileName)) sb.AppendLine($"OriginalFilename: {s.OriginalFileName}");
        if (!string.IsNullOrEmpty(s.FileVersion)) sb.AppendLine($"FileVersion: {s.FileVersion}");

        // ===== 真正的内容研判素材 =====
        if (s.SuspiciousIndicators.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("== 命中的可疑 API/关键词(来自内容扫描) ==");
            sb.AppendLine(string.Join(", ", s.SuspiciousIndicators));
        }

        if (s.IsTextScript && !string.IsNullOrWhiteSpace(s.ScriptText))
        {
            sb.AppendLine();
            sb.AppendLine("== 脚本/文本源码(请逐行审计其行为) ==");
            sb.AppendLine("```");
            sb.AppendLine(s.ScriptText);
            sb.AppendLine("```");
        }
        else if (s.Strings.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine($"== 从二进制提取的可打印字符串(共{s.Strings.Count}条,香农熵={s.Entropy:F2}/8) ==");
            var joined = string.Join('\n', s.Strings);
            if (joined.Length > 1_200_000) joined = joined[..1_200_000] + "\n...(字符串过多已截断)...";
            sb.AppendLine(joined);
            if (s.Entropy >= 7.2)
                sb.AppendLine("(提示:熵值偏高,可能加壳/加密,需结合字符串与导入特征判断)");
        }

        sb.AppendLine();
        sb.AppendLine("== 研判要求(务必严格遵守) ==");
        sb.AppendLine("1. 只能依据上面文件的【实际内容证据】(具体的恶意代码段、可疑 API 组合、明文 C2 地址/命令、");
        sb.AppendLine("   勒索信文本、混淆解码再执行的代码等)下结论。证据要可复核:在 summary/reasons 里引用你");
        sb.AppendLine("   真正看到的具体内容(如某个 API 名、某行代码、某条字符串),不要泛泛而谈。");
        sb.AppendLine("2. 【严禁】仅凭元数据下 Malicious 判定。以下都属元数据/弱信号,单独出现绝不构成恶意证据,");
        sb.AppendLine("   也不得作为 Malicious 的理由:未签名、文件位于桌面/Temp/下载目录、本机首见、文件较新、");
        sb.AppendLine("   熵值偏高(加壳本身不等于恶意)、文件名像安装包(setup/install 等)。");
        sb.AppendLine("3. 判定档位(就高不就低必须有对应证据支撑):");
        sb.AppendLine("   · Malicious = 内容里有【明确的】恶意行为证据(注入/反调试/凭据窃取/混淆下载执行/勒索/");
        sb.AppendLine("     删除卷影/关闭杀软/键盘记录/横向移动等),且证据具体可指认;");
        sb.AppendLine("   · Suspicious = 有个别可疑迹象但不足以确认恶意(例如仅加壳且字符串极少无法判读);");
        sb.AppendLine("   · Clean = 未见恶意内容证据(含:带可信签名且发行商/原始文件名一致的常规软件,");
        sb.AppendLine("     或虽未签名但内容明显是正常程序/安装包)。");
        sb.AppendLine("4. 用词要【准确、确定】,与 verdict 一致:判 Malicious 时直接陈述查到的事实,");
        sb.AppendLine("   禁止使用『疑似/可能/或许/也许/大概』等不确定措辞;证据不够确凿就降为 Suspicious 或 Clean。");
        sb.AppendLine("5. 若文件内容不足以判断(如加壳后几乎无可读信息),如实说明『内容不足以判定』并判 Suspicious,");
        sb.AppendLine("   不要硬凑成 Malicious。");
        sb.AppendLine();
        sb.AppendLine("以如下 JSON 格式回复(不要其他文字):");
        sb.AppendLine("{\"verdict\":\"Clean|Suspicious|Malicious\",\"confidence\":\"高|中|低\",\"summary\":\"基于具体内容证据的确定性结论(一句话,不得含疑似/可能等措辞)\",\"reasons\":[\"引用看到的具体证据1\",\"具体证据2\"]}");
        return sb.ToString();
    }

    private static AiFileVerdict ParseFileVerdict(string? reply, FileInspector.FileSnapshot s)
    {
        var result = new AiFileVerdict
        {
            Path = s.Path,
            Sha256 = s.Sha256,
            Size = s.Size,
            Signed = s.Signed,
            Publisher = s.Publisher,
            Available = false
        };
        if (string.IsNullOrWhiteSpace(reply)) return result;

        try
        {
            var json = ExtractJson(reply);
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var verdictStr = root.TryGetProperty("verdict", out var v) ? v.GetString() : "Clean";
            result.Verdict = verdictStr switch
            {
                "Malicious" => AiVerdict.Malicious,
                "Suspicious" => AiVerdict.Suspicious,
                _ => AiVerdict.Clean
            };
            result.Confidence = root.TryGetProperty("confidence", out var c) ? c.GetString() : null;
            result.Summary = root.TryGetProperty("summary", out var sm) ? sm.GetString() : null;
            if (root.TryGetProperty("reasons", out var rs) && rs.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in rs.EnumerateArray())
                {
                    var str = item.GetString();
                    if (!string.IsNullOrWhiteSpace(str))
                        result.Reasons.Add(str);
                }
            }
            result.Available = true;

            // 准确性闸门:一次"判定恶意 -> 直接拦截"的结论必须是确定性的。
            // 若模型在判 Malicious 的同时还用『疑似/可能/或许』等不确定措辞,说明它自己也没把握 ——
            // 这与"恶意"是自相矛盾的。按低误报原则,把这种不自洽的结论降级为 Suspicious(不拦截),
            // 避免把"拿不准"的文件当成确诊恶意去处置,确保给用户的是准确而非含糊的信息。
            if (result.Verdict == AiVerdict.Malicious && IsHedged(result.Summary, result.Reasons))
            {
                result.Verdict = AiVerdict.Suspicious;
                result.Reasons.Insert(0, "(磐垒校正:模型结论含不确定措辞,证据不足以确诊恶意,按可疑处理不予拦截)");
            }
        }
        catch (Exception ex) { result.Error = ex.Message; }
        return result;
    }

    /// <summary>
    /// 判断一段研判结论是否使用了"不确定措辞"。用于把"判恶意却又含糊其辞"的自相矛盾结论
    /// 拦下来降级 —— 确诊恶意(会直接拦截/结束进程)必须是确定性的,不能基于"疑似"。
    /// </summary>
    private static bool IsHedged(string? summary, List<string> reasons)
    {
        var text = (summary ?? string.Empty) + " " + string.Join(" ", reasons);
        if (string.IsNullOrWhiteSpace(text)) return false;
        var lower = text.ToLowerInvariant();
        string[] hedges =
        {
            "疑似", "可能", "或许", "也许", "大概", "似乎", "好像", "貌似",
            "推测", "怀疑", "不排除", "不能确定", "无法确定", "尚不确定", "有待",
            "maybe", "may be", "possibly", "perhaps", "might", "could be",
            "suspected", "appears to", "seems", "likely", "probably"
        };
        foreach (var h in hedges)
            if (lower.Contains(h)) return true;
        return false;
    }

    /// <summary>证据类别的中文短标签(用于 AI 提示词里的证据链展示)。</summary>
    private static string KindLabel(EvidenceKind kind) => kind switch
    {
        EvidenceKind.HardIndicator => "硬指标",
        EvidenceKind.Corroboration => "互证升格",
        EvidenceKind.SoftSignal => "软信号",
        EvidenceKind.Trust => "信任",
        EvidenceKind.Rule => "规则",
        EvidenceKind.Decision => "裁决",
        _ => "信息"
    };

    private static string FormatSize(long size)
    {
        if (size < 1024) return $"{size} B";
        if (size < 1024 * 1024) return $"{size / 1024.0:F1} KB";
        if (size < 1024L * 1024 * 1024) return $"{size / 1024.0 / 1024.0:F1} MB";
        return $"{size / 1024.0 / 1024.0 / 1024.0:F2} GB";
    }

    // ========== 工具方法 ==========

    private static string ExtractJson(string text)
    {
        var trimmed = text.Trim();
        if (trimmed.StartsWith("```"))
        {
            var firstNewLine = trimmed.IndexOf('\n');
            if (firstNewLine > 0) trimmed = trimmed[(firstNewLine + 1)..];
            if (trimmed.EndsWith("```")) trimmed = trimmed[..^3];
            trimmed = trimmed.Trim();
        }
        return trimmed;
    }

    public void Dispose() => _http.Dispose();
}

/// <summary>AI 文件扫描裁决。</summary>
public enum AiVerdict { Clean, Suspicious, Malicious }

/// <summary>AI 对单文件的扫描结果。</summary>
public sealed class AiFileVerdict
{
    public string Path { get; set; } = string.Empty;
    public string? Sha256 { get; set; }
    public long Size { get; set; }
    public bool Signed { get; set; }
    public string? Publisher { get; set; }
    public bool Available { get; set; }
    public AiVerdict Verdict { get; set; } = AiVerdict.Clean;
    public string? Confidence { get; set; }
    public string? Summary { get; set; }
    public List<string> Reasons { get; set; } = new();
    public string? Error { get; set; }
    public DateTime ScannedAtUtc { get; set; } = DateTime.UtcNow;
}

/// <summary>AI 推荐的规则建议。</summary>
public sealed class AiRuleSuggestion
{
    public string? ActorPattern { get; set; }
    public string? TypeStr { get; set; }
    public string? TargetPattern { get; set; }
    public string? CommandLinePattern { get; set; }
    public string? ActionStr { get; set; }
    public string? Reason { get; set; }

    public EventType? ParseType()
        => Enum.TryParse<EventType>(TypeStr, true, out var t) ? t : null;

    public VerdictAction ParseAction()
        => string.Equals(ActionStr, "Allow", StringComparison.OrdinalIgnoreCase)
            ? VerdictAction.Allow
            : VerdictAction.Block;
}
