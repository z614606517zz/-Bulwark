using Bulwark.Core.Engine;
using Bulwark.Service;
using Bulwark.Service.Ipc;
using Bulwark.Service.Monitoring;
using Bulwark.Service.Storage;

// 全局崩溃日志:把未处理异常(含来自 P/Invoke 的 AccessViolationException 等
// CSE)完整写入 %ProgramData%\Bulwark\crash.log,便于事后定位真正的故障栈。
// 控制台只会显示被截断的一行,无法看到完整调用栈,故必须落盘。
static void WriteCrash(string phase, Exception? ex)
{
    try
    {
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Bulwark");
        Directory.CreateDirectory(dir);
        var line = $"==== {DateTime.Now:O} [{phase}] PID={Environment.ProcessId} ====\n{ex}\n\n";
        File.AppendAllText(Path.Combine(dir, "crash.log"), line);
    }
    catch { /* 崩溃日志本身绝不能再抛 */ }
}

AppDomain.CurrentDomain.UnhandledException += (_, e) =>
    WriteCrash("UnhandledException", e.ExceptionObject as Exception);
System.Threading.Tasks.TaskScheduler.UnobservedTaskException += (_, e) =>
{
    WriteCrash("UnobservedTaskException", e.Exception);
    e.SetObserved();
};

var builder = Host.CreateApplicationBuilder(args);

// 文件日志:无控制台(服务 / 提权后台)运行时也能持续记录内核连接/重连等行为,
// 落盘到 %ProgramData%\Bulwark\service.log,便于排查。
builder.Logging.AddProvider(new FileLoggerProvider());

// 允许作为 Windows 服务运行(也可直接控制台运行用于调试)
builder.Services.AddWindowsService(options => options.ServiceName = "Bulwark Defense");

// 绑定配置
var options = new BulwarkOptions();
builder.Configuration.GetSection(BulwarkOptions.SectionName).Bind(options);
builder.Services.AddSingleton(options);

// 规则引擎(应用配置)
builder.Services.AddSingleton(sp =>
{
    var engine = new RuleEngine
    {
        TrustSignedActors = options.TrustSignedActors,
        DefaultAction = options.DefaultAction
    };
    return engine;
});

builder.Services.AddSingleton<RuleStore>();
builder.Services.AddSingleton<SettingsStore>();
builder.Services.AddSingleton<VtScanHistoryStore>();
builder.Services.AddSingleton<BaselineStore>();
builder.Services.AddSingleton<AuditLog>();
builder.Services.AddSingleton(new AlertExporter(options.ExportEcsAlerts));
builder.Services.AddSingleton<QuarantineManager>();
builder.Services.AddSingleton<IpcServer>();

// AI 病毒扫描器
builder.Services.AddSingleton<IVirusScanner>(sp =>
{
    var logger = sp.GetRequiredService<ILogger<VirusScanner>>();
    return new VirusScanner(null, msg => logger.LogInformation("[VirusScanner] {Message}", msg));
});

// VirusTotal 哈希信誉:客户端(带限流)+ 持久化缓存 + 后台查询协调器。
// 全程"锦上添花":未配置 Key / 关闭时自动禁用,绝不影响内核实时防护。
builder.Services.AddSingleton<Bulwark.Service.Reputation.ReputationCache>(_ =>
    new Bulwark.Service.Reputation.ReputationCache(
        TimeSpan.FromDays(Math.Max(1, options.VirusTotal.CleanCacheTtlDays)),
        TimeSpan.FromHours(Math.Max(1, options.VirusTotal.UnknownCacheTtlHours)),
        TimeSpan.FromHours(Math.Max(1, options.VirusTotal.SuspiciousCacheTtlHours))));
// 信誉源(各自带限流/降级/缓存约定)。逐个注册为 IHashReputationService,
// 由 AggregateReputationService 并发查询并合并结论。新增源只需在此追加一行。
// VirusTotalClient 额外注册为具体类型,供「双击上传扫描」直接调用其上传 API。
builder.Services.AddSingleton<Bulwark.Service.Reputation.VirusTotalClient>();
builder.Services.AddSingleton<Bulwark.Core.Engine.IHashReputationService>(sp =>
    sp.GetRequiredService<Bulwark.Service.Reputation.VirusTotalClient>());
builder.Services.AddSingleton<Bulwark.Core.Engine.IHashReputationService,
    Bulwark.Service.Reputation.MalwareBazaarClient>();
builder.Services.AddSingleton<Bulwark.Core.Engine.IHashReputationService,
    Bulwark.Service.Reputation.OtxClient>();
builder.Services.AddSingleton<Bulwark.Service.Reputation.ThreatBookClient>();
builder.Services.AddSingleton<Bulwark.Core.Engine.IHashReputationService>(sp =>
    sp.GetRequiredService<Bulwark.Service.Reputation.ThreatBookClient>());
builder.Services.AddSingleton<Bulwark.Core.Engine.IHashReputationService,
    Bulwark.Service.Reputation.MetaDefenderClient>();
builder.Services.AddSingleton<Bulwark.Core.Engine.IHashReputationService,
    Bulwark.Service.Reputation.HybridAnalysisClient>();

// 聚合器:对上层(ReputationManager)呈现为单一 IHashReputationService。
// ReputationManager 显式消费聚合器,避免与上面的多注册产生歧义。
builder.Services.AddSingleton<Bulwark.Service.Reputation.AggregateReputationService>(sp =>
    new Bulwark.Service.Reputation.AggregateReputationService(
        sp.GetRequiredService<ILogger<Bulwark.Service.Reputation.AggregateReputationService>>(),
        sp.GetServices<Bulwark.Core.Engine.IHashReputationService>()));
builder.Services.AddSingleton<Bulwark.Service.Reputation.ReputationManager>(sp =>
    new Bulwark.Service.Reputation.ReputationManager(
        sp.GetRequiredService<ILogger<Bulwark.Service.Reputation.ReputationManager>>(),
        sp.GetRequiredService<Bulwark.Service.Reputation.AggregateReputationService>(),
        sp.GetRequiredService<Bulwark.Service.Reputation.ReputationCache>()));

// 进程链关联跟踪器:把孤立事件按进程树聚合,供裁决时还原整条攻击链。
builder.Services.AddSingleton<ProcessChainTracker>();

// 事件源架构:
//  - 基础(用户态)源:始终运行,用于观测(WMI 真实监控 或 模拟演示)。
//  - 内核驱动源:由"内核驱动开关"在运行时按需启停(需已加载 Bulwark.sys)。
//  - EventSourceCoordinator 合并两路事件,并把裁决回写路由到正确的源。
if (OperatingSystem.IsWindows())
{
#pragma warning disable CA1416 // 以下分支均在 OperatingSystem.IsWindows() 保护下
    // 选择基础用户态源
    if (string.Equals(options.EventSource, "Simulated", StringComparison.OrdinalIgnoreCase))
        builder.Services.AddSingleton<SimulatedEventSource>();
    else
        builder.Services.AddSingleton<WmiProcessEventSource>();

    // 内核驱动源(瞬态:开关每次开启时新建一个连接实例)
    builder.Services.AddTransient<DriverEventSource>();

    // 用户态「持续行为」源:无需驱动也能监视事后危险行为(自启动持久化 + 勒索蜜罐)。
    // 始终随协调器一起运行,弥补 WMI 仅能观测进程创建的盲区。
    builder.Services.AddSingleton<UserModeBehaviorSource>();

    // 协调器作为对外统一事件源 + 裁决回写汇聚点
    builder.Services.AddSingleton<EventSourceCoordinator>(sp =>
    {
        IEventSource baseSource =
            string.Equals(options.EventSource, "Simulated", StringComparison.OrdinalIgnoreCase)
                ? sp.GetRequiredService<SimulatedEventSource>()
                : sp.GetRequiredService<WmiProcessEventSource>();

        return new EventSourceCoordinator(
            sp.GetRequiredService<ILogger<EventSourceCoordinator>>(),
            baseSource,
            () => sp.GetRequiredService<DriverEventSource>(),
            sp.GetRequiredService<UserModeBehaviorSource>());
    });
    builder.Services.AddSingleton<IEventSource>(sp => sp.GetRequiredService<EventSourceCoordinator>());
#pragma warning restore CA1416
}
else
{
    builder.Services.AddSingleton<IEventSource, SimulatedEventSource>();
}

builder.Services.AddHostedService<Worker>();

var host = builder.Build();
host.Run();
