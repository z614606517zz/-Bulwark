# bulwark_service: the headless daemon (IPC server, monitoring, storage).
# Runs as a Windows service (or console for debugging). Mirrors the .NET
# Bulwark.Service project. Links the shared contract/engine layer.
#
# PHASE B (minimal runnable daemon): storage + named-pipe IPC server + an ETW
# event source wired to the RuleEngine, so the service runs and talks
# to the UI end-to-end. Heavier modules (monitoring/ProcessInspector, the full
# reputation clients, quarantine/remediation, kernel driver IPC) are ported in
# later phases and added back below as they land.
find_package(Qt6 REQUIRED COMPONENTS Core Network)

# Use qt_add_executable (not plain add_executable) so AUTOMOC reliably processes
# the Q_OBJECT headers (same as the UI target, which links cleanly).
qt_add_executable(bulwark_service
    app.rc                     # embeds the brand badge as the exe/Explorer icon
    src/main.cpp
    src/Logger.cpp
    src/BulwarkOptions.cpp
    # storage
    src/SettingsStore.cpp
    src/RuleStore.cpp
    src/FirstSeenStore.cpp
    src/BaselineStore.cpp
    src/AuditLog.cpp
    src/AlertExporter.cpp
    src/VtScanHistoryStore.cpp
    src/ThreatIntelContribStore.cpp
    src/reputation/ThreatIntelUploader.cpp
    # storage (recovered .cpp, headers reconstructed this round)
    src/EventHistoryStore.cpp
    src/QuarantineManager.cpp
    src/RegSurgery.cpp
    # reputation (curl-based intel clients + tiered cache + rate limiting)
    src/reputation/ReputationCurl.cpp
    src/reputation/RateLimiting.cpp
    src/reputation/ReputationCache.cpp
    src/reputation/HashReputationClients.cpp
    src/reputation/AggregateReputationService.cpp
    src/reputation/ProxyReputationService.cpp
    src/reputation/ReputationManager.cpp
    src/reputation/VirusTotalClient.cpp
    src/reputation/ThreatBookClient.cpp
    src/reputation/ThreatFoxFeed.cpp
    # 攻击链组合引擎:下载服务器挖出的行为组合表 + 给每个进程记账 + 凑齐即喂证据
    src/AttackChainEngine.cpp
    # 在线更新:取清单 + 下载 + 四道校验(名字白名单/大小/SHA-256/签名指纹钉死)
    src/UpdateService.cpp
    # monitoring (Authenticode/PE/hash forensics + process control)
    src/monitoring/ProcessInspector.cpp
    # monitoring: 进程启动来源溯源(PID -> 具体服务名 / 具体计划任务名)+ 在跑进程快照
    src/monitoring/ProcessOriginResolver.cpp
    src/monitoring/ProcessEnumerator.cpp
    # 取证查询:事件时间线过滤 + 攻击图构建(读事件历史,只读)
    src/ForensicsService.cpp
    # remediation (quarantine malicious files + strip registry/IFEO/service persistence)
    src/ThreatRemediator.cpp
    # persistence audit (read-only enumeration of 7 autostart points + risk scoring)
    src/PersistenceScanner.cpp

    # ipc + orchestration (Q_OBJECT headers listed so AUTOMOC processes them)
    include/bulwark/service/EventSource.h
    include/bulwark/service/EtwProcessEventSource.h
    include/bulwark/service/DriverEventSource.h
    include/bulwark/service/UserModeBehaviorSource.h
    include/bulwark/service/UserModeExecBlock.h
    include/bulwark/service/UserModeNetworkBlock.h
    include/bulwark/service/UserModeProcessContainment.h
    include/bulwark/service/SystemHardening.h
    include/bulwark/service/EventSourceCoordinator.h
    include/bulwark/service/IpcServer.h
    include/bulwark/service/Worker.h
    src/IpcServer.cpp
    # 控制管道客户端认证(GetNamedPipeClientProcessId -> 安装目录/映像名强制校验 + 可选签名加固)
    src/IpcClientAuth.cpp
    src/EtwProcessEventSource.cpp
    # kernel driver (R0) integration: minifilter comms + auto register/load
    src/DriverEventSource.cpp
    src/DriverControl.cpp
    # user-mode continuous behavior (canary honeypots + autostart delta), source
    # coordinator (multi-source + runtime kernel toggle), service originator tracer
    src/UserModeBehaviorSource.cpp
    # 无驱动时的执行前拦截原语(长期持有 share-mode-0 独占句柄 -> CreateProcess/加载器打不开)
    src/UserModeExecBlock.cpp
    # 无驱动时的出站封禁原语(WFP ALE_AUTH_CONNECT_V4 上的 BLOCK 过滤器 -> connect 返回 WSAEACCES)
    src/UserModeNetworkBlock.cpp
    # 读不了/删不掉的文件:备份特权绕 DACL(不绕共享冲突)+ Restart Manager 报出占用者
    src/OccupiedFileAccess.cpp
    # 进程收容与处置阶梯:可逆冻结(NtSuspendProcess)+ 不可逆断子(Job ActiveProcessLimit=1)
    #   + 有次序的终结(先锁映像再冻结再断子再杀,最后 waitForExit 确认)
    src/UserModeProcessContainment.cpp
    # 阶段 3 用户确认型加固:跨重启的「拒绝执行」ACE(独占句柄做不到的那一半)、
    #   恶意独占键的注册表 DENY ACE、RegNotifyChangeKeyValue 即时监视 + 自动回滚、
    #   以及 RunAsPPL / 自身服务 DACL 的只读体检(默认不擅自应用)
    src/SystemHardening.cpp
    src/EventSourceCoordinator.cpp
    src/ServiceControlTracer.cpp
    src/Worker.cpp
)

# --- Later phases (uncomment as each is ported/verified) ---------------------
#   src/reputation/VirusTotalClient.cpp upload/scan path (double-click / dropped
#     payload) + VtScanStage progress + VtScan IPC — deferred (query path done).
#   src/reputation/ThreatBookClient.cpp / ThreatFoxFeed.cpp
# Ported: ProcessInspector, ThreatRemediator, ProcessChainTracker, the reputation
#   subsystem (4 generic clients + VirusTotal query + AggregateReputationService +
#   ReputationManager), all wired into Worker for enrichment/enforcement/remediation.

target_include_directories(bulwark_service
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
    # krabsetw (Microsoft, MIT, header-only) — vendored ETW consumer wrapper.
    # Include dir is the folder holding krabs.hpp, so `#include <krabs.hpp>` works.
    PRIVATE ${CMAKE_SOURCE_DIR}/third_party/krabsetw/krabs
    # Kernel driver protocol header (Protocol.h) — single source of truth for the
    # kernel<->service message layout; DriverEventSource #includes it directly so
    # the C++ side never re-declares the structs (no layout drift vs the .sys).
    PRIVATE ${CMAKE_SOURCE_DIR}/../Bulwark.Driver)

# bulwark_shared is linked PUBLIC-ly, so its include dir (cpp/shared/include)
# propagates here automatically -> #include <bulwark/...> just works.
target_link_libraries(bulwark_service PRIVATE bulwark_shared Qt6::Core Qt6::Network)

# Win32 registry surgery / SID / ACL / delete-on-reboot APIs (later phases) +
# tdh (TDH event schema/property parsing used by krabsetw). ETW session APIs
# (StartTrace/OpenTrace/ProcessTrace/EnableTraceEx2) live in advapi32.
if(WIN32)
    # fltlib: Filter Manager user-mode API (DriverEventSource <-> Bulwark.sys).
    # ole32/uuid/oleaut32: COM + IShellLink (UserModeBehaviorSource resolves startup .lnk
    #   targets) + ITaskService (ProcessOriginResolver matches a PID to its scheduled task;
    #   oleaut32 provides VariantInit/SysFreeString used on that path).
    # fwpuclnt: WFP 用户态过滤引擎 API(UserModeNetworkBlock 在 ALE_AUTH_CONNECT_V4 挂 BLOCK
    #   过滤器 —— 无内核驱动时唯一的出站前拦截手段)。ws2_32: winsock 类型/字节序。
    # rstrtmgr: Restart Manager(OccupiedFileAccess 用它查出「是谁占着这个文件」——
    #   隔离失败时把占用者 PID/映像名写进日志,原先那条路径一个字都不说)。
    target_link_libraries(bulwark_service PRIVATE advapi32 kernel32 wintrust crypt32 tdh fltlib ole32 uuid oleaut32 fwpuclnt ws2_32 rstrtmgr)
endif()

target_compile_features(bulwark_service PRIVATE cxx_std_20)

if(MSVC)
    target_compile_options(bulwark_service PRIVATE /W4 /permissive- /utf-8)
    target_compile_definitions(bulwark_service PRIVATE UNICODE _UNICODE)
else()
    target_compile_options(bulwark_service PRIVATE -Wall -Wextra)
endif()

# Ship the default appsettings.json next to the exe (the service reads it from
# applicationDirPath at startup). copy_if_different keeps rebuilds cheap.
add_custom_command(TARGET bulwark_service POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_CURRENT_SOURCE_DIR}/appsettings.json"
        "$<TARGET_FILE_DIR:bulwark_service>/appsettings.json"
    COMMENT "Deploying appsettings.json next to bulwark_service.exe")
