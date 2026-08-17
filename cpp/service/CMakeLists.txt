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
    # 磁盘垃圾清理:编译期固定的类别/根目录表 + 扫描 + 删除,七道安全护栏见 JunkCleaner.h
    src/JunkCleaner.cpp
    # ipc + orchestration (Q_OBJECT headers listed so AUTOMOC processes them)
    include/bulwark/service/EventSource.h
    include/bulwark/service/EtwProcessEventSource.h
    include/bulwark/service/DriverEventSource.h
    include/bulwark/service/UserModeBehaviorSource.h
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
    # shell32: SHQueryRecycleBin / SHEmptyRecycleBin (JunkCleaner 的回收站维度 —— 刻意走
    #   Shell API 而不是手工遍历 $Recycle.Bin,见 JunkCleaner.h 的产品决定)。
    target_link_libraries(bulwark_service PRIVATE advapi32 kernel32 wintrust crypt32 tdh fltlib ole32 uuid oleaut32 shell32)
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
