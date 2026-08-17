# bulwark_shared: language-agnostic contract + domain models + IPC + (later) engine.
# Equivalent to the .NET Bulwark.Core. Depends only on Qt6::Core so both the
# service (headless) and the UI reuse it. Engine files are added back in Task 3.
add_library(bulwark_shared STATIC
    src/models/Evidence.cpp
    src/models/ChainEventInfo.cpp
    src/models/SecurityEvent.cpp
    src/models/Verdict.cpp
    src/models/FileReputation.cpp
    src/models/DefenseRule.cpp
    src/models/RuntimeSettings.cpp
    src/models/VtScanRecord.cpp
    src/models/ReputationUsage.cpp
    src/models/IpReputation.cpp
    src/models/PersistenceEntry.cpp
    src/models/AttackGraph.cpp
    src/models/ProcessEntry.cpp
    # 磁盘垃圾清理的契约模型(类别 / 风险档 / 位置聚合 / 清理结果)
    src/models/JunkEntry.cpp
    src/ipc/IpcMessage.cpp
    src/ipc/Payloads.cpp

    # engine: analyzers + orchestrator, re-ported from .NET Bulwark.Core/Engine.
    src/engine/SystemPaths.cpp
    src/engine/AttackCatalog.cpp
    src/engine/AttackAnnotator.cpp
    src/engine/LolbinAnalyzer.cpp
    src/engine/CommandObfuscationAnalyzer.cpp
    src/engine/DgaDomainAnalyzer.cpp
    src/engine/CredentialAccessAnalyzer.cpp
    src/engine/DefenseEvasionAnalyzer.cpp
    src/engine/InjectionAnalyzer.cpp
    src/engine/RemoteControlAnalyzer.cpp
    src/engine/ScriptAnalyzer.cpp
    src/engine/KillChainAnalyzer.cpp
    src/engine/ProcessChainTracker.cpp
    src/engine/AttackGraphBuilder.cpp
    src/engine/BeaconDetector.cpp
    src/engine/EgressRateMonitor.cpp
    src/engine/BaselineAnalyzer.cpp
    src/engine/RansomwareBehaviorMonitor.cpp
    src/engine/TrustPolicy.cpp
    src/engine/ThreatDetector.cpp
    src/engine/DefaultRules.cpp
    src/engine/RuleEngine.cpp
    src/engine/EcsAlertFormatter.cpp
    src/engine/PersistenceAnalyzer.cpp
    src/engine/AiDecisionPolicy.cpp
)

target_include_directories(bulwark_shared
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(bulwark_shared PUBLIC Qt6::Core)

target_compile_features(bulwark_shared PUBLIC cxx_std_20)

if(MSVC)
    target_compile_options(bulwark_shared PRIVATE /W4 /permissive- /utf-8)
else()
    target_compile_options(bulwark_shared PRIVATE -Wall -Wextra)
endif()
