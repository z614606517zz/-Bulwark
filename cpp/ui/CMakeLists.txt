# bulwark_ui: Qt Widgets desktop front-end (redesigned).
# QML/Quick are not present in this Qt install, so the UI is built with Qt
# Widgets + Qt Style Sheets + custom painting for a modern dark security
# console. Same C++/CMake stack; reuses bulwark_shared for models + IPC.
find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets Network)

# WIN32 => GUI subsystem (no console window), matching the .NET WinExe UI.
qt_add_executable(bulwark_ui WIN32
    src/main.cpp
    src/Theme.h
    src/Theme.cpp
    src/MainWindow.h
    src/MainWindow.cpp
    src/widgets/AppIcon.h
    src/widgets/AppIcon.cpp
    src/widgets/NavButton.h
    src/widgets/NavButton.cpp
    src/widgets/ToggleSwitch.h
    src/widgets/ToggleSwitch.cpp
    src/widgets/Ui.h
    src/widgets/Cards.h
    src/widgets/TableKit.h
    src/pages/DashboardPage.h
    src/pages/DashboardPage.cpp
    src/pages/TablePages.h
    src/pages/TablePages.cpp
    src/pages/CardPages.h
    src/pages/CardPages.cpp
    src/dialogs/EventFormat.h
    src/dialogs/PromptDialog.h
    src/dialogs/PromptDialog.cpp
    src/dialogs/RemediationReportDialog.h
    src/dialogs/RemediationReportDialog.cpp
    src/dialogs/AttackTimelineWindow.h
    src/dialogs/AttackTimelineWindow.cpp
    src/dialogs/ToastWindow.h
    src/dialogs/ToastWindow.cpp
    src/dialogs/ToastNotifier.h
    src/dialogs/ToastNotifier.cpp
    src/dialogs/ScanProgressWindow.h
    src/dialogs/ScanProgressWindow.cpp
    src/ipc/IpcClient.h
    src/ipc/IpcClient.cpp
    src/ai/AiScanner.h
    src/ai/AiScanner.cpp
    src/ai/AiScanHistoryStore.h
    src/ai/AiScanHistoryStore.cpp
    src/ai/StaticFeatureExtractor.h
    src/ai/StaticFeatureExtractor.cpp
)

target_include_directories(bulwark_ui PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_link_libraries(bulwark_ui PRIVATE
    bulwark_shared
    Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Network)

target_compile_features(bulwark_ui PRIVATE cxx_std_20)

if(MSVC)
    target_compile_options(bulwark_ui PRIVATE /W4 /permissive- /utf-8)
    target_compile_definitions(bulwark_ui PRIVATE UNICODE _UNICODE)
else()
    target_compile_options(bulwark_ui PRIVATE -Wall -Wextra)
endif()
