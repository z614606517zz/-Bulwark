# bulwark_ui: Qt Widgets desktop front-end.
# QML/Quick are not present in this Qt install, so the UI is built with Qt
# Widgets + a Qt Style Sheet + custom painting (the "Bedrock" dark design
# system under src/design/). Reuses bulwark_shared for models + IPC.
find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets Network)

# WIN32 => GUI subsystem (no console window), matching the .NET WinExe UI.
qt_add_executable(bulwark_ui WIN32
    app.rc                     # embeds the brand badge as the exe/Explorer icon
    src/main.cpp
    src/Bootstrap.h
    src/Bootstrap.cpp
    src/MainWindow.h
    src/MainWindow.cpp
    src/Nav.h
    src/Nav.cpp

    # "Bedrock" design system: tokens + style sheet, backdrop materials, icons, surfaces, controls.
    src/design/Theme.h
    src/design/Theme.cpp
    src/design/Identity.h      # page identity hues + record kind hues (never a status colour)
    src/design/Tone.h
    src/design/Format.h
    src/design/Motion.h
    src/design/Motion.cpp
    src/design/Icons.h
    src/design/Icons.cpp
    src/design/IconTile.h
    src/design/GlowCard.h
    src/design/GlowCard.cpp
    src/design/Backdrop.h
    src/design/Backdrop.cpp
    src/design/ShieldEmblem.h
    src/design/ShieldEmblem.cpp
    src/design/NavButton.h
    src/design/NavButton.cpp
    src/design/ToggleSwitch.h
    src/design/ToggleSwitch.cpp
    src/design/Components.h
    src/design/TableKit.h
    # Composite controls shared by pages and dialogs.
    src/design/FlowLayout.h
    src/design/FlowLayout.cpp
    src/design/Segmented.h
    src/design/Segmented.cpp
    src/design/FilterChip.h
    src/design/FilterChip.cpp
    src/design/EmptyState.h
    src/design/EmptyState.cpp
    src/design/Banner.h
    src/design/Banner.cpp
    src/design/Inspector.h
    src/design/Inspector.cpp
    src/design/RecordModel.h
    src/design/RecordModel.cpp
    src/design/RecordDelegate.h
    src/design/RecordDelegate.cpp
    src/design/ListShell.h
    src/design/ListShell.cpp
    src/design/Sheet.h
    src/design/Sheet.cpp
    src/design/Confirm.h
    src/design/Confirm.cpp
    src/design/Stepper.h
    src/design/Stepper.cpp
    src/design/CountdownBar.h
    src/design/CountdownBar.cpp
    src/design/DropZone.h
    src/design/DropZone.cpp
    src/design/FilePicker.h
    src/design/FilePicker.cpp
    src/design/FitScroll.h
    src/design/CountTile.h
    src/design/StatusStrip.h

    src/widgets/ElidingLabel.h
    src/widgets/WrapLabel.h
    src/widgets/TableColumns.h
    src/widgets/TableColumns.cpp
    src/pages/DashboardPage.h
    src/pages/DashboardPage.cpp
    src/pages/TablePages.h      # factory declarations of the list pages below
    src/pages/PageKit.h
    src/pages/EventsPage.cpp
    src/pages/TimelinePage.cpp
    src/pages/ChainPage.cpp
    src/pages/ProcessesPage.cpp
    src/pages/RulesPage.cpp
    src/pages/TrustPage.cpp
    src/pages/QuarantinePage.cpp
    src/pages/PersistencePage.cpp
    src/pages/CardPages.h       # factory declarations of the three pages below
    src/pages/SettingsPage.cpp
    src/pages/ReputationPage.cpp
    src/pages/AiPage.cpp

    src/dialogs/EventFormat.h
    src/dialogs/EventViews.h
    src/dialogs/EventViews.cpp
    src/dialogs/ProcessViews.h
    src/dialogs/ProcessViews.cpp
    src/dialogs/ChainViews.h
    src/dialogs/ChainViews.cpp
    src/dialogs/PromptDialog.h
    src/dialogs/PromptDialog.cpp
    src/dialogs/UpdateDialog.h
    src/dialogs/UpdateDialog.cpp
    src/dialogs/RemediationReportDialog.h
    src/dialogs/RemediationReportDialog.cpp
    src/dialogs/AiCleanupDialog.h
    src/dialogs/AiCleanupDialog.cpp
    src/dialogs/AttackTimelineWindow.h
    src/dialogs/AttackTimelineWindow.cpp
    src/dialogs/AttackGraphWindow.h
    src/dialogs/AttackGraphWindow.cpp
    src/dialogs/ProcessDetailDialog.h
    src/dialogs/ProcessDetailDialog.cpp
    src/dialogs/AttackChainDetailDialog.h
    src/dialogs/AttackChainDetailDialog.cpp
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

if(WIN32)
    # Bootstrap.cpp 用 ShellExecuteExW 提权拉起 bulwark_service.exe --bootstrap。
    # design/Theme.cpp 用 DwmSetWindowAttribute 设置深色标题栏与弹出层圆角。
    # design/FilePicker.cpp 直接用 IFileOpenDialog(COM)弹出列出隐藏项的原生选择框。
    target_link_libraries(bulwark_ui PRIVATE shell32 dwmapi ole32)
endif()

target_compile_features(bulwark_ui PRIVATE cxx_std_20)

if(MSVC)
    target_compile_options(bulwark_ui PRIVATE /W4 /permissive- /utf-8)
    target_compile_definitions(bulwark_ui PRIVATE UNICODE _UNICODE)
else()
    target_compile_options(bulwark_ui PRIVATE -Wall -Wextra)
endif()
