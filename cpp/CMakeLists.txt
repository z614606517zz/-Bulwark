cmake_minimum_required(VERSION 3.21)

# Bulwark (磐垒主动防御) - C++/Qt rewrite.
# Top-level build. The shared library depends only on Qt6::Core so it can be
# reused by both the service (headless) and the UI (Qt Widgets/QML).
project(Bulwark LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# =============================================================================
#  编译 / 链接加固
# -----------------------------------------------------------------------------
#  在此之前这个文件里【没有任何】编译或链接选项,也就是说三个二进制完全跑在 MSVC 默认值上:
#  没有 Control Flow Guard、没有 CET 影子栈、没有 Spectre 缓解、警告级别也是默认的 /W1。
#  对一个以 SYSTEM 常驻、解析大量不可信输入(内核遥测、网络 JSON、注册表/文件路径、
#  服务器下发的规则包)的安全产品来说,缺 CFG 是最显眼的一处:它恰好是缓解「劫持间接调用」
#  这类利用的基础项,而本进程里到处是 std::function 回调与虚表(IpcServer 的请求回调、
#  EventSource 多态、Qt 的信号槽)。
#
#  这里只加【不改变程序语义、且不需要额外安装组件】的项:
#    /guard:cf     Control Flow Guard(编译 + 链接两侧都要给,少一侧就不生效)
#    /CETCOMPAT    标记支持硬件影子栈(在支持的 CPU 上生效,不支持则忽略)
#    /W4           把警告级别提到 4 —— 先看清楚有多少,再决定要不要 /WX
#    /permissive-  收紧到标准 C++(Qt 与本项目代码都已符合)
#
#  刻意【不加】/WX:现有代码在 /W4 下几乎必然有一批既有告警,一次性开成错误会把构建打死,
#  那属于单独一轮清理工作,不该混在安全修复里。
#
#  /Qspectre 做成【可选】而不是默认开:它要求 VS 安装器里单独勾选「缓解了 Spectre 漏洞的库」
#  组件,否则链接期直接 MSB8040 失败(本机实测)。默认开等于把「能不能编译」绑到一个容易漏装
#  的可选组件上 —— 那会让别人拉下代码就编不过,而收益是一个本进程并不特别暴露的侧信道
#  (它不做「用不可信索引读数组」这类可利用模式)。发布构建的机器上装好组件后用
#  -DBULWARK_ENABLE_SPECTRE=ON 打开。
# =============================================================================
option(BULWARK_ENABLE_SPECTRE
       "Add /Qspectre (requires the VS 'Spectre-mitigated libs' component)" OFF)
if(MSVC)
    add_compile_options(/W4 /permissive- /guard:cf /utf-8)
    add_link_options(/guard:cf /CETCOMPAT /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA)
    if(BULWARK_ENABLE_SPECTRE)
        add_compile_options(/Qspectre)
    endif()
endif()

# Only Core is needed for the shared contract layer. Later phases add:
#   Widgets (UI), Network (reputation HTTP clients).
find_package(Qt6 REQUIRED COMPONENTS Core)

add_subdirectory(shared)
add_subdirectory(service)   # phase B: daemon (IPC server, ETW source, storage)
add_subdirectory(ui)        # phase 7: Qt Widgets front-end (redesigned)

# 裁决快照测试 —— 「12 步决策管线的行为没被改坏」的唯一形式化判据:
# 一份固定语料(tests/data/corpus.json)+ 一份黄金裁决(tests/data/golden.json),
# 回放后逐字段比对。管线里任何一处改动只要改变了既有裁决,这条测试立刻变红。
# 见 tests/SnapshotTool.cpp 顶部说明。
enable_testing()
add_subdirectory(tests)
