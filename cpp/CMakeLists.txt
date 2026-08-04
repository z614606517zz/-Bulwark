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
