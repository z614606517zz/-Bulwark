# bulwark_snapshot: 裁决快照工具 —— 决策管线的回归基准。
#
# 语料(corpus.json)与黄金裁决(golden.json)都进版本库,是「12 步决策管线当前行为」的
# 唯一形式化记录。改了管线之后若裁决发生变化,必须是有意的:先说清为什么,再用 --record 重录。
find_package(Qt6 REQUIRED COMPONENTS Core)

add_executable(bulwark_snapshot SnapshotTool.cpp)
target_link_libraries(bulwark_snapshot PRIVATE bulwark_shared Qt6::Core)
target_compile_features(bulwark_snapshot PRIVATE cxx_std_20)

if(MSVC)
    target_compile_options(bulwark_snapshot PRIVATE /W4 /permissive- /utf-8)
    target_compile_definitions(bulwark_snapshot PRIVATE UNICODE _UNICODE)
else()
    target_compile_options(bulwark_snapshot PRIVATE -Wall -Wextra)
endif()

# 语料与黄金文件放在源码树里(与测试代码同目录),便于 diff 审阅。
set(BLW_CORPUS "${CMAKE_CURRENT_SOURCE_DIR}/data/corpus.json")
set(BLW_GOLDEN "${CMAKE_CURRENT_SOURCE_DIR}/data/golden.json")

# 回归测试:重放语料,与黄金裁决逐字段比对。
add_test(NAME verdict_snapshot
         COMMAND bulwark_snapshot --verify "${BLW_CORPUS}" "${BLW_GOLDEN}")

# 内置规则集不变量:id 必须两两不同。loadRules 以 id 为 QHash 键,撞 id 会【静默丢规则】,
# 即检测能力凭空消失且无任何报错。见 SnapshotTool.cpp 的 checkRuleset()。
add_test(NAME builtin_ruleset_ids
         COMMAND bulwark_snapshot --check-ruleset)

# 攻击链组合引擎回归测试。
#
# 复用 bulwark_service 自己的 --attackchain-selftest 模式,而不新建一个测试可执行体:
# 测试骨架(装表 / 记账 / 命中 / 定档 / 可达性)本来就在引擎里,缺的只是「表从哪来」——
# 生产路径是从服务器现拉,那就不确定。本模式改成读固定语料,于是同一份输入永远得到同一份
# 结论。另建测试工程反而要把 ReputationCurl 这些网络依赖拖进来(AttackChainEngine 在
# bulwark_service 里,而 bulwark_snapshot 只链 bulwark_shared)。
#
# 该模式只读语料 + 用临时目录隔离状态:不联网、不碰 %ProgramData% 下的真实组合表缓存与
# 命中记录、不启动 ETW/驱动/IPC,因此在 CI 与装着运行中驱动的真机上都能安全执行。
set(BLW_CHAIN_TABLE "${CMAKE_CURRENT_SOURCE_DIR}/data/chain_table.json")
add_test(NAME attackchain_regression
         COMMAND bulwark_service --attackchain-selftest "${BLW_CHAIN_TABLE}")

# 运行期需要能找到 Qt6Core.dll。从 Qt6::Core 目标反推出它的 bin 目录,而不是写死路径。
get_target_property(_blw_qtcore_loc Qt6::Core LOCATION)
get_filename_component(_blw_qt_bin "${_blw_qtcore_loc}" DIRECTORY)

# QT_HASH_SEED=0:钉死 QHash/QSet 的迭代顺序。规则排序本身已是全序(RuleEngine 步骤 6 的
# 比较器末级按 id 定序),这里再钉一次是为了让其它容器遍历也稳定,消除最后一点抖动来源。
set_tests_properties(verdict_snapshot builtin_ruleset_ids PROPERTIES
    ENVIRONMENT "QT_HASH_SEED=0"
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${_blw_qt_bin}"
    LABELS "engine;snapshot")

# 攻击链测试同样钉死 QT_HASH_SEED:装载期的标记分桶与组合索引都走 QHash,而 Qt6 的 QHash
# 每进程随机化种子。测试自己也带一条「二次装载结论相同」的断言,两道一起用 —— 钉种子保证
# 本次运行稳定,那条断言保证逻辑不依赖遍历顺序(否则换台机器才炸)。
set_tests_properties(attackchain_regression PROPERTIES
    ENVIRONMENT "QT_HASH_SEED=0"
    ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${_blw_qt_bin}"
    LABELS "engine;attackchain")

# ============================================================================
# driver_match_unit: 内核驱动名单匹配核心的用户态单元测试
# ============================================================================
#
# 驱动【不能在开发机上加载】(内核回调出错直接蓝屏,加载验证只在带快照的测试 VM 里做),
# 所以在此之前,驱动侧匹配语义的改动只有「编译通过」这一级验证 —— 而项目里已有两次实测
# 事故正是出在这几个函数上(见 DriverMatchTest.c 头部)。
#
# Bulwark.Driver/MatchCore.c 里全是纯函数:不碰 g_Blw、不取锁、不依赖 IRQL,因此可以
# 在用户态原样编译。这里直接把那个 .c 拉进来,用 BLW_MATCHCORE_HOST 打开 MatchCore.h
# 的用户态垫片(垫片刻意不含 <windows.h>,避免引入 UNICODE_STRING 由谁定义之类的环境差异)。
#
# 刻意不链 Qt:本测试与引擎/规则无关,也就不会踩「运行前得把 Qt bin 加进 PATH」那个坑。
#
# 【为什么给这两个 .c 显式指定 LANGUAGE CXX】本工程的 project() 只声明了 CXX
# (cpp/CMakeLists.txt:6 `project(Bulwark LANGUAGES CXX)`),没有启用 C。若不指定,
# MSVC 生成器会把 .c 静默跳过 —— 表现是链接期报「找不到 main」,很难一眼看出原因。
# 在这里指定比去改顶层 project() 更克制:那会牵动整个工程重新配置。
# 代价仅是 MatchCore.c 在本测试里按 C++ 编译(内核侧仍是 C),而它本身是 C/C++ 双兼容的
# 纯 C 代码,判定逻辑逐字节相同。
#
# 往 MatchCore.c 里加东西时,必须同时在 DriverMatchTest.c 补上对应形态的断言。
set(BLW_DRIVER_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../Bulwark.Driver")

add_executable(driver_match_unit
    DriverMatchTest.c
    "${BLW_DRIVER_DIR}/MatchCore.c")
set_source_files_properties(
    DriverMatchTest.c "${BLW_DRIVER_DIR}/MatchCore.c"
    PROPERTIES LANGUAGE CXX)
target_include_directories(driver_match_unit PRIVATE "${BLW_DRIVER_DIR}")
target_compile_definitions(driver_match_unit PRIVATE BLW_MATCHCORE_HOST)
# 本测试不含任何 Qt 类型,关掉 autogen 省掉一个空的 mocs_compilation 编译单元。
set_target_properties(driver_match_unit PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)

if(MSVC)
    # 与驱动工程同样的 /W4 + warning-as-error:内核代码里的告警在用户态这一侧也别放过。
    target_compile_options(driver_match_unit PRIVATE /W4 /WX /utf-8)
else()
    target_compile_options(driver_match_unit PRIVATE -Wall -Wextra -Werror)
endif()

add_test(NAME driver_match_unit COMMAND driver_match_unit)
set_tests_properties(driver_match_unit PROPERTIES LABELS "driver;match")
