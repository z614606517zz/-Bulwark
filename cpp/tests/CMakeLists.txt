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
