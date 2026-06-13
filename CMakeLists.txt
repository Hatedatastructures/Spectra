cmake_minimum_required(VERSION 3.23)
project(Spectra LANGUAGES C CXX)

# CMake 4.0+ 将 CMP0167 行为改为 NEW（FindBoost 弃用），此处显式设置避免警告
if(POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Qt AUTOMOC/AUTORCC 必须在 add_subdirectory 之前全局开启
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

# 全局编译选项：允许成员变量名与类型名相同（Linux GCC 严格要求）
add_compile_options($<$<COMPILE_LANGUAGE:C,CXX>:-Wno-error=changes-meaning>)

# Release 模式优化：-O3 最大优化，-ffunction-sections/-fdata-sections 配合链接器 --gc-sections 裁剪未使用符号
# 仅对 C/CXX 生效，避免传给 NASM 汇编器导致编译失败
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(
        $<$<COMPILE_LANGUAGE:C,CXX>:-O3>
        $<$<COMPILE_LANGUAGE:C,CXX>:-ffunction-sections>
        $<$<COMPILE_LANGUAGE:C,CXX>:-fdata-sections>
    )
    add_link_options(-Wl,--gc-sections)
endif()

# === 所有依赖均通过 FetchContent 或本地查找自动解决 ===
include(FetchContent)

# --- spdlog v1.17.0 ---
# 日志库。含少量编译组件（rotating_file_sink、async_logger 等），源码量小，编译快。
set(SPDLOG_BUILD_EXAMPLE OFF CACHE BOOL "" FORCE)
set(SPDLOG_BUILD_TESTS OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    spdlog
    URL https://github.com/gabime/spdlog/archive/refs/tags/v1.17.0.tar.gz
    URL_HASH SHA256=d8862955c6d74e5846b3f580b1605d2428b11d97a410d86e2fb13e857cd3a744
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(spdlog)

# --- Boost 1.89.0 ---
# 仅使用 Boost.Asio（协程/异步 I/O）和 Boost.System（error_code），均为 header-only。
# 从 Boost 官方归档下载完整源码包，首次下载后 CMake 缓存复用。
FetchContent_Declare(
    boost_src
    URL https://archives.boost.io/release/1.89.0/source/boost_1_89_0.tar.bz2
    URL_HASH SHA256=85a33fa22621b4f314f8e85e1a5e2a9363d22e4f4992925d4bb3bc631b5a0c7a
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(boost_src)

# 创建 INTERFACE 库：仅传递头文件路径和编译宏，不产生编译产物
set(boost_include_dir "${boost_src_SOURCE_DIR}")
add_library(boost_system_header_only INTERFACE)
target_include_directories(boost_system_header_only INTERFACE ${boost_include_dir})
# BOOST_ERROR_CODE_HEADER_ONLY: boost::system::error_code 纯头文件实现
# BOOST_SYSTEM_NO_LIB: 禁止 CMake 自动链接 Boost.System 共享库
target_compile_definitions(boost_system_header_only INTERFACE BOOST_ERROR_CODE_HEADER_ONLY BOOST_SYSTEM_NO_LIB)
add_library(Boost::system ALIAS boost_system_header_only)

# --- glaze v6.5.1 ---
# 高性能 JSON 序列化库，纯 header-only。用于 config 序列化和数据交换。
set(GLAZE_INSTALL OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    glaze
    URL https://github.com/stephenberry/glaze/archive/refs/tags/v6.5.1.tar.gz
    URL_HASH SHA256=90303d360752bbac0a71c929fd4ba141892567a6dd10ecb3f27eb27779413662
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(glaze)

# --- SQLite3 amalgamation ---
# 嵌入式数据库，用于设备扫描结果、流量日志、告警记录的本地持久化。
# 使用 amalgamation（合并源文件）方式集成，编译为静态库。
FetchContent_Declare(
    sqlite3_src
    URL https://www.sqlite.org/2026/sqlite-amalgamation-3530100.zip
    URL_HASH SHA256=36ad6e7f38540a3b21a2ac36340833f0a9e426bc1c752751c3ba669466827eae
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(sqlite3_src)

# --- Npcap SDK ---
# Windows 抓包驱动 Npcap 的开发包。提供 pcap.h 头文件和 wpcap.lib/Packet.lib 导入库。
# 安装 Npcap 运行时后，wpcap.dll/Packet.dll 在 C:/Windows/System32/Npcap/ 下。
# SDK 通过 FetchContent 拉取，无需编译，仅使用其头文件和导入库。
if(WIN32)
    FetchContent_Declare(
        npcap_sdk
        URL https://npcap.com/dist/npcap-sdk-1.13.zip
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    FetchContent_MakeAvailable(npcap_sdk)

    set(NPCAP_INCLUDE_DIR "${npcap_sdk_SOURCE_DIR}/Include")
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(NPCAP_LIB_DIR "${npcap_sdk_SOURCE_DIR}/Lib/x64")
    else()
        set(NPCAP_LIB_DIR "${npcap_sdk_SOURCE_DIR}/Lib")
    endif()
endif()

# SQLite3 静态库（amalgamation 编译）
add_library(sqlite3_static STATIC ${sqlite3_src_SOURCE_DIR}/sqlite3.c)
target_include_directories(sqlite3_static PUBLIC ${sqlite3_src_SOURCE_DIR})
# SQLITE_THREADSAFE=1: 启用多线程安全（序列化模式）
# SQLITE_ENABLE_COLUMN_METADATA: 启用列元数据 API
target_compile_definitions(sqlite3_static PRIVATE
    SQLITE_THREADSAFE=1
    SQLITE_ENABLE_COLUMN_METADATA
)
find_package(Threads REQUIRED)
target_link_libraries(sqlite3_static PUBLIC Threads::Threads)

# --- Qt 6 ---
# GUI 框架，使用 Quick/QML 声明式界面。
# 通过 aqtinstall 自动安装到 C:/Qt/6.8.3/mingw_64。
# 暂时禁用 Qt — 仅使用 CLI + TUI，避免 Qt6::Quick 拉入 4GB+ 内存
# if(WIN32)
#     list(APPEND CMAKE_PREFIX_PATH "C:/Qt/6.8.3/mingw_64")
# endif()
# find_package(Qt6 COMPONENTS Core Gui Quick)

# === TUI 依赖：cpp-terminal + cmark-gfm ===
# 下载阶段使用 7890 代理，下载完成后恢复
set(_saved_http_proxy "$ENV{http_proxy}")
set(_saved_https_proxy "$ENV{https_proxy}")
set(ENV{http_proxy} "http://127.0.0.1:7890")
set(ENV{https_proxy} "http://127.0.0.1:7890")

# --- cpp-terminal ---
# 轻量 C++ 终端库，替代 FTXUI。提供 Term::Window cell buffer、事件处理、TrueColor。
FetchContent_Declare(
    cpp_terminal
    GIT_REPOSITORY https://github.com/jupyter-xeus/cpp-terminal.git
    GIT_TAG        master
    GIT_SHALLOW    TRUE
)
set(CPPTERMINAL_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(CPPTERMINAL_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(CPPTERMINAL_ENABLE_DOCS OFF CACHE BOOL "" FORCE)
set(CPPTERMINAL_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(cpp_terminal)

# CJK 宽字符补丁：cmake reconfigure 后自动应用
# 覆盖 window.cpp 使 render() 跳过宽字符的第二个 cell，避免中文显示乱码
set(_CJK_WINDOW    "${cpp_terminal_SOURCE_DIR}/cpp-terminal/window.cpp")
set(_CJK_MARKER    "${CMAKE_BINARY_DIR}/cpp-terminal-cjk-patched")
add_custom_command(
    OUTPUT "${_CJK_MARKER}"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${CMAKE_SOURCE_DIR}/patches/window.cpp.cjk"
                "${_CJK_WINDOW}"
    COMMAND ${CMAKE_COMMAND} -E touch "${_CJK_MARKER}"
    DEPENDS "${CMAKE_SOURCE_DIR}/patches/window.cpp.cjk"
    COMMENT "Applying CJK wide character patch to cpp-terminal"
)
add_custom_target(cpp-terminal-cjk-patch DEPENDS "${_CJK_MARKER}")
add_dependencies(cpp-terminal cpp-terminal-cjk-patch)

# --- cmark-gfm 0.29.0.gfm.13 ---
# GitHub 使用 的 C 语言 Markdown 解析器（GFM 扩展）
set(CMARK_TESTS OFF CACHE BOOL "" FORCE)
set(CMARK_STATIC ON CACHE BOOL "" FORCE)
set(CMARK_SHARED OFF CACHE BOOL "" FORCE)
# cmark-gfm 旧版 CMakeLists 兼容性
set(CMAKE_POLICY_VERSION_MINIMUM 3.5 CACHE STRING "" FORCE)
FetchContent_Declare(
    cmark_gfm
    GIT_REPOSITORY https://github.com/github/cmark-gfm.git
    GIT_TAG        0.29.0.gfm.13
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(cmark_gfm)
unset(CMAKE_POLICY_VERSION_MINIMUM CACHE)

set(ENV{http_proxy} "${_saved_http_proxy}")
set(ENV{https_proxy} "${_saved_https_proxy}")

enable_testing()

add_subdirectory(src)
add_subdirectory(tests)
