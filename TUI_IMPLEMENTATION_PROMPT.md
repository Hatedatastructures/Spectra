# Spectra TUI 实现任务书

你将负责为 Spectra 项目（`I:\code\Spectra`）实现一个类 Claude Code 风格的终端用户界面（TUI），替换现有的朴素 `std::getline` CLI 交互。这个 TUI 必须具备：现代终端 UI 外观、Markdown 渲染、AI 对话能力（远程 API 流式 + 本地 ONNX 推理双模式），以及所有现有 CLI 命令的 TUI 化。

## 1. 项目背景

### 1.1 Spectra 是什么

Spectra 是 C++23 局域网安全态势感知平台，结合 Wireshark + Nmap + Snort + Cuckoo 的功能。纯协程架构 + PMR 内存管理，分为五层：Presentation(GUI/CLI) → Analysis(scanner/decoder/detector/sandbox) → Engine(协程网络引擎) → Transport(raw socket/pcap) → Data(SQLite)。

### 1.2 当前 CLI 实现

当前 CLI 位于 `src/sec/cli/application.cpp`（982 行），使用 `std::getline` + ANSI 转义码实现了一个朴素的交互式命令行。它通过 `co_spawn` + `promise/future` 模式桥接异步协程和同步 CLI。

### 1.3 目标

实现一个 FTXUI 驱动的 TUI，风格类似 Claude Code 的终端界面：
- 上方为 AI 对话区（Markdown 渲染，支持流式输出）
- 下方为命令输入区（支持命令补全、历史记录）
- 左侧可折叠侧边栏（设备列表/告警/扫描状态）
- 所有现有 10 个命令的 TUI 可视化版本
- AI 远程 API（OpenAI 兼容）流式对话 + 本地 ONNX 推理双模式

---

## 2. 技术栈

| 库 | 版本 | 用途 | 集成方式 |
|---|---|---|---|
| **FTXUI** | 最新 master | TUI 框架（组件/布局/事件） | FetchContent |
| **cmark-gfm** | 最新 release | Markdown → AST 解析 | FetchContent |
| **Boost.Beast** | 1.89.0（已包含在 Boost 中） | HTTP 客户端（AI API SSE 流式） | 已有 Boost 依赖 |
| **Boost.Asio** | 1.89.0（已包含） | 协程/异步 I/O | 已有依赖 |

**关键决策说明：**
- FTXUI 是 C++ 中唯一仍在活跃维护、支持组件化布局、自适应终端尺寸、支持鼠标的 TUI 框架
- cmark-gfm 是 GitHub 使用的 C 语言 Markdown 解析器，我们用它解析 Markdown 为 AST，然后自行实现 AST→ANSI 彩色渲染（C++ 没有现成的 Markdown→终端渲染库，必须手写）
- Boost.Beast 已经包含在项目的 Boost 1.89.0 依赖中，无需额外引入

---

## 3. 文件结构

所有 TUI 代码放在 `src/sec/tui/` 目录下，头文件放在 `include/sec/tui/` 下。

```
include/sec/tui/
├── tui.hpp                  # 聚合头文件
├── application.hpp          # TUI 应用主类（替换 cli/application）
├── ai_chat.hpp              # AI 对话管理器（远程 API + 本地 ONNX 双模式）
├── markdown_renderer.hpp    # cmark AST → ANSI 彩色文本渲染器
├── command_registry.hpp     # 命令注册表（补全/分发/帮助）
└── components/              # FTXUI 组件
    ├── chat_panel.hpp       # 对话面板（消息列表 + 流式输出区）
    ├── input_bar.hpp        # 输入栏（补全 + 历史 + 多行）
    ├── sidebar.hpp          # 侧边栏（设备/告警/扫描标签页）
    ├── status_bar.hpp       # 底部状态栏（连接状态/扫描进度/AI 模式）
    ├── device_table.hpp     # 设备表格组件
    ├── alert_list.hpp       # 告警列表组件
    ├── scan_panel.hpp       # 扫描操作面板
    └── traffic_view.hpp     # 流量查看面板

src/sec/tui/
├── application.cpp          # TUI 应用主类实现
├── ai_chat.cpp              # AI 对话管理器实现
├── markdown_renderer.cpp    # Markdown 渲染器实现
├── command_registry.cpp     # 命令注册表实现
└── components/              # FTXUI 组件实现
    ├── chat_panel.cpp
    ├── input_bar.cpp
    ├── sidebar.cpp
    ├── status_bar.cpp
    ├── device_table.cpp
    ├── alert_list.cpp
    ├── scan_panel.cpp
    └── traffic_view.cpp
```

---

## 4. CMake 集成

### 4.1 根 CMakeLists.txt 添加 FetchContent

在 `I:\code\Spectra\CMakeLists.txt` 的 `add_subdirectory(src)` **之前**添加：

```cmake
# --- FTXUI ---
# 现代 C++ TUI 框架，支持组件化布局和自适应终端尺寸
FetchContent_Declare(
    ftxui
    GIT_REPOSITORY https://github.com/ArthurSonzogni/ftxui.git
    GIT_TAG        v6.1.2
)
FetchContent_MakeAvailable(ftxui)

# --- cmark-gfm ---
# GitHub 使用的 C 语言 Markdown 解析器（GFM 扩展）
FetchContent_Declare(
    cmark_gfm
    GIT_REPOSITORY https://github.com/github/cmark-gfm.git
    GIT_TAG        0.29.0.gfm.13
)
# cmark-gfm 使用 cmake，编译为静态库
set(CMARK_TESTS OFF CACHE BOOL "" FORCE)
set(CMARK_STATIC ON CACHE BOOL "" FORCE)
set(CMARK_SHARED OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(cmark_gfm)
```

**注意：** FTXUI 依赖已随 Boost 1.89.0 一起满足（FTXUI 内部也用信号处理等标准库，不依赖额外第三方库）。cmark-gfm 是纯 C 库，编译为 `libcmark-gfm_static.a`,项目全部为云端拉取

### 4.2 src/sec/tui/CMakeLists.txt

新建文件 `src/sec/tui/CMakeLists.txt`：

```cmake
target_sources(${PROJECT_NAME}_static_library
    PUBLIC FILE_SET public_headers TYPE HEADERS
    BASE_DIRS ${PROJECT_SOURCE_DIR}/include
    FILES
        ${PROJECT_SOURCE_DIR}/include/sec/tui/tui.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/tui/application.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/tui/ai_chat.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/tui/markdown_renderer.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/tui/command_registry.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/tui/components/chat_panel.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/tui/components/input_bar.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/tui/components/sidebar.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/tui/components/status_bar.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/tui/components/device_table.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/tui/components/alert_list.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/tui/components/scan_panel.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/tui/components/traffic_view.hpp
    PRIVATE
        application.cpp
        ai_chat.cpp
        markdown_renderer.cpp
        command_registry.cpp
        components/chat_panel.cpp
        components/input_bar.cpp
        components/sidebar.cpp
        components/status_bar.cpp
        components/device_table.cpp
        components/alert_list.cpp
        components/scan_panel.cpp
        components/traffic_view.cpp
)

target_link_libraries(${PROJECT_NAME}_static_library
    PUBLIC
        ftxui::screen
        ftxui::dom
        ftxui::component
        cmark-gfm_static
)
```

### 4.3 src/sec/CMakeLists.txt 修改

在 `I:\code\Spectra\src\sec\CMakeLists.txt` 末尾添加：

```cmake
add_subdirectory(tui)
```

### 4.4 入口切换

修改 `src/main.cpp`，通过命令行参数 `--tui` / `--cli` 选择模式，默认 TUI：

```cpp
#include <sec/config.hpp>
#include <sec/cli/application.hpp>
#include <sec/tui/application.hpp>
#include <iostream>
#include <string_view>

auto main(int argc, char *argv[]) -> int
{
    sec::config cfg;

    // 检查是否使用传统 CLI 模式
    auto use_cli = false;
    for (auto i = 1; i < argc; ++i)
    {
        if (std::string_view{argv[i]} == "--cli")
        {
            use_cli = true;
            break;
        }
    }

    try
    {
        if (use_cli)
        {
            sec::cli::application app{cfg};
            return app.run(argc, argv);
        }
        else
        {
            sec::tui::application app{cfg};
            return app.run(argc, argv);
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "Fatal: " << e.what() << "\n";
        return 1;
    }
}
```

**注意：** 原有 `cli/application.hpp` 和 `cli/application.cpp` 保持不动，不删除。新 TUI 与旧 CLI 并存。

---

## 5. 核心类设计

### 5.1 tui::application（主应用类）

**文件：** `include/sec/tui/application.hpp`

```cpp
#pragma once

#include <sec/config.hpp>
#include <sec/engine/context.hpp>
#include <sec/scanner/arp_scanner.hpp>
#include <sec/scanner/mdns_scanner.hpp>
#include <sec/scanner/port_scanner.hpp>
#include <sec/scanner/ssdp_scanner.hpp>
#include <sec/decoder/pipeline.hpp>
#include <sec/detector/detection_pipeline.hpp>
#include <sec/mitm/pipeline.hpp>
#include <sec/store/database.hpp>
#include <sec/store/migration.hpp>
#include <sec/store/query.hpp>
#include <sec/store/persist.hpp>

#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>

#include <atomic>
#include <memory>
#include <string>
#include <thread>

namespace sec::tui
{
    // 前向声明
    class ai_chat;
    class command_registry;

    namespace components
    {
        class chat_panel;
        class input_bar;
        class sidebar;
        class status_bar;
    }

    class application
    {
    public:
        explicit application(const sec::config &cfg);
        ~application() noexcept;

        [[nodiscard]] auto run(int argc, char *argv[]) -> int;

        // 供组件回调使用
        auto context() noexcept -> engine::context & { return context_; }
        auto config() const noexcept -> const sec::config & { return config_; }

        // 子系统访问
        auto arp() noexcept -> scanner::arp_scanner & { return arp_; }
        auto mdns() noexcept -> scanner::mdns_scanner & { return mdns_; }
        auto ssdp() noexcept -> scanner::ssdp_scanner & { return ssdp_; }
        auto port() noexcept -> scanner::port_scanner & { return port_; }
        auto database() noexcept -> store::database & { return *db_; }
        auto device_query() noexcept -> store::device_query & { return *device_q_; }
        auto scan_query() noexcept -> store::scan_query & { return *scan_q_; }
        auto traffic_query() noexcept -> store::traffic_query & { return *traffic_q_; }
        auto alert_query() noexcept -> store::alert_query & { return *alert_q_; }
        auto persister() noexcept -> store::scan_persister & { return *persister_; }
        auto decoder() noexcept -> decoder::pipeline & { return decoder_; }
        auto detection() noexcept -> detector::detection_pipeline & { return *detection_; }
        auto chat() noexcept -> ai_chat & { return *chat_; }
        auto registry() noexcept -> command_registry & { return *registry_; }

        auto running() const noexcept -> bool { return running_; }
        auto request_stop() -> void { running_ = false; }

    private:
        auto start_background_thread() -> void;
        auto stop_background_thread() -> void;
        auto build_ui() -> ftxui::Component;

        sec::config config_;
        engine::context context_;

        std::unique_ptr<store::database> db_;
        std::unique_ptr<store::device_query> device_q_;
        std::unique_ptr<store::scan_query> scan_q_;
        std::unique_ptr<store::traffic_query> traffic_q_;
        std::unique_ptr<store::alert_query> alert_q_;
        std::unique_ptr<store::scan_persister> persister_;

        decoder::pipeline decoder_;
        std::unique_ptr<detector::detection_pipeline> detection_;
        std::unique_ptr<mitm::mitm_pipeline> mitm_;

        scanner::arp_scanner arp_;
        scanner::mdns_scanner mdns_;
        scanner::ssdp_scanner ssdp_;
        scanner::port_scanner port_;

        std::unique_ptr<ai_chat> chat_;
        std::unique_ptr<command_registry> registry_;

        // UI 组件
        std::shared_ptr<components::chat_panel> chat_panel_;
        std::shared_ptr<components::input_bar> input_bar_;
        std::shared_ptr<components::sidebar> sidebar_;
        std::shared_ptr<components::status_bar> status_bar_;

        ftxui::ScreenInteractive screen_{ftxui::ScreenInteractive::Fullscreen()};
        std::thread bg_thread_;
        std::atomic<bool> running_{false};
        std::optional<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>> work_guard_;
    };
}
```

**关键点：**
- `tui::application` 持有与 `cli::application` 完全相同的子系统成员（db、queries、scanners 等），因为它们都需要相同的初始化
- 构造函数执行相同的初始化流程：创建 db → migration → queries → persister → detection → mitm
- `run()` 方法创建 FTXUI 的 `ScreenInteractive::Fullscreen()`，构建组件树，然后进入 `screen.Loop()`
- 后台线程运行 `io_context` 事件循环（与 CLI 版相同）
- `build_ui()` 构建完整的 FTXUI 组件树

**构造函数实现**（`application.cpp`）必须复制 `cli/application.cpp:94-119` 的完整初始化逻辑：

```cpp
application::application(const sec::config &cfg)
    : config_{cfg}
    , context_{cfg}
    , arp_{context_}
    , mdns_{context_}
    , ssdp_{context_}
    , port_{context_}
{
    db_ = std::make_unique<store::database>(cfg.store.database_path);
    auto ec = std::error_code{};
    store::migration_manager migration{*db_};
    if (!migration.migrate(ec))
    {
        throw std::system_error(ec);
    }
    device_q_ = std::make_unique<store::device_query>(*db_);
    scan_q_ = std::make_unique<store::scan_query>(*db_);
    traffic_q_ = std::make_unique<store::traffic_query>(*db_);
    alert_q_ = std::make_unique<store::alert_query>(*db_);
    persister_ = std::make_unique<store::scan_persister>(*db_);
    detection_ = std::make_unique<detector::detection_pipeline>(decoder_);
    mitm_ = std::make_unique<mitm::mitm_pipeline>(decoder_, alert_q_.get());

    chat_ = std::make_unique<ai_chat>(cfg.ai);
    registry_ = std::make_unique<command_registry>(*this);
}
```

**run() 方法**：

```cpp
auto application::run(int argc, char *argv[]) -> int
{
    start_background_thread();

    auto ui = build_ui();
    screen_.Loop(ui);

    stop_background_thread();
    return 0;
}
```

**build_ui() 布局**：

```cpp
auto application::build_ui() -> ftxui::Component
{
    // 创建组件
    chat_panel_ = std::make_shared<components::chat_panel>(*this);
    input_bar_ = std::make_shared<components::input_bar>(*this);
    sidebar_ = std::make_shared<components::sidebar>(*this);
    status_bar_ = std::make_shared<components::status_bar>(*this);

    // 主布局：左侧边栏 | 右侧(对话区 + 输入栏) + 底部状态栏
    auto main_content = ftxui::ResizableSplitLeft(
        sidebar_->render(),                          // 左侧边栏（可折叠）
        ftxui::vbox({
            chat_panel_->render() | ftxui::flex,     // 对话区（弹性填充）
            ftxui::separator(),                       // 分割线
            input_bar_->render(),                     // 输入栏
        }),
        sidebar_->width()                            // 初始宽度 30 字符
    );

    auto full_ui = ftxui::vbox({
        main_content | ftxui::flex,                   // 主内容（弹性填充）
        ftxui::separator(),                            // 分割线
        status_bar_->render(),                         // 底部状态栏
    });

    // 包装为 Modal 式组件，处理全局快捷键
    return ftxui::Modal(full_ui, /* modal */ ftxui::Make::Empty());
}
```

### 5.2 ai_chat（AI 对话管理器）

**文件：** `include/sec/tui/ai_chat.hpp`

双模式 AI 对话：远程 API 流式 + 本地 ONNX 推理。

```cpp
#pragma once

#include <sec/config.hpp>
#include <sec/ai/feature.hpp>
#include <sec/ai/model.hpp>
#include <sec/ai/runtime.hpp>
#include <sec/decoder/frame.hpp>

#include <boost/asio.hpp>

#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <vector>

namespace sec::tui
{
    /**
     * @brief AI 模式
     */
    enum class ai_mode
    {
        /** @brief 禁用 */
        off,
        /** @brief 本地 ONNX 推理 */
        local,
        /** @brief 远程 API 流式 */
        remote
    };

    /**
     * @brief 对话消息
     */
    struct chat_message
    {
        enum role : std::uint8_t
        {
            user,
            assistant,
            system
        };

        role who;
        std::string content;
        /** @brief 是否正在流式接收中 */
        bool streaming{false};
        /** @brief 时间戳 */
        std::chrono::steady_clock::time_point timestamp{std::chrono::steady_clock::now()};
    };

    /**
     * @brief 远程 API 配置（OpenAI 兼容接口）
     */
    struct remote_config
    {
        std::string endpoint{"https://api.openai.com/v1/chat/completions"};
        std::string api_key;
        std::string model{"gpt-4o"};
        std::uint16_t max_tokens{4096};
        float temperature{0.7f};
    };

    class ai_chat
    {
    public:
        explicit ai_chat(const sec::ai_config &ai_cfg);

        ~ai_chat();

        /**
         * @brief 设置远程 API 配置
         */
        auto set_remote(const remote_config &cfg) -> void;

        /**
         * @brief 切换 AI 模式
         */
        auto set_mode(ai_mode mode) -> void;

        /**
         * @brief 获取当前模式
         */
        [[nodiscard]] auto mode() const noexcept -> ai_mode;

        /**
         * @brief 发送用户消息并获取回复
         * @param text 用户输入文本
         * @param on_chunk 流式回调（每个文本片段触发一次）
         * @param on_done 完成回调
         * @note 远程模式下 on_chunk 会多次调用（流式），本地模式下 on_done 一次性返回
         */
        auto send(const std::string &text,
                  std::function<void(std::string_view)> on_chunk,
                  std::function<void()> on_done) -> void;

        /**
         * @brief 中止当前生成
         */
        auto abort() -> void;

        /**
         * @brief 获取对话历史
         */
        [[nodiscard]] auto history() const -> const std::vector<chat_message> &;

        /**
         * @brief 清空对话历史
         */
        auto clear_history() -> void;

        /**
         * @brief 注入系统提示词
         */
        auto set_system_prompt(std::string prompt) -> void;

        /**
         * @brief 注入数据包信息到本地 ONNX 推理
         */
        auto observe_packet(const decoder::packet_info &frame) -> void;

        /**
         * @brief 是否正在生成中
         */
        [[nodiscard]] auto is_generating() const noexcept -> bool;

        /**
         * @brief 加载本地 ONNX 模型
         */
        [[nodiscard]] auto load_local_model() -> bool;

    private:
        auto do_local_inference(const std::string &text,
                                std::function<void(std::string_view)> on_chunk,
                                std::function<void()> on_done) -> void;

        auto do_remote_request(const std::string &text,
                               std::function<void(std::string_view)> on_chunk,
                               std::function<void()> on_done) -> void;

        // SSE 流式解析
        auto parse_sse_chunk(std::string_view data,
                             std::function<void(std::string_view)> on_chunk) -> bool;

        sec::ai_config ai_cfg_;
        remote_config remote_cfg_;
        ai_mode mode_{ai_mode::off};

        std::string system_prompt_;
        std::vector<chat_message> history_;

        // 本地推理
        std::unique_ptr<sec::ai::anomaly_model> local_model_;
        sec::ai::feature_extractor extractor_;

        // 远程推理
        boost::asio::io_context remote_ioc_;
        std::optional<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>> remote_work_;
        std::thread remote_thread_;

        std::atomic<bool> generating_{false};
        std::atomic<bool> abort_flag_{false};
        mutable std::mutex history_mutex_;
    };
}
```

**关键实现细节：**

#### 5.2.1 本地 ONNX 推理（`do_local_inference`）

```cpp
auto ai_chat::do_local_inference(const std::string &text,
                                  std::function<void(std::string_view)> on_chunk,
                                  std::function<void()> on_done) -> void
{
    // 1. 从特征提取器获取所有被跟踪的 IP
    auto tracked = extractor_.tracked_ips();

    // 2. 对每个 IP 执行推理，收集异常分数
    auto findings = std::vector<std::string>{};
    for (auto ip : tracked)
    {
        auto result = local_model_->detect(ip);
        if (result)
        {
            auto score = /* 从 alert 获取分数 */;
            findings.push_back(fmt::format("IP {} 异常分数: {:.2f} — {}",
                sec::decoder::ip_to_string(ip), score, result->description));
        }
    }

    // 3. 生成 Markdown 格式的回复
    auto reply = std::string{"## 本地安全分析结果\n\n"};
    if (findings.empty())
    {
        reply += "当前未检测到异常流量。所有被监控的 IP 行为正常。\n";
    }
    else
    {
        reply += fmt::format("发现 **{}** 个异常:\n\n", findings.size());
        for (const auto &f : findings)
        {
            reply += "- " + f + "\n";
        }
    }

    // 4. 统计信息
    reply += fmt::format("\n---\n监控 IP 数: {} | 特征窗口: {}秒",
        tracked.size(), ai_cfg_.feature_window_size);

    // 5. 一次性回调（本地推理无流式）
    on_chunk(reply);
    on_done();
}
```

#### 5.2.2 远程 API 流式请求（`do_remote_request`）

使用 Boost.Beast 的 HTTP 客户端进行 SSE 流式请求：

```cpp
auto ai_chat::do_remote_request(const std::string &text,
                                  std::function<void(std::string_view)> on_chunk,
                                  std::function<void()> on_done) -> void
{
    generating_ = true;

    // 在 remote_thread_ 上运行异步操作
    net::co_spawn(remote_ioc_,
        [this, text, on_chunk = std::move(on_chunk), on_done = std::move(on_done)]()
        -> net::awaitable<void>
        {
            namespace beast = boost::beast;
            namespace http = beast::http;

            try
            {
                // 1. 解析 endpoint URL → host + port + path
                auto url = parse_url(remote_cfg_.endpoint);
                auto resolver = net::use_awaitable_t::as_default_on(
                    beast::tcp_stream{co_await net::this_coro::executor});
                auto const results = co_await resolver.async_resolve(url.host, url.port);

                // 2. TCP 连接
                beast::tcp_stream stream{co_await net::this_coro::executor};
                stream.expires_after(std::chrono::seconds(30));
                co_await stream.async_connect(results);

                // 3. 构造 OpenAI 兼容请求 JSON
                // {"model":"gpt-4o","stream":true,"messages":[{"role":"system",...},{"role":"user",...}]}
                auto body = build_request_json(text);

                http::request<http::string_body> req{http::verb::post, url.path, 11};
                req.set(http::field::host, url.host);
                req.set(http::field::authorization, "Bearer " + remote_cfg_.api_key);
                req.set(http::field::content_type, "application/json");
                req.body() = body;
                req.prepare_payload();

                co_await http::async_write(stream, req);

                // 4. 流式读取 SSE 响应
                beast::flat_buffer buffer;
                auto response_text = std::string{};

                // 使用 beast::read_some 或逐块读取
                // SSE 格式: "data: {...}\n\n" 每行一个 JSON chunk
                while (!abort_flag_)
                {
                    http::response<http::string_body> res;
                    // 使用动态读取或 parser 逐块读
                    // ...

                    // 5. 解析 SSE chunk → 提取 content delta
                    // JSON: {"choices":[{"delta":{"content":"Hello"}}]}
                    if (parse_sse_chunk(/* chunk data */, on_chunk))
                    {
                        break; // [DONE]
                    }
                }

                // 6. 完成
                on_done();
            }
            catch (const std::exception &e)
            {
                on_chunk(fmt::format("**Error:** {}", e.what()));
                on_done();
            }

            generating_ = false;
        },
        net::detached);
}
```

**SSE 解析器**：
```cpp
auto ai_chat::parse_sse_chunk(std::string_view data,
                                std::function<void(std::string_view)> on_chunk) -> bool
{
    // SSE 行格式: "data: {json}\n" 或 "data: [DONE]\n"
    // 每个消息之间用空行 "\n\n" 分隔

    if (data == "[DONE]")
    {
        return true; // 流结束
    }

    // 用 glaze 解析 JSON（项目已依赖 glaze）
    // 提取 choices[0].delta.content 字段
    // ...

    on_chunk(content_delta);
    return false;
}
```

**请求 JSON 构造**（使用 glaze）：
```cpp
auto ai_chat::build_request_json(const std::string &user_text) const -> std::string
{
    // 使用 glaze 构建 JSON，格式：
    // {
    //   "model": "gpt-4o",
    //   "stream": true,
    //   "max_tokens": 4096,
    //   "temperature": 0.7,
    //   "messages": [
    //     {"role": "system", "content": "...系统提示词..."},
    //     {"role": "user", "content": "...历史消息1..."},
    //     {"role": "assistant", "content": "...历史回复1..."},
    //     ...
    //     {"role": "user", "content": "...当前消息..."}
    //   ]
    // }
}
```

### 5.3 markdown_renderer（Markdown 渲染器）

**文件：** `include/sec/tui/markdown_renderer.hpp`

将 cmark-gfm AST 转换为 FTXUI 可显示的彩色文本元素。

```cpp
#pragma once

#include <ftxui/dom/elements.hpp>

#include <string>
#include <string_view>

namespace sec::tui
{
    /**
     * @brief Markdown → FTXUI Elements 渲染器
     * @details 使用 cmark-gfm 解析 Markdown 为 AST，
     * 然后遍历 AST 节点生成带样式的 FTXUI Elements。
     */
    class markdown_renderer
    {
    public:
        /**
         * @brief 将 Markdown 文本渲染为 FTXUI Element
         * @param markdown 输入的 Markdown 文本
         * @return 可显示的 FTXUI Element
         */
        [[nodiscard]] static auto render(std::string_view markdown) -> ftxui::Element;

    private:
        /**
         * @brief 递归遍历 cmark AST 节点，生成 Element
         * @param node cmark 节点指针
         * @return FTXUI Element
         */
        static auto render_node(void *node) -> ftxui::Element;

        /**
         * @brief 渲染行内节点（文本、代码、强调、链接等）
         * @param node cmark 行内节点
         * @return FTXUI Element 列表（可拼接）
         */
        static auto render_inline(void *node) -> ftxui::Element;

        /**
         * @brief 收集节点下的纯文本
         */
        static auto collect_text(void *node) -> std::string;

        /**
         * @brief ANSI 颜色常量
         */
        static auto heading_color(int level) -> ftxui::Color;
        static constexpr auto code_bg = ftxui::Color::RGB(40, 44, 52);    // One Dark 背景
        static constexpr auto code_fg = ftxui::Color::RGB(171, 178, 191); // One Dark 前景
        static constexpr auto link_color = ftxui::Color::RGB(86, 156, 214);   // VS Code 蓝
        static constexpr auto bold_color = ftxui::Color::White;
        static constexpr auto quote_border = ftxui::Color::RGB(106, 153, 85);  // VS Code 绿
    };
}
```

**cmark-gfm AST 遍历实现**（`markdown_renderer.cpp`）：

```cpp
#include <sec/tui/markdown_renderer.hpp>

// cmark-gfm C API
extern "C"
{
    #include <cmark-gfm.h>
    #include <cmark-gfm-core-extensions.h>
}

namespace sec::tui
{
    auto markdown_renderer::render(std::string_view markdown) -> ftxui::Element
    {
        // 1. 解析 Markdown → cmark AST
        auto *doc = cmark_parse_document(
            markdown.data(), markdown.size(),
            CMARK_OPT_DEFAULT | CMARK_OPT_UNSAFE);

        // 2. 递归渲染 AST 节点
        auto elements = std::vector<ftxui::Element>{};
        auto *iter = cmark_iter_new(doc);
        auto ev = CMARK_EVENT_NONE;

        while ((ev = cmark_iter_next(iter)) != CMARK_EVENT_DONE)
        {
            if (ev == CMARK_EVENT_ENTER)
            {
                auto *node = cmark_iter_get_node(iter);
                elements.push_back(render_node(node));
            }
        }

        cmark_iter_free(iter);
        cmark_node_free(doc);

        if (elements.empty())
        {
            return ftxui::text("");
        }

        return ftxui::vbox(std::move(elements));
    }

    auto markdown_renderer::render_node(void *node) -> ftxui::Element
    {
        auto *n = static_cast<cmark_node *>(node);
        auto type = cmark_node_get_type(n);

        switch (type)
        {
        case CMARK_NODE_HEADING:
        {
            auto level = cmark_node_get_heading_level(n);
            auto text = collect_text(n);
            auto color = heading_color(level);
            // 标题：粗体 + 彩色 + 下划线
            return ftxui::hbox({
                ftxui::text(std::string(level, '#') + " ") | ftxui::color(ftxui::Color::GrayDark),
                ftxui::text(text) | ftxui::bold | ftxui::color(color)
            });
        }

        case CMARK_NODE_PARAGRAPH:
        {
            auto text = collect_text(n);
            return ftxui::paragraph(text);
        }

        case CMARK_NODE_CODE_BLOCK:
        {
            auto code = cmark_node_get_literal(n);
            if (!code) code = "";
            // 代码块：背景色 + 等宽字体效果
            return ftxui::vbox({
                ftxui::separator(),
                ftxui::paragraph(code) | ftxui::bgcolor(code_bg) | ftxui::color(code_fg),
                ftxui::separator()
            });
        }

        case CMARK_NODE_CODE:
        {
            auto code = cmark_node_get_literal(n);
            if (!code) code = "";
            // 行内代码：背景色高亮
            return ftxui::text(code) | ftxui::bgcolor(code_bg) | ftxui::color(code_fg);
        }

        case CMARK_NODE_LIST:
        {
            auto items = std::vector<ftxui::Element>{};
            auto *child = cmark_node_first_child(n);
            auto idx = 0;
            auto list_type = cmark_node_get_list_type(n);
            while (child)
            {
                auto prefix = (list_type == CMARK_BULLET_LIST)
                    ? "  • "
                    : fmt::format("  {}. ", ++idx);
                items.push_back(ftxui::hbox({
                    ftxui::text(prefix) | ftxui::color(ftxui::Color::Cyan),
                    render_node(child)
                }));
                child = cmark_node_next(child);
            }
            return ftxui::vbox(std::move(items));
        }

        case CMARK_NODE_ITEM:
        {
            return render_node(cmark_node_first_child(n));
        }

        case CMARK_NODE_BLOCK_QUOTE:
        {
            auto text = collect_text(n);
            return ftxui::hbox({
                ftxui::text("│ ") | ftxui::color(quote_border) | ftxui::bold,
                ftxui::paragraph(text) | ftxui::color(quote_border)
            });
        }

        case CMARK_NODE_STRONG:
        {
            auto text = collect_text(n);
            return ftxui::text(text) | ftxui::bold | ftxui::color(bold_color);
        }

        case CMARK_NODE_EMPH:
        {
            auto text = collect_text(n);
            return ftxui::text(text) | ftxui::color(ftxui::Color::Yellow);
        }

        case CMARK_NODE_LINK:
        {
            auto text = collect_text(n);
            auto url = cmark_node_get_url(n);
            return ftxui::text(text) | ftxui::color(link_color) | ftxui::underlined;
        }

        case CMARK_NODE_THEMATIC_BREAK:
        {
            return ftxui::separator();
        }

        default:
        {
            auto text = collect_text(n);
            return text.empty() ? ftxui::text("") : ftxui::text(text);
        }
        }
    }

    auto markdown_renderer::heading_color(int level) -> ftxui::Color
    {
        switch (level)
        {
        case 1: return ftxui::Color::RGB(255, 121, 198);  // 粉红
        case 2: return ftxui::Color::RGB(139, 233, 253);  // 青色
        case 3: return ftxui::Color::RGB(241, 250, 140);  // 黄色
        default: return ftxui::Color::White;
        }
    }

    auto markdown_renderer::collect_text(void *node) -> std::string
    {
        auto *n = static_cast<cmark_node *>(node);
        // cmark_render_plaintext 可以提取纯文本
        auto *text = cmark_render_plaintext(n, CMARK_OPT_DEFAULT, 0);
        std::string result{text};
        free(text);
        // 去掉末尾换行
        while (!result.empty() && result.back() == '\n')
        {
            result.pop_back();
        }
        return result;
    }
}
```

### 5.4 command_registry（命令注册表）

**文件：** `include/sec/tui/command_registry.hpp`

```cpp
#pragma once

#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace sec::tui
{
    class application;

    /**
     * @brief 命令描述
     */
    struct command_entry
    {
        /** @brief 命令名称 */
        std::string name;
        /** @brief 参数格式 */
        std::string usage;
        /** @brief 简短描述 */
        std::string description;
        /** @brief 执行回调，返回输出文本 */
        std::function<std::string(const std::vector<std::string> &)> execute;
    };

    /**
     * @brief 命令注册表
     * @details 管理所有可用命令，提供补全和分发。
     */
    class command_registry
    {
    public:
        explicit command_registry(application &app);

        /**
         * @brief 分发命令
         * @param input 用户输入（命令 + 参数）
         * @return 命令输出文本（可以是 Markdown 格式）
         */
        [[nodiscard]] auto dispatch(const std::string &input) -> std::string;

        /**
         * @brief 命令补全
         * @param partial 部分输入
         * @return 匹配的候选列表
         */
        [[nodiscard]] auto complete(std::string_view partial) const -> std::vector<std::string>;

        /**
         * @brief 获取所有命令（帮助面板用）
         */
        [[nodiscard]] auto commands() const -> const std::vector<command_entry> &;

    private:
        auto register_builtin_commands() -> void;

        application &app_;
        std::vector<command_entry> entries_;
    };
}
```

**命令注册实现**（`command_registry.cpp`）：

每个命令的 `execute` 回调内部使用与 `cli/application.cpp` 相同的 `co_spawn` + `promise/future` 模式桥接异步操作。但输出不再是 `std::cout`，而是构建 Markdown 格式的字符串返回值。

```cpp
#include <sec/tui/command_registry.hpp>
#include <sec/tui/application.hpp>
#include <sec/scanner/fingerprint.hpp>
#include <sec/decoder/frame.hpp>

#include <boost/asio.hpp>
#include <spdlog/spdlog.h>

#include <future>
#include <iomanip>
#include <sstream>

namespace sec::tui
{
    command_registry::command_registry(application &app)
        : app_{app}
    {
        register_builtin_commands();
    }

    auto command_registry::register_builtin_commands() -> void
    {
        // === 1. ARP 扫描 ===
        entries_.push_back({
            "arp",
            "arp <subnet>",
            "ARP 扫描子网（如 192.168.1.0/24）",
            [this](const std::vector<std::string> &args) -> std::string
            {
                if (args.size() < 2) return "**用法:** `arp <subnet>`\n例如: `arp 192.168.1.0/24`";

                auto subnet = args[1];
                auto promise = std::make_shared<std::promise<std::vector<scanner::device>>>();
                auto future = promise->get_future();

                namespace net = boost::asio;
                net::co_spawn(
                    app_.context().executor(),
                    [this, subnet_str = subnet, promise]() -> net::awaitable<void>
                    {
                        try
                        {
                            auto ec = std::error_code{};
                            auto devices = co_await app_.arp().scan_subnet(subnet_str, ec);
                            if (ec)
                            {
                                spdlog::error("ARP scan error: {}", ec.message());
                            }
                            promise->set_value(std::move(devices));
                        }
                        catch (const std::exception &e)
                        {
                            spdlog::error("ARP scan exception: {}", e.what());
                            promise->set_value({});
                        }
                    },
                    net::detached);

                auto devices = future.get();
                for (auto &dev : devices)
                {
                    scanner::fingerprint::identify(dev);
                }
                // 持久化（与 CLI 版相同逻辑）
                // ...

                if (devices.empty())
                {
                    return "未发现设备。";
                }

                // 生成 Markdown 表格
                auto ss = std::stringstream{};
                ss << "## ARP 扫描结果 — " << subnet << "\n\n";
                ss << "发现 **" << devices.size() << "** 台设备:\n\n";
                ss << "| IP | MAC | 主机名 | 厂商 | OS | 网关 |\n";
                ss << "|---|---|---|---|---|---|\n";
                for (const auto &dev : devices)
                {
                    ss << "| " << dev.ip_address
                       << " | " << std::string{dev.mac_address}
                       << " | " << (dev.hostname.empty() ? "-" : std::string{dev.hostname})
                       << " | " << (dev.vendor.empty() ? "-" : std::string{dev.vendor})
                       << " | " << (dev.os_guess.empty() ? "-" : std::string{dev.os_guess})
                       << " | " << (dev.is_gateway ? "✓" : "-")
                       << " |\n";
                }
                return ss.str();
            }
        });

        // === 2. mDNS 扫描 ===
        entries_.push_back({
            "mdns", "mdns", "通过 mDNS 发现设备",
            [this](const std::vector<std::string> &) -> std::string
            {
                // 与 cli 版 cmd_scan_mdns() 相同的 co_spawn 模式
                // 输出改为 Markdown
                // ...
            }
        });

        // === 3. SSDP 扫描 ===
        entries_.push_back({
            "ssdp", "ssdp", "通过 SSDP/UPnP 发现设备",
            [this](const std::vector<std::string> &) -> std::string
            {
                // 同上
                // ...
            }
        });

        // === 4. 端口扫描 ===
        entries_.push_back({
            "port", "port <ip> [range]", "TCP 端口扫描（默认 1-1024）",
            [this](const std::vector<std::string> &args) -> std::string
            {
                if (args.size() < 2) return "**用法:** `port <ip> [range]`";
                // ...
            }
        });

        // === 5. 设备列表 ===
        entries_.push_back({
            "devices", "devices", "列出所有已发现设备",
            [this](const std::vector<std::string> &) -> std::string
            {
                auto ec = std::error_code{};
                auto devices = app_.device_query().find_all(ec);
                if (ec) return fmt::format("**查询错误:** {}", ec.message());
                if (devices.empty()) return "尚未发现设备。请先运行 `arp <subnet>` 扫描。";

                auto ss = std::stringstream{};
                ss << "## 已发现设备 (" << devices.size() << ")\n\n";
                ss << "| ID | IP | MAC | 主机名 | 厂商 | OS | 最后发现 |\n";
                ss << "|---|---|---|---|---|---|---|\n";
                for (const auto &dev : devices)
                {
                    ss << "| " << dev.id
                       << " | " << dev.ip_address
                       << " | " << dev.mac_address
                       << " | " << (dev.hostname.empty() ? "-" : dev.hostname)
                       << " | " << (dev.vendor.empty() ? "-" : dev.vendor)
                       << " | " << (dev.os_guess.empty() ? "-" : dev.os_guess)
                       << " | " << format_time(dev.last_seen)
                       << " |\n";
                }
                return ss.str();
            }
        });

        // === 6. 设备详情 ===
        entries_.push_back({
            "device", "device <ip>", "查看设备详情",
            [this](const std::vector<std::string> &args) -> std::string
            {
                if (args.size() < 2) return "**用法:** `device <ip>`";
                auto ec = std::error_code{};
                auto dev = app_.device_query().find_by_ip(args[1], ec);
                if (ec) return fmt::format("**查询错误:** {}", ec.message());
                if (!dev) return fmt::format("未找到设备: `{}`", args[1]);

                return fmt::format(
                    "## 设备详情: {}\n\n"
                    "- **IP:** {}\n"
                    "- **MAC:** {}\n"
                    "- **主机名:** {}\n"
                    "- **厂商:** {}\n"
                    "- **OS:** {}\n"
                    "- **开放端口:** {}\n"
                    "- **网关:** {}\n"
                    "- **首次发现:** {}\n"
                    "- **最后发现:** {}",
                    dev->ip_address, dev->ip_address, dev->mac_address,
                    dev->hostname.empty() ? "-" : dev->hostname,
                    dev->vendor.empty() ? "-" : dev->vendor,
                    dev->os_guess.empty() ? "-" : dev->os_guess,
                    dev->open_ports == "[]" ? "无" : dev->open_ports,
                    dev->is_gateway ? "是" : "否",
                    format_time(dev->first_seen),
                    format_time(dev->last_seen));
            }
        });

        // === 7. 告警列表 ===
        entries_.push_back({
            "alerts", "alerts", "查看未确认告警",
            [this](const std::vector<std::string> &) -> std::string
            {
                // ...
            }
        });

        // === 8. 确认告警 ===
        entries_.push_back({
            "ack", "ack <id>", "确认告警",
            [this](const std::vector<std::string> &args) -> std::string
            {
                // ...
            }
        });

        // === 9. 扫描历史 ===
        entries_.push_back({
            "scans", "scans", "查看扫描历史",
            [this](const std::vector<std::string> &) -> std::string
            {
                // ...
            }
        });

        // === 10. 流量日志 ===
        entries_.push_back({
            "traffic", "traffic", "查看最近流量",
            [this](const std::vector<std::string> &) -> std::string
            {
                // ...
            }
        });

        // === AI 相关命令 ===
        entries_.push_back({
            "ai", "ai [on|off|local|remote]", "切换 AI 模式",
            [this](const std::vector<std::string> &args) -> std::string
            {
                if (args.size() < 2) return "**当前模式:** ...";
                // ...
            }
        });

        entries_.push_back({
            "model", "model <path>", "加载本地 ONNX 模型",
            [this](const std::vector<std::string> &args) -> std::string
            {
                // ...
            }
        });

        entries_.push_back({
            "api", "api <endpoint> <key> [model]", "配置远程 AI API",
            [this](const std::vector<std::string> &args) -> std::string
            {
                // ...
            }
        });

        entries_.push_back({
            "help", "help", "显示帮助",
            [this](const std::vector<std::string> &) -> std::string
            {
                auto ss = std::stringstream{};
                ss << "## 可用命令\n\n";
                for (const auto &cmd : entries_)
                {
                    ss << "- **`" << cmd.name << "`** — " << cmd.description << "\n";
                    ss << "  `" << cmd.usage << "`\n";
                }
                return ss.str();
            }
        });
    }

    // ... dispatch / complete 实现
}
```

---

## 6. FTXUI 组件详细设计

### 6.1 chat_panel（对话面板）

**文件：** `include/sec/tui/components/chat_panel.hpp`

这是主界面核心组件，显示 AI 对话消息。每条消息经过 `markdown_renderer` 渲染后显示。

```cpp
#pragma once

#include <sec/tui/application.hpp>
#include <sec/tui/markdown_renderer.hpp>

#include <ftxui/component/component.hpp>
#include <ftxui/dom/elements.hpp>

#include <mutex>

namespace sec::tui::components
{
    class chat_panel
    {
    public:
        explicit chat_panel(application &app);

        /**
         * @brief 返回 FTXUI Component
         */
        [[nodiscard]] auto render() -> ftxui::Component;

        /**
         * @brief 添加用户消息
         */
        auto add_user_message(const std::string &text) -> void;

        /**
         * @brief 添加助手回复（流式追加）
         */
        auto append_assistant(const std::string &chunk) -> void;

        /**
         * @brief 完成当前助手消息
         */
        auto finish_assistant() -> void;

        /**
         * @brief 添加系统消息（命令输出）
         */
        auto add_system_output(const std::string &markdown_text) -> void;

    private:
        struct message_entry
        {
            enum type : std::uint8_t { user, assistant, system } kind;
            std::string raw_text;           // 原始文本
            ftxui::Element rendered;        // 渲染后的 Element
            bool is_streaming{false};       // 是否正在流式接收
        };

        application &app_;
        std::vector<message_entry> messages_;
        std::mutex messages_mutex_;
        int scroll_offset_{0};
        bool auto_scroll_{true};
    };
}
```

**实现要点：**
- 每条消息存储原始文本和渲染后的 `ftxui::Element`
- 流式消息：先创建一个 `is_streaming=true` 的消息，每次 `append_assistant` 更新文本并重新渲染
- 使用 `ftxui::vbox` 纵向排列所有消息
- 使用 `ftxui::focus` + `ftxui::scroll` 实现滚动
- 用户消息右对齐，助手消息左对齐，系统消息居中灰色背景
- `auto_scroll_` 模式下新消息自动滚到底部

### 6.2 input_bar（输入栏）

**文件：** `include/sec/tui/components/input_bar.hpp`

```cpp
#pragma once

#include <sec/tui/application.hpp>

#include <ftxui/component/component.hpp>

#include <string>
#include <vector>

namespace sec::tui::components
{
    class input_bar
    {
    public:
        explicit input_bar(application &app);

        [[nodiscard]] auto render() -> ftxui::Component;

    private:
        auto on_submit() -> void;
        auto on_change() -> void;
        auto show_completions() -> void;

        application &app_;

        ftxui::InputOption input_option_;
        std::string input_text_;
        std::vector<std::string> completions_;
        int completion_index_{-1};

        // 命令历史
        std::vector<std::string> history_;
        int history_index_{-1};

        // 输入模式
        enum class input_mode : std::uint8_t
        {
            command,    // 命令模式（默认）
            chat        // 对话模式（与 AI 聊天）
        };
        input_mode mode_{input_mode::command};
    };
}
```

**实现要点：**
- `ftxui::Input` 组件 + 自定义事件处理
- `command` 模式：输入以 `/` 开头的命令（如 `/arp 192.168.1.0/24`），通过 `command_registry` 分发
- `chat` 模式：直接输入文本发送给 AI，模式通过 `Tab` 键或快捷键切换
- `Enter` 提交，`Up/Down` 浏览历史，`Tab` 补全
- 补全下拉菜单使用 `ftxui::Menu` 浮层
- 底部显示当前模式指示器：`[命令] spectra> _` 或 `[对话] 你> _`

### 6.3 sidebar（侧边栏）

**文件：** `include/sec/tui/components/sidebar.hpp`

```cpp
#pragma once

#include <sec/tui/application.hpp>

#include <ftxui/component/component.hpp>

#include <string>

namespace sec::tui::components
{
    class sidebar
    {
    public:
        explicit sidebar(application &app);

        [[nodiscard]] auto render() -> ftxui::Component;
        [[nodiscard]] auto width() const -> int { return collapsed_ ? 0 : width_; }
        auto toggle() -> void { collapsed_ = !collapsed_; }

    private:
        application &app_;
        int width_{30};
        bool collapsed_{false};

        // 标签页
        enum class tab : std::uint8_t { devices, alerts, scans };
        tab active_tab_{tab::devices};

        ftxui::Component tab_toggle_;
    };
}
```

**实现要点：**
- 使用 `ftxui::Toggle` 实现标签页切换（设备/告警/扫描）
- 设备标签：实时从 `device_query` 读取，显示 IP + 主机名列表，选中可查看详情
- 告警标签：实时从 `alert_query` 读取未确认告警，按严重程度着色
- 扫描标签：显示最近扫描记录和状态
- `Ctrl+B` 快捷键折叠/展开侧边栏

### 6.4 status_bar（状态栏）

**文件：** `include/sec/tui/components/status_bar.hpp`

```cpp
#pragma once

#include <sec/tui/application.hpp>
#include <ftxui/component/component.hpp>
#include <string>

namespace sec::tui::components
{
    class status_bar
    {
    public:
        explicit status_bar(application &app);
        [[nodiscard]] auto render() -> ftxui::Component;

    private:
        application &app_;
    };
}
```

**实现要点：**
- 左侧显示：AI 模式状态（本地/远程/关闭）、模型加载状态
- 中间显示：扫描进度（如果有正在进行的扫描）
- 右侧显示：在线设备数、告警数、时间
- 使用不同颜色区分状态

### 6.5 其他组件

`device_table`、`alert_list`、`scan_panel`、`traffic_view` 这四个组件在侧边栏的不同标签页中使用，它们封装了具体的数据查询和 FTXUI 表格渲染逻辑。

---

## 7. 配置扩展

### 7.1 config.hpp 修改

在 `include/sec/config.hpp` 中添加 TUI 相关配置：

```cpp
/**
 * @brief TUI 界面配置
 */
struct tui_config
{
    bool enable_sidebar{true};
    std::int32_t sidebar_width{30};
    std::string theme{"dark"};
};

/**
 * @brief 远程 AI API 配置
 */
struct remote_ai_config
{
    std::string endpoint{"https://api.openai.com/v1/chat/completions"};
    std::string api_key;
    std::string model{"gpt-4o"};
    std::uint16_t max_tokens{4096};
    float temperature{0.7f};
};
```

在 `config` 结构体中添加新字段：

```cpp
struct config
{
    engine_config engine{};
    scanner_config scanner{};
    store_config store{};
    ai_config ai{};
    trace_config trace{};
    tui_config tui{};             // 新增
    remote_ai_config remote_ai{}; // 新增
};
```

对应的 `glz::meta` 特化也要添加（参见现有 `config.hpp` 底部的格式）。

---

## 8. 现有代码复用

### 8.1 不可修改的文件

以下文件是现有代码，**不能删除或大幅修改**，只能读取复用：
- `src/sec/cli/application.cpp` — 旧 CLI 实现，保持不变
- `include/sec/cli/application.hpp` — 旧 CLI 头文件，保持不变
- `src/main.cpp` — 仅修改入口点添加 `--tui`/`--cli` 切换

### 8.2 必须复用的逻辑

以下逻辑在新 TUI 中必须完整复现（从 `cli/application.cpp` 提取）：

1. **子系统初始化**（第 94-119 行）：db → migration → queries → persister → detection → mitm
2. **后台线程管理**（第 130-150 行）：start/stop + work_guard
3. **所有 cmd_* 方法的协程模式**：
   - `co_spawn` + `promise` + `future.get()` 桥接
   - 扫描器的 `co_await xxx.scan(ec)` 调用
   - 指纹识别 `scanner::fingerprint::identify(dev)`
   - 持久化 `persist_devices()`
4. **`parse_port_range()`**（第 918-979 行）：端口范围解析
5. **`format_time()`**（第 36-47 行）：时间格式化
6. **`persist_devices()`**（第 855-914 行）：设备持久化

### 8.3 共享代码提取建议

为避免代码重复，建议将以下功能提取为共享工具函数（放在公共头文件中）：

- `sec::cli::format_time()` → 移到 `include/sec/util/format.hpp`
- `sec::cli::trim()` / `split()` → 移到 `include/sec/util/string.hpp`
- `sec::cli::application::parse_port_range()` → 移到 `include/sec/scanner/util.hpp`
- `sec::cli::application::persist_devices()` → 移到 `include/sec/store/util.hpp`

这样 `cli::application` 和 `tui::application` 都能复用。

---

## 9. 构建顺序

按照以下顺序实现，每步确保编译通过：

1. **Phase 1 — 基础设施**（不涉及 UI）
   - 修改 `CMakeLists.txt` 添加 FTXUI + cmark-gfm FetchContent
   - 创建 `src/sec/tui/` 目录和空 CMakeLists.txt
   - 修改 `src/sec/CMakeLists.txt` 添加 `add_subdirectory(tui)`
   - 验证编译通过

2. **Phase 2 — Markdown 渲染器**（独立模块）
   - 实现 `markdown_renderer.hpp/.cpp`
   - 确保与 cmark-gfm 正确链接
   - 编译验证

3. **Phase 3 — 命令注册表**（独立模块）
   - 实现 `command_registry.hpp/.cpp`
   - 所有 10 个命令 + AI 命令
   - 编译验证

4. **Phase 4 — FTXUI 组件**
   - 实现 `chat_panel`、`input_bar`、`sidebar`、`status_bar`
   - 编译验证

5. **Phase 5 — AI 对话管理器**
   - 实现 `ai_chat.hpp/.cpp`
   - 本地 ONNX 推理 + 远程 API 流式
   - 编译验证

6. **Phase 6 — TUI Application 主类**
   - 实现 `tui::application.hpp/.cpp`
   - 组件组装 + 事件循环
   - 修改 `main.cpp` 添加 `--tui` 切换
   - 全量编译验证

7. **Phase 7 — 集成测试**
   - 启动 `Spectra --tui` 验证界面显示
   - 测试各命令功能
   - 测试 AI 对话

---

## 10. 编码规范

严格遵守 Spectra 项目的编码规范（来自 CLAUDE.md）：

- **命名空间**: `sec::tui`
- **文件**: snake_case
- **类/函数/类型/结构体**: 全部 snake_case
- **头文件保护**: `#pragma once`
- **返回类型**: 尾随返回类型 (`auto func() -> return_type`)
- **`[[nodiscard]]`**: 有意义的返回值
- **注释**: Doxygen 风格中文 (`@file`, `@brief`, `@details`, `@return`, `@note`)
- **函数参数**: 不超过 3 个，超过用 struct 收敛
- **函数体**: 不超过 120 行
- **Lambda**: 不超过 10 行，超长提取为命名函数
- **禁止 `using namespace`**: 用显式限定或 namespace 别名
- **Boost.Asio 别名**: `namespace net = boost::asio;`
- **PMR**: 热路径容器使用 PMR 分配器
- **协程纯度**: 禁止在协程中使用阻塞操作

### FTXUI 特有注意事项

- FTXUI 组件继承 `ftxui::ComponentBase`，使用 `ftxui::Make` 创建
- 布局使用 `ftxui::vbox`、`ftxui::hbox`、`ftxui::flex` 等组合
- 样式通过 `|` 操作符管道式应用：`text | bold | color(Color::Red)`
- 事件处理通过 `ftxui::CatchEvent` 包装
- 组件间通信通过回调或共享引用（application 持有所有子系统）

---

## 11. 远程 AI API 协议详情

### 11.1 OpenAI 兼容接口

**请求格式**（POST）：
```json
{
  "model": "gpt-4o",
  "stream": true,
  "max_tokens": 4096,
  "temperature": 0.7,
  "messages": [
    {"role": "system", "content": "你是 Spectra 安全分析助手..."},
    {"role": "user", "content": "当前网络有什么异常？"},
    {"role": "assistant", "content": "分析发现..."},
    {"role": "user", "content": "帮我扫描 192.168.1.0/24"}
  ]
}
```

**SSE 流式响应格式**：
```
data: {"id":"chatcmpl-xxx","choices":[{"delta":{"content":"当前"},"index":0}]}

data: {"id":"chatcmpl-xxx","choices":[{"delta":{"content":"网络"},"index":0}]}

data: {"id":"chatcmpl-xxx","choices":[{"delta":{"content":"安全"},"index":0}]}

data: [DONE]
```

每个 `data:` 行是一个 JSON 对象，`choices[0].delta.content` 包含增量文本。最后一个 `data: [DONE]` 表示流结束。

### 11.2 系统提示词

AI 对话的系统提示词应该包含 Spectra 的安全分析上下文：

```
你是 Spectra 安全分析助手，一个专业的局域网安全态势分析 AI。

你可以帮助用户：
- 分析网络安全状况
- 解读扫描结果和告警
- 提供安全建议和最佳实践
- 执行扫描和检测操作（通过命令）

当前网络状态：
- 已发现设备数: {device_count}
- 未确认告警数: {alert_count}
- AI 模式: {ai_mode}

请用 Markdown 格式回复，可以包含表格、列表和代码块。
```

---

## 12. 注意事项

1. **cmark-gfm 的 C API**: 所有 cmark 函数在 `extern "C"` 块中使用，cmark-gfm 头文件路径为 `<cmark-gfm.h>` 和 `<cmark-gfm-core-extensions.h>`
2. **FTXUI 线程安全**: FTXUI 的 `ScreenInteractive::Loop()` 必须在主线程运行，异步操作通过 `screen.Post()` 调度 UI 更新
3. **io_context 线程**: 后台 `io_context` 线程运行所有异步操作（扫描、AI API 请求等），与 FTXUI 主循环并行
4. **FTXUI ScreenInteractive::Post()**: 从后台线程更新 UI 必须通过 `screen_.Post()` 投递到主线程
5. **终端尺寸**: FTXUI 自动适应终端尺寸变化，使用 `ftxui::flex` 和 `ftxui::fill` 让布局自适应
6. **Windows 终端**: Windows Terminal 完整支持 ANSI 转义码和真彩色，FTXUI 在 Windows Terminal 上工作良好
7. **编译器**: 使用 MinGW GCC 13+，C++23 标准，与现有 Spectra 构建环境一致
8. **链接顺序**: FTXUI 的三个库（screen/dom/component）都需要链接，cmark-gfm 链接静态库 `cmark-gfm_static`
9. **构建线程**: 白天 `-j 16`，晚间 22:00-08:00 强制 `-j 1`
10. **禁止 Python**: 不使用任何 Python 脚本
