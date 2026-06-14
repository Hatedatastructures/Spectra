/**
 * @file application.hpp
 * @brief TUI 应用主类
 * @details cpp-terminal 驱动的终端界面。
 * 单线程事件循环：非阻塞轮询控制台输入 + UI 事件 + 即时模式渲染。
 */
#pragma once

#include <sec/config.hpp>
#include <sec/engine/context.hpp>
#include <sec/scanner/arp.hpp>
#include <sec/scanner/mdns.hpp>
#include <sec/scanner/port.hpp>
#include <sec/scanner/ssdp.hpp>
#include <sec/decoder/pipeline.hpp>
#include <sec/detector/pipeline.hpp>
#include <sec/mitm/pipeline.hpp>
#include <sec/store/database.hpp>
#include <sec/store/query.hpp>
#include <sec/store/persist.hpp>

#include <sec/tui/event.hpp>
#include <sec/tui/theme.hpp>

#include <cpp-terminal/window.hpp>
#include <cpp-terminal/event.hpp>
#include <cpp-terminal/screen.hpp>
#include <cpp-terminal/key.hpp>

#include <atomic>
#include <memory>
#include <chrono>
#include <optional>
#include <string>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#endif

namespace sec::tui
{
    class ai_chat;
    class command_registry;

    namespace components
    {
        class chat_panel;
        class input_bar;
        class sidebar;
        class status_bar;
    }

    /**
     * @brief TUI 应用主类
     */
    class application
    {
    public:
        friend class components::chat_panel;
        friend class components::input_bar;
        friend class components::sidebar;
        friend class components::status_bar;

        explicit application(const sec::config &cfg);
        ~application() noexcept;

        [[nodiscard]] auto run(int argc, char *argv[]) -> int;

        [[nodiscard]] auto context() noexcept -> engine::context &
        {
            return context_;
        }

        [[nodiscard]] auto config() const noexcept -> const sec::config &
        {
            return config_;
        }

        [[nodiscard]] auto arp() noexcept -> scanner::arp_scanner &
        {
            return arp_;
        }

        [[nodiscard]] auto mdns() noexcept -> scanner::mdns_scanner &
        {
            return mdns_;
        }

        [[nodiscard]] auto ssdp() noexcept -> scanner::ssdp_scanner &
        {
            return ssdp_;
        }

        [[nodiscard]] auto port() noexcept -> scanner::port_scanner &
        {
            return port_;
        }

        [[nodiscard]] auto database() noexcept -> store::database &
        {
            return *db_;
        }

        [[nodiscard]] auto device_query() noexcept -> store::device_query &
        {
            return *device_q_;
        }

        [[nodiscard]] auto scan_query() noexcept -> store::scan_query &
        {
            return *scan_q_;
        }

        [[nodiscard]] auto traffic_query() noexcept -> store::traffic_query &
        {
            return *traffic_q_;
        }

        [[nodiscard]] auto alert_query() noexcept -> store::alert_query &
        {
            return *alert_q_;
        }

        [[nodiscard]] auto persister() noexcept -> store::scan_persister &
        {
            return *persister_;
        }

        [[nodiscard]] auto analysis_query() noexcept -> store::analysis_query &
        {
            if (!analysis_q_)
            {
                analysis_q_ = std::make_unique<store::analysis_query>(*db_);
            }
            return *analysis_q_;
        }

        [[nodiscard]] auto decoder() noexcept -> decoder::pipeline &
        {
            return decoder_;
        }

        [[nodiscard]] auto detection() noexcept -> detector::detection_pipeline &
        {
            return *detection_;
        }

        [[nodiscard]] auto mitm() noexcept -> mitm::mitm_pipeline &
        {
            return *mitm_;
        }

        [[nodiscard]] auto chat() noexcept -> ai_chat &
        {
            return *chat_;
        }

        [[nodiscard]] auto registry() noexcept -> command_registry &
        {
            return *registry_;
        }

        [[nodiscard]] auto event_queue() noexcept -> ui_event_queue &
        {
            return event_queue_;
        }

        [[nodiscard]] auto running() const noexcept -> bool
        {
            return running_;
        }

        void request_stop()
        {
            running_ = false;
        }

        [[nodiscard]] auto theme() const noexcept -> const theme_palette &
        {
            return active_theme_;
        }

        [[nodiscard]] auto theme_mode_value() const noexcept -> theme_mode
        {
            return active_theme_mode_;
        }

        void cycle_theme();

    private:
        void setup_windows_console();
        void start_background_thread();
        void stop_background_thread();
        void render_frame();
        void restore_terminal();
        void process_ui_events_one(const ui_event &ev);
        void poll_console_input();
        void handle_key_value(std::int32_t val);
        static auto map_virtual_key(WORD vk, DWORD ctrl_state) -> std::int32_t;
        auto get_terminal_size() -> std::pair<int, int>;

        sec::config config_;
        engine::context context_;

        std::unique_ptr<store::database> db_;
        std::unique_ptr<store::device_query> device_q_;
        std::unique_ptr<store::scan_query> scan_q_;
        std::unique_ptr<store::traffic_query> traffic_q_;
        std::unique_ptr<store::alert_query> alert_q_;
        std::unique_ptr<store::scan_persister> persister_;
        std::unique_ptr<store::analysis_query> analysis_q_;

        decoder::pipeline decoder_;
        std::unique_ptr<detector::detection_pipeline> detection_;
        std::unique_ptr<mitm::mitm_pipeline> mitm_;

        scanner::arp_scanner arp_;
        scanner::mdns_scanner mdns_;
        scanner::ssdp_scanner ssdp_;
        scanner::port_scanner port_;

        std::unique_ptr<ai_chat> chat_;
        std::unique_ptr<command_registry> registry_;

        std::shared_ptr<components::chat_panel> chat_panel_;
        std::shared_ptr<components::input_bar> input_bar_;
        std::shared_ptr<components::sidebar> sidebar_;
        std::shared_ptr<components::status_bar> status_bar_;

        ui_event_queue event_queue_;

        std::thread bg_thread_;
        std::atomic<bool> running_{false};
        std::atomic<bool> dirty_{true};

        bool sidebar_visible_{false};
        theme_mode active_theme_mode_{theme_mode::auto_detect};
        theme_palette active_theme_;
        int last_rows_{0};
        int last_cols_{0};
        std::string last_render_;
        std::chrono::steady_clock::time_point last_status_tick_;

        std::optional<boost::asio::executor_work_guard<
            boost::asio::io_context::executor_type>> work_guard_;
    };

} // namespace sec::tui
