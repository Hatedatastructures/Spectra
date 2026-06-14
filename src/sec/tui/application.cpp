// TUI 应用主类实现 — Windows 原生控制台 + cpp-terminal 仅用于渲染

#include <sec/tui/application.hpp>
#include <sec/tui/chat.hpp>
#include <sec/tui/command.hpp>
#include <sec/tui/components/chat.hpp>
#include <sec/tui/components/input.hpp>
#include <sec/tui/components/side.hpp>
#include <sec/tui/components/status.hpp>
#include <sec/tui/layout.hpp>
#include <sec/tui/terminal.hpp>
#include <sec/tui/theme.hpp>
#include <sec/store/migration.hpp>

#include <boost/asio.hpp>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>

#include <cpp-terminal/window.hpp>
#include <cpp-terminal/screen.hpp>

#ifdef _WIN32
#include <windows.h>
#else
#include <cpp-terminal/input.hpp>
#include <cpp-terminal/terminal.hpp>
#endif

#include <algorithm>
#include <atomic>
#include <chrono>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>


namespace sec::tui
{

    static auto tui_log() -> std::shared_ptr<spdlog::logger>
    {
        static auto logger = std::shared_ptr<spdlog::logger>{};
        if (!logger)
        {
            logger = spdlog::basic_logger_mt("tui", "tui_debug.log", true);
            logger->set_pattern("[%H:%M:%S.%e] %v");
            logger->set_level(spdlog::level::debug);
            logger->flush_on(spdlog::level::debug);
        }
        return logger;
    }


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
        auto migration = store::migration_manager{*db_};
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

        spdlog::info("AI config: endpoint=[{}] model=[{}] key_len={}",
            cfg.ai.remote_endpoint, cfg.ai.remote_model, cfg.ai.remote_api_key.size());

        if (!cfg.ai.remote_endpoint.empty())
        {
            auto rc = remote_config{};
            rc.endpoint = cfg.ai.remote_endpoint;
            rc.api_key = cfg.ai.remote_api_key;
            rc.model = cfg.ai.remote_model;
            rc.protocol = cfg.ai.remote_protocol == "anthropic"
                ? api_protocol::anthropic : api_protocol::openai;
            chat_->set_remote(rc);
            chat_->set_mode(ai_mode::remote);
            spdlog::info("AI mode set to REMOTE");
        }
        else
        {
            spdlog::warn("AI remote_endpoint is empty, staying OFF");
        }
    }


    application::~application() noexcept
    {
        running_ = false;
        stop_background_thread();
    }


#ifdef _WIN32
    static auto saved_out_mode = DWORD{};
    static auto saved_in_mode = DWORD{};
    static auto modes_saved = false;
#endif


    auto application::run(int argc, char *argv[]) -> int
    {
        // 初始化主题
        if (config_.tui.theme == "light") active_theme_mode_ = theme_mode::light;
        else if (config_.tui.theme == "dark") active_theme_mode_ = theme_mode::dark;
        else active_theme_mode_ = theme_mode::auto_detect;
        active_theme_ = resolve_theme(active_theme_mode_);

        chat_panel_ = std::make_shared<components::chat_panel>(*this);
        input_bar_ = std::make_shared<components::input_bar>(*this);
        sidebar_ = std::make_shared<components::sidebar>(*this);
        status_bar_ = std::make_shared<components::status_bar>(*this);

#ifdef _WIN32
        setup_windows_console();
#else
        Term::terminal.setOptions(Term::Option::Raw, Term::Option::NoSignalKeys, Term::Option::NoCursor);
#endif

        auto [init_rows, init_cols] = get_terminal_size();
        last_rows_ = init_rows;
        last_cols_ = init_cols;

        running_ = true;
        dirty_ = true;
        last_status_tick_ = std::chrono::steady_clock::now();

        start_background_thread();

        try
        {
            while (running_)
            {
                poll_console_input();

                auto events = event_queue_.poll_all();
                for (auto &ev : events)
                {
                    process_ui_events_one(ev);
                }
                if (!events.empty())
                {
                    dirty_ = true;
                }

                auto [rows, cols] = get_terminal_size();
                if (rows != last_rows_ || cols != last_cols_)
                {
                    last_rows_ = rows;
                    last_cols_ = cols;
                    dirty_ = true;
                }

                // 状态栏每秒刷新一次
                auto now_tick = std::chrono::steady_clock::now();
                if (now_tick - last_status_tick_ >= std::chrono::seconds{1})
                {
                    last_status_tick_ = now_tick;
                    dirty_ = true;
                }

                if (dirty_)
                {
                    try
                    {
                        render_frame();
                    }
                    catch (const std::exception &)
                    {
                    }
                    dirty_ = false;
                }

                std::this_thread::sleep_for(std::chrono::milliseconds{16});
            }
        }
        catch (const std::exception &)
        {
            running_ = false;
            stop_background_thread();
            restore_terminal();
            throw;
        }

        stop_background_thread();
        restore_terminal();
        return 0;
    }


#ifdef _WIN32
    void application::setup_windows_console()
    {
        // 设置控制台输入/输出代码页为 UTF-8
        SetConsoleCP(65001);
        SetConsoleOutputCP(65001);

        auto out = GetStdHandle(STD_OUTPUT_HANDLE);
        auto in = GetStdHandle(STD_INPUT_HANDLE);

        // 保存原始模式
        GetConsoleMode(out, &saved_out_mode);
        GetConsoleMode(in, &saved_in_mode);
        modes_saved = true;

        // 输出：启用虚拟终端序列（ANSI 转义）
        SetConsoleMode(out, saved_out_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

        // 输入：启用窗口 resize + 鼠标，关闭行缓冲（raw）
        SetConsoleMode(in, ENABLE_WINDOW_INPUT | ENABLE_MOUSE_INPUT | ENABLE_EXTENDED_FLAGS);

        // 隐藏光标
        using std::cout;
        using std::flush;
        cout << "\033[?25l" << flush;
    }


    void application::restore_terminal()
    {
        using std::cout;
        using std::flush;

        // 清屏
        cout << "\033[2J\033[H";
        // 显示光标
        cout << "\033[?25h";
        // 重置所有样式
        cout << "\033[0m";
        // 启用自动换行
        cout << "\033[?7h";
        // 禁用鼠标追踪（防万一）
        cout << "\033[?1000l\033[?1003l\033[?1006l\033[?1015l";
        cout << "\r\n" << flush;

        // 恢复控制台模式
        if (modes_saved)
        {
            auto out = GetStdHandle(STD_OUTPUT_HANDLE);
            auto in = GetStdHandle(STD_INPUT_HANDLE);
            SetConsoleMode(out, saved_out_mode);
            SetConsoleMode(in, saved_in_mode);
            modes_saved = false;
        }
    }


    void application::poll_console_input()
    {
        auto handle = GetStdHandle(STD_INPUT_HANDLE);
        if (handle == INVALID_HANDLE_VALUE) return;

        DWORD available = 0;
        if (!GetNumberOfConsoleInputEvents(handle, &available) || available == 0) return;

        auto buf = std::vector<INPUT_RECORD>{};
        buf.resize(std::min(available, DWORD{64}));

        DWORD read = 0;
        if (!ReadConsoleInputW(handle, buf.data(), static_cast<DWORD>(buf.size()), &read)) return;

        for (DWORD i = 0; i < read; ++i)
        {
            auto &rec = buf[i];

            if (rec.EventType == KEY_EVENT && rec.Event.KeyEvent.bKeyDown)
            {
                auto &ke = rec.Event.KeyEvent;
                auto ch = ke.uChar.UnicodeChar;
                auto vk = ke.wVirtualKeyCode;
                auto ctrl = ke.dwControlKeyState;
                auto repeat = ke.wRepeatCount;

                auto ctrl_pressed = (ctrl & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED)) != 0;

                tui_log()->debug("KEY down: vk={} ch=U+{:04X} repeat={} ctrl={}", vk, (unsigned)ch, repeat, ctrl_pressed);

                if (ch != 0 && !ctrl_pressed)
                {
                    for (auto r = WORD{0}; r < repeat; ++r)
                        handle_key_value(static_cast<std::int32_t>(ch));
                }
                else
                {
                    auto key_val = map_virtual_key(vk, ctrl);
                    if (key_val >= 0)
                    {
                        for (auto r = WORD{0}; r < repeat; ++r)
                            handle_key_value(key_val);
                    }
                }
            }
            else if (rec.EventType == KEY_EVENT && !rec.Event.KeyEvent.bKeyDown)
            {
                auto &ke = rec.Event.KeyEvent;
                auto ch = ke.uChar.UnicodeChar;
                auto vk = ke.wVirtualKeyCode;
                tui_log()->debug("KEY up:   vk={} ch=U+{:04X}", vk, (unsigned)ch);
            }
            else if (rec.EventType == WINDOW_BUFFER_SIZE_EVENT)
            {
                dirty_ = true;
            }
            else if (rec.EventType == MOUSE_EVENT)
            {
                // 鼠标滚轮：dwEventFlags 含 MOUSE_WHEELED，
                // 滚动方向在 dwButtonState 的高位字（WHEEL_DELTA = 120）
                auto &me = rec.Event.MouseEvent;
                if (me.dwEventFlags & MOUSE_WHEELED)
                {
                    auto delta = static_cast<std::int16_t>(HIWORD(me.dwButtonState));
                    if (delta > 0)
                    {
                        chat_panel_->scroll_up(3);
                        dirty_ = true;
                    }
                    else if (delta < 0)
                    {
                        chat_panel_->scroll_down(3);
                        dirty_ = true;
                    }
                }
                // 其他鼠标事件（移动/点击）忽略
            }
            // FOCUS_EVENT / MENU_EVENT 忽略
        }
    }


    auto application::map_virtual_key(WORD vk, DWORD ctrl_state) -> std::int32_t
    {
        constexpr auto base = static_cast<std::int32_t>(0x10FFFF);

        switch (vk)
        {
        case VK_LEFT:   return base + 1;
        case VK_RIGHT:  return base + 2;
        case VK_UP:     return base + 3;
        case VK_DOWN:   return base + 4;
        case VK_HOME:   return base + 6;
        case VK_END:    return base + 8;
        case VK_PRIOR:  return base + 9;
        case VK_NEXT:   return base + 10;
        case VK_INSERT: return base + 11;
        case VK_DELETE: return 127;
        case VK_BACK:   return 8;
        case VK_RETURN: return 13;
        case VK_TAB:    return 9;
        case VK_ESCAPE: return 27;
        default: break;
        }

        if (vk >= 0x41 && vk <= 0x5A &&
            (ctrl_state & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED)))
        {
            return vk - 0x41 + 1;
        }

        return -1;
    }
#else
    void application::setup_windows_console() {}
    void application::restore_terminal()
    {
        using std::cout;
        using std::flush;
        cout << "\033[2J\033[H";
        cout << "\033[?25h";
        cout << "\033[0m";
        cout << "\033[?7h";
        cout << "\033[?1000l\033[?1003l";
        cout << "\r\n" << flush;
        try { Term::terminal.setOptions(Term::Option::ClearScreen); } catch (...) {}
    }

    void application::poll_console_input()
    {
        try
        {
            auto event = Term::read_event();
            if (event.type() == Term::Event::Type::Key)
            {
                auto key_ptr = event.get_if_key();
                if (key_ptr)
                {
                    handle_key_value(static_cast<std::int32_t>(*key_ptr));
                }
            }
            else if (event.type() == Term::Event::Type::Screen)
            {
                dirty_ = true;
            }
        }
        catch (const std::exception &)
        {
        }
    }

    auto application::map_virtual_key(WORD, DWORD) -> std::int32_t
    {
        return -1;
    }
#endif


    void application::handle_key_value(std::int32_t val)
    {
        auto key = Term::Key{val};

        tui_log()->debug("handle_key_value: val={} ({:#x})", val, val);

        if (key == Term::Key::Ctrl_B)
        {
            sidebar_->toggle();
            sidebar_visible_ = !sidebar_visible_;
            dirty_ = true;
            return;
        }
        if (key == Term::Key::Ctrl_T)
        {
            input_bar_->toggle_mode();
            dirty_ = true;
            return;
        }
        if (key == Term::Key::Ctrl_F)
        {
            cycle_theme();
            dirty_ = true;
            return;
        }
        if (key == Term::Key::Ctrl_C)
        {
            request_stop();
            return;
        }

        if (key == Term::Key::PageUp)
        {
            chat_panel_->page_up();
            dirty_ = true;
            return;
        }
        if (key == Term::Key::PageDown)
        {
            chat_panel_->page_down();
            dirty_ = true;
            return;
        }

        if (sidebar_visible_ && !sidebar_->is_collapsed() &&
            (key == Term::Key::ArrowLeft || key == Term::Key::ArrowRight))
        {
            if (sidebar_->handle_key(key))
            {
                dirty_ = true;
                return;
            }
        }

        input_bar_->handle_key(key);
        dirty_ = true;
    }


    void application::process_ui_events_one(const ui_event &ev)
    {
        switch (ev.type)
        {
        case ui_event_type::key_press:
            break;
        case ui_event_type::chat_user_message:
            chat_panel_->add_user_message(ev.payload);
            break;
        case ui_event_type::chat_assistant_chunk:
            chat_panel_->append_assistant(ev.payload);
            break;
        case ui_event_type::chat_assistant_done:
            chat_panel_->finish_assistant();
            break;
        case ui_event_type::chat_system_output:
            chat_panel_->add_system_output(ev.payload);
            break;
        case ui_event_type::refresh_sidebar:
        case ui_event_type::force_redraw:
            break;
        }
    }


    void application::render_frame()
    {
        auto rows = last_rows_;
        auto cols = last_cols_;

        if (rows < 10 || cols < 20) return;

        auto sw = sidebar_->width();
        auto lay = layout::calculate(rows, cols, sw,
            sidebar_visible_ ? sidebar_state::visible : sidebar_state::hidden);

        try
        {
            Term::Window win(Term::Size(Term::Rows(static_cast<std::uint16_t>(rows)),
                                         Term::Columns(static_cast<std::uint16_t>(cols))));

            win.clear();

            chat_panel_->paint(win, lay.chat);
            input_bar_->paint(win, lay.input_area);
            status_bar_->paint(win, lay.status);

            if (sidebar_visible_ && sw > 0)
            {
                sidebar_->paint(win, lay.sidebar);

                auto sep_col = static_cast<std::size_t>(sw + 1);
                for (auto r = 0; r < lay.sidebar.rows; ++r)
                {
                    auto row = static_cast<std::size_t>(lay.sidebar.row + r);
                    if (sep_col <= static_cast<std::size_t>(win.columns()) && row <= static_cast<std::size_t>(win.rows()))
                    {
                        win.set_char(sep_col, row, U'│');
                        win.set_fg(sep_col, row, active_theme_.border);
                    }
                }
            }

            // 全量渲染：直接输出所有行，放弃差量渲染
            // cpp-terminal 的 render() 不感知 CJK 宽字符，
            // 我们的 paint 阶段已经把宽字符只写到一个 cell，
            // 所以 render() 输出的每 cell 一个字符是正确的
            {
                using std::cout;
                using std::flush;
                cout << "\033[?25l\033[H" << win.render(1, 1, false) << flush;
            }
        }
        catch (const std::exception &)
        {
        }
    }


    auto application::get_terminal_size() -> std::pair<int, int>
    {
#ifdef _WIN32
        auto handle = GetStdHandle(STD_OUTPUT_HANDLE);
        if (handle != INVALID_HANDLE_VALUE)
        {
            auto info = CONSOLE_SCREEN_BUFFER_INFO{};
            if (GetConsoleScreenBufferInfo(handle, &info))
            {
                auto cols = info.srWindow.Right - info.srWindow.Left + 1;
                auto rows = info.srWindow.Bottom - info.srWindow.Top + 1;
                return {std::max(static_cast<int>(rows), 1), std::max(static_cast<int>(cols), 1)};
            }
        }
        return {24, 80};
#else
        try
        {
            auto screen = Term::screen_size();
            return {std::max(static_cast<int>(screen.rows()), 1),
                    std::max(static_cast<int>(screen.columns()), 1)};
        }
        catch (const std::exception &)
        {
            return {24, 80};
        }
#endif
    }


    void application::start_background_thread()
    {
        work_guard_.emplace(boost::asio::make_work_guard(context_.io_context()));
        bg_thread_ = std::thread{[this]()
        {
            try
            {
                context_.io_context().run();
            }
            catch (const std::exception &)
            {
            }
        }};
    }


    void application::stop_background_thread()
    {
        if (work_guard_)
        {
            work_guard_.reset();
        }
        if (bg_thread_.joinable())
        {
            bg_thread_.join();
        }
    }


    void application::cycle_theme()
    {
        switch (active_theme_mode_)
        {
        case theme_mode::dark:
            active_theme_mode_ = theme_mode::light;
            break;
        case theme_mode::light:
            active_theme_mode_ = theme_mode::auto_detect;
            break;
        case theme_mode::auto_detect:
            active_theme_mode_ = theme_mode::dark;
            break;
        }
        active_theme_ = resolve_theme(active_theme_mode_);
        chat_panel_->re_render_messages(active_theme_);
    }


} // namespace sec::tui
