// TUI 主题系统实现 — dark/light 调色板 + 终端背景检测

#include <sec/tui/theme.hpp>

#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <termios.h>
#endif

#include <cstdio>
#include <cstring>
#include <string>

namespace sec::tui
{

    auto make_dark_theme() -> theme_palette
    {
        // One Dark Pro — 当前默认配色
        return theme_palette{};
    }


    auto make_light_theme() -> theme_palette
    {
        auto th = theme_palette{};
        th.success = {56, 162, 68};
        th.info = {56, 132, 244};
        th.error = {226, 76, 107};
        th.accent = {166, 104, 214};
        th.warning = {210, 170, 50};
        th.high_severity = {216, 120, 48};
        th.dim_text = {160, 161, 167};
        th.border = {210, 210, 210};
        th.placeholder = {180, 180, 180};
        th.body_text = {56, 58, 66};
        th.header_text = {38, 40, 48};
        th.secondary_text = {124, 126, 133};
        th.background = {245, 245, 245};
        th.active_tab_bg = {220, 240, 220};
        th.cursor_fg = {255, 255, 255};
        th.cursor_bg = {56, 58, 66};
        th.emphasis = {148, 90, 196};
        th.raw_html = {106, 153, 85};
        th.code_text = {76, 79, 88};
        th.heading_h1 = {226, 76, 107};
        th.heading_h2 = {56, 162, 68};
        th.heading_h3 = {210, 170, 50};
        th.heading_h4 = {166, 104, 214};
        th.streaming_cursor = {56, 162, 68};
        th.syn_keyword = {56, 132, 244};
        th.syn_string = {180, 90, 50};
        th.syn_comment = {120, 130, 100};
        th.syn_number = {40, 140, 80};
        th.syn_function = {170, 130, 30};
        th.syn_operator = {100, 100, 100};
        th.syn_punct = {76, 79, 88};
        th.box_border = {180, 180, 180};
        th.quote_bar = {160, 160, 160};
        return th;
    }


    auto detect_terminal_background() -> bool
    {
#ifdef _WIN32
        // 读取 Windows 系统主题设置
        // HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize
        // SystemUsesLightTheme: DWORD (0=dark, 1=light)
        auto key = HKEY{};
        auto status = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
            0, KEY_READ, &key);

        if (status != ERROR_SUCCESS) return false;

        auto value = DWORD{};
        auto size = DWORD{sizeof(DWORD)};
        status = RegQueryValueExW(key, L"SystemUsesLightTheme", nullptr, nullptr,
            reinterpret_cast<LPBYTE>(&value), &size);
        RegCloseKey(key);

        if (status != ERROR_SUCCESS) return false;
        return value != 0;  // 1 = 浅色，0 = 深色
#else
        // 向终端查询背景色: OSC 11
        // 需要 stdout 是真正的终端
        if (!isatty(STDOUT_FILENO)) return false;

        // 保存原始终端属性
        auto orig = termios{};
        if (tcgetattr(STDIN_FILENO, &orig) != 0) return false;

        // 设置非阻塞读取
        auto raw = orig;
        raw.c_lflag &= ~(ICANON | ECHO);
        raw.c_cc[VMIN] = 0;
        raw.c_cc[VTIME] = 0;
        if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) != 0) return false;

        // 发送 OSC 11 查询
        std::fputs("\033]11;?\007", stdout);
        std::fflush(stdout);

        // 等待响应 (最多 200ms)
        auto pfd = pollfd{STDIN_FILENO, POLLIN, 0};
        auto buf = std::string{};
        for (auto i = 0; i < 20; ++i)
        {
            pfd.revents = 0;
            auto ret = poll(&pfd, 1, 10);
            if (ret > 0 && (pfd.revents & POLLIN))
            {
                auto tmp = char{};
                if (read(STDIN_FILENO, &tmp, 1) == 1)
                {
                    buf += tmp;
                    // 响应以 BEL(0x07) 或 ST("\033\\") 结尾
                    if (tmp == '\x07' || (buf.size() >= 2 && buf.substr(buf.size() - 2) == "\033\\")) break;
                }
            }
        }

        // 恢复终端属性
        tcsetattr(STDIN_FILENO, TCSANOW, &orig);

        // 刷新残留输入（丢弃多余字符）
        {
            auto flags = fcntl(STDIN_FILENO, F_GETFL);
            fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
            auto discard = char{};
            while (read(STDIN_FILENO, &discard, 1) == 1) {}
            fcntl(STDIN_FILENO, F_SETFL, flags);
        }

        // 解析响应: \033]11;rgb:RRRR/GGGG/BBBB\007
        // 或 \033]11;rgb:RR/GG/BB\007
        auto prefix = std::string{"\033]11;rgb:"};
        auto pos = buf.find(prefix);
        if (pos == std::string::npos) return false;

        auto color_str = buf.substr(pos + prefix.size());
        auto slash1 = color_str.find('/');
        auto slash2 = color_str.find('/', slash1 + 1);
        if (slash1 == std::string::npos || slash2 == std::string::npos) return false;

        auto parse_hex = [](const std::string &s) -> int
        {
            try
            {
                return static_cast<int>(std::stoul(s, nullptr, 16));
            }
            catch (...)
            {
                return 0;
            }
        };

        auto r = parse_hex(color_str.substr(0, slash1));
        auto g = parse_hex(color_str.substr(slash1 + 1, slash2 - slash1 - 1));
        auto b_str = color_str.substr(slash2 + 1);
        // 去掉尾部 BEL/ST
        auto bel = b_str.find('\x07');
        if (bel != std::string::npos) b_str = b_str.substr(0, bel);
        auto st = b_str.find("\033\\");
        if (st != std::string::npos) b_str = b_str.substr(0, st);
        auto b = parse_hex(b_str);

        // 归一化到 [0, 65535] 再到 [0.0, 1.0]
        auto max_val = std::max({r, g, b, 1});
        auto norm_r = static_cast<double>(r) / max_val;
        auto norm_g = static_cast<double>(g) / max_val;
        auto norm_b = static_cast<double>(b) / max_val;

        // 相对亮度
        auto luminance = 0.299 * norm_r + 0.587 * norm_g + 0.114 * norm_b;
        return luminance > 0.5;
#endif
    }


    auto resolve_theme(theme_mode mode) -> theme_palette
    {
        switch (mode)
        {
        case theme_mode::dark:
            return make_dark_theme();
        case theme_mode::light:
            return make_light_theme();
        case theme_mode::auto_detect:
            return detect_terminal_background() ? make_light_theme() : make_dark_theme();
        }
        return make_dark_theme();
    }


    auto theme_mode_name(theme_mode mode) -> const char *
    {
        switch (mode)
        {
        case theme_mode::dark: return "dark";
        case theme_mode::light: return "light";
        case theme_mode::auto_detect: return "auto";
        }
        return "auto";
    }

} // namespace sec::tui
