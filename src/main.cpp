// Spectra 程序入口 — 默认 TUI，--cli 退回旧 CLI

#include <sec/config.hpp>
#include <sec/cli/application.hpp>
#include <sec/tui/application.hpp>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>

#include <filesystem>
#include <iostream>
#include <new>
#include <string_view>

auto main(int argc, char *argv[]) -> int
{
    // 设置 spdlog 默认 logger 为文件输出（TUI 模式下 stdout 被覆盖）
    try
    {
        auto log_dir = std::filesystem::path{argv[0]}.parent_path();
        auto logger = spdlog::basic_logger_mt("main", (log_dir / "spectra.log").string(), true);
        logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] %v");
        logger->set_level(spdlog::level::debug);
        logger->flush_on(spdlog::level::debug);
        spdlog::set_default_logger(logger);
    }
    catch (...) {}

    // 入口判定：
    // - 无参数 → TUI
    // - 第一参数是 --tui → TUI（消费该标志后传给后端）
    // - 第一参数是 --cli → CLI 交互模式（消费该标志后传给 CLI）
    // - 其他 → CLI 子命令直跑（argv 原样传给 CLI）
    auto use_cli = false;
    auto cli_argv = std::vector<char *>{};
    cli_argv.push_back(argv[0]);

    if (argc == 1)
    {
        use_cli = false;
    }
    else if (std::string_view{argv[1]} == "--tui")
    {
        use_cli = false;
        for (auto i = 2; i < argc; ++i) cli_argv.push_back(argv[i]);
    }
    else if (std::string_view{argv[1]} == "--cli")
    {
        use_cli = true;
    }
    else
    {
        use_cli = true;
        for (auto i = 1; i < argc; ++i) cli_argv.push_back(argv[i]);
    }

    try
    {
        sec::config cfg;

        auto cwd = std::filesystem::current_path();
        auto exe_dir = std::filesystem::path{argv[0]}.parent_path();
        spdlog::info("cwd={}, exe_dir={}", cwd.string(), exe_dir.string());

        // UAC 提权后 CWD 可能变成 C:\Windows\System32，
        // 所以必须用 exe 绝对路径往上搜索项目根目录
        auto exe_abs = std::filesystem::absolute(exe_dir);
        auto cfg_paths = std::vector<std::filesystem::path>{
            cwd / "spectra.json",
            exe_abs / "spectra.json",
            exe_abs / ".." / "spectra.json",
            exe_abs / ".." / ".." / "spectra.json",
            exe_abs / ".." / ".." / ".." / "spectra.json",
        };

        auto loaded = false;
        for (const auto &p : cfg_paths)
        {
            try
            {
                if (std::filesystem::exists(p))
                {
                    cfg = sec::load_config(p.string());
                    spdlog::info("Loaded config from: {}", p.string());
                    loaded = true;
                    break;
                }
            }
            catch (const std::exception &e)
            {
                spdlog::warn("Failed to parse config {}: {}", p.string(), e.what());
            }
        }

        if (!loaded)
        {
            spdlog::warn("No spectra.json found, using defaults");
        }

        if (use_cli)
        {
            sec::cli::application app{cfg};
            auto cli_argc = static_cast<int>(cli_argv.size());
            return app.run(cli_argc, cli_argv.data());
        }
        sec::tui::application app{cfg};
        return app.run(argc, argv);
    }
    catch (const std::exception &e)
    {
        std::cerr << "Fatal: " << e.what() << "\n";
        return 1;
    }
}
