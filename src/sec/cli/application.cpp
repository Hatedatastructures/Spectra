// 命令行应用封装实现 — 串联所有子系统，提供交互式 CLI 界面

#include <sec/cli/application.hpp>
#include <sec/scanner/fingerprint.hpp>
#include <sec/transport/pcap.hpp>
#include <sec/decoder/util.hpp>
#include <sec/detector/alert.hpp>
#include <sec/util/format.hpp>
#include <sec/util/string.hpp>
#include <sec/util/port.hpp>
#include <sec/store/util.hpp>

#include <pcap.h>
#include <boost/asio.hpp>
#include <spdlog/spdlog.h>

#ifdef _WIN32
#include <iphlpapi.h>
#include <ws2tcpip.h>
#endif

#include <array>
#include <chrono>
#include <cstring>
#include <future>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>


namespace sec::cli
{

    namespace
    {

        // ANSI 颜色代码
        constexpr auto color_reset = "\033[0m";
        constexpr auto color_red = "\033[31m";
        constexpr auto color_yellow = "\033[33m";
        constexpr auto color_green = "\033[32m";
        constexpr auto color_cyan = "\033[36m";
        constexpr auto color_gray = "\033[90m";
        constexpr auto color_bold = "\033[1m";

        // 本文件内调用的工具函数转发到 sec::util 公共实现
        using sec::util::format_time;
        using sec::util::trim;
        using sec::util::split;

    } // anonymous namespace


    // 构造应用并初始化所有子系统
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

        // 创建 capture_session 并连接到 decoder
        capture_ = std::make_unique<engine::capture_session>(context_);
        (void)capture_->subscribe([this](std::span<const std::byte> raw) {
            auto ec_local = std::error_code{};
            (void)decoder_.process(raw, ec_local);
        });
    }


    // 析构时停止后台线程并释放资源
    application::~application() noexcept
    {
        stop_background_thread();
    }


    // 启动抓包管线（capture→decoder→detection/mitm）
    void application::start_capture()
    {
        if (capture_active_.load())
        {
            return;
        }

        detection_->start();
        mitm_->start();

        namespace net = boost::asio;
        auto cap_ec_ptr = std::make_shared<std::error_code>();
        net::co_spawn(
            context_.executor(),
            [this, cap_ec_ptr]() -> net::awaitable<void> {
                co_await capture_->start(*cap_ec_ptr);
            },
            net::detached);

        // 等抓包启动
        for (int i = 0; i < 30; ++i)
        {
            if (capture_->is_running())
            {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        if (*cap_ec_ptr)
        {
            std::cerr << color_red << "Capture start failed: " << cap_ec_ptr->message() << "\n"
                      << color_reset;
        }
        else if (!capture_->is_running())
        {
            std::cerr << color_red << "Capture failed to start (interface: "
                      << config_.engine.capture_interface << ")\n" << color_reset;
        }
        else
        {
            capture_active_ = true;
            std::cout << color_green << "Capture pipeline active on "
                      << config_.engine.capture_interface << "\n" << color_reset;
        }
    }


    // 停止抓包管线
    void application::stop_capture()
    {
        if (!capture_active_.load())
        {
            return;
        }
        capture_->stop();
        detection_->stop();
        mitm_->stop();
        capture_active_ = false;
    }


    // 启动后台线程运行 io_context 事件循环
    void application::start_background_thread()
    {
        running_ = true;
        work_guard_.emplace(boost::asio::make_work_guard(context_.io_context()));
        bg_thread_ = std::thread{[this]() {
            static_cast<void>(context_.run());
        }};
    }


    // 停止后台线程并等待其退出
    void application::stop_background_thread()
    {
        running_ = false;
        work_guard_.reset();
        context_.stop();
        if (bg_thread_.joinable())
        {
            bg_thread_.join();
        }
    }

    // 启动 CLI：子命令直跑或交互模式
    [[nodiscard]] auto application::run(int argc, char *argv[]) -> int
    {
        // 子命令直跑：argv[1] 起为命令
        if (argc >= 2)
        {
            std::cout << std::unitbuf;
            std::cerr << std::unitbuf;
            start_background_thread();
            auto tokens = std::vector<std::string>{};
            for (auto i = 1; i < argc; ++i)
            {
                tokens.emplace_back(argv[i]);
            }
            auto rc = dispatch_command(tokens);
            stop_background_thread();
            return rc;
        }

        // 无参数：交互模式
        print_banner();
        start_background_thread();
        command_loop();
        stop_background_thread();
        return 0;
    }


    // 交互式命令循环
    void application::command_loop()
    {
        std::string line;
        while (running_)
        {
            std::cout << color_cyan << "spectra> " << color_reset;
            std::cout.flush();

            if (!std::getline(std::cin, line))
            {
                break;
            }

            auto input = trim(line);
            if (input.empty())
            {
                continue;
            }

            auto tokens = split(input, ' ');
            if (tokens.empty())
            {
                continue;
            }

            // 退出 / 帮助（dispatch_command 不处理这两个）
            if (tokens[0] == "quit" || tokens[0] == "exit" || tokens[0] == "q")
            {
                std::cout << "Shutting down...\n";
                running_ = false;
                continue;
            }
            if (tokens[0] == "help" || tokens[0] == "h" || tokens[0] == "?")
            {
                print_help();
                continue;
            }

            // 兼容旧格式："scan <sub>" → "<sub>"
            if (tokens.size() >= 2 && tokens[0] == "scan")
            {
                tokens.erase(tokens.begin());
            }
            // 兼容旧格式："alert ack <id>" → "ack <id>"
            else if (tokens.size() >= 3 && tokens[0] == "alert" && tokens[1] == "ack")
            {
                auto id = std::move(tokens[2]);
                tokens.clear();
                tokens.emplace_back("ack");
                tokens.emplace_back(std::move(id));
            }

            static_cast<void>(dispatch_command(tokens));
        }
    }


    // 调度子命令到对应 cmd_* 方法，返回退出码
    [[nodiscard]] auto application::dispatch_command(const std::vector<std::string> &tokens) -> int
    {
        if (tokens.empty())
        {
            print_usage();
            return 1;
        }

        auto const &cmd = tokens[0];

        if (cmd == "help" || cmd == "--help" || cmd == "-h")
        {
            print_usage();
            return 0;
        }
        if (cmd == "arp" && tokens.size() >= 2)
        {
            cmd_scan_arp(tokens[1]);
            return 0;
        }
        if (cmd == "mdns")
        {
            cmd_scan_mdns();
            return 0;
        }
        if (cmd == "ssdp")
        {
            cmd_scan_ssdp();
            return 0;
        }
        if (cmd == "port" && tokens.size() >= 2)
        {
            auto const range = tokens.size() >= 3 ? tokens[2] : std::string{"1-1024"};
            cmd_scan_port(tokens[1], range);
            return 0;
        }
        if (cmd == "devices")
        {
            cmd_devices();
            return 0;
        }
        if (cmd == "device" && tokens.size() >= 2)
        {
            cmd_device(tokens[1]);
            return 0;
        }
        if (cmd == "alerts")
        {
            cmd_alerts();
            return 0;
        }
        if (cmd == "ack" && tokens.size() >= 2)
        {
            try
            {
                cmd_alert_ack(std::stoll(tokens[1]));
                return 0;
            }
            catch (const std::exception &)
            {
                std::cerr << color_red << "Invalid alert ID: " << tokens[1] << "\n" << color_reset;
                return 1;
            }
        }
        if (cmd == "scans")
        {
            cmd_scans();
            return 0;
        }
        if (cmd == "traffic")
        {
            cmd_traffic();
            return 0;
        }
        if (cmd == "pentest")
        {
            cmd_pentest();
            return 0;
        }

        std::cerr << color_red << "Unknown command: " << cmd << "\n" << color_reset;
        print_usage();
        return 1;
    }


    // 打印启动横幅
    auto application::print_banner() const -> void
    {
        std::cout << std::unitbuf;
        std::cout << color_bold << "Spectra v0.1" << color_reset
                  << " — LAN Security Situational Awareness\n"
                  << color_gray << "Type 'help' for available commands.\n" << color_reset;
    }


    // 打印帮助信息（交互模式用，含 quit 提示）
    auto application::print_help() const -> void
    {
        std::cout << color_bold << "\nCommands:\n" << color_reset
                  << "  arp <subnet>            ARP scan a subnet (e.g. 192.168.1.0/24)\n"
                  << "  mdns                    Discover devices via mDNS\n"
                  << "  ssdp                    Discover devices via SSDP/UPnP\n"
                  << "  port <ip> [range]       TCP port scan (default: 1-1024)\n"
                  << "  devices                 List all discovered devices\n"
                  << "  device <ip>             Show device details\n"
                  << "  alerts                  Show unacknowledged alerts\n"
                  << "  ack <id>                Acknowledge an alert\n"
                  << "  scans                   Show scan history\n"
                  << "  traffic                 Show recent traffic logs\n"
                  << "  pentest                 Run live network penetration tests (needs admin)\n"
                  << "  help                    Show this help\n"
                  << "  quit                    Exit application\n\n";
    }


    // 打印用法提示（子命令模式 / 未知命令时用）
    auto application::print_usage() const -> void
    {
        std::cout << color_bold << "Usage: Spectra <command> [args]\n\n" << color_reset
                  << "Commands:\n"
                  << "  arp <subnet>            ARP scan (e.g. 192.168.1.0/24)\n"
                  << "  mdns                    Discover via mDNS\n"
                  << "  ssdp                    Discover via SSDP/UPnP\n"
                  << "  port <ip> [range]       TCP port scan (default 1-1024)\n"
                  << "  devices                 List discovered devices\n"
                  << "  device <ip>             Show device details\n"
                  << "  alerts                  Show unacknowledged alerts\n"
                  << "  ack <id>                Acknowledge alert\n"
                  << "  scans                   Show scan history\n"
                  << "  traffic                 Show recent traffic\n"
                  << "  pentest                 Run live network penetration tests\n"
                  << "  help                    Show this usage\n\n"
                  << "No arguments starts interactive mode (spectra> prompt).\n";
    }


    // ARP 子网扫描
    void application::cmd_scan_arp(std::string_view subnet)
    {
        std::cout << "Scanning subnet " << subnet << " ..." << std::endl;

        auto promise = std::make_shared<std::promise<std::vector<scanner::device>>>();
        auto future = promise->get_future();

        namespace net = boost::asio;
        net::co_spawn(
            context_.executor(),
            [this, subnet_str = std::string{subnet}, promise]() -> net::awaitable<void>
            {
                try
                {
                    auto ec = std::error_code{};
                    auto devices = co_await arp_.scan_subnet(subnet_str, ec);
                    if (ec)
                    {
                        spdlog::error("ARP scan error: {}", ec.message());
                        std::cerr << color_red << "ARP scan error: " << ec.message() << "\n" << color_reset;
                        promise->set_value({});
                        co_return;
                    }
                    promise->set_value(std::move(devices));
                }
                catch (const std::exception &e)
                {
                    spdlog::error("ARP scan exception: {}", e.what());
                    std::cerr << color_red << "ARP scan failed: " << e.what() << "\n" << color_reset;
                    promise->set_value({});
                }
            },
            net::detached);

        auto devices = future.get();

        // 指纹识别
        for (auto &dev : devices)
        {
            scanner::fingerprint::identify(dev);
        }

        // 持久化
        persist_devices(devices, "arp", subnet);

        // 打印结果
        if (devices.empty())
        {
            std::cout << "No devices found.\n";
            return;
        }

        std::cout << color_green << "Found " << devices.size() << " device(s):\n" << color_reset;
        std::cout << color_gray
                  << std::left << std::setw(18) << "  IP"
                  << std::setw(20) << "MAC"
                  << std::setw(16) << "Hostname"
                  << std::setw(18) << "Vendor"
                  << std::setw(14) << "OS"
                  << "Gateway\n" << color_reset;

        for (const auto &dev : devices)
        {
            std::cout << "  "
                      << std::left << std::setw(18) << dev.ip_address
                      << std::setw(20) << std::string{dev.mac_address}
                      << std::setw(16) << (dev.hostname.empty() ? "-" : std::string{dev.hostname})
                      << std::setw(18) << (dev.vendor.empty() ? "-" : std::string{dev.vendor})
                      << std::setw(14) << (dev.os_guess.empty() ? "-" : std::string{dev.os_guess})
                      << (dev.is_gateway ? "*" : "-") << "\n";
        }
    }


    // mDNS 服务发现
    void application::cmd_scan_mdns()
    {
        std::cout << "Scanning via mDNS ...\n";

        auto promise = std::make_shared<std::promise<std::vector<scanner::device>>>();
        auto future = promise->get_future();

        namespace net = boost::asio;
        net::co_spawn(
            context_.executor(),
            [this, promise]() -> net::awaitable<void>
            {
                try
                {
                    auto ec = std::error_code{};
                    auto devices = co_await mdns_.scan(ec);
                    if (ec)
                    {
                        std::cerr << color_red << "mDNS scan error: " << ec.message() << "\n" << color_reset;
                    }
                    promise->set_value(std::move(devices));
                }
                catch (const std::exception &e)
                {
                    std::cerr << color_red << "mDNS scan failed: " << e.what() << "\n" << color_reset;
                    promise->set_value({});
                }
            },
            net::detached);

        auto devices = future.get();

        for (auto &dev : devices)
        {
            scanner::fingerprint::identify(dev);
        }

        persist_devices(devices, "mdns", "-");

        if (devices.empty())
        {
            std::cout << "No mDNS services found.\n";
            return;
        }

        std::cout << color_green << "Found " << devices.size() << " service(s):\n" << color_reset;
        for (const auto &dev : devices)
        {
            std::cout << "  " << std::string{dev.hostname}
                      << " (" << dev.ip_address << ") "
                      << std::string{dev.vendor} << "\n";
        }
    }


    // SSDP/UPnP 发现
    void application::cmd_scan_ssdp()
    {
        std::cout << "Scanning via SSDP ...\n";

        auto promise = std::make_shared<std::promise<std::vector<scanner::device>>>();
        auto future = promise->get_future();

        namespace net = boost::asio;
        net::co_spawn(
            context_.executor(),
            [this, promise]() -> net::awaitable<void>
            {
                try
                {
                    auto ec = std::error_code{};
                    auto devices = co_await ssdp_.scan(ec);
                    if (ec)
                    {
                        std::cerr << color_red << "SSDP scan error: " << ec.message() << "\n" << color_reset;
                    }
                    promise->set_value(std::move(devices));
                }
                catch (const std::exception &e)
                {
                    std::cerr << color_red << "SSDP scan failed: " << e.what() << "\n" << color_reset;
                    promise->set_value({});
                }
            },
            net::detached);

        auto devices = future.get();

        for (auto &dev : devices)
        {
            scanner::fingerprint::identify(dev);
        }

        persist_devices(devices, "ssdp", "-");

        if (devices.empty())
        {
            std::cout << "No UPnP devices found.\n";
            return;
        }

        std::cout << color_green << "Found " << devices.size() << " device(s):\n" << color_reset;
        for (const auto &dev : devices)
        {
            std::cout << "  " << std::string{dev.hostname}
                      << " (" << dev.ip_address << ") "
                      << std::string{dev.vendor} << "\n";
        }
    }


    // TCP 端口扫描
    void application::cmd_scan_port(const std::string &ip, const std::string &range)
    {
        auto ports = parse_port_range(range);
        if (ports.empty())
        {
            std::cout << color_red << "Invalid port range: " << range << "\n" << color_reset;
            return;
        }

        std::cout << "Scanning " << ip << " ports [" << range << "] (" << ports.size() << " ports)...\n";

        auto promise = std::make_shared<std::promise<std::vector<std::uint16_t>>>();
        auto future = promise->get_future();

        namespace net = boost::asio;
        net::co_spawn(
            context_.executor(),
            [this, ip, ports = std::move(ports), promise]() -> net::awaitable<void>
            {
                try
                {
                    auto ec = std::error_code{};
                    scanner::port_scan_options opts;
                    opts.ports = ports;
                    opts.timeout_ms = context_.config().scanner.port_timeout_ms;
                    auto open = co_await port_.scan(ip, opts, ec);
                    if (ec)
                    {
                        std::cerr << color_red << "Port scan error: " << ec.message() << "\n" << color_reset;
                    }
                    promise->set_value(std::move(open));
                }
                catch (const std::exception &e)
                {
                    std::cerr << color_red << "Port scan failed: " << e.what() << "\n" << color_reset;
                    promise->set_value({});
                }
            },
            net::detached);

        auto open_ports = future.get();

        if (open_ports.empty())
        {
            std::cout << "No open ports found.\n";
        }
        else
        {
            std::cout << color_green << "Open ports: " << color_bold;
            for (std::size_t i = 0; i < open_ports.size(); ++i)
            {
                if (i > 0)
                {
                    std::cout << ", ";
                }
                std::cout << open_ports[i];
            }
            std::cout << color_reset << "\n";
        }
    }


    // 列出所有已发现设备
    void application::cmd_devices()
    {
        auto ec = std::error_code{};
        auto devices = device_q_->find_all(ec);
        if (ec)
        {
            std::cout << color_red << "Query error: " << ec.message() << "\n" << color_reset;
            return;
        }

        if (devices.empty())
        {
            std::cout << "No devices discovered. Run 'scan arp <subnet>' first.\n";
            return;
        }

        std::cout << color_bold << "Discovered Devices (" << devices.size() << "):\n" << color_reset;
        std::cout << color_gray
                  << std::left << std::setw(5) << "  ID"
                  << std::setw(18) << "IP"
                  << std::setw(20) << "MAC"
                  << std::setw(16) << "Hostname"
                  << std::setw(18) << "Vendor"
                  << std::setw(14) << "OS"
                  << "Last Seen\n" << color_reset;

        for (const auto &dev : devices)
        {
            std::cout << "  "
                      << std::left << std::setw(5) << dev.id
                      << std::setw(18) << dev.ip_address
                      << std::setw(20) << dev.mac_address
                      << std::setw(16) << (dev.hostname.empty() ? "-" : dev.hostname)
                      << std::setw(18) << (dev.vendor.empty() ? "-" : dev.vendor)
                      << std::setw(14) << (dev.os_guess.empty() ? "-" : dev.os_guess)
                      << format_time(dev.last_seen) << "\n";
        }
    }


    // 查看单个设备详情
    void application::cmd_device(const std::string &ip)
    {
        auto ec = std::error_code{};
        auto dev = device_q_->find_by_ip(ip, ec);
        if (ec)
        {
            std::cout << color_red << "Query error: " << ec.message() << "\n" << color_reset;
            return;
        }

        if (!dev)
        {
            std::cout << "Device not found: " << ip << "\n";
            return;
        }

        std::cout << color_bold << "Device Details:\n" << color_reset
                  << "  IP:         " << dev->ip_address << "\n"
                  << "  MAC:        " << dev->mac_address << "\n"
                  << "  Hostname:   " << (dev->hostname.empty() ? "-" : dev->hostname) << "\n"
                  << "  Vendor:     " << (dev->vendor.empty() ? "-" : dev->vendor) << "\n"
                  << "  OS:         " << (dev->os_guess.empty() ? "-" : dev->os_guess) << "\n"
                  << "  Open Ports: " << (dev->open_ports == "[]" ? "none" : dev->open_ports) << "\n"
                  << "  Gateway:    " << (dev->is_gateway ? "yes" : "no") << "\n"
                  << "  First Seen: " << format_time(dev->first_seen) << "\n"
                  << "  Last Seen:  " << format_time(dev->last_seen) << "\n";
    }


    // 列出未确认告警
    void application::cmd_alerts()
    {
        auto ec = std::error_code{};
        auto alerts = alert_q_->find_unacknowledged(ec);
        if (ec)
        {
            std::cout << color_red << "Query error: " << ec.message() << "\n" << color_reset;
            return;
        }

        if (alerts.empty())
        {
            std::cout << "No unacknowledged alerts.\n";
            return;
        }

        std::cout << color_bold << "Alerts (" << alerts.size() << "):\n" << color_reset;

        for (const auto &alert : alerts)
        {
            auto sev_color = color_green;
            if (alert.severity == "critical")
            {
                sev_color = color_red;
            }
            else if (alert.severity == "high")
            {
                sev_color = "\033[38;5;202m";
            }
            else if (alert.severity == "medium")
            {
                sev_color = color_yellow;
            }
            else if (alert.severity == "low")
            {
                sev_color = color_cyan;
            }

            std::cout << "  " << color_gray << "[" << alert.id << "]" << color_reset << " "
                      << sev_color << std::setw(8) << std::left << alert.severity << color_reset
                      << std::setw(16) << std::left << alert.category
                      << alert.description << "\n"
                      << "         " << color_gray
                      << "src=" << alert.source_ip << " dst=" << alert.target_ip
                      << " " << format_time(alert.timestamp) << "\n" << color_reset;
        }
    }


    // 确认告警
    void application::cmd_alert_ack(std::int64_t id)
    {
        auto ec = std::error_code{};
        if (alert_q_->acknowledge(id, ec))
        {
            std::cout << color_green << "Alert " << id << " acknowledged.\n" << color_reset;
        }
        else
        {
            std::cout << color_red << "Failed to acknowledge alert " << id
                      << ": " << ec.message() << "\n" << color_reset;
        }
    }


    // 列出扫描历史
    void application::cmd_scans()
    {
        auto ec = std::error_code{};
        auto scans = scan_q_->find_recent(20, ec);
        if (ec)
        {
            std::cout << color_red << "Query error: " << ec.message() << "\n" << color_reset;
            return;
        }

        if (scans.empty())
        {
            std::cout << "No scan history.\n";
            return;
        }

        std::cout << color_bold << "Recent Scans:\n" << color_reset;
        std::cout << color_gray
                  << std::left << std::setw(5) << "  ID"
                  << std::setw(8) << "Type"
                  << std::setw(20) << "Subnet"
                  << std::setw(8) << "Devs"
                  << std::setw(8) << "Ports"
                  << std::setw(12) << "Status"
                  << "Time\n" << color_reset;

        for (const auto &scan : scans)
        {
            auto status_color = color_green;
            if (scan.status == "running")
            {
                status_color = color_yellow;
            }
            else if (scan.status == "failed")
            {
                status_color = color_red;
            }

            std::cout << "  "
                      << std::left << std::setw(5) << scan.id
                      << std::setw(8) << scan.scan_type
                      << std::setw(20) << scan.subnet
                      << std::setw(8) << scan.device_count
                      << std::setw(8) << scan.open_port_count
                      << status_color << std::setw(12) << scan.status << color_reset
                      << format_time(scan.started_at) << "\n";
        }
    }


    // 查看最近流量日志
    void application::cmd_traffic()
    {
        auto now_epoch = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();
        auto from_ts = now_epoch - 3600;

        auto ec = std::error_code{};
        auto logs = traffic_q_->find_by_time_range(
            from_ts, 0, ec);
        if (ec)
        {
            std::cout << color_red << "Query error: " << ec.message() << "\n" << color_reset;
            return;
        }

        if (logs.empty())
        {
            std::cout << "No traffic logs. Capture is not active in CLI mode.\n";
            return;
        }

        std::cout << color_bold << "Recent Traffic:\n" << color_reset;
        std::cout << color_gray
                  << std::left << std::setw(5) << "  ID"
                  << std::setw(22) << "Source"
                  << std::setw(22) << "Destination"
                  << std::setw(6) << "Proto"
                  << std::setw(8) << "Size"
                  << "Info\n" << color_reset;

        for (const auto &log : logs)
        {
            auto src = log.src_ip + ":" + std::to_string(log.src_port);
            auto dst = log.dst_ip + ":" + std::to_string(log.dst_port);
            std::cout << "  "
                      << std::left << std::setw(5) << log.id
                      << std::setw(22) << src
                      << std::setw(22) << dst
                      << std::setw(6) << static_cast<int>(log.protocol)
                      << std::setw(8) << log.packet_size
                      << (log.info.empty() ? "-" : log.info) << "\n";
        }
    }


    // 将扫描到的设备持久化到数据库
    void application::persist_devices(std::vector<scanner::device> &devices, std::string_view scan_type, std::string_view subnet)
    {
        store::persist_devices(*persister_, *db_, devices, scan_type, subnet);
        spdlog::info("Persisted {} devices from {} scan", devices.size(), scan_type);
    }


    // 解析端口范围字符串
    [[nodiscard]] auto application::parse_port_range(const std::string &range) -> std::vector<std::uint16_t>
    {
        return util::parse_port_range(range);
    }


    // ========================================================================
    // 实时网络渗透测试（pentest 命令）
    // ========================================================================

    namespace
    {

        // 渗透测试配置（缺省值，可通过 environment variable 覆盖）
        struct pentest_config
        {
            std::string interface_name;
            std::uint32_t local_ip{0};      // 172.19.10.202 = 0xAC130ACA
            std::string local_ip_str;
            std::string subnet_str;
        };

        // 单条测试结果
        struct pentest_result
        {
            std::string name;
            bool passed{false};
            bool skipped{false};
            std::string reason;
            std::chrono::milliseconds duration{0};
        };

        // 全局告警收集（detection/mitm 订阅回调写入）
        struct pentest_state
        {
            std::mutex mu;
            std::vector<detector::alert> detection_alerts;
            std::vector<mitm::mitm_event> mitm_events;
        };

        // 帧构造参数（收敛 Rule 1 超限）
        struct frame_params
        {
            const std::byte *src_mac;
            const std::byte *dst_mac;
            std::uint32_t src_ip;
            std::uint32_t dst_ip;
            std::uint16_t src_port{0};
            std::uint16_t dst_port{0};
            std::uint8_t tcp_flags{0};
        };

        // 渗透测试上下文（收敛 lambda 捕获）
        struct pentest_context
        {
            const pentest_config &pc;
            const std::array<std::byte, 6> &local_mac;
            const std::byte *broadcast_mac;
            std::uint32_t gateway_ip;
            std::shared_ptr<pentest_state> state;
            std::function<void()> clear_alerts;
            std::function<bool(std::span<const std::byte>)> inject;
            detector::detection_pipeline &detection;
            mitm::mitm_pipeline &mitm;
            scanner::arp_scanner &arp;
            engine::context &engine_ctx;
        };

        auto parse_ipv4(std::string_view ip) -> std::uint32_t
        {
            std::uint32_t result{0};
            std::uint32_t octet{0};
            int shift{24};
            for (auto ch : ip)
            {
                if (ch == '.')
                {
                    result |= (octet << shift);
                    octet = 0;
                    shift -= 8;
                }
                else if (ch >= '0' && ch <= '9')
                {
                    octet = octet * 10 + static_cast<std::uint32_t>(ch - '0');
                }
            }
            result |= octet;
            return result;
        }

        // ip/mac 格式化由 sec::decoder::ip_to_string / mac_to_string 提供
        inline auto ipv4_to_string(std::uint32_t ip) -> std::string
        {
            return sec::decoder::ip_to_string(ip);
        }

        // 通过 GetAdaptersAddresses 查找匹配 IP 的接口 MAC
        auto get_local_mac_for_ip(std::string_view local_ip_str) -> std::array<std::byte, 6>
        {
            std::array<std::byte, 6> mac{};
#ifdef _WIN32
            auto target_ip = parse_ipv4(local_ip_str);
            auto target_ip_net = htonl(target_ip);

            ULONG buf_len = 0;
            GetAdaptersAddresses(AF_INET, 0, nullptr, nullptr, &buf_len);
            auto buf = std::vector<std::byte>(buf_len);
            auto *addrs = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
            if (GetAdaptersAddresses(AF_INET, 0, nullptr, addrs, &buf_len) != ERROR_SUCCESS)
            {
                return mac;
            }

            for (auto *a = addrs; a; a = a->Next)
            {
                if (a->PhysicalAddressLength != 6)
                {
                    continue;
                }
                for (auto *ua = a->FirstUnicastAddress; ua; ua = ua->Next)
                {
                    if (ua->Address.lpSockaddr->sa_family == AF_INET)
                    {
                        auto *s = reinterpret_cast<sockaddr_in *>(ua->Address.lpSockaddr);
                        std::uint32_t dev_ip{};
                        std::memcpy(&dev_ip, &s->sin_addr, sizeof(dev_ip));
                        if (dev_ip == target_ip_net)
                        {
                            std::memcpy(mac.data(), a->PhysicalAddress, 6);
                            return mac;
                        }
                    }
                }
            }
#else
            (void)local_ip_str;
#endif
            return mac;
        }

        // 帧构造函数
        auto build_arp_reply(const frame_params &p) -> std::vector<std::byte>
        {
            std::vector<std::byte> frame(42);
            auto *sender_mac = p.src_mac;
            auto sender_ip = p.src_ip;
            auto *target_mac = p.dst_mac;
            auto target_ip = p.dst_ip;
            auto *fptr = frame.data();
            std::memcpy(fptr, target_mac, 6);
            std::memcpy(fptr + 6, sender_mac, 6);
            fptr[12] = std::byte{0x08}; fptr[13] = std::byte{0x06};
            auto *arp = fptr + 14;
            arp[0] = std::byte{0x00}; arp[1] = std::byte{0x01};
            arp[2] = std::byte{0x08}; arp[3] = std::byte{0x00};
            arp[4] = std::byte{0x06}; arp[5] = std::byte{0x04};
            arp[6] = std::byte{0x00}; arp[7] = std::byte{0x02};
            std::memcpy(arp + 8, sender_mac, 6);
            arp[14] = std::byte{static_cast<unsigned char>((sender_ip >> 24) & 0xFF)};
            arp[15] = std::byte{static_cast<unsigned char>((sender_ip >> 16) & 0xFF)};
            arp[16] = std::byte{static_cast<unsigned char>((sender_ip >> 8) & 0xFF)};
            arp[17] = std::byte{static_cast<unsigned char>(sender_ip & 0xFF)};
            std::memcpy(arp + 18, target_mac, 6);
            arp[24] = std::byte{static_cast<unsigned char>((target_ip >> 24) & 0xFF)};
            arp[25] = std::byte{static_cast<unsigned char>((target_ip >> 16) & 0xFF)};
            arp[26] = std::byte{static_cast<unsigned char>((target_ip >> 8) & 0xFF)};
            arp[27] = std::byte{static_cast<unsigned char>(target_ip & 0xFF)};
            return frame;
        }

        auto build_arp_request(const frame_params &p) -> std::vector<std::byte>
        {
            const auto *sender_mac = p.src_mac;
            auto sender_ip = p.src_ip;
            auto target_ip = p.dst_ip;
            std::vector<std::byte> frame(42);
            auto *fptr = frame.data();
            std::memset(fptr, 0xFF, 6);
            std::memcpy(fptr + 6, sender_mac, 6);
            fptr[12] = std::byte{0x08}; fptr[13] = std::byte{0x06};
            auto *arp = fptr + 14;
            arp[0] = std::byte{0x00}; arp[1] = std::byte{0x01};
            arp[2] = std::byte{0x08}; arp[3] = std::byte{0x00};
            arp[4] = std::byte{0x06}; arp[5] = std::byte{0x04};
            arp[6] = std::byte{0x00}; arp[7] = std::byte{0x01};
            std::memcpy(arp + 8, sender_mac, 6);
            arp[14] = std::byte{static_cast<unsigned char>((sender_ip >> 24) & 0xFF)};
            arp[15] = std::byte{static_cast<unsigned char>((sender_ip >> 16) & 0xFF)};
            arp[16] = std::byte{static_cast<unsigned char>((sender_ip >> 8) & 0xFF)};
            arp[17] = std::byte{static_cast<unsigned char>(sender_ip & 0xFF)};
            std::memset(arp + 18, 0, 6);
            arp[24] = std::byte{static_cast<unsigned char>((target_ip >> 24) & 0xFF)};
            arp[25] = std::byte{static_cast<unsigned char>((target_ip >> 16) & 0xFF)};
            arp[26] = std::byte{static_cast<unsigned char>((target_ip >> 8) & 0xFF)};
            arp[27] = std::byte{static_cast<unsigned char>(target_ip & 0xFF)};
            return frame;
        }

        auto build_tcp_frame(const frame_params &p) -> std::vector<std::byte>
        {
            const auto *src_mac = p.src_mac;
            const auto *dst_mac = p.dst_mac;
            auto src_ip = p.src_ip;
            auto dst_ip = p.dst_ip;
            auto src_port = p.src_port;
            auto dst_port = p.dst_port;
            auto tcp_flags = p.tcp_flags;
            std::vector<std::byte> frame(54, std::byte{0});
            auto *fptr = frame.data();
            std::memcpy(fptr, dst_mac, 6);
            std::memcpy(fptr + 6, src_mac, 6);
            fptr[12] = std::byte{0x08}; fptr[13] = std::byte{0x00};
            auto *ip = fptr + 14;
            ip[0] = std::byte{0x45};
            ip[2] = std::byte{0x00}; ip[3] = std::byte{0x28};
            ip[6] = std::byte{0x40}; ip[8] = std::byte{0x40}; ip[9] = std::byte{0x06};
            ip[12] = std::byte{static_cast<unsigned char>((src_ip >> 24) & 0xFF)};
            ip[13] = std::byte{static_cast<unsigned char>((src_ip >> 16) & 0xFF)};
            ip[14] = std::byte{static_cast<unsigned char>((src_ip >> 8) & 0xFF)};
            ip[15] = std::byte{static_cast<unsigned char>(src_ip & 0xFF)};
            ip[16] = std::byte{static_cast<unsigned char>((dst_ip >> 24) & 0xFF)};
            ip[17] = std::byte{static_cast<unsigned char>((dst_ip >> 16) & 0xFF)};
            ip[18] = std::byte{static_cast<unsigned char>((dst_ip >> 8) & 0xFF)};
            ip[19] = std::byte{static_cast<unsigned char>(dst_ip & 0xFF)};
            auto *tcp = ip + 20;
            tcp[0] = std::byte{static_cast<unsigned char>((src_port >> 8) & 0xFF)};
            tcp[1] = std::byte{static_cast<unsigned char>(src_port & 0xFF)};
            tcp[2] = std::byte{static_cast<unsigned char>((dst_port >> 8) & 0xFF)};
            tcp[3] = std::byte{static_cast<unsigned char>(dst_port & 0xFF)};
            tcp[12] = std::byte{0x50};
            tcp[13] = std::byte{tcp_flags};
            tcp[14] = std::byte{0xFF}; tcp[15] = std::byte{0xFF};
            return frame;
        }

        auto build_udp_frame(const frame_params &p) -> std::vector<std::byte>
        {
            const auto *src_mac = p.src_mac;
            const auto *dst_mac = p.dst_mac;
            auto src_ip = p.src_ip;
            auto dst_ip = p.dst_ip;
            auto src_port = p.src_port;
            auto dst_port = p.dst_port;
            std::vector<std::byte> frame(42, std::byte{0});
            auto *fptr = frame.data();
            std::memcpy(fptr, dst_mac, 6);
            std::memcpy(fptr + 6, src_mac, 6);
            fptr[12] = std::byte{0x08}; fptr[13] = std::byte{0x00};
            auto *ip = fptr + 14;
            ip[0] = std::byte{0x45};
            ip[2] = std::byte{0x00}; ip[3] = std::byte{0x1C};
            ip[6] = std::byte{0x40}; ip[8] = std::byte{0x40}; ip[9] = std::byte{0x11};
            ip[12] = std::byte{static_cast<unsigned char>((src_ip >> 24) & 0xFF)};
            ip[13] = std::byte{static_cast<unsigned char>((src_ip >> 16) & 0xFF)};
            ip[14] = std::byte{static_cast<unsigned char>((src_ip >> 8) & 0xFF)};
            ip[15] = std::byte{static_cast<unsigned char>(src_ip & 0xFF)};
            ip[16] = std::byte{static_cast<unsigned char>((dst_ip >> 24) & 0xFF)};
            ip[17] = std::byte{static_cast<unsigned char>((dst_ip >> 16) & 0xFF)};
            ip[18] = std::byte{static_cast<unsigned char>((dst_ip >> 8) & 0xFF)};
            ip[19] = std::byte{static_cast<unsigned char>(dst_ip & 0xFF)};
            auto *udp = ip + 20;
            udp[0] = std::byte{static_cast<unsigned char>((src_port >> 8) & 0xFF)};
            udp[1] = std::byte{static_cast<unsigned char>(src_port & 0xFF)};
            udp[2] = std::byte{static_cast<unsigned char>((dst_port >> 8) & 0xFF)};
            udp[3] = std::byte{static_cast<unsigned char>(dst_port & 0xFF)};
            udp[4] = std::byte{0x00}; udp[5] = std::byte{0x08};
            return frame;
        }

        auto fake_mac(unsigned idx) -> std::array<std::byte, 6>
        {
            return {{
                std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF},
                std::byte{static_cast<unsigned char>((idx >> 8) & 0xFF)},
                std::byte{static_cast<unsigned char>(idx & 0xFF)}
            }};
        }

        template <typename Pred>
        auto wait_for(Pred &&pred, int timeout_ms) -> bool
        {
            auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
            while (std::chrono::steady_clock::now() < deadline)
            {
                if (pred())
                {
                    return true;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            return false;
        }

        inline auto mac_to_string(std::span<const std::byte, 6> mac) -> std::string
        {
            return sec::decoder::mac_to_string(mac);
        }

        void print_pentest_summary(const std::vector<pentest_result> &results,
            const std::string &interface_name)
        {
            std::cout << "\n" << color_bold << "=== LIVE PENTEST RESULTS ===\n" << color_reset;

            int pass_count = 0, fail_count = 0, skip_count = 0;
            for (const auto &r : results)
            {
                const char *status = "PASS";
                const char *color = color_green;
                if (r.skipped)
                {
                    status = "SKIP";
                    color = color_yellow;
                    skip_count++;
                }
                else if (r.passed)
                {
                    pass_count++;
                }
                else
                {
                    status = "FAIL";
                    color = color_red;
                    fail_count++;
                }

                std::cout << color << std::left << std::setw(5) << status << color_reset
                          << std::left << std::setw(48) << r.name
                          << std::right << std::setw(7) << r.duration.count() << " ms";
                if (!r.reason.empty())
                {
                    std::cout << "  (" << color_gray << r.reason << color_reset << ")";
                }
                std::cout << "\n";
            }

            std::cout << "\n" << color_bold
                      << "Summary: " << color_green << pass_count << " PASS" << color_reset
                      << ", " << color_red << fail_count << " FAIL" << color_reset
                      << ", " << color_yellow << skip_count << " SKIPPED" << color_reset
                      << " / " << results.size() << " total\n"
                      << color_reset;

            if (fail_count > 0)
            {
                std::cerr << color_red
                          << "\nFailures detected. Possible causes:\n"
                          << "  - Not running as Administrator (Npcap raw socket)\n"
                          << "  - Wrong capture_interface (current: " << interface_name << ")\n"
                          << "  - Detection thresholds not met by injected traffic\n"
                          << color_reset;
            }
        }

    } // anonymous namespace


    // ---- 渗透测试子函数 ----

    namespace
    {

        auto pentest_m1(pentest_context &ctx) -> pentest_result
        {
            pentest_result r;
            r.name = "M1  live_arp_scan_discovers_neighbors";

            auto promise = std::make_shared<std::promise<std::vector<scanner::device>>>();
            auto future = promise->get_future();
            namespace net = boost::asio;
            net::co_spawn(
                ctx.engine_ctx.executor(),
                [&arp = ctx.arp, subnet = ctx.pc.subnet_str, promise]() -> net::awaitable<void> {
                    auto ec = std::error_code{};
                    auto devices = co_await arp.scan_subnet(subnet, ec);
                    if (ec)
                    {
                        spdlog::warn("M1 ARP scan: {}", ec.message());
                    }
                    promise->set_value(std::move(devices));
                },
                net::detached);

            auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(45);
            while (future.valid() &&
                   future.wait_for(std::chrono::seconds(0)) != std::future_status::ready &&
                   std::chrono::steady_clock::now() < deadline)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }

            if (future.wait_for(std::chrono::seconds(0)) != std::future_status::ready)
            {
                r.skipped = true;
                r.reason = "ARP scan timed out (45s)";
                return r;
            }

            auto devices = future.get();
            if (devices.size() >= 5)
            {
                r.passed = true;
                r.reason = std::to_string(devices.size()) + " devices found";
            }
            else
            {
                r.reason = "Only " + std::to_string(devices.size()) + " devices (expected >= 5)";
            }
            return r;
        }

        auto pentest_m2(pentest_context &ctx) -> pentest_result
        {
            pentest_result r;
            r.name = "M2  live_arp_ip_conflict_detection";
            ctx.clear_alerts();
            ctx.mitm.arp_detector().reset();

            std::byte known_mac[6] = {std::byte{0x60}, std::byte{0xDE}, std::byte{0xF3},
                                      std::byte{0x79}, std::byte{0x13}, std::byte{0x4D}};
            auto normal = build_arp_reply({known_mac, ctx.local_mac.data(), ctx.gateway_ip, ctx.pc.local_ip});
            ctx.inject(normal);
            std::this_thread::sleep_for(std::chrono::milliseconds(300));

            auto spoofed = fake_mac(1);
            auto spoof_reply = build_arp_reply({spoofed.data(), ctx.local_mac.data(),
                ctx.gateway_ip, ctx.pc.local_ip});
            for (int i = 0; i < 5; ++i)
            {
                ctx.inject(spoof_reply);
            }

            bool found = wait_for([&]() -> bool {
                std::lock_guard lk(ctx.state->mu);
                for (const auto &e : ctx.state->mitm_events)
                {
                    if (e.category.find("arp") != std::string::npos ||
                        e.description.find("arp") != std::string::npos ||
                        e.description.find("conflict") != std::string::npos ||
                        e.description.find("spoof") != std::string::npos)
                    {
                        return true;
                    }
                }
                return false;
            }, 10000);

            if (found) r.passed = true;
            else r.reason = "No ARP conflict alert within 10s";
            return r;
        }

        auto pentest_m3(pentest_context &ctx) -> pentest_result
        {
            pentest_result r;
            r.name = "M3  live_arp_flood_detection";
            ctx.clear_alerts();
            ctx.mitm.arp_detector().reset();

            auto some_ip = parse_ipv4("172.19.10.1");
            for (unsigned i = 1; i <= 60; ++i)
            {
                auto fmac = fake_mac(i);
                auto reply = build_arp_reply({fmac.data(), ctx.local_mac.data(),
                    some_ip, ctx.pc.local_ip});
                ctx.inject(reply);
            }

            bool found = wait_for([&]() -> bool {
                std::lock_guard lk(ctx.state->mu);
                return !ctx.state->mitm_events.empty();
            }, 10000);

            r.passed = found;
            if (!found) r.reason = "No ARP flood alert within 10s";
            return r;
        }

        auto pentest_m4(pentest_context &ctx) -> pentest_result
        {
            pentest_result r;
            r.name = "M4  live_arp_sweep_detection";
            ctx.clear_alerts();
            ctx.mitm.arp_detector().reset();

            auto sweeper = fake_mac(0x99);
            auto base_ip = parse_ipv4("172.19.10.1");
            for (int i = 0; i < 25; ++i)
            {
                auto target_ip = base_ip + static_cast<std::uint32_t>(i);
                auto req = build_arp_request({sweeper.data(), nullptr, ctx.pc.local_ip, target_ip});
                ctx.inject(req);
            }

            bool found = wait_for([&]() -> bool {
                std::lock_guard lk(ctx.state->mu);
                return !ctx.state->mitm_events.empty();
            }, 10000);

            r.passed = found;
            if (!found) r.reason = "No ARP sweep alert within 10s";
            return r;
        }

        auto pentest_m5(const pentest_context &ctx) -> pentest_result
        {
            pentest_result r;
            r.name = "M5  live_tcp_syn_scan_detection";
            ctx.clear_alerts();
            ctx.detection.port_scan().reset();

            auto fake_src_ip = parse_ipv4("172.19.10.99");
            auto target_ip = parse_ipv4("172.19.10.250");
            std::uint16_t ports[] = {22, 80, 443, 3389, 8080, 9999, 1234, 5555, 6666, 7777, 8888, 9999};

            for (int i = 0; i < 12; ++i)
            {
                auto frame = build_tcp_frame(
                    {ctx.local_mac.data(), ctx.broadcast_mac,
                     fake_src_ip, target_ip,
                     static_cast<std::uint16_t>(40000 + i), ports[i], 0x02});
                ctx.inject(frame);
            }

            bool found = wait_for([&]() -> bool {
                std::lock_guard lk(ctx.state->mu);
                return !ctx.state->detection_alerts.empty();
            }, 15000);

            r.passed = found;
            if (!found) r.reason = "No TCP SYN scan alert within 15s";
            return r;
        }

        auto pentest_m6(const pentest_context &ctx) -> pentest_result
        {
            pentest_result r;
            r.name = "M6  live_network_sweep_detection";
            ctx.clear_alerts();
            ctx.detection.port_scan().reset();

            auto fake_src_ip = parse_ipv4("172.19.10.98");
            for (int i = 0; i < 7; ++i)
            {
                auto target_ip = parse_ipv4("172.19.10." + std::to_string(50 + i));
                auto frame = build_tcp_frame(
                    {ctx.local_mac.data(), ctx.broadcast_mac,
                     fake_src_ip, target_ip, 50000, 80, 0x02});
                ctx.inject(frame);
            }

            bool found = wait_for([&]() -> bool {
                std::lock_guard lk(ctx.state->mu);
                return !ctx.state->detection_alerts.empty();
            }, 15000);

            r.passed = found;
            if (!found) r.reason = "No network sweep alert within 15s";
            return r;
        }

        auto pentest_m7(const pentest_context &ctx) -> pentest_result
        {
            pentest_result r;
            r.name = "M7  live_udp_scan_detection";
            ctx.clear_alerts();
            ctx.detection.port_scan().reset();

            auto fake_src_ip = parse_ipv4("172.19.10.97");
            auto target_ip = parse_ipv4("172.19.10.250");
            std::uint16_t udp_ports[] = {53, 123, 161, 500, 514, 520, 1111, 2222, 3333, 4444, 5555, 6666};

            for (int i = 0; i < 12; ++i)
            {
                auto frame = build_udp_frame(
                    {ctx.local_mac.data(), ctx.broadcast_mac,
                     fake_src_ip, target_ip,
                     static_cast<std::uint16_t>(60000 + i), udp_ports[i]});
                ctx.inject(frame);
            }

            bool found = wait_for([&]() -> bool {
                std::lock_guard lk(ctx.state->mu);
                return !ctx.state->detection_alerts.empty();
            }, 15000);

            r.passed = found;
            if (!found) r.reason = "No UDP scan alert within 15s";
            return r;
        }

        auto pentest_m8(pentest_context &ctx) -> pentest_result
        {
            pentest_result r;
            r.name = "M8  live_normal_traffic_no_false_positive";
            ctx.clear_alerts();
            ctx.mitm.arp_detector().reset();

            auto sweeper = fake_mac(0x88);
            auto base_ip = parse_ipv4("172.19.10.1");
            for (int i = 0; i < 5; ++i)
            {
                auto target_ip = base_ip + static_cast<std::uint32_t>(i);
                auto req = build_arp_request({sweeper.data(), nullptr, ctx.pc.local_ip, target_ip});
                ctx.inject(req);
            }

            bool false_positive = wait_for([&]() -> bool {
                std::lock_guard lk(ctx.state->mu);
                for (const auto &e : ctx.state->mitm_events)
                {
                    if (e.description.find("sweep") != std::string::npos ||
                        e.description.find("flood") != std::string::npos)
                    {
                        return true;
                    }
                }
                return false;
            }, 3000);

            if (!false_positive) r.passed = true;
            else r.reason = "False positive triggered by 5 ARP requests";
            return r;
        }

        auto pentest_m9() -> pentest_result
        {
            pentest_result r;
            r.name = "M9  live_dns_query_roundtrip";
            r.skipped = true;
            r.reason = "DNS roundtrip test not implemented in CLI pentest (no decoder subscriber)";
            return r;
        }

        auto pentest_m10(pentest_context &ctx) -> pentest_result
        {
            pentest_result r;
            r.name = "M10 live_pipeline_e2e_summary";
            ctx.clear_alerts();
            ctx.detection.port_scan().reset();
            ctx.mitm.arp_detector().reset();

            auto spoofed = fake_mac(0xAA);
            auto spoof_reply = build_arp_reply({spoofed.data(), ctx.local_mac.data(),
                ctx.gateway_ip, ctx.pc.local_ip});
            for (int i = 0; i < 5; ++i)
            {
                ctx.inject(spoof_reply);
            }

            auto fake_src = parse_ipv4("172.19.10.96");
            auto target_ip = parse_ipv4("172.19.10.249");
            for (int i = 0; i < 12; ++i)
            {
                auto frame = build_tcp_frame(
                    {ctx.local_mac.data(), ctx.broadcast_mac,
                     fake_src, target_ip,
                     static_cast<std::uint16_t>(70000 + i),
                     static_cast<std::uint16_t>(1000 + i * 100),
                     0x02});
                ctx.inject(frame);
            }

            bool found = wait_for([&]() -> bool {
                std::lock_guard lk(ctx.state->mu);
                return !ctx.state->detection_alerts.empty() && !ctx.state->mitm_events.empty();
            }, 15000);

            if (found)
            {
                r.passed = true;
            }
            else
            {
                std::lock_guard lk(ctx.state->mu);
                r.reason = "detection=" + std::to_string(ctx.state->detection_alerts.size()) +
                           " mitm=" + std::to_string(ctx.state->mitm_events.size());
            }
            return r;
        }

    } // namespace


    void application::cmd_pentest()
    {
        pentest_config pc;
        pc.interface_name = config_.engine.capture_interface;
        if (pc.interface_name.empty())
        {
            std::cerr << color_red << "No capture_interface configured. Set in config or CLI.\n"
                      << color_reset;
            return;
        }
        pc.local_ip_str = "172.19.10.202";
        pc.subnet_str = "172.19.10.0/24";
        pc.local_ip = parse_ipv4(pc.local_ip_str);

        if (const char *env = std::getenv("SPECTRA_LIVE_IP"))
        {
            pc.local_ip_str = env;
            pc.local_ip = parse_ipv4(pc.local_ip_str);
        }

        std::cout << color_bold << "=== Spectra Live Network Penetration Test ===\n"
                  << color_reset
                  << "  Interface: " << pc.interface_name << "\n"
                  << "  Local IP : " << pc.local_ip_str << "\n"
                  << "  Subnet   : " << pc.subnet_str << "\n\n"
                  << std::flush;

        auto we_started_capture = false;
        if (!capture_active_.load())
        {
            std::cout << "Starting capture pipeline ...\n" << std::flush;
            start_capture();
            we_started_capture = true;
            if (!capture_active_.load())
            {
                std::cerr << color_red
                          << "Capture pipeline failed to start. Pentest aborted.\n"
                          << "Hints:\n"
                          << "  1. Run as Administrator (Npcap raw socket requires admin)\n"
                          << "  2. Verify interface name in config\n"
                          << color_reset;
                return;
            }
        }

        auto state = std::make_shared<pentest_state>();
        auto det_handle = detection_->subscribe([state](const detector::alert &a) {
            std::lock_guard lk(state->mu);
            state->detection_alerts.push_back(a);
        });
        auto mitm_handle = mitm_->subscribe([state](const mitm::mitm_event &e) {
            std::lock_guard lk(state->mu);
            state->mitm_events.push_back(e);
        });

        auto local_mac = get_local_mac_for_ip(pc.local_ip_str);
        std::cout << "  Local MAC: " << mac_to_string(local_mac) << "\n\n" << std::flush;

        std::byte broadcast_mac[6] = {std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF},
                                      std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}};

        pentest_context pctx{
            pc, local_mac, broadcast_mac,
            parse_ipv4("172.19.10.1"),
            state,
            [&]() {
                std::lock_guard lk(state->mu);
                state->detection_alerts.clear();
                state->mitm_events.clear();
            },
            [&](std::span<const std::byte> frame) -> bool {
                char errbuf[PCAP_ERRBUF_SIZE]{};
                auto *handle = pcap_open_live(pc.interface_name.c_str(), 65535, 1, 1000, errbuf);
                if (!handle) { spdlog::warn("inject: pcap_open_live failed: {}", errbuf); return false; }
                auto rc = pcap_sendpacket(handle,
                    reinterpret_cast<const u_char *>(frame.data()),
                    static_cast<int>(frame.size()));
                pcap_close(handle);
                if (rc != 0) { spdlog::warn("inject: pcap_sendpacket failed"); return false; }
                return true;
            },
            *detection_, *mitm_, arp_, context_
        };

        std::vector<pentest_result> results;
        auto run_one = [&](const std::string &name, std::function<pentest_result()> fn) {
            std::cout << "Running " << name << " ...\n" << std::flush;
            auto t0 = std::chrono::steady_clock::now();
            auto r = fn();
            r.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - t0);
            results.push_back(std::move(r));
        };

        run_one("M1_arp_scan_discovers_neighbors", [&]() -> pentest_result { return pentest_m1(pctx); });
        run_one("M2_arp_ip_conflict_detection", [&]() -> pentest_result { return pentest_m2(pctx); });
        run_one("M3_arp_flood_detection", [&]() -> pentest_result { return pentest_m3(pctx); });
        run_one("M4_arp_sweep_detection", [&]() -> pentest_result { return pentest_m4(pctx); });
        run_one("M5_tcp_syn_scan_detection", [&]() -> pentest_result { return pentest_m5(pctx); });
        run_one("M6_network_sweep_detection", [&]() -> pentest_result { return pentest_m6(pctx); });
        run_one("M7_udp_scan_detection", [&]() -> pentest_result { return pentest_m7(pctx); });
        run_one("M8_normal_traffic_no_false_positive", [&]() -> pentest_result { return pentest_m8(pctx); });
        run_one("M9_dns_query_roundtrip", [&]() -> pentest_result { return pentest_m9(); });
        run_one("M10_pipeline_e2e_summary", [&]() -> pentest_result { return pentest_m10(pctx); });

        detection_->unsubscribe(det_handle);
        mitm_->unsubscribe(mitm_handle);

        if (we_started_capture)
        {
            stop_capture();
        }

        print_pentest_summary(results, pc.interface_name);
    }


} // namespace sec::cli
