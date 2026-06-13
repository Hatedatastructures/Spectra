// 命令注册表实现 — 所有 CLI 命令的 TUI 版本，返回 Markdown 格式

#include <sec/tui/command_registry.hpp>
#include <sec/tui/application.hpp>
#include <sec/tui/ai_chat.hpp>
#include <sec/scanner/fingerprint.hpp>
#include <sec/util/format.hpp>
#include <sec/util/string.hpp>
#include <sec/util/port.hpp>

#include <boost/asio.hpp>
#include <spdlog/spdlog.h>

#include <chrono>
#include <future>
#include <sstream>
#include <string>
#include <vector>


namespace sec::tui
{

    namespace
    {

        auto sev_emoji(const std::string &severity) -> std::string
        {
            if (severity == "critical") return "**CRITICAL**";
            if (severity == "high") return "*HIGH*";
            if (severity == "medium") return "MEDIUM";
            if (severity == "low") return "`LOW`";
            return severity;
        }

    } // anonymous namespace


    command_registry::command_registry(application &app)
        : app_{app}
    {
        register_builtin_commands();
    }


    auto command_registry::dispatch(const std::string &input) -> std::string
    {
        auto tokens = util::split(input, ' ');
        if (tokens.empty())
        {
            return "";
        }

        if (tokens.size() >= 2 && tokens[0] == "scan")
        {
            tokens.erase(tokens.begin());
        }
        if (tokens.size() >= 3 && tokens[0] == "alert" && tokens[1] == "ack")
        {
            auto id = std::move(tokens[2]);
            tokens.clear();
            tokens.emplace_back("ack");
            tokens.emplace_back(std::move(id));
        }

        auto cmd = tokens[0];
        for (auto &entry : entries_)
        {
            if (entry.name == cmd)
            {
                return entry.execute(tokens);
            }
        }

        auto ss = std::ostringstream{};
        ss << "**Unknown command:** `" << cmd << "`\n\n";
        ss << "Type `help` for available commands.\n";
        return ss.str();
    }


    auto command_registry::complete(std::string_view partial) const -> std::vector<std::string>
    {
        auto result = std::vector<std::string>{};
        for (const auto &entry : entries_)
        {
            if (entry.name.size() >= partial.size() &&
                entry.name.substr(0, partial.size()) == partial)
            {
                result.push_back(entry.name);
            }
        }
        return result;
    }


    auto command_registry::commands() const noexcept -> const std::vector<command_entry> &
    {
        return entries_;
    }


    void command_registry::register_builtin_commands()
    {
        register_help();
        register_arp();
        register_mdns();
        register_ssdp();
        register_port();
        register_devices();
        register_device();
        register_alerts();
        register_ack();
        register_scans();
        register_traffic();
        register_ai();
        register_api();
    }


    void command_registry::register_help()
    {
        entries_.push_back({
            "help", "help",
            "Show all available commands",
            [](const std::vector<std::string> &) -> std::string
            {
                auto ss = std::ostringstream{};
                ss << "## Available Commands\n\n";
                ss << "| Command | Usage | Description |\n";
                ss << "| --- | --- | --- |\n";
                ss << "| `arp` | `arp <subnet>` | ARP scan a subnet |\n";
                ss << "| `mdns` | `mdns` | Discover devices via mDNS |\n";
                ss << "| `ssdp` | `ssdp` | Discover devices via SSDP/UPnP |\n";
                ss << "| `port` | `port <ip> [range]` | TCP port scan |\n";
                ss << "| `devices` | `devices` | List all discovered devices |\n";
                ss << "| `device` | `device <ip>` | Show device details |\n";
                ss << "| `alerts` | `alerts` | Show unacknowledged alerts |\n";
                ss << "| `ack` | `ack <id>` | Acknowledge an alert |\n";
                ss << "| `scans` | `scans` | Show scan history |\n";
                ss << "| `traffic` | `traffic` | Show recent traffic logs |\n";
                ss << "| `ai` | `ai [on/off/remote]` | AI mode control |\n";
                ss << "| `api` | `api <endpoint> <key> [model] [proto]` | Configure remote AI (openai/anthropic) |\n";
                ss << "| `help` | `help` | Show this help |\n\n";
                ss << "> **Tip:** Press `Ctrl+T` to switch between command and chat mode.\n";
                return ss.str();
            }
        });
    }


    void command_registry::register_arp()
    {
        entries_.push_back({
            "arp", "arp <subnet>", "ARP scan a subnet",
            [this](const std::vector<std::string> &args) -> std::string
            {
                if (args.size() < 2)
                {
                    return "**Usage:** `arp <subnet>` (e.g. `arp 192.168.1.0/24`)\n";
                }
                auto subnet = args[1];
                auto promise = std::make_shared<std::promise<std::vector<scanner::device>>>();
                auto future = promise->get_future();

                namespace net = boost::asio;
                net::co_spawn(
                    app_.context().executor(),
                    [this, subnet, promise]() -> net::awaitable<void>
                    {
                        try
                        {
                            auto ec = std::error_code{};
                            auto devices = co_await app_.arp().scan_subnet(subnet, ec);
                            if (ec) { spdlog::error("ARP scan error: {}", ec.message()); }
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
                for (auto &dev : devices) { scanner::fingerprint::identify(dev); }
                {
                    auto ec_begin = std::error_code{};
                    static_cast<void>(app_.persister().begin_scan("arp", subnet, ec_begin));
                }

                if (devices.empty())
                {
                    return "No devices found on " + subnet + ".\n";
                }

                auto ss = std::ostringstream{};
                ss << "## ARP Scan Results\n\n";
                ss << "Found **" << devices.size() << "** device(s) on `" << subnet << "`\n\n";
                ss << "| IP | MAC | Hostname | Vendor | OS | Gateway |\n";
                ss << "| --- | --- | --- | --- | --- | --- |\n";
                for (const auto &dev : devices)
                {
                    ss << "| " << dev.ip_address
                       << " | " << std::string{dev.mac_address}
                       << " | " << (dev.hostname.empty() ? "-" : std::string{dev.hostname})
                       << " | " << (dev.vendor.empty() ? "-" : std::string{dev.vendor})
                       << " | " << (dev.os_guess.empty() ? "-" : std::string{dev.os_guess})
                       << " | " << (dev.is_gateway ? "yes" : "no")
                       << " |\n";
                }
                return ss.str();
            }
        });
    }


    void command_registry::register_mdns()
    {
        entries_.push_back({
            "mdns", "mdns", "Discover devices via mDNS",
            [this](const std::vector<std::string> &) -> std::string
            {
                auto promise = std::make_shared<std::promise<std::vector<scanner::device>>>();
                auto future = promise->get_future();

                namespace net = boost::asio;
                net::co_spawn(
                    app_.context().executor(),
                    [this, promise]() -> net::awaitable<void>
                    {
                        try
                        {
                            auto ec = std::error_code{};
                            auto devices = co_await app_.mdns().scan(ec);
                            if (ec) { spdlog::error("mDNS scan error: {}", ec.message()); }
                            promise->set_value(std::move(devices));
                        }
                        catch (const std::exception &e)
                        {
                            spdlog::error("mDNS scan exception: {}", e.what());
                            promise->set_value({});
                        }
                    },
                    net::detached);

                auto devices = future.get();
                for (auto &dev : devices) { scanner::fingerprint::identify(dev); }

                if (devices.empty())
                {
                    return "No mDNS services found.\n";
                }

                auto ss = std::ostringstream{};
                ss << "## mDNS Services\n\n";
                ss << "Found **" << devices.size() << "** service(s)\n\n";
                ss << "| Hostname | IP | Vendor |\n";
                ss << "| --- | --- | --- |\n";
                for (const auto &dev : devices)
                {
                    ss << "| " << std::string{dev.hostname}
                       << " | " << dev.ip_address
                       << " | " << (dev.vendor.empty() ? "-" : std::string{dev.vendor})
                       << " |\n";
                }
                return ss.str();
            }
        });
    }


    void command_registry::register_ssdp()
    {
        entries_.push_back({
            "ssdp", "ssdp", "Discover devices via SSDP/UPnP",
            [this](const std::vector<std::string> &) -> std::string
            {
                auto promise = std::make_shared<std::promise<std::vector<scanner::device>>>();
                auto future = promise->get_future();

                namespace net = boost::asio;
                net::co_spawn(
                    app_.context().executor(),
                    [this, promise]() -> net::awaitable<void>
                    {
                        try
                        {
                            auto ec = std::error_code{};
                            auto devices = co_await app_.ssdp().scan(ec);
                            if (ec) { spdlog::error("SSDP scan error: {}", ec.message()); }
                            promise->set_value(std::move(devices));
                        }
                        catch (const std::exception &e)
                        {
                            spdlog::error("SSDP scan exception: {}", e.what());
                            promise->set_value({});
                        }
                    },
                    net::detached);

                auto devices = future.get();
                for (auto &dev : devices) { scanner::fingerprint::identify(dev); }

                if (devices.empty())
                {
                    return "No UPnP devices found.\n";
                }

                auto ss = std::ostringstream{};
                ss << "## SSDP/UPnP Devices\n\n";
                ss << "Found **" << devices.size() << "** device(s)\n\n";
                ss << "| Hostname | IP | Vendor |\n";
                ss << "| --- | --- | --- |\n";
                for (const auto &dev : devices)
                {
                    ss << "| " << std::string{dev.hostname}
                       << " | " << dev.ip_address
                       << " | " << (dev.vendor.empty() ? "-" : std::string{dev.vendor})
                       << " |\n";
                }
                return ss.str();
            }
        });
    }


    void command_registry::register_port()
    {
        entries_.push_back({
            "port", "port <ip> [range]", "TCP port scan",
            [this](const std::vector<std::string> &args) -> std::string
            {
                if (args.size() < 2)
                {
                    return "**Usage:** `port <ip> [range]` (e.g. `port 192.168.1.1 1-1024`)\n";
                }
                auto ip = args[1];
                auto range = args.size() >= 3 ? args[2] : std::string{"1-1024"};
                auto ports = util::parse_port_range(range);
                if (ports.empty())
                {
                    return "**Invalid port range:** `" + range + "`\n";
                }

                auto promise = std::make_shared<std::promise<std::vector<std::uint16_t>>>();
                auto future = promise->get_future();

                namespace net = boost::asio;
                net::co_spawn(
                    app_.context().executor(),
                    [this, ip, ports = std::move(ports), promise]() -> net::awaitable<void>
                    {
                        try
                        {
                            auto ec = std::error_code{};
                            auto opts = scanner::port_scan_options{};
                            opts.ports = ports;
                            opts.timeout_ms = app_.config().scanner.port_timeout_ms;
                            auto open = co_await app_.port().scan(ip, opts, ec);
                            if (ec) { spdlog::error("Port scan error: {}", ec.message()); }
                            promise->set_value(std::move(open));
                        }
                        catch (const std::exception &e)
                        {
                            spdlog::error("Port scan exception: {}", e.what());
                            promise->set_value({});
                        }
                    },
                    net::detached);

                auto open_ports = future.get();

                if (open_ports.empty())
                {
                    return "No open ports found on `" + ip + "` range `" + range + "`.\n";
                }

                auto ss = std::ostringstream{};
                ss << "## Port Scan: `" << ip << "`\n\n";
                ss << "Range: `" << range << "` (" << ports.size() << " ports)\n\n";
                ss << "**Open ports:** ";
                for (std::size_t i = 0; i < open_ports.size(); ++i)
                {
                    if (i > 0) ss << ", ";
                    ss << "`" << open_ports[i] << "`";
                }
                ss << "\n";
                return ss.str();
            }
        });
    }


    void command_registry::register_devices()
    {
        entries_.push_back({
            "devices", "devices", "List all discovered devices",
            [this](const std::vector<std::string> &) -> std::string
            {
                auto ec = std::error_code{};
                auto devices = app_.device_query().find_all(ec);
                if (ec)
                {
                    return "**Query error:** " + ec.message() + "\n";
                }
                if (devices.empty())
                {
                    return "No devices discovered yet. Run `arp <subnet>` first.\n";
                }

                auto ss = std::ostringstream{};
                ss << "## Discovered Devices (" << devices.size() << ")\n\n";
                ss << "| ID | IP | MAC | Hostname | Vendor | OS | Last Seen |\n";
                ss << "| --- | --- | --- | --- | --- | --- | --- |\n";
                for (const auto &dev : devices)
                {
                    ss << "| " << dev.id
                       << " | `" << dev.ip_address << "`"
                       << " | " << dev.mac_address
                       << " | " << (dev.hostname.empty() ? "-" : dev.hostname)
                       << " | " << (dev.vendor.empty() ? "-" : dev.vendor)
                       << " | " << (dev.os_guess.empty() ? "-" : dev.os_guess)
                       << " | " << util::format_time(dev.last_seen)
                       << " |\n";
                }
                return ss.str();
            }
        });
    }


    void command_registry::register_device()
    {
        entries_.push_back({
            "device", "device <ip>", "Show device details",
            [this](const std::vector<std::string> &args) -> std::string
            {
                if (args.size() < 2)
                {
                    return "**Usage:** `device <ip>`\n";
                }
                auto ec = std::error_code{};
                auto dev = app_.device_query().find_by_ip(args[1], ec);
                if (ec)
                {
                    return "**Query error:** " + ec.message() + "\n";
                }
                if (!dev)
                {
                    return "**Device not found:** `" + args[1] + "`\n";
                }

                auto ss = std::ostringstream{};
                ss << "## Device Details\n\n";
                ss << "| Field | Value |\n| --- | --- |\n";
                ss << "| **IP** | `" << dev->ip_address << "` |\n";
                ss << "| **MAC** | `" << dev->mac_address << "` |\n";
                ss << "| **Hostname** | " << (dev->hostname.empty() ? "-" : dev->hostname) << " |\n";
                ss << "| **Vendor** | " << (dev->vendor.empty() ? "-" : dev->vendor) << " |\n";
                ss << "| **OS** | " << (dev->os_guess.empty() ? "-" : dev->os_guess) << " |\n";
                ss << "| **Open Ports** | " << (dev->open_ports == "[]" ? "none" : dev->open_ports) << " |\n";
                ss << "| **Gateway** | " << (dev->is_gateway ? "yes" : "no") << " |\n";
                ss << "| **First Seen** | " << util::format_time(dev->first_seen) << " |\n";
                ss << "| **Last Seen** | " << util::format_time(dev->last_seen) << " |\n";
                return ss.str();
            }
        });
    }


    void command_registry::register_alerts()
    {
        entries_.push_back({
            "alerts", "alerts", "Show unacknowledged alerts",
            [this](const std::vector<std::string> &) -> std::string
            {
                auto ec = std::error_code{};
                auto alerts = app_.alert_query().find_unacknowledged(ec);
                if (ec)
                {
                    return "**Query error:** " + ec.message() + "\n";
                }
                if (alerts.empty())
                {
                    return "No unacknowledged alerts.\n";
                }

                auto ss = std::ostringstream{};
                ss << "## Unacknowledged Alerts (" << alerts.size() << ")\n\n";
                ss << "| ID | Severity | Category | Description |\n";
                ss << "| --- | --- | --- | --- |\n";
                for (const auto &alert : alerts)
                {
                    ss << "| " << alert.id
                       << " | " << sev_emoji(alert.severity)
                       << " | " << alert.category
                       << " | " << alert.description
                       << " |\n";
                    ss << "| | | | `src=" << alert.source_ip
                       << " dst=" << alert.target_ip
                       << " " << util::format_time(alert.timestamp) << "` |\n";
                }
                return ss.str();
            }
        });
    }


    void command_registry::register_ack()
    {
        entries_.push_back({
            "ack", "ack <id>", "Acknowledge an alert",
            [this](const std::vector<std::string> &args) -> std::string
            {
                if (args.size() < 2)
                {
                    return "**Usage:** `ack <id>`\n";
                }
                try
                {
                    auto id = std::stoll(args[1]);
                    auto ec = std::error_code{};
                    if (app_.alert_query().acknowledge(id, ec))
                    {
                        return "Alert `" + std::to_string(id) + "` acknowledged.\n";
                    }
                    return "**Failed to acknowledge alert `" + std::to_string(id) + "`:** " + ec.message() + "\n";
                }
                catch (const std::exception &)
                {
                    return "**Invalid alert ID:** `" + args[1] + "`\n";
                }
            }
        });
    }


    void command_registry::register_scans()
    {
        entries_.push_back({
            "scans", "scans", "Show scan history",
            [this](const std::vector<std::string> &) -> std::string
            {
                auto ec = std::error_code{};
                auto scans = app_.scan_query().find_recent(20, ec);
                if (ec)
                {
                    return "**Query error:** " + ec.message() + "\n";
                }
                if (scans.empty())
                {
                    return "No scan history.\n";
                }

                auto ss = std::ostringstream{};
                ss << "## Recent Scans\n\n";
                ss << "| ID | Type | Subnet | Devices | Ports | Status | Time |\n";
                ss << "| --- | --- | --- | --- | --- | --- | --- |\n";
                for (const auto &scan : scans)
                {
                    ss << "| " << scan.id
                       << " | " << scan.scan_type
                       << " | " << scan.subnet
                       << " | " << scan.device_count
                       << " | " << scan.open_port_count
                       << " | " << scan.status
                       << " | " << util::format_time(scan.started_at)
                       << " |\n";
                }
                return ss.str();
            }
        });
    }


    void command_registry::register_traffic()
    {
        entries_.push_back({
            "traffic", "traffic", "Show recent traffic logs",
            [this](const std::vector<std::string> &) -> std::string
            {
                auto now_epoch = std::chrono::duration_cast<std::chrono::seconds>(
                                     std::chrono::system_clock::now().time_since_epoch())
                                     .count();
                auto ec = std::error_code{};
                auto logs = app_.traffic_query().find_by_time_range(now_epoch - 3600, 0, ec);
                if (ec)
                {
                    return "**Query error:** " + ec.message() + "\n";
                }
                if (logs.empty())
                {
                    return "No traffic logs in the last hour.\n";
                }

                auto ss = std::ostringstream{};
                ss << "## Recent Traffic (last hour)\n\n";
                ss << "| ID | Source | Destination | Proto | Size | Info |\n";
                ss << "| --- | --- | --- | --- | --- | --- |\n";
                for (const auto &log : logs)
                {
                    auto src = log.src_ip + ":" + std::to_string(log.src_port);
                    auto dst = log.dst_ip + ":" + std::to_string(log.dst_port);
                    ss << "| " << log.id
                       << " | `" << src << "`"
                       << " | `" << dst << "`"
                       << " | " << static_cast<int>(log.protocol)
                       << " | " << log.packet_size
                       << " | " << (log.info.empty() ? "-" : log.info)
                       << " |\n";
                }
                return ss.str();
            }
        });
    }


    void command_registry::register_ai()
    {
        entries_.push_back({
            "ai", "ai [on/off/remote]", "AI mode control",
            [this](const std::vector<std::string> &args) -> std::string
            {
                if (args.size() < 2)
                {
                    auto mode_str = std::string{"off"};
                    auto m = app_.chat().mode();
                    if (m == ai_mode::remote) mode_str = "remote";
                    return "Current AI mode: **" + mode_str + "**\n\nUsage: `ai [on|off|remote]`\n";
                }
                auto sub = args[1];
                if (sub == "on" || sub == "remote")
                {
                    app_.chat().set_mode(ai_mode::remote);
                    return "AI mode set to **remote** (OpenAI / Anthropic API).\n";
                }
                if (sub == "off")
                {
                    app_.chat().set_mode(ai_mode::off);
                    return "AI mode set to **off**.\n";
                }
                return "**Unknown AI mode:** `" + sub + "`. Use `on`, `off`, or `remote`.\n";
            }
        });
    }


    void command_registry::register_api()
    {
        entries_.push_back({
            "api", "api <endpoint> <key> [model] [protocol]", "Configure remote AI API",
            [this](const std::vector<std::string> &args) -> std::string
            {
                if (args.size() < 3)
                {
                    return "**Usage:** `api <endpoint> <api_key> [model_name] [protocol]`\n\n"
                           "Protocols: `openai` (default), `anthropic`\n\n"
                           "Examples:\n"
                           "- `api https://api.openai.com/v1/chat/completions sk-xxx gpt-4o`\n"
                           "- `api https://api.anthropic.com/v1/messages sk-xxx claude-sonnet-4-20250514 anthropic`\n";
                }
                auto cfg = remote_config{};
                cfg.endpoint = args[1];
                cfg.api_key = args[2];
                if (args.size() >= 4)
                {
                    cfg.model = args[3];
                }
                if (args.size() >= 5 && args[4] == "anthropic")
                {
                    cfg.protocol = api_protocol::anthropic;
                }
                else
                {
                    // 自动检测：endpoint 包含 "anthropic" 则使用 Anthropic 协议
                    if (cfg.endpoint.find("anthropic") != std::string::npos)
                    {
                        cfg.protocol = api_protocol::anthropic;
                    }
                }
                app_.chat().set_remote(cfg);
                auto proto_str = cfg.protocol == api_protocol::anthropic ? "anthropic" : "openai";
                return "Remote AI configured.\n\n"
                       "- Endpoint: `" + cfg.endpoint + "`\n"
                       "- Model: `" + cfg.model + "`\n"
                       "- Protocol: `" + proto_str + "`\n";
            }
        });
    }


} // namespace sec::tui
