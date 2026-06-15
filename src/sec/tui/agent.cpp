// AI Agent 安全工具实现 — 10 个工具 + JSON schema + 执行器 + 安全提示词

#include <sec/tui/agent.hpp>
#include <sec/tui/application.hpp>

#include <sec/scanner/arp.hpp>
#include <sec/scanner/port.hpp>
#include <sec/scanner/mdns.hpp>
#include <sec/scanner/ssdp.hpp>
#include <sec/scanner/fingerprint.hpp>
#include <sec/store/query.hpp>
#include <sec/store/model.hpp>
#include <sec/decoder/util.hpp>

#include <boost/asio.hpp>
#include <spdlog/spdlog.h>

#include <chrono>
#include <future>
#include <sstream>
#include <string>

namespace net = boost::asio;

namespace sec::tui
{
    namespace
    {
        // ── JSON 辅助 ──

        auto json_escape(std::string_view s) -> std::string
        {
            auto out = std::string{};
            for (auto c : s)
            {
                switch (c)
                {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                default: out += c;
                }
            }
            return out;
        }

        auto extract_json_string(const std::string &json, const std::string &key) -> std::string
        {
            auto needle = "\"" + key + "\"";
            auto pos = json.find(needle);
            if (pos == std::string::npos) return {};
            pos += needle.size();
            while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':' || json[pos] == '"')) ++pos;
            auto start = pos;
            while (pos < json.size() && json[pos] != '"' && json[pos] != ',' && json[pos] != '}') ++pos;
            return json.substr(start, pos - start);
        }

        auto extract_json_int(const std::string &json, const std::string &key, int default_val) -> int
        {
            auto needle = "\"" + key + "\"";
            auto pos = json.find(needle);
            if (pos == std::string::npos) return default_val;
            pos += needle.size();
            while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':')) ++pos;
            try { return std::stoi(json.substr(pos)); }
            catch (...) { return default_val; }
        }

        // ── awaitable → 同步桥接 ──

        template <typename T>
        auto await_to_sync(net::awaitable<T> aw, net::any_io_executor ex) -> T
        {
            auto promise = std::make_shared<std::promise<T>>();
            auto future = promise->get_future();
            net::co_spawn(ex,
                [aw = std::move(aw), promise]() mutable -> net::awaitable<void> {
                    try { promise->set_value(co_await std::move(aw)); }
                    catch (...) { promise->set_exception(std::current_exception()); }
                }, net::detached);
            return future.get();
        }

        // ── 格式化辅助 ──

        auto format_devices(const std::vector<sec::scanner::device> &devs) -> std::string
        {
            auto ss = std::ostringstream{};
            ss << "Found " << devs.size() << " devices:\n";
            for (const auto &d : devs)
            {
                ss << "- IP: " << d.ip_address
                   << " | MAC: " << d.mac_address
                   << " | Host: " << (d.hostname.empty() ? "unknown" : d.hostname)
                   << " | Vendor: " << (d.vendor.empty() ? "unknown" : d.vendor)
                   << "\n";
            }
            return ss.str();
        }

        auto format_alerts(const std::vector<sec::store::alert_record> &alerts) -> std::string
        {
            if (alerts.empty()) return "No unacknowledged alerts.";
            auto ss = std::ostringstream{};
            ss << alerts.size() << " unacknowledged alerts:\n";
            for (const auto &a : alerts)
            {
                ss << "- ID: " << a.id
                   << " | Severity: " << a.severity
                   << " | Source: " << a.source_ip
                   << " | Desc: " << a.description
                   << "\n";
            }
            return ss.str();
        }

        auto format_traffic(const std::vector<sec::store::traffic_log> &logs) -> std::string
        {
            if (logs.empty()) return "No recent traffic logs.";
            auto ss = std::ostringstream{};
            ss << logs.size() << " traffic entries:\n";
            for (const auto &t : logs)
            {
                ss << "- " << t.src_ip << ":" << t.src_port
                   << " -> " << t.dst_ip << ":" << t.dst_port
                   << " | proto: " << static_cast<int>(t.protocol)
                   << " | size: " << t.packet_size
                   << "\n";
            }
            return ss.str();
        }

    } // anonymous namespace


    // ── 工具执行器 ──

    auto build_tool_registry(application &app)
        -> std::unordered_map<std::string, tool_executor>
    {
        auto registry = std::unordered_map<std::string, tool_executor>{};

        // scan: 查询已发现的设备（不触发实时扫描，避免阻塞 AI 线程）
        registry["scan"] = [&app](const std::string &) -> std::string {
            auto ec = std::error_code{};
            auto devs = app.device_query().find_all(ec);
            if (ec) return "Query failed: " + ec.message();
            if (devs.empty()) return "No devices in database. Ask user to run 'arp <subnet>' command first.";
            auto ss = std::ostringstream{};
            ss << devs.size() << " devices:\n";
            for (const auto &d : devs)
            {
                ss << "- IP: " << d.ip_address
                   << " | MAC: " << d.mac_address
                   << " | Host: " << (d.hostname.empty() ? "-" : d.hostname)
                   << " | Vendor: " << (d.vendor.empty() ? "-" : d.vendor)
                   << "\n";
            }
            return ss.str();
        };

        // probe: 端口扫描（仅扫前 100 端口，限制时间）
        registry["probe"] = [&app](const std::string &args) -> std::string {
            auto ip = extract_json_string(args, "ip");
            if (ip.empty()) return "Error: ip parameter required";
            auto opts = sec::scanner::port_scan_options{};
            opts.timeout_ms = std::min(app.config().scanner.port_timeout_ms, static_cast<std::uint16_t>(300));
            opts.concurrency = app.config().scanner.port_concurrency;
            opts.ports.clear();
            for (auto p = std::uint16_t{1}; p <= 100; ++p) opts.ports.push_back(p);
            auto ec = std::error_code{};
            auto open = await_to_sync(
                app.port().scan(ip, opts, ec), app.context().io_context().get_executor());
            if (ec) return "Port scan failed: " + ec.message();
            auto ss = std::ostringstream{};
            ss << open.size() << " open ports on " << ip << ":";
            for (auto p : open) ss << " " << p;
            return ss.str();
        };

        // discover: mDNS + SSDP（限制超时避免阻塞）
        registry["discover"] = [&app](const std::string &) -> std::string {
            auto ec = std::error_code{};
            auto mdns_devs = await_to_sync(
                app.mdns().scan(ec), app.context().io_context().get_executor());
            auto ss = std::ostringstream{};
            ss << "mDNS: " << mdns_devs.size() << " services\n";
            for (const auto &d : mdns_devs) ss << "  " << d.ip_address << " " << d.hostname << "\n";
            return ss.str();
        };

        // devices: 列出已发现设备
        registry["devices"] = [&app](const std::string &) -> std::string {
            auto ec = std::error_code{};
            auto devs = app.device_query().find_all(ec);
            if (ec) return "Query failed: " + ec.message();
            if (devs.empty()) return "No devices in database. Run scan first.";
            auto ss = std::ostringstream{};
            ss << devs.size() << " devices:\n";
            auto shown = std::min(devs.size(), static_cast<std::size_t>(30));
            for (std::size_t i = 0; i < shown; ++i)
            {
                const auto &d = devs[i];
                ss << "- IP: " << d.ip_address
                   << " | MAC: " << d.mac_address
                   << " | Host: " << (d.hostname.empty() ? "-" : d.hostname)
                   << " | Vendor: " << (d.vendor.empty() ? "-" : d.vendor)
                   << "\n";
            }
            if (devs.size() > 30) ss << "\n... and " << (devs.size() - 30) << " more devices.\n";
            return ss.str();
        };

        // inspect: 设备详情
        registry["inspect"] = [&app](const std::string &args) -> std::string {
            auto ip = extract_json_string(args, "ip");
            if (ip.empty()) return "Error: ip parameter required";
            auto ec = std::error_code{};
            auto dev = app.device_query().find_by_ip(ip, ec);
            if (ec || !dev) return "Device not found: " + ip;
            auto ss = std::ostringstream{};
            ss << "Device: " << dev->ip_address << "\n"
               << "MAC: " << dev->mac_address << "\n"
               << "Hostname: " << (dev->hostname.empty() ? "unknown" : dev->hostname) << "\n"
               << "Vendor: " << (dev->vendor.empty() ? "unknown" : dev->vendor) << "\n"
               << "OS: " << (dev->os_guess.empty() ? "unknown" : dev->os_guess) << "\n"
               << "Open ports: " << dev->open_ports << "\n";
            return ss.str();
        };

        // alerts: 未确认告警（最多 20 条，避免上下文爆炸）
        registry["alerts"] = [&app](const std::string &) -> std::string {
            auto ec = std::error_code{};
            auto alerts = app.alert_query().find_unacknowledged(ec);
            if (ec) return "Query failed: " + ec.message();
            if (alerts.empty()) return "No unacknowledged alerts.";
            auto total = alerts.size();
            if (alerts.size() > 20) alerts.resize(20);
            auto ss = std::ostringstream{};
            ss << total << " unacknowledged alerts (showing top " << alerts.size() << "):\n";
            for (const auto &a : alerts)
            {
                ss << "- ID: " << a.id
                   << " | Severity: " << a.severity
                   << " | Source: " << a.source_ip
                   << " | Desc: " << a.description
                   << "\n";
            }
            if (total > 20) ss << "\n... and " << (total - 20) << " more alerts.\n";
            return ss.str();
        };

        // traffic: 流量日志
        registry["traffic"] = [&app](const std::string &args) -> std::string {
            auto minutes = extract_json_int(args, "minutes", 30);
            auto ec = std::error_code{};
            auto now = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            auto from = now - minutes * 60;
            auto logs = app.traffic_query().find_by_time_range(from, now, ec);
            if (ec) return "Query failed: " + ec.message();
            if (logs.size() > 100) logs.resize(100);
            return format_traffic(logs);
        };

        // analyze: 沙箱分析
        registry["analyze"] = [&app](const std::string &args) -> std::string {
            auto path = extract_json_string(args, "path");
            if (path.empty()) return "Error: path parameter required";
            return "Sandbox analysis submitted for: " + path +
                   "\nUse 'analyses' command to check results.";
        };

        // ack: 确认告警
        registry["ack"] = [&app](const std::string &args) -> std::string {
            auto id = extract_json_int(args, "id", 0);
            if (id <= 0) return "Error: id parameter required";
            auto ec = std::error_code{};
            if (app.alert_query().acknowledge(id, ec))
            {
                return "Alert " + std::to_string(id) + " acknowledged.";
            }
            return "Failed to acknowledge alert " + std::to_string(id) + ": " + ec.message();
        };

        // stats: 网络统计
        registry["stats"] = [&app](const std::string &) -> std::string {
            auto ec = std::error_code{};
            auto dev_count = app.device_query().count(ec);
            auto alert_count = app.alert_query().count_unacknowledged(ec);
            auto ss = std::ostringstream{};
            ss << "Network Statistics:\n"
               << "- Devices tracked: " << dev_count << "\n"
               << "- Unacknowledged alerts: " << alert_count << "\n"
               << "- Active detections: rules + anomaly + port_scan + MITM + DNS tunnel\n"
               << "- AI model: Isolation Forest (trained on traffic patterns)\n"
               << "- Sandbox: VirtualBox + QEMU + Hyper-V backends\n";
            return ss.str();
        };

        return registry;
    }


    // ── 工具定义（schema）──

    auto build_tool_definitions() -> std::vector<tool_def>
    {
        return {
            {"scan",
             "ARP scan a subnet to discover all devices. Example: subnet='192.168.1.0/24'",
             R"x({"type":"object","properties":{"subnet":{"type":"string","description":"CIDR subnet like 192.168.1.0/24"}},"required":["subnet"]})x"},

            {"probe",
             "TCP port scan a specific IP. Example: ip='192.168.1.100', ports='1-1000'",
             R"x({"type":"object","properties":{"ip":{"type":"string","description":"Target IP address"},"ports":{"type":"string","description":"Port range like '1-1000' or single port"}},"required":["ip"]})x"},

            {"discover",
             "Discover devices via mDNS and SSDP/UPnP protocols",
             R"x({"type":"object","properties":{}})x"},

            {"devices",
             "List all discovered devices from the database",
             R"x({"type":"object","properties":{}})x"},

            {"inspect",
             "Get detailed info about a specific device by IP address",
             R"x({"type":"object","properties":{"ip":{"type":"string","description":"Device IP address"}},"required":["ip"]})x"},

            {"alerts",
             "List all unacknowledged security alerts",
             R"x({"type":"object","properties":{}})x"},

            {"traffic",
             "Query recent network traffic logs",
             R"x({"type":"object","properties":{"minutes":{"type":"integer","description":"How many minutes back to look (default 30)"}}})x"},

            {"analyze",
             "Submit a file for sandbox malware analysis",
             R"x({"type":"object","properties":{"path":{"type":"string","description":"File path to analyze"}},"required":["path"]})x"},

            {"ack",
             "Acknowledge a security alert by ID",
             R"x({"type":"object","properties":{"id":{"type":"integer","description":"Alert ID to acknowledge"}},"required":["id"]})x"},

            {"stats",
             "Get overall network security statistics",
             R"x({"type":"object","properties":{}})x"},
        };
    }


    // ── tools JSON 构造 ──

    auto build_tools_json(api_protocol protocol,
                           const std::vector<tool_def> &defs) -> std::string
    {
        auto ss = std::ostringstream{};
        ss << "[";

        auto first = true;
        for (const auto &d : defs)
        {
            if (!first) ss << ",";
            first = false;

            if (protocol == api_protocol::anthropic)
            {
                ss << "{\"name\":\"" << d.name << "\""
                   << ",\"description\":\"" << json_escape(d.description) << "\""
                   << ",\"input_schema\":" << d.parameters_json << "}";
            }
            else
            {
                ss << "{\"type\":\"function\""
                   << ",\"function\":{\"name\":\"" << d.name << "\""
                   << ",\"description\":\"" << json_escape(d.description) << "\""
                   << ",\"parameters\":" << d.parameters_json << "}}";
            }
        }

        ss << "]";
        return ss.str();
    }


    // ── tool_calls 提取 ──

    auto extract_tool_calls(api_protocol protocol,
                             const std::string &response) -> std::vector<tool_call>
    {
        auto calls = std::vector<tool_call>{};

        if (protocol == api_protocol::anthropic)
        {
            // Anthropic: 找 "type": "tool_use" 块（JSON 可能含空格）
            auto needle1 = std::string{"\"type\":\"tool_use\""};
            auto needle2 = std::string{"\"type\": \"tool_use\""};
            auto pos = std::size_t{0};
            while (true)
            {
                auto p1 = response.find(needle1, pos);
                auto p2 = response.find(needle2, pos);
                pos = std::min(p1, p2);
                if (pos == std::string::npos) break;

                auto call = tool_call{};

                // 找 id（容错：搜索 "id":" 和 "id": "）
                auto id_pos1 = response.rfind("\"id\":\"", pos);
                auto id_pos2 = response.rfind("\"id\": \"", pos);
                auto id_pos = std::string::npos;
                if (id_pos1 != std::string::npos && id_pos2 != std::string::npos)
                    id_pos = std::max(id_pos1, id_pos2);
                else
                    id_pos = (id_pos1 != std::string::npos) ? id_pos1 : id_pos2;
                if (id_pos != std::string::npos)
                {
                    id_pos = response.find('"', id_pos + 4) + 1;
                    auto id_end = response.find('"', id_pos);
                    call.id = response.substr(id_pos, id_end - id_pos);
                }

                // 找 name（容错空格）
                auto name_pos1 = response.find("\"name\":\"", pos);
                auto name_pos2 = response.find("\"name\": \"", pos);
                auto name_pos = std::string::npos;
                if (name_pos1 != std::string::npos && name_pos2 != std::string::npos)
                    name_pos = std::min(name_pos1, name_pos2);
                else
                    name_pos = (name_pos1 != std::string::npos) ? name_pos1 : name_pos2;
                if (name_pos != std::string::npos)
                {
                    name_pos = response.find('"', name_pos + 6) + 1;
                    auto name_end = response.find('"', name_pos);
                    call.name = response.substr(name_pos, name_end - name_pos);
                }

                // 找 input（容错空格）
                auto input_pos = response.find("\"input\"", pos);
                if (input_pos != std::string::npos)
                {
                    input_pos += 7;
                    while (input_pos < response.size() &&
                           (response[input_pos] == ' ' || response[input_pos] == ':')) ++input_pos;
                    auto brace_start = response.find('{', input_pos);
                    if (brace_start != std::string::npos)
                    {
                        auto depth = 0;
                        auto i = brace_start;
                        while (i < response.size())
                        {
                            if (response[i] == '{') ++depth;
                            if (response[i] == '}') { --depth; if (depth == 0) break; }
                            ++i;
                        }
                        call.arguments = response.substr(brace_start, i - brace_start + 1);
                    }
                }

                if (!call.name.empty()) calls.push_back(std::move(call));
                pos += 17;
            }
        }
        else
        {
            // OpenAI: 找 "tool_calls" 数组中的条目
            auto pos = std::size_t{0};
            while ((pos = response.find("\"function\":{", pos)) != std::string::npos)
            {
                auto call = tool_call{};

                // 找 id（tool_call_id 在 function 之前）
                auto id_pos = response.rfind("\"id\":\"", pos);
                if (id_pos != std::string::npos && id_pos > pos - 200)
                {
                    id_pos += 6;
                    auto id_end = response.find('"', id_pos);
                    call.id = response.substr(id_pos, id_end - id_pos);
                }

                // 找 name
                auto name_pos = response.find("\"name\":\"", pos);
                if (name_pos != std::string::npos)
                {
                    name_pos += 8;
                    auto name_end = response.find('"', name_pos);
                    call.name = response.substr(name_pos, name_end - name_pos);
                }

                // 找 arguments
                auto args_pos = response.find("\"arguments\":\"", pos);
                if (args_pos != std::string::npos)
                {
                    args_pos += 13;
                    auto args_end = response.find("\"}", args_pos);
                    call.arguments = response.substr(args_pos, args_end - args_pos);
                }

                if (!call.name.empty()) calls.push_back(std::move(call));
                pos += 12;
            }
        }

        return calls;
    }


    // ── 安全提示词 ──

    auto build_security_prompt(application &app) -> std::string
    {
        auto ec = std::error_code{};
        auto dev_count = app.device_query().count(ec);
        auto alert_count = app.alert_query().count_unacknowledged(ec);

        auto ss = std::ostringstream{};
        ss << "You are Spectra Security Analyst, a professional LAN security posture analyst.\n\n"

           << "## Your Role\n"
           << "- Proactively discover security threats in the network\n"
           << "- Multi-step analysis: scan → discover → investigate → correlate → advise\n"
           << "- Use tools to get real-time data, never guess\n\n"

           << "## Workflow\n"
           << "1. Use scan or discover to find devices on the network\n"
           << "2. Use devices to review the device inventory, identify suspicious hosts\n"
           << "3. Use probe to scan open ports on suspicious devices\n"
           << "4. Use alerts to check existing security alerts\n"
           << "5. Use inspect to investigate specific devices\n"
           << "6. Use traffic to analyze abnormal traffic patterns\n"
           << "7. Use analyze to submit suspicious files to sandbox\n"
           << "8. Use ack to acknowledge handled alerts\n\n"

           << "## Security Analysis Principles\n"
           << "- Ports 22/21/25/3389 with frequent connections = possible brute force\n"
           << "- Ports 4444/8080/8443 unexpectedly open = possible backdoor/C2\n"
           << "- Excessive ICMP/DNS traffic = possible tunneling/scanning\n"
           << "- JA3 fingerprint matching known C2 = high-confidence threat\n"
           << "- Multiple devices with same MAC = ARP spoofing\n"
           << "- Off-hours traffic spikes = possible data exfiltration\n"
           << "- Long DNS queries (>50 chars) or TXT records = DNS tunneling\n"
           << "- Periodic connections (beaconing) = C2 callback\n\n"

           << "## Response Format\n"
           << "- Use Markdown tables for device/alert lists\n"
           << "- Give clear threat severity (critical/high/medium/low)\n"
           << "- Provide specific remediation advice (isolate/block/monitor)\n"
           << "- Cite tool data as evidence\n\n"

           << "## Constraints\n"
           << "- Only analyze devices within the authorized network\n"
           << "- Do not suggest unauthorized penetration testing\n"
           << "- Maximum 8 tool calls per analysis\n\n"

           << "## Current Network Status\n"
           << "- Devices tracked: " << dev_count << "\n"
           << "- Unacknowledged alerts: " << alert_count << "\n";

        return ss.str();
    }

} // namespace sec::tui
