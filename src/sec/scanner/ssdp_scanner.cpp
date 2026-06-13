// SSDP/UPnP 设备发现扫描器实现 — 通过 M-SEARCH 发现 UPnP 设备

#include <sec/scanner/ssdp_scanner.hpp>
#include <sec/fault/compatible.hpp>
#include <sec/fault/code.hpp>

#include <boost/system/error_code.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <string_view>

namespace net = boost::asio;


namespace sec::scanner
{

    namespace
    {

        constexpr std::string_view ssdp_multicast_addr{"239.255.255.250"};
        constexpr std::uint16_t ssdp_port{1900};
        constexpr std::string_view ssdp_search_target{"ssdp:all"};
        constexpr std::string_view ssdp_mx{"3"};

        // 构造 M-SEARCH 请求原始字符串
        auto build_msearch_raw() -> std::string
        {
            return "M-SEARCH * HTTP/1.1\r\n"
                   "HOST: 239.255.255.250:1900\r\n"
                   "MAN: \"ssdp:discover\"\r\n"
                   "MX: " + std::string(ssdp_mx) + "\r\n"
                   "ST: " + std::string(ssdp_search_target) + "\r\n"
                   "\r\n";
        }

        // 从 SSDP 响应中提取指定 HTTP 头字段值（大小写不敏感）
        auto extract_header_value(std::string_view response, std::string_view header_name) -> std::string
        {
            auto to_lower = [](char c) -> char {
                return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            };

            auto header_lower = std::string(header_name);
            std::transform(header_lower.begin(), header_lower.end(),
                           header_lower.begin(), to_lower);

            std::size_t pos{0};
            while (pos < response.size())
            {
                auto line_end = response.find("\r\n", pos);
                if (line_end == std::string_view::npos) break;

                auto line = response.substr(pos, line_end - pos);
                auto colon_pos = line.find(':');
                if (colon_pos != std::string_view::npos)
                {
                    auto key = std::string(line.substr(0, colon_pos));
                    std::transform(key.begin(), key.end(), key.begin(), to_lower);

                    if (key == header_lower)
                    {
                        auto value = line.substr(colon_pos + 1);
                        while (!value.empty() && value.front() == ' ')
                            value.remove_prefix(1);
                        return std::string(value);
                    }
                }

                pos = line_end + 2;
            }

            return {};
        }

    } // anonymous namespace


    // 构造 SSDP 扫描器
    ssdp_scanner::ssdp_scanner(engine::context &ctx)
        : ctx_{ctx}
    {
    }


    // 将 M-SEARCH 请求转换为字节向量
    auto ssdp_scanner::build_msearch_request() const -> std::vector<std::byte>
    {
        auto raw = build_msearch_raw();
        std::vector<std::byte> result(raw.size());
        std::transform(raw.begin(), raw.end(), result.begin(),
                       [](char c) { return static_cast<std::byte>(c); });
        return result;
    }


    // 解析 SSDP 响应报文，提取 UPnP 设备信息
    auto ssdp_scanner::parse_ssdp_response(std::span<const std::byte> data) const -> std::vector<device>
    {
        std::vector<device> devices;

        std::string response(data.size(), '\0');
        std::transform(data.begin(), data.end(), response.begin(),
                       [](std::byte b) { return static_cast<char>(b); });

        if (response.find("HTTP/1.") == std::string::npos)
        {
            return devices;
        }

        device dev;

        auto location = extract_header_value(response, "LOCATION");
        auto server = extract_header_value(response, "SERVER");
        auto usn = extract_header_value(response, "USN");

        if (!usn.empty())
        {
            auto uuid_start = usn.find("uuid:");
            if (uuid_start != std::string::npos)
            {
                auto uuid_end = usn.find("::", uuid_start);
                if (uuid_end == std::string::npos) uuid_end = usn.size();
                dev.hostname = usn.substr(uuid_start + 5, uuid_end - uuid_start - 5);
            }
        }

        if (!location.empty())
        {
            auto http_pos = location.find("http://");
            if (http_pos != std::string::npos)
            {
                auto ip_start = http_pos + 7;
                auto port_pos = location.find(':', ip_start);
                auto path_pos = location.find('/', ip_start);
                auto ip_end = std::string::npos;

                if (port_pos != std::string::npos && path_pos != std::string::npos)
                    ip_end = std::min(port_pos, path_pos);
                else if (port_pos != std::string::npos)
                    ip_end = port_pos;
                else if (path_pos != std::string::npos)
                    ip_end = path_pos;

                if (ip_end != std::string::npos)
                    dev.ip_address = location.substr(ip_start, ip_end - ip_start);
            }
        }

        if (!server.empty())
        {
            dev.vendor = server;
        }

        dev.last_seen = std::chrono::steady_clock::now();
        devices.push_back(std::move(dev));

        return devices;
    }


    // 执行 SSDP/UPnP 设备发现扫描
    auto ssdp_scanner::scan(std::error_code &ec) -> net::awaitable<std::vector<device>>
    {
        auto executor = co_await net::this_coro::executor;

        net::ip::udp::socket socket{executor};
        socket.open(net::ip::udp::v4());

        socket.set_option(net::ip::multicast::enable_loopback{true});
        socket.set_option(net::ip::multicast::hops{4});

        auto request = build_msearch_request();

        net::ip::udp::endpoint multicast_endpoint{
            net::ip::make_address(std::string(ssdp_multicast_addr)), ssdp_port};

        auto send_ec = boost::system::error_code{};
        co_await socket.async_send_to(
            net::buffer(request.data(), request.size()),
            multicast_endpoint,
            net::redirect_error(net::use_awaitable, send_ec));

        if (send_ec)
        {
            spdlog::warn("SSDP send failed: {}", send_ec.message());
            ec = make_error_code(fault::code::arp_failed);
            co_return std::vector<device>{};
        }

        std::array<std::byte, 4096> recv_buf{};
        std::vector<device> all_devices;

        auto timer = net::steady_timer(executor, std::chrono::seconds(4));
        bool timed_out{false};
        timer.async_wait([&](std::error_code) { timed_out = true; });

        while (!timed_out)
        {
            net::ip::udp::endpoint sender{};
            auto recv_ec = boost::system::error_code{};
            auto nbytes = co_await socket.async_receive_from(
                net::buffer(recv_buf),
                sender,
                net::redirect_error(net::use_awaitable, recv_ec));

            if (recv_ec) break;

            auto parsed = parse_ssdp_response(
                std::span<const std::byte>{recv_buf.data(), nbytes});

            for (auto &dev : parsed)
            {
                if (dev.ip_address.empty())
                {
                    dev.ip_address = sender.address().to_string();
                }
                all_devices.push_back(std::move(dev));
            }
        }

        timer.cancel();
        socket.close();

        spdlog::info("SSDP scan complete: {} devices found", all_devices.size());

        ec.clear();
        co_return all_devices;
    }


} // namespace sec::scanner
