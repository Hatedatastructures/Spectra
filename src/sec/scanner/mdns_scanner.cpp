// mDNS 服务发现扫描器实现 — 通过 mDNS 查询发现局域网服务

#include <sec/scanner/mdns_scanner.hpp>
#include <sec/fault/compatible.hpp>
#include <sec/fault/code.hpp>

#include <boost/system/error_code.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <cstring>

namespace net = boost::asio;


namespace sec::scanner
{

    namespace
    {

        constexpr std::uint16_t mdns_port{5353};

        // 以大端序写入 16 位整数到缓冲区并前移偏移
        void put_u16(std::span<std::byte> buf, std::size_t &offset, std::uint16_t val)
        {
            buf[offset++] = static_cast<std::byte>((val >> 8) & 0xFF);
            buf[offset++] = static_cast<std::byte>(val & 0xFF);
        }

        // 从缓冲区以大端序读取 16 位整数并前移偏移
        [[nodiscard]] auto get_u16(std::span<const std::byte> buf, std::size_t &offset) -> std::uint16_t
        {
            auto val = (static_cast<std::uint16_t>(buf[offset]) << 8) |
                       static_cast<std::uint16_t>(buf[offset + 1]);
            offset += 2;
            return val;
        }

        // 解析 DNS 名称字段，支持标签压缩指针
        auto parse_dns_name(std::span<const std::byte> data, std::size_t offset) -> std::string
        {
            std::string name;
            bool jumped{false};
            std::size_t jump_offset{0};

            while (offset < data.size())
            {
                auto len = static_cast<std::uint8_t>(data[offset]);

                if (len == 0)
                {
                    if (!jumped) ++offset;
                    break;
                }

                if ((len & 0xC0) == 0xC0)
                {
                    if (!jumped) jump_offset = offset + 2;
                    offset = ((static_cast<std::size_t>(len) & 0x3F) << 8) |
                             static_cast<std::size_t>(data[offset + 1]);
                    jumped = true;
                    continue;
                }

                ++offset;
                if (offset + len > data.size()) break;

                if (!name.empty()) name += '.';
                for (std::size_t i = 0; i < len && offset < data.size(); ++i, ++offset)
                {
                    name += static_cast<char>(data[offset]);
                }
            }

            return name;
        }

    } // anonymous namespace


    // 构造 mDNS 扫描器
    mdns_scanner::mdns_scanner(engine::context &ctx)
        : ctx_{ctx}
    {
    }


    // 构造 DNS-SD 服务发现查询包
    auto mdns_scanner::build_mdns_query() const -> std::vector<std::byte>
    {
        std::vector<std::byte> packet(256, std::byte{0});
        std::span<std::byte> buf{packet};
        std::size_t offset{0};

        put_u16(buf, offset, 0x0000);
        put_u16(buf, offset, 0x0000);
        put_u16(buf, offset, 0x0001);
        put_u16(buf, offset, 0x0000);
        put_u16(buf, offset, 0x0000);
        put_u16(buf, offset, 0x0000);

        auto write_label = [&](const char *label) {
            auto len = static_cast<std::uint8_t>(std::strlen(label));
            buf[offset++] = static_cast<std::byte>(len);
            for (std::size_t i = 0; i < len; ++i)
                buf[offset++] = static_cast<std::byte>(label[i]);
        };

        write_label("_services");
        write_label("_dns-sd");
        write_label("_udp");
        write_label("local");
        buf[offset++] = std::byte{0};

        put_u16(buf, offset, 0x000C);
        put_u16(buf, offset, 0x0001);

        packet.resize(offset);
        return packet;
    }


    // 解析 mDNS 响应报文，提取服务设备信息
    auto mdns_scanner::parse_mdns_response(std::span<const std::byte> data) const -> std::vector<device>
    {
        std::vector<device> devices;

        if (data.size() < 12) return devices;

        std::size_t offset{0};

        [[maybe_unused]] auto id = get_u16(data, offset);
        auto flags = get_u16(data, offset);
        auto qdcount = get_u16(data, offset);
        auto ancount = get_u16(data, offset);
        [[maybe_unused]] auto nscount = get_u16(data, offset);
        [[maybe_unused]] auto arcount = get_u16(data, offset);

        if ((flags & 0x8000) == 0) return devices;

        for (std::uint16_t i = 0; i < qdcount && offset < data.size(); ++i)
        {
            while (offset < data.size())
            {
                auto len = static_cast<std::uint8_t>(data[offset]);
                if (len == 0) { offset += 1; break; }
                if ((len & 0xC0) == 0xC0) { offset += 2; break; }
                offset += 1 + len;
            }
            offset += 4;
        }

        for (std::uint16_t i = 0; i < ancount && offset < data.size(); ++i)
        {
            [[maybe_unused]] auto name = parse_dns_name(data, offset);
            auto rtype = get_u16(data, offset);
            [[maybe_unused]] auto rclass = get_u16(data, offset);
            [[maybe_unused]] auto ttl_hi = get_u16(data, offset);
            [[maybe_unused]] auto ttl_lo = get_u16(data, offset);
            auto rdlength = get_u16(data, offset);

            if (offset + rdlength > data.size()) break;

            if (rtype == 12 && rdlength > 0)
            {
                auto rdata_start = offset;
                auto service_name = parse_dns_name(data, rdata_start);

                device dev;
                auto dot_pos = service_name.find('.');
                dev.hostname = (dot_pos != std::string::npos)
                    ? service_name.substr(0, dot_pos)
                    : service_name;
                dev.last_seen = std::chrono::steady_clock::now();
                devices.push_back(std::move(dev));
            }

            offset += rdlength;
        }

        return devices;
    }


    // 执行 mDNS 服务发现扫描
    auto mdns_scanner::scan(std::error_code &ec) -> net::awaitable<std::vector<device>>
    {
        auto executor = co_await net::this_coro::executor;

        net::ip::udp::socket socket{executor};
        socket.open(net::ip::udp::v4());

        net::ip::multicast::enable_loopback option{true};
        socket.set_option(option);

        auto query = build_mdns_query();

        net::ip::udp::endpoint multicast_endpoint{
            net::ip::make_address("224.0.0.251"), mdns_port};

        auto send_ec = boost::system::error_code{};
        co_await socket.async_send_to(
            net::buffer(query.data(), query.size()),
            multicast_endpoint,
            net::redirect_error(net::use_awaitable, send_ec));

        if (send_ec)
        {
            spdlog::warn("mDNS send failed: {}", send_ec.message());
            ec = make_error_code(fault::code::arp_failed);
            co_return std::vector<device>{};
        }

        std::array<std::byte, 4096> recv_buf{};
        std::vector<device> all_devices;

        auto timer = net::steady_timer(executor, std::chrono::milliseconds(3000));
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

            auto parsed = parse_mdns_response(
                std::span<const std::byte>{recv_buf.data(), nbytes});

            for (auto &dev : parsed)
            {
                dev.ip_address = sender.address().to_string();
                all_devices.push_back(std::move(dev));
            }
        }

        timer.cancel();
        socket.close();

        spdlog::info("mDNS scan complete: {} services found", all_devices.size());

        ec.clear();
        co_return all_devices;
    }


} // namespace sec::scanner
