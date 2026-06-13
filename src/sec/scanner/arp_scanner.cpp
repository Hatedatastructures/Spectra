// ARP 扫描器实现 — 构造 ARP 请求广播包，解析回复以发现局域网设备

#include <sec/scanner/arp_scanner.hpp>
#include <sec/fault/compatible.hpp>
#include <sec/fault/code.hpp>

#ifdef _WIN32
#include <pcap.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#pragma comment(lib, "iphlpapi.lib")
#endif

#include <boost/system/error_code.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <optional>
#include <vector>

namespace net = boost::asio;


namespace sec::scanner
{

    namespace
    {

        // 以太网帧头 (14 bytes)
        struct ethernet_header
        {
            std::array<std::byte, 6> dst_mac{};
            std::array<std::byte, 6> src_mac{};
            std::uint16_t ethertype{0x0806}; // ARP
        };

        // ARP 包 (28 bytes)
#pragma pack(push, 1)
        struct arp_packet
        {
            std::uint16_t hardware_type{0x0001};
            std::uint16_t protocol_type{0x0800};
            std::uint8_t hardware_size{6};
            std::uint8_t protocol_size{4};
            std::uint16_t opcode{0x0001};
            std::array<std::byte, 6> sender_mac{};
            std::uint32_t sender_ip{0};
            std::array<std::byte, 6> target_mac{};
            std::uint32_t target_ip{0};
        };
#pragma pack(pop)

        static_assert(sizeof(ethernet_header) == 14);
        static_assert(sizeof(arp_packet) == 28);

        // 将点分十进制 IPv4 字符串解析为 32 位整数
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

        // 将 32 位整数转换为点分十进制字符串
        auto ipv4_to_string(std::uint32_t ip) -> std::string
        {
            return std::to_string((ip >> 24) & 0xFF) + "." +
                   std::to_string((ip >> 16) & 0xFF) + "." +
                   std::to_string((ip >> 8) & 0xFF) + "." +
                   std::to_string(ip & 0xFF);
        }

        // 将 6 字节 MAC 地址转换为冒号分隔的十六进制字符串
        auto mac_to_string(std::span<const std::byte, 6> mac) -> std::string
        {
            char buf[18]{};
            std::snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
                          static_cast<unsigned>(mac[0]),
                          static_cast<unsigned>(mac[1]),
                          static_cast<unsigned>(mac[2]),
                          static_cast<unsigned>(mac[3]),
                          static_cast<unsigned>(mac[4]),
                          static_cast<unsigned>(mac[5]));
            return buf;
        }

        // 将 CIDR 子网转换为 IP 地址范围
        auto subnet_to_range(std::string_view subnet) -> std::pair<std::uint32_t, std::uint32_t>
        {
            auto slash_pos = subnet.find('/');
            if (slash_pos == std::string_view::npos)
            {
                auto ip = parse_ipv4(subnet);
                return {ip, ip};
            }

            auto network_ip = parse_ipv4(subnet.substr(0, slash_pos));
            auto prefix_len = static_cast<std::uint32_t>(
                std::stoul(std::string(subnet.substr(slash_pos + 1))));

            std::uint32_t mask{0};
            if (prefix_len > 0)
            {
                mask = ~static_cast<std::uint32_t>(0) << (32 - prefix_len);
            }

            auto network = network_ip & mask;
            auto broadcast = network | ~mask;

            return {network + 1, broadcast - 1};
        }

        // 将 16 位整数以大端序写入缓冲区
        void put_u16_be(std::span<std::byte> buf, std::size_t offset, std::uint16_t val)
        {
            buf[offset] = static_cast<std::byte>((val >> 8) & 0xFF);
            buf[offset + 1] = static_cast<std::byte>(val & 0xFF);
        }

        // 将 32 位整数以大端序写入缓冲区
        void put_u32_be(std::span<std::byte> buf, std::size_t offset, std::uint32_t val)
        {
            buf[offset] = static_cast<std::byte>((val >> 24) & 0xFF);
            buf[offset + 1] = static_cast<std::byte>((val >> 16) & 0xFF);
            buf[offset + 2] = static_cast<std::byte>((val >> 8) & 0xFF);
            buf[offset + 3] = static_cast<std::byte>(val & 0xFF);
        }

        [[nodiscard]] auto get_u16_be(std::span<const std::byte> buf, std::size_t offset) -> std::uint16_t
        {
            return (static_cast<std::uint16_t>(buf[offset]) << 8) |
                   static_cast<std::uint16_t>(buf[offset + 1]);
        }

        [[nodiscard]] auto get_u32_be(std::span<const std::byte> buf, std::size_t offset) -> std::uint32_t
        {
            return (static_cast<std::uint32_t>(buf[offset]) << 24) |
                   (static_cast<std::uint32_t>(buf[offset + 1]) << 16) |
                   (static_cast<std::uint32_t>(buf[offset + 2]) << 8) |
                   static_cast<std::uint32_t>(buf[offset + 3]);
        }

        constexpr std::array<std::byte, 6> broadcast_mac{
            std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF},
            std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}};

    } // anonymous namespace


#ifdef _WIN32
    namespace
    {

        // 根据目标 IP 选择最佳网卡的接口名、MAC、IP
        auto resolve_interface(std::uint32_t target_ip)
            -> std::tuple<std::string, std::array<std::byte, 6>, std::uint32_t>
        {
            // GetBestInterface 找到目标 IP 走哪个接口
            DWORD best_if_index{};
            auto dest = htonl(target_ip);
            if (GetBestInterface(dest, &best_if_index) != NO_ERROR)
            {
                spdlog::warn("GetBestInterface failed for {}", ipv4_to_string(target_ip));
                return {};
            }

            // GetAdaptersAddresses 获取该接口的 MAC 和 IP
            ULONG buf_len = 0;
            GetAdaptersAddresses(AF_INET, 0, nullptr, nullptr, &buf_len);
            auto buf = std::vector<std::byte>(buf_len);
            auto *addrs = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
            if (GetAdaptersAddresses(AF_INET, 0, nullptr, addrs, &buf_len) != ERROR_SUCCESS)
            {
                return {};
            }

            std::array<std::byte, 6> mac{};
            std::uint32_t ip{};

            for (auto *a = addrs; a; a = a->Next)
            {
                if (static_cast<DWORD>(a->IfIndex) != best_if_index)
                {
                    continue;
                }
                if (a->PhysicalAddressLength == 6)
                {
                    std::memcpy(mac.data(), a->PhysicalAddress, 6);
                }
                for (auto *ua = a->FirstUnicastAddress; ua; ua = ua->Next)
                {
                    if (ua->Address.lpSockaddr->sa_family == AF_INET)
                    {
                        auto *s = reinterpret_cast<sockaddr_in *>(ua->Address.lpSockaddr);
                        std::memcpy(&ip, &s->sin_addr, sizeof(ip));
                        ip = ntohl(ip);
                        break;
                    }
                }
                break;
            }

            // 匹配 pcap 接口名：通过 IP 地址匹配
            auto src_ip_net = htonl(ip);
            pcap_if_t *alldevs{};
            char errbuf[PCAP_ERRBUF_SIZE]{};
            std::string iface;
            if (pcap_findalldevs(&alldevs, errbuf) == 0 && alldevs)
            {
                for (auto *dev = alldevs; dev; dev = dev->next)
                {
                    if (dev->flags & PCAP_IF_LOOPBACK)
                    {
                        continue;
                    }
                    for (auto *a = dev->addresses; a; a = a->next)
                    {
                        if (!a->addr || a->addr->sa_family != AF_INET)
                        {
                            continue;
                        }
                        auto *sin = reinterpret_cast<sockaddr_in *>(a->addr);
                        std::uint32_t dev_ip{};
                        std::memcpy(&dev_ip, &sin->sin_addr, sizeof(dev_ip));
                        if (dev_ip == src_ip_net)
                        {
                            iface = dev->name;
                            break;
                        }
                    }
                    if (!iface.empty())
                    {
                        break;
                    }
                }
                pcap_freealldevs(alldevs);
            }

            spdlog::info("resolve_interface: target={} => IF={} MAC={} IP={}",
                         ipv4_to_string(target_ip), iface,
                         mac_to_string(mac), ipv4_to_string(ip));

            return {iface, mac, ip};
        }

    } // anonymous namespace
#endif


    // 构造 ARP 扫描器
    arp_scanner::arp_scanner(engine::context &ctx)
        : ctx_{ctx}
        , arp_timeout_ms_{ctx.config().scanner.arp_timeout_ms}
    {
    }


    // 构造 ARP 请求广播包
    auto arp_scanner::build_arp_request(std::uint32_t sender_ip, std::uint32_t target_ip) const -> std::vector<std::byte>
    {
        std::vector<std::byte> packet(42, std::byte{0});
        std::span<std::byte> buf{packet};

        // 以太网头：dst=广播，src=本机 MAC（pcap 路径会覆盖 src MAC，这里先填本机 MAC 让 raw 路径也可用）
        std::copy(broadcast_mac.begin(), broadcast_mac.end(),
                  buf.subspan<0, 6>().begin());
        std::copy(sender_mac_.begin(), sender_mac_.end(),
                  buf.subspan<6, 6>().begin());

        put_u16_be(buf, 12, 0x0806);

        put_u16_be(buf, 14, 0x0001);
        put_u16_be(buf, 16, 0x0800);
        buf[18] = std::byte{6};
        buf[19] = std::byte{4};
        put_u16_be(buf, 20, 0x0001);

        std::copy(sender_mac_.begin(), sender_mac_.end(),
                  buf.subspan(22, 6).begin());
        put_u32_be(buf, 28, sender_ip);

        put_u32_be(buf, 38, target_ip);

        return packet;
    }


    // 解析 ARP 回复包
    auto arp_scanner::parse_arp_reply(std::span<const std::byte> data) const -> std::optional<device>
    {
        if (data.size() < 42)
        {
            return std::nullopt;
        }

        auto ethertype = get_u16_be(data, 12);
        if (ethertype != 0x0806)
        {
            return std::nullopt;
        }

        auto opcode = get_u16_be(data, 20);
        if (opcode != 0x0002)
        {
            return std::nullopt;
        }

        auto hw_type = get_u16_be(data, 14);
        auto proto_type = get_u16_be(data, 16);
        if (hw_type != 0x0001 || proto_type != 0x0800)
        {
            return std::nullopt;
        }

        std::array<std::byte, 6> sender_mac{};
        std::copy(data.subspan(22, 6).begin(), data.subspan(22, 6).end(),
                  sender_mac.begin());

        bool all_zero = std::all_of(sender_mac.begin(), sender_mac.end(),
                                    [](std::byte b) { return b == std::byte{0}; });
        if (all_zero)
        {
            return std::nullopt;
        }

        auto sender_ip = get_u32_be(data, 28);

        device dev;
        dev.ip_address = ipv4_to_string(sender_ip);
        dev.mac_address = mac_to_string(sender_mac);
        dev.last_seen = std::chrono::steady_clock::now();

        return dev;
    }


    // 扫描整个子网
    auto arp_scanner::scan_subnet(std::string_view subnet, std::error_code &ec) -> net::awaitable<std::vector<device>>
    {
        auto [start_ip, end_ip] = subnet_to_range(subnet);

        if (start_ip > end_ip)
        {
            ec = fault::make_error_code(fault::code::arp_failed);
            co_return std::vector<device>{};
        }

#ifdef _WIN32
        co_return co_await scan_subnet_pcap(start_ip, end_ip, ec);
#else
        spdlog::info("ARP scan_subnet: range {} - {}", ipv4_to_string(start_ip), ipv4_to_string(end_ip));

        auto executor = co_await net::this_coro::executor;
        transport::raw raw_sock{executor};

        std::vector<device> devices;
        std::array<std::byte, 4096> recv_buf{};

        for (std::uint32_t ip = start_ip; ip <= end_ip; ++ip)
        {
            auto request = build_arp_request(sender_ip_, ip);

            transport::endpoint dest{};
            dest.address = ip;

            auto send_ec = boost::system::error_code{};
            co_await raw_sock.async_send_to(request, dest, send_ec);
            if (send_ec)
            {
                spdlog::warn("ARP send failed {}: {}", ipv4_to_string(ip), send_ec.message());
                continue;
            }

            auto timer = net::steady_timer(executor,
                                           std::chrono::milliseconds(arp_timeout_ms_));

            bool found{false};
            bool timed_out{false};
            timer.async_wait([&](std::error_code) {
                timed_out = true;
                raw_sock.cancel();
            });

            while (!found && !timed_out)
            {
                transport::endpoint sender{};
                auto recv_ec = boost::system::error_code{};
                auto nbytes = co_await raw_sock.async_receive_from(recv_buf, sender, recv_ec);

                if (recv_ec || timed_out)
                {
                    break;
                }

                auto parsed = parse_arp_reply(std::span<const std::byte>{
                    recv_buf.data(), nbytes});
                if (parsed)
                {
                    if (parse_ipv4(parsed->ip_address) == ip)
                    {
                        spdlog::info("ARP found device: {} ({})", parsed->ip_address, std::string{parsed->mac_address});
                        devices.push_back(std::move(*parsed));
                        found = true;
                    }
                }
            }

            timer.cancel();
        }

        spdlog::info("ARP subnet scan complete: {} devices found", devices.size());
        ec.clear();
        co_return devices;
#endif
    }


    // 扫描单个 IP 地址
    auto arp_scanner::scan_single(std::string_view target_ip, std::error_code &ec) -> net::awaitable<std::optional<device>>
    {
#ifdef _WIN32
        auto ip = parse_ipv4(target_ip);
        co_return co_await scan_single_pcap(ip, ec);
#else
        auto ip = parse_ipv4(target_ip);

        auto executor = co_await net::this_coro::executor;
        transport::raw raw_sock{executor};

        auto request = build_arp_request(sender_ip_, ip);

        transport::endpoint dest{};
        dest.address = ip;

        auto send_ec = boost::system::error_code{};
        co_await raw_sock.async_send_to(request, dest, send_ec);
        if (send_ec)
        {
            ec = make_error_code(fault::code::arp_failed);
            co_return std::nullopt;
        }

        std::array<std::byte, 4096> recv_buf{};
        auto timer = net::steady_timer(executor,
                                       std::chrono::milliseconds(arp_timeout_ms_));

        bool timed_out{false};
        timer.async_wait([&](boost::system::error_code) { timed_out = true; });

        while (!timed_out)
        {
            transport::endpoint sender{};
            auto recv_ec = boost::system::error_code{};
            auto nbytes = co_await raw_sock.async_receive_from(recv_buf, sender, recv_ec);

            if (recv_ec || timed_out)
            {
                break;
            }

            auto parsed = parse_arp_reply(std::span<const std::byte>{
                recv_buf.data(), nbytes});
            if (parsed && parse_ipv4(parsed->ip_address) == ip)
            {
                timer.cancel();
                ec.clear();
                co_return parsed;
            }
        }

        timer.cancel();
        spdlog::debug("ARP single scan no reply: {}", target_ip);
        co_return std::nullopt;
#endif
    }


#ifdef _WIN32

    // Windows pcap 路径：子网扫描
    auto arp_scanner::scan_subnet_pcap(std::uint32_t start_ip, std::uint32_t end_ip,
                                        std::error_code &ec) -> net::awaitable<std::vector<device>>
    {
        auto executor = co_await net::this_coro::executor;

        auto [iface, mac, src_ip] = resolve_interface(start_ip);
        if (iface.empty() || mac[0] == std::byte{})
        {
            spdlog::error("ARP scan: no suitable interface found for {}", ipv4_to_string(start_ip));
            ec = fault::make_error_code(fault::code::arp_failed);
            co_return std::vector<device>{};
        }
        sender_mac_ = mac;
        sender_ip_ = src_ip;

        spdlog::info("ARP pcap scan: {} - {} on {} (src={}/{})",
                     ipv4_to_string(start_ip), ipv4_to_string(end_ip), iface,
                     ipv4_to_string(sender_ip_), mac_to_string(sender_mac_));

        transport::pcap_capture cap{iface, executor};
        std::error_code filter_ec{};
        cap.set_filter("arp and arp[6:2] = 2", filter_ec);
        if (filter_ec)
        {
            spdlog::error("ARP scan: BPF filter set failed");
            ec = filter_ec;
            co_return std::vector<device>{};
        }

        std::error_code start_ec{};
        co_await cap.start_capture(start_ec);
        if (start_ec)
        {
            spdlog::error("ARP scan: pcap start_capture failed");
            ec = start_ec;
            co_return std::vector<device>{};
        }

        auto state = std::make_shared<reply_state>(executor);
        cap.set_packet_handler([state](std::span<const std::byte> pkt) {
            state->queue.emplace_back(pkt.begin(), pkt.end());
            state->wakeup.cancel();
        });

        std::vector<device> devices;

        for (std::uint32_t ip = start_ip; ip <= end_ip; ++ip)
        {
            auto request = build_arp_request(sender_ip_, ip);
            std::error_code send_ec{};
            cap.send_packet(request, send_ec);
            if (send_ec)
            {
                spdlog::warn("ARP pcap send failed: {}", ipv4_to_string(ip));
                continue;
            }

            auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(arp_timeout_ms_);
            state->wakeup.expires_at(deadline);

            bool found{false};
            while (!found)
            {
                // 排空队列匹配目标 IP
                for (auto it = state->queue.begin(); it != state->queue.end();)
                {
                    auto parsed = parse_arp_reply(*it);
                    if (parsed && parse_ipv4(parsed->ip_address) == ip)
                    {
                        spdlog::info("ARP found: {} ({})", parsed->ip_address, std::string{parsed->mac_address});
                        devices.push_back(std::move(*parsed));
                        found = true;
                        break;
                    }
                    ++it;
                }

                if (found)
                {
                    break;
                }

                // 等待 handler 唤醒或超时
                auto wait_ec = boost::system::error_code{};
                co_await state->wakeup.async_wait(
                    net::redirect_error(net::use_awaitable, wait_ec));

                if (wait_ec == net::error::operation_aborted)
                {
                    // handler 唤醒，重新检查队列
                    continue;
                }

                // 超时，跳到下一个 IP
                break;
            }

            state->queue.clear();
        }

        cap.stop_capture();
        spdlog::info("ARP pcap subnet scan complete: {} devices found", devices.size());
        ec.clear();
        co_return devices;
    }


    // Windows pcap 路径：单目标扫描
    auto arp_scanner::scan_single_pcap(std::uint32_t target_ip,
                                        std::error_code &ec) -> net::awaitable<std::optional<device>>
    {
        auto executor = co_await net::this_coro::executor;

        auto [iface, mac, src_ip] = resolve_interface(target_ip);
        if (iface.empty() || mac[0] == std::byte{})
        {
            ec = fault::make_error_code(fault::code::arp_failed);
            co_return std::nullopt;
        }
        sender_mac_ = mac;
        sender_ip_ = src_ip;

        transport::pcap_capture cap{iface, executor};
        std::error_code filter_ec{};
        cap.set_filter("arp and arp[6:2] = 2", filter_ec);
        if (filter_ec)
        {
            ec = filter_ec;
            co_return std::nullopt;
        }

        std::error_code start_ec{};
        co_await cap.start_capture(start_ec);
        if (start_ec)
        {
            ec = start_ec;
            co_return std::nullopt;
        }

        auto state = std::make_shared<reply_state>(executor);
        cap.set_packet_handler([state](std::span<const std::byte> pkt) {
            state->queue.emplace_back(pkt.begin(), pkt.end());
            state->wakeup.cancel();
        });

        auto request = build_arp_request(sender_ip_, target_ip);
        std::error_code send_ec{};
        cap.send_packet(request, send_ec);
        if (send_ec)
        {
            cap.stop_capture();
            ec = send_ec;
            co_return std::nullopt;
        }

        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(arp_timeout_ms_);
        state->wakeup.expires_at(deadline);

        while (true)
        {
            for (auto it = state->queue.begin(); it != state->queue.end(); ++it)
            {
                auto parsed = parse_arp_reply(*it);
                if (parsed && parse_ipv4(parsed->ip_address) == target_ip)
                {
                    cap.stop_capture();
                    ec.clear();
                    co_return parsed;
                }
            }

            auto wait_ec = boost::system::error_code{};
            co_await state->wakeup.async_wait(
                net::redirect_error(net::use_awaitable, wait_ec));

            if (wait_ec == net::error::operation_aborted)
            {
                continue;
            }

            break;
        }

        cap.stop_capture();
        spdlog::debug("ARP pcap single scan no reply: {}", ipv4_to_string(target_ip));
        co_return std::nullopt;
    }

#endif // _WIN32


} // namespace sec::scanner
