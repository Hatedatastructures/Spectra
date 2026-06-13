// 数据包帧解析实现

#include <sec/decoder/frame.hpp>
#include <sec/fault/compatible.hpp>

#include <cstring>


namespace sec::decoder
{

    namespace
    {

        // Ethernet II 头部长度（6+6+2 = 14 字节）
        constexpr std::size_t eth_header_len{14};

        // EtherType 值
        constexpr std::uint16_t ethertype_ipv4{0x0800};
        constexpr std::uint16_t ethertype_arp{0x0806};

        // IPv4 头部最小长度（20 字节）
        constexpr std::size_t ipv4_min_header_len{20};

        // TCP 头部最小长度（20 字节）
        constexpr std::size_t tcp_min_header_len{20};

        // UDP 头部长度（8 字节）
        constexpr std::size_t udp_header_len{8};

        // 协议号
        constexpr std::uint8_t proto_tcp{6};
        constexpr std::uint8_t proto_udp{17};

        // ARP payload 最小长度：HTYPE(2)+PTYPE(2)+HLEN(1)+PLEN(1)+OPER(2)+SHA(6)+SPA(4)+THA(6)+TPA(4) = 28
        constexpr std::size_t arp_min_payload_len{28};

    } // anonymous namespace


    namespace
    {

        auto parse_arp(const std::byte *arp_data, std::size_t arp_len,
            std::error_code &ec) noexcept -> std::optional<packet_info>
        {
            if (arp_len < arp_min_payload_len)
            {
                ec = sec::fault::make_error_code(sec::fault::code::protocol_error);
                return std::nullopt;
            }

            packet_info info{};
            info.protocol = 0;

            arp_packet arp{};
            arp.opcode = read_u16_be(arp_data + 6);
            std::memcpy(arp.sender_mac.data(), arp_data + 8, 6);
            arp.sender_ip = read_u32_be(arp_data + 14);
            std::memcpy(arp.target_mac.data(), arp_data + 18, 6);
            arp.target_ip = read_u32_be(arp_data + 24);

            info.src_ip = arp.sender_ip;
            info.dst_ip = arp.target_ip;
            info.arp = std::move(arp);
            return info;
        }

        void parse_tcp(const std::byte *transport_data, std::size_t ip_payload_len,
            packet_info &info, std::error_code &ec) noexcept
        {
            if (ip_payload_len < tcp_min_header_len)
            {
                ec = sec::fault::make_error_code(sec::fault::code::protocol_error);
                return;
            }

            info.src_port = read_u16_be(transport_data);
            info.dst_port = read_u16_be(transport_data + 2);
            info.tcp_flags = static_cast<std::uint8_t>(transport_data[13]);

            const auto data_offset = (static_cast<std::uint8_t>(transport_data[12]) >> 4) * 4;

            if (ip_payload_len > data_offset)
            {
                info.payload = std::span<const std::byte>{
                    transport_data + data_offset,
                    ip_payload_len - data_offset
                };
            }
        }

        void parse_udp(const std::byte *transport_data, std::size_t ip_payload_len,
            packet_info &info) noexcept
        {
            if (ip_payload_len < udp_header_len)
            {
                return;
            }

            info.src_port = read_u16_be(transport_data);
            info.dst_port = read_u16_be(transport_data + 2);

            const auto udp_length = read_u16_be(transport_data + 4);
            const auto udp_payload_len = (udp_length > udp_header_len)
                ? udp_length - udp_header_len
                : std::size_t{0};
            const auto actual_payload = std::min(udp_payload_len, ip_payload_len - udp_header_len);

            if (actual_payload > 0)
            {
                info.payload = std::span<const std::byte>{
                    transport_data + udp_header_len,
                    actual_payload
                };
            }
        }

        auto parse_ipv4(const std::byte *ip_data, std::size_t ip_total_len,
            std::error_code &ec) noexcept -> std::optional<packet_info>
        {
            const auto version_ihl = static_cast<std::uint8_t>(ip_data[0]);
            const auto version = (version_ihl >> 4) & 0x0F;

            if (version != 4)
            {
                ec = sec::fault::make_error_code(sec::fault::code::protocol_error);
                return std::nullopt;
            }

            const auto ihl = (version_ihl & 0x0F) * 4;

            if (ihl < ipv4_min_header_len || ip_total_len < ihl)
            {
                ec = sec::fault::make_error_code(sec::fault::code::protocol_error);
                return std::nullopt;
            }

            packet_info info{};
            info.protocol = static_cast<std::uint8_t>(ip_data[9]);
            info.src_ip = read_u32_be(ip_data + 12);
            info.dst_ip = read_u32_be(ip_data + 16);

            const auto total_length = read_u16_be(ip_data + 2);
            const auto ip_payload_len = (total_length > ip_total_len)
                ? ip_total_len - ihl
                : total_length - ihl;

            const auto *transport_data = ip_data + ihl;

            if (info.protocol == proto_tcp)
            {
                parse_tcp(transport_data, ip_payload_len, info, ec);
                if (ec) return std::nullopt;
            }
            else if (info.protocol == proto_udp)
            {
                parse_udp(transport_data, ip_payload_len, info);
            }
            else
            {
                info.payload = std::span<const std::byte>{transport_data, ip_payload_len};
            }

            return info;
        }

    } // anonymous namespace


    [[nodiscard]] auto frame_parser::parse(std::span<const std::byte> raw_data, std::error_code &ec) noexcept
        -> std::optional<packet_info>
    {
        ec.clear();

        if (raw_data.size() < eth_header_len)
        {
            ec = sec::fault::make_error_code(sec::fault::code::protocol_error);
            return std::nullopt;
        }

        const auto *eth = raw_data.data();
        const auto ethertype = read_u16_be(eth + 12);

        if (ethertype == ethertype_arp)
        {
            auto result = parse_arp(eth + eth_header_len, raw_data.size() - eth_header_len, ec);
            if (result)
            {
                result->timestamp = std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now().time_since_epoch());
            }
            return result;
        }

        if (ethertype != ethertype_ipv4)
        {
            return std::nullopt;
        }

        auto result = parse_ipv4(eth + eth_header_len, raw_data.size() - eth_header_len, ec);
        if (result)
        {
            result->timestamp = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now().time_since_epoch());
        }
        return result;
    }


} // namespace sec::decoder
