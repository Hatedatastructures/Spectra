// SOCKS5 协议解码器实现

#include <sec/decoder/socks5.hpp>


namespace sec::decoder
{

    namespace
    {

        auto read_u8(const std::byte *p) noexcept -> std::uint8_t
        {
            return static_cast<std::uint8_t>(*p);
        }


        auto read_u16_be(const std::byte *p) noexcept -> std::uint16_t
        {
            return (static_cast<std::uint16_t>(p[0]) << 8) |
                   (static_cast<std::uint16_t>(p[1]));
        }

    } // anonymous namespace


    [[nodiscard]] auto socks5_decoder::decode(std::span<const std::byte> payload) noexcept
        -> std::optional<socks5_info>
    {
        if (payload.size() < 3)
        {
            return std::nullopt;
        }

        const auto *p = payload.data();
        auto version = read_u8(p);

        // SOCKS5 版本号必须是 0x05
        if (version != 0x05)
        {
            return std::nullopt;
        }

        socks5_info info;
        info.version = version;
        info.method_count = read_u8(p + 1);

        // 方法协商阶段：VER(1) + NMETHODS(1) + METHODS(N)
        if (payload.size() < static_cast<std::size_t>(2 + info.method_count))
        {
            return std::nullopt;
        }

        // 检查是否为请求阶段（VER=5, CMD=1/2/3）
        if (payload.size() >= 10 && read_u8(p + 1) <= 0x03)
        {
            auto cmd = read_u8(p + 1);
            // 验证 RSV=0 和 ATYP
            auto atyp = read_u8(p + 3);

            if (atyp == 0x01 && payload.size() >= 10)
            {
                // IPv4: ATYP(1) + ADDR(4) + PORT(2)
                info.command = cmd;
                info.target_address = std::to_string(read_u8(p + 4)) + "." +
                                      std::to_string(read_u8(p + 5)) + "." +
                                      std::to_string(read_u8(p + 6)) + "." +
                                      std::to_string(read_u8(p + 7));
                info.target_port = read_u16_be(p + 8);
            }
            else if (atyp == 0x03 && payload.size() >= 7)
            {
                // 域名: ATYP(1) + LEN(1) + DOMAIN(N) + PORT(2)
                auto domain_len = read_u8(p + 4);
                if (payload.size() >= static_cast<std::size_t>(5 + domain_len + 2))
                {
                    info.command = cmd;
                    info.target_address.assign(
                        reinterpret_cast<const char *>(p + 5), domain_len);
                    info.target_port = read_u16_be(p + 5 + domain_len);
                }
            }
        }

        return info;
    }


} // namespace sec::decoder
