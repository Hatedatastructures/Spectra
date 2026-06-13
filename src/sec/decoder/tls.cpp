// TLS ClientHello 解码器实现

#include <sec/decoder/tls.hpp>

#include <sstream>


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


        auto read_u24_be(const std::byte *p) noexcept -> std::uint32_t
        {
            return (static_cast<std::uint32_t>(p[0]) << 16) |
                   (static_cast<std::uint32_t>(p[1]) << 8) |
                   (static_cast<std::uint32_t>(p[2]));
        }


        // TLS Content Type
        constexpr std::uint8_t content_type_handshake{22};

        // TLS Handshake Type
        constexpr std::uint8_t handshake_type_client_hello{1};

        // TLS Extension Types
        constexpr std::uint16_t ext_server_name{0x0000};
        constexpr std::uint16_t ext_supported_versions{0x002B};
        constexpr std::uint16_t ext_elliptic_curves{0x000A};
        constexpr std::uint16_t ext_ec_point_formats{0x000B};

        // SNI Name Type
        constexpr std::uint8_t sni_type_hostname{0};


        auto join_ints(const std::vector<std::uint16_t> &vals) -> std::string
        {
            std::ostringstream oss;
            for (std::size_t i = 0; i < vals.size(); ++i)
            {
                if (i > 0)
                {
                    oss << '-';
                }
                oss << vals[i];
            }
            return oss.str();
        }


        auto join_bytes(const std::vector<std::uint8_t> &vals) -> std::string
        {
            std::ostringstream oss;
            for (std::size_t i = 0; i < vals.size(); ++i)
            {
                if (i > 0)
                {
                    oss << '-';
                }
                oss << static_cast<int>(vals[i]);
            }
            return oss.str();
        }

    } // anonymous namespace


    namespace
    {

        void parse_record_header(const std::byte *p, std::span<const std::byte> payload,
            tls_info &info, std::size_t &offset, bool &ok) noexcept
        {
            auto content_type = read_u8(p);
            if (content_type != content_type_handshake)
            {
                ok = false;
                return;
            }

            info.record_version = read_u16_be(p + 1);
            auto hs_type = read_u8(p + 5);

            if (hs_type != handshake_type_client_hello)
            {
                ok = false;
                return;
            }

            offset = 9;
        }

        void parse_client_hello_body(const std::byte *p, std::span<const std::byte> payload,
            tls_info &info, std::size_t &offset) noexcept
        {
            if (offset + 35 > payload.size())
            {
                return;
            }

            info.client_version = read_u16_be(p + offset);
            offset += 2 + 32;

            auto session_id_len = read_u8(p + offset);
            offset += 1 + session_id_len;

            if (offset + 2 > payload.size())
            {
                return;
            }

            auto cs_length = read_u16_be(p + offset);
            offset += 2;

            if (offset + cs_length > payload.size())
            {
                return;
            }

            for (std::size_t i = 0; i + 1 < cs_length; i += 2)
            {
                info.cipher_suites.push_back(read_u16_be(p + offset + i));
            }
            offset += cs_length;

            if (offset + 1 > payload.size())
            {
                return;
            }

            auto comp_len = read_u8(p + offset);
            offset += 1 + comp_len;
        }

        void parse_extensions(const std::byte *p, std::size_t extensions_end,
            tls_info &info, std::size_t &offset) noexcept
        {
            while (offset + 4 <= extensions_end)
            {
                auto ext_type = read_u16_be(p + offset);
                auto ext_len = read_u16_be(p + offset + 2);
                offset += 4;

                info.extensions.push_back(ext_type);

                if (offset + ext_len > extensions_end)
                {
                    break;
                }

                if (ext_type == ext_server_name && ext_len > 5)
                {
                    auto name_type = read_u8(p + offset + 2);
                    if (name_type == sni_type_hostname)
                    {
                        auto name_len = read_u16_be(p + offset + 3);
                        if (offset + 5 + name_len <= extensions_end)
                        {
                            info.sni.assign(
                                reinterpret_cast<const char *>(p + offset + 5),
                                name_len);
                        }
                    }
                }
                else if (ext_type == ext_supported_versions && ext_len > 1)
                {
                    auto sv_list_len = read_u8(p + offset);
                    for (std::size_t i = 0; i + 1 < sv_list_len && offset + 1 + i + 1 < extensions_end; i += 2)
                    {
                        info.supported_versions.push_back(
                            read_u16_be(p + offset + 1 + i));
                    }
                }
                else if (ext_type == ext_elliptic_curves && ext_len > 1)
                {
                    auto ec_list_len = read_u16_be(p + offset);
                    for (std::size_t i = 0; i + 1 < ec_list_len && offset + 2 + i + 1 < extensions_end; i += 2)
                    {
                        info.elliptic_curves.push_back(
                            read_u16_be(p + offset + 2 + i));
                    }
                }
                else if (ext_type == ext_ec_point_formats && ext_len > 1)
                {
                    auto pf_list_len = read_u8(p + offset);
                    for (std::size_t i = 0; i < pf_list_len && offset + 1 + i < extensions_end; ++i)
                    {
                        info.ec_point_formats.push_back(read_u8(p + offset + 1 + i));
                    }
                }

                offset += ext_len;
            }
        }

        void compute_ja3(tls_info &info)
        {
            std::ostringstream ja3_input;
            ja3_input << info.client_version << ',';
            ja3_input << join_ints(info.cipher_suites) << ',';
            ja3_input << join_ints(info.extensions) << ',';
            ja3_input << join_ints(info.elliptic_curves) << ',';
            ja3_input << join_bytes(info.ec_point_formats);
            info.ja3 = ja3_input.str();
        }

    } // anonymous namespace


    [[nodiscard]] auto tls_decoder::decode(std::span<const std::byte> payload) noexcept
        -> std::optional<tls_info>
    {
        if (payload.size() < 5)
        {
            return std::nullopt;
        }

        tls_info info;
        std::size_t offset = 0;
        bool ok = true;

        parse_record_header(payload.data(), payload, info, offset, ok);
        if (!ok)
        {
            return std::nullopt;
        }

        parse_client_hello_body(payload.data(), payload, info, offset);

        if (offset + 2 > payload.size())
        {
            return info;
        }

        auto extensions_total_len = read_u16_be(payload.data() + offset);
        offset += 2;

        auto extensions_end = offset + extensions_total_len;
        if (extensions_end > payload.size())
        {
            extensions_end = payload.size();
        }

        parse_extensions(payload.data(), extensions_end, info, offset);
        compute_ja3(info);

        return info;
    }


} // namespace sec::decoder
