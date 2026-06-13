// DNS 协议解码器实现

#include <sec/decoder/dns.hpp>

#include <cstring>


namespace sec::decoder
{

    namespace
    {

        auto read_u16_be(const std::byte *p) noexcept -> std::uint16_t
        {
            return (static_cast<std::uint16_t>(p[0]) << 8) |
                   (static_cast<std::uint16_t>(p[1]));
        }


        auto read_u32_be(const std::byte *p) noexcept -> std::uint32_t
        {
            return (static_cast<std::uint32_t>(p[0]) << 24) |
                   (static_cast<std::uint32_t>(p[1]) << 16) |
                   (static_cast<std::uint32_t>(p[2]) << 8) |
                   (static_cast<std::uint32_t>(p[3]));
        }


        // 解析 DNS 名称，处理标签指针压缩
        auto parse_name(std::span<const std::byte> data, std::size_t offset) -> std::string
        {
            std::string result;
            auto pos = offset;
            bool jumped = false;
            std::size_t jump_pos = 0;

            while (pos < data.size())
            {
                auto label_len = static_cast<std::uint8_t>(data[pos]);

                if (label_len == 0)
                {
                    if (!jumped)
                    {
                        jump_pos = pos + 1;
                    }
                    break;
                }

                // 检查指针压缩（高 2 位为 11）
                if ((label_len & 0xC0) == 0xC0)
                {
                    if (pos + 1 >= data.size())
                    {
                        break;
                    }

                    if (!jumped)
                    {
                        jump_pos = pos + 2;
                    }

                    jumped = true;
                    pos = ((static_cast<std::size_t>(label_len) & 0x3F) << 8) |
                          static_cast<std::size_t>(data[pos + 1]);
                    continue;
                }

                pos++;
                if (pos + label_len > data.size())
                {
                    break;
                }

                if (!result.empty())
                {
                    result += '.';
                }

                for (std::size_t i = 0; i < label_len; ++i)
                {
                    result += static_cast<char>(data[pos + i]);
                }

                pos += label_len;
            }

            return result;
        }


        // 跳过 DNS 名称并返回名称结束位置
        auto skip_name(std::span<const std::byte> data, std::size_t offset) -> std::size_t
        {
            auto pos = offset;

            while (pos < data.size())
            {
                auto label_len = static_cast<std::uint8_t>(data[pos]);

                if (label_len == 0)
                {
                    return pos + 1;
                }

                if ((label_len & 0xC0) == 0xC0)
                {
                    return pos + 2;
                }

                pos += 1 + label_len;
            }

            return pos;
        }

    } // anonymous namespace


    [[nodiscard]] auto dns_decoder::decode(std::span<const std::byte> payload) noexcept
        -> std::optional<dns_info>
    {
        // DNS 头部最小 12 字节
        if (payload.size() < 12)
        {
            return std::nullopt;
        }

        const auto *p = payload.data();

        dns_info info;
        info.transaction_id = read_u16_be(p);
        auto flags = read_u16_be(p + 2);
        info.is_response = (flags & 0x8000) != 0;
        info.opcode = (flags >> 11) & 0x0F;
        info.rcode = flags & 0x0F;

        auto qdcount = read_u16_be(p + 4);
        auto ancount = read_u16_be(p + 6);
        auto nscount = read_u16_be(p + 8);
        auto arcount = read_u16_be(p + 10);

        // 安全限制：防止恶意 DNS 包导致过度分配
        if (qdcount > 100 || ancount > 500)
        {
            return std::nullopt;
        }

        std::size_t offset = 12;

        // 解析 Question 部分
        for (std::uint16_t i = 0; i < qdcount && offset < payload.size(); ++i)
        {
            dns_entry entry;
            entry.name = parse_name(payload, offset);
            offset = skip_name(payload, offset);

            if (offset + 4 > payload.size())
            {
                break;
            }

            auto rtype = read_u16_be(payload.data() + offset);
            entry.type = static_cast<dns_record_type>(rtype);
            offset += 4; // QTYPE(2) + QCLASS(2)

            info.questions.push_back(std::move(entry));
        }

        // 解析 Answer 部分
        for (std::uint16_t i = 0; i < ancount && offset < payload.size(); ++i)
        {
            dns_entry entry;
            entry.name = parse_name(payload, offset);
            offset = skip_name(payload, offset);

            if (offset + 10 > payload.size())
            {
                break;
            }

            auto rtype = read_u16_be(payload.data() + offset);
            entry.type = static_cast<dns_record_type>(rtype);
            // skip CLASS(2)
            entry.ttl = read_u32_be(payload.data() + offset + 4);
            auto rdlength = read_u16_be(payload.data() + offset + 8);
            offset += 10;

            if (offset + rdlength > payload.size())
            {
                break;
            }

            // 根据 record type 解析 rdata
            if (entry.type == dns_record_type::a && rdlength == 4)
            {
                const auto *ip = payload.data() + offset;
                entry.data = std::to_string(static_cast<int>(ip[0])) + "." +
                             std::to_string(static_cast<int>(ip[1])) + "." +
                             std::to_string(static_cast<int>(ip[2])) + "." +
                             std::to_string(static_cast<int>(ip[3]));
            }
            else if (entry.type == dns_record_type::aaaa && rdlength == 16)
            {
                const auto *ip = payload.data() + offset;
                char buf[48]{};
                std::snprintf(buf, sizeof(buf),
                    "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                    static_cast<int>(ip[0]), static_cast<int>(ip[1]),
                    static_cast<int>(ip[2]), static_cast<int>(ip[3]),
                    static_cast<int>(ip[4]), static_cast<int>(ip[5]),
                    static_cast<int>(ip[6]), static_cast<int>(ip[7]),
                    static_cast<int>(ip[8]), static_cast<int>(ip[9]),
                    static_cast<int>(ip[10]), static_cast<int>(ip[11]),
                    static_cast<int>(ip[12]), static_cast<int>(ip[13]),
                    static_cast<int>(ip[14]), static_cast<int>(ip[15]));
                entry.data = buf;
            }
            else if (entry.type == dns_record_type::cname || entry.type == dns_record_type::ns)
            {
                entry.data = parse_name(payload, offset);
            }
            else if (entry.type == dns_record_type::txt && rdlength > 0)
            {
                auto txt_len = static_cast<std::uint8_t>(payload[offset]);
                if (txt_len < rdlength)
                {
                    entry.data.assign(
                        reinterpret_cast<const char *>(payload.data() + offset + 1),
                        txt_len);
                }
            }

            offset += rdlength;
            info.answers.push_back(std::move(entry));
        }

        return info;
    }


} // namespace sec::decoder
