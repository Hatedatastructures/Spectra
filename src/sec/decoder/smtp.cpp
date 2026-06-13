// SMTP 协议解码器实现

#include <sec/decoder/smtp.hpp>

#include <algorithm>
#include <cctype>


namespace sec::decoder
{

    namespace
    {

        auto to_string_view(std::span<const std::byte> data) noexcept -> std::string_view
        {
            return {reinterpret_cast<const char *>(data.data()), data.size()};
        }


        bool is_smtp_command(std::string_view token) noexcept
        {
            static constexpr std::string_view commands[] = {
                "HELO", "EHLO", "MAIL", "RCPT", "DATA",
                "RSET", "VRFY", "EXPN", "HELP", "NOOP",
                "QUIT", "STARTTLS", "AUTH",  "BDAT"
            };

            for (const auto &cmd : commands)
            {
                if (token == cmd)
                {
                    return true;
                }
            }
            return false;
        }

    } // anonymous namespace


    [[nodiscard]] auto smtp_decoder::decode(std::span<const std::byte> payload) noexcept
        -> std::optional<smtp_info>
    {
        if (payload.size() < 4)
        {
            return std::nullopt;
        }

        auto sv = to_string_view(payload);

        // 去除尾部 CRLF
        while (!sv.empty() && (sv.back() == '\r' || sv.back() == '\n'))
        {
            sv.remove_suffix(1);
        }

        if (sv.empty())
        {
            return std::nullopt;
        }

        smtp_info info;

        // 检查是否为服务器响应（三位数字开头）
        if (sv.size() >= 3 &&
            std::isdigit(static_cast<unsigned char>(sv[0])) &&
            std::isdigit(static_cast<unsigned char>(sv[1])) &&
            std::isdigit(static_cast<unsigned char>(sv[2])))
        {
            info.type = smtp_message_type::response;
            info.status_code = (sv[0] - '0') * 100 +
                               (sv[1] - '0') * 10 +
                               (sv[2] - '0');

            if (sv.size() > 4)
            {
                info.argument = std::string(sv.substr(4));
            }
        }
        else
        {
            // 检查是否为 SMTP 命令
            auto space_pos = sv.find(' ');
            auto cmd = (space_pos != std::string_view::npos)
                ? sv.substr(0, space_pos)
                : sv;

            // 转大写比较
            std::string cmd_upper(cmd);
            std::transform(cmd_upper.begin(), cmd_upper.end(), cmd_upper.begin(),
                [](unsigned char c) { return std::toupper(c); });

            if (!is_smtp_command(cmd_upper))
            {
                return std::nullopt;
            }

            info.type = smtp_message_type::command;
            info.command = cmd_upper;

            if (space_pos != std::string_view::npos && sv.size() > space_pos + 1)
            {
                info.argument = std::string(sv.substr(space_pos + 1));
            }
        }

        return info;
    }


} // namespace sec::decoder
