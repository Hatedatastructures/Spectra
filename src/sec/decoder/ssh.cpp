// SSH 协议解码器实现

#include <sec/decoder/ssh.hpp>


namespace sec::decoder
{

    [[nodiscard]] auto ssh_decoder::decode(std::span<const std::byte> payload) noexcept
        -> std::optional<ssh_info>
    {
        // SSH 标识最小 "SSH-2.0-\r\n" = 9 字节
        if (payload.size() < 9)
        {
            return std::nullopt;
        }

        auto sv = std::string_view{
            reinterpret_cast<const char *>(payload.data()),
            payload.size()};

        // SSH 标识必须以 "SSH-" 开头
        if (sv.substr(0, 4) != "SSH-")
        {
            return std::nullopt;
        }

        // 查找行尾
        auto crlf = sv.find("\r\n");
        if (crlf == std::string_view::npos)
        {
            crlf = sv.find('\n');
            if (crlf == std::string_view::npos)
            {
                crlf = sv.size();
            }
        }

        auto ident_line = sv.substr(0, crlf);

        // 格式：SSH-protoversion-softwareversion SP comments CR/LF
        ssh_info info;

        // 提取协议版本（第一个 '-' 到第二个 '-' 之间）
        auto dash1 = ident_line.find('-', 4);
        if (dash1 == std::string_view::npos)
        {
            return std::nullopt;
        }

        info.protocol_version = std::string(ident_line.substr(4, dash1 - 4));

        // 提取软件版本（第二个 '-' 到空格或行尾）
        auto sp = ident_line.find(' ', dash1 + 1);
        auto sv_end = (sp != std::string_view::npos) ? sp : ident_line.size();

        info.software_version = std::string(ident_line.substr(dash1 + 1, sv_end - dash1 - 1));

        // 通过常见的服务端标识判断
        // 服务端常见：OpenSSH, dropbear 等（通常以大写开头）
        info.is_server = (ident_line.find("OpenSSH") != std::string_view::npos);

        return info;
    }


} // namespace sec::decoder
