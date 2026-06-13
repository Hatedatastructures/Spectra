// 解码器管线实现

#include <sec/decoder/pipeline.hpp>


namespace sec::decoder
{

    namespace
    {

        // 基于端口号的协议识别
        auto guess_protocol(std::uint16_t src_port, std::uint16_t dst_port) noexcept
            -> int
        {
            // 目标端口优先识别
            switch (dst_port)
            {
            case 80:   return 0;  // HTTP
            case 53:   return 1;  // DNS
            case 443:  return 2;  // TLS
            case 1080: return 3;  // SOCKS5
            case 22:   return 4;  // SSH
            case 21:   return 5;  // FTP
            case 25:   return 6;  // SMTP
            default:   break;
            }

            // 源端口识别（响应方向）
            switch (src_port)
            {
            case 80:   return 0;
            case 53:   return 1;
            case 443:  return 2;
            case 1080: return 3;
            case 22:   return 4;
            case 21:   return 5;
            case 25:   return 6;
            default:   return -1;
            }
        }

    } // anonymous namespace


    [[nodiscard]] auto pipeline::process(std::span<const std::byte> raw_packet, std::error_code &ec) noexcept
        -> std::optional<decoded_packet>
    {
        auto frame_opt = parser_.parse(raw_packet, ec);
        if (!frame_opt)
        {
            return std::nullopt;
        }

        decoded_packet result;
        result.frame = *frame_opt;

        const auto payload = result.frame.payload;
        if (payload.empty())
        {
            dispatch(result);
            return result;
        }

        const auto proto = guess_protocol(result.frame.src_port, result.frame.dst_port);

        switch (proto)
        {
        case 0:
        {
            auto decoded = http_.decode(payload);
            if (decoded) { result.protocol = std::move(*decoded); }
            break;
        }
        case 1:
        {
            auto decoded = dns_.decode(payload);
            if (decoded) { result.protocol = std::move(*decoded); }
            break;
        }
        case 2:
        {
            auto decoded = tls_.decode(payload);
            if (decoded) { result.protocol = std::move(*decoded); }
            break;
        }
        case 3:
        {
            auto decoded = socks5_.decode(payload);
            if (decoded) { result.protocol = std::move(*decoded); }
            break;
        }
        case 4:
        {
            auto decoded = ssh_.decode(payload);
            if (decoded) { result.protocol = std::move(*decoded); }
            break;
        }
        case 5:
        {
            auto decoded = ftp_.decode(payload);
            if (decoded) { result.protocol = std::move(*decoded); }
            break;
        }
        case 6:
        {
            auto decoded = smtp_.decode(payload);
            if (decoded) { result.protocol = std::move(*decoded); }
            break;
        }
        default:
            break;
        }

        dispatch(result);
        return result;
    }


    [[nodiscard]] auto pipeline::subscribe(decoded_callback callback)
        -> std::size_t
    {
        auto handle = next_handle_++;
        subscribers_.push_back(std::move(callback));
        return handle;
    }


    void pipeline::unsubscribe(std::size_t handle)
    {
        if (handle < subscribers_.size())
        {
            subscribers_[handle] = nullptr;
        }
    }


    void pipeline::dispatch(decoded_packet &packet)
    {
        for (auto &cb : subscribers_)
        {
            if (cb)
            {
                cb(packet);
            }
        }
    }


} // namespace sec::decoder
