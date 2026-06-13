// HTTP 协议解码器实现

#include <sec/decoder/http.hpp>
#include <sec/decoder/util.hpp>

#include <algorithm>
#include <cctype>
#include <cstring>


namespace sec::decoder
{

    namespace
    {

        using sec::decoder::to_string_view;


        auto find_crlf(std::string_view sv, std::size_t offset = 0) noexcept -> std::size_t
        {
            auto pos = sv.find("\r\n", offset);
            return (pos == std::string_view::npos) ? sv.size() : pos;
        }


        auto find_header_end(std::string_view sv) noexcept -> std::size_t
        {
            auto pos = sv.find("\r\n\r\n");
            return (pos == std::string_view::npos) ? sv.size() : pos;
        }


        auto to_lower(std::string_view sv) -> std::string
        {
            std::string result(sv);
            std::transform(result.begin(), result.end(), result.begin(),
                [](unsigned char c) { return std::tolower(c); });
            return result;
        }


        auto extract_header_value(std::string_view headers, std::string_view name) -> std::string
        {
            auto lower_headers = to_lower(headers);
            auto lower_name = to_lower(name);

            // 搜索 "name: " 模式
            auto search_key = lower_name;
            search_key = search_key + ": ";

            auto pos = lower_headers.find(search_key);
            if (pos == std::string_view::npos)
            {
                return {};
            }

            auto value_start = pos + search_key.size();
            auto value_end = find_crlf(headers, pos);
            auto value_len = (value_end > value_start) ? value_end - value_start : std::size_t{0};

            return std::string(headers.substr(value_start, value_len));
        }


        bool is_http_request_line(std::string_view line) noexcept
        {
            // 检查是否以 HTTP 方法开头
            static constexpr std::string_view methods[] = {
                "GET ", "POST ", "PUT ", "DELETE ",
                "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "
            };

            for (const auto &m : methods)
            {
                if (line.size() >= m.size() && line.substr(0, m.size()) == m)
                {
                    return true;
                }
            }
            return false;
        }


        bool is_http_status_line(std::string_view line) noexcept
        {
            return line.size() >= 5 && line.substr(0, 5) == "HTTP/";
        }

    } // anonymous namespace


    [[nodiscard]] auto http_decoder::decode(std::span<const std::byte> payload) noexcept
        -> std::optional<http_info>
    {
        if (payload.size() < 16)
        {
            return std::nullopt;
        }

        auto sv = to_string_view(payload);
        auto first_line_end = find_crlf(sv);

        if (first_line_end == 0 || first_line_end >= sv.size())
        {
            return std::nullopt;
        }

        auto first_line = sv.substr(0, first_line_end);
        http_info info;

        if (is_http_request_line(first_line))
        {
            info.type = http_message_type::request;

            // 解析 "METHOD URI HTTP/1.x"
            auto space1 = first_line.find(' ');
            auto space2 = first_line.find(' ', space1 + 1);

            if (space1 != std::string_view::npos && space2 != std::string_view::npos)
            {
                info.method = std::string(first_line.substr(0, space1));
                info.uri = std::string(first_line.substr(space1 + 1, space2 - space1 - 1));

                auto ver_start = space2 + 1;
                if (first_line.size() > ver_start + 5)
                {
                    info.version = std::string(first_line.substr(ver_start + 5));
                }
            }
        }
        else if (is_http_status_line(first_line))
        {
            info.type = http_message_type::response;

            // 解析 "HTTP/1.x STATUS_CODE REASON"
            auto space1 = first_line.find(' ');
            if (space1 != std::string_view::npos && first_line.size() > space1 + 4)
            {
                auto status_str = first_line.substr(space1 + 1, 3);
                info.status_code = std::stoi(std::string(status_str));

                if (first_line.size() > space1 + 5)
                {
                    info.version = std::string(first_line.substr(5, space1 - 5));
                }
            }
        }
        else
        {
            return std::nullopt;
        }

        // 提取头部字段
        auto headers_end = find_header_end(sv);
        if (headers_end >= sv.size())
        {
            return info;
        }

        auto headers = sv.substr(0, headers_end);
        info.host = extract_header_value(headers, "Host");
        info.user_agent = extract_header_value(headers, "User-Agent");
        info.content_type = extract_header_value(headers, "Content-Type");

        auto cl_str = extract_header_value(headers, "Content-Length");
        if (!cl_str.empty())
        {
            try
            {
                info.content_length = std::stoll(cl_str);
            }
            catch (...)
            {
                info.content_length = -1;
            }
        }

        // 提取 body
        auto body_offset = headers_end + 4;
        if (sv.size() > body_offset)
        {
            info.body = payload.subspan(body_offset);
        }

        return info;
    }


} // namespace sec::decoder
