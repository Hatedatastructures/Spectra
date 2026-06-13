#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace sec::util
{
    /// 去除字符串两端空白（空格、制表符、回车、换行）
    [[nodiscard]] inline auto trim(std::string_view sv) -> std::string_view
    {
        while (!sv.empty() && (sv.front() == ' ' || sv.front() == '\t'))
        {
            sv.remove_prefix(1);
        }
        while (!sv.empty() && (sv.back() == ' ' || sv.back() == '\t' || sv.back() == '\r' || sv.back() == '\n'))
        {
            sv.remove_suffix(1);
        }
        return sv;
    }

    /// 按 delim 分割字符串，去除每段两端空白并丢弃空段
    [[nodiscard]] inline auto split(std::string_view sv, char delim) -> std::vector<std::string>
    {
        auto tokens = std::vector<std::string>{};
        auto start = std::size_t{0};
        while (start < sv.size())
        {
            auto pos = sv.find(delim, start);
            if (pos == std::string_view::npos)
            {
                auto tok = trim(sv.substr(start));
                if (!tok.empty())
                {
                    tokens.emplace_back(tok);
                }
                break;
            }
            auto tok = trim(sv.substr(start, pos - start));
            if (!tok.empty())
            {
                tokens.emplace_back(tok);
            }
            start = pos + 1;
        }
        return tokens;
    }
}
