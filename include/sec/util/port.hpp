#pragma once

#include <sec/util/string.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace sec::util
{
    /// 解析端口范围字符串。支持 "22,80,443"、"1-1024"、单个端口三种格式。
    [[nodiscard]] inline auto parse_port_range(const std::string &range) -> std::vector<std::uint16_t>
    {
        auto result = std::vector<std::uint16_t>{};

        // 逗号分隔的列表，如 "22,80,443"
        if (range.find(',') != std::string::npos)
        {
            auto parts = split(range, ',');
            for (const auto &part : parts)
            {
                try
                {
                    auto port = static_cast<std::uint16_t>(std::stoul(part));
                    if (port > 0)
                    {
                        result.push_back(port);
                    }
                }
                catch (const std::exception &)
                {
                    // 跳过无效端口
                }
            }
            return result;
        }

        // 范围，如 "1-1024"
        auto dash_pos = range.find('-');
        if (dash_pos != std::string::npos)
        {
            try
            {
                auto start = static_cast<std::uint16_t>(std::stoul(range.substr(0, dash_pos)));
                auto end = static_cast<std::uint16_t>(std::stoul(range.substr(dash_pos + 1)));
                for (auto p = start; p <= end && p > 0; ++p)
                {
                    result.push_back(p);
                }
            }
            catch (const std::exception &)
            {
                // 返回空
            }
            return result;
        }

        // 单个端口
        try
        {
            auto port = static_cast<std::uint16_t>(std::stoul(range));
            if (port > 0)
            {
                result.push_back(port);
            }
        }
        catch (const std::exception &)
        {
            // 返回空
        }

        return result;
    }
}
