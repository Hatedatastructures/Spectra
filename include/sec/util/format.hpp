#pragma once

#include <ctime>
#include <cstdint>
#include <string>

namespace sec::util
{
    /// 将 epoch 秒数格式化为 "YYYY-MM-DD HH:MM:SS" 字符串
    [[nodiscard]] inline auto format_time(std::int64_t epoch_seconds) -> std::string
    {
        auto time_val = static_cast<std::time_t>(epoch_seconds);
        auto tm_val = std::localtime(&time_val);
        if (!tm_val)
        {
            return "-";
        }
        char buf[32]{};
        std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm_val);
        return buf;
    }
}
