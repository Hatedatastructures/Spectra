/**
 * @file monitor.hpp
 * @brief 行为监控抽象接口
 * @details 定义 ETW/sysmon/strace/VMI 共用的监控接口。
 */
#pragma once

#include <sec/sandbox/types.hpp>

#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace sec::sandbox
{
    /**
     * @brief 行为监控抽象接口
     */
    class monitor
    {
    public:
        virtual ~monitor() = default;

        /**
         * @brief 开始收集行为事件
         * @param vm_name 要监控的 VM 名称
         */
        virtual auto start(std::string_view vm_name, std::error_code &ec) -> void = 0;

        /**
         * @brief 停止收集
         */
        virtual auto stop() -> void = 0;

        /**
         * @brief 获取已收集的事件列表
         */
        [[nodiscard]] virtual auto events() const -> const std::vector<behavior_event> & = 0;

        /**
         * @brief 是否正在收集
         */
        [[nodiscard]] virtual auto is_running() const -> bool = 0;
    };

} // namespace sec::sandbox
