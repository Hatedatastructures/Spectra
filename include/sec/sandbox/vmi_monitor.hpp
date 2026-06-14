/**
 * @file vmi_monitor.hpp
 * @brief VMI 行为监控（通过 DRAKVUF）
 * @details 从 hypervisor 层隐蔽监控 Guest 行为，不注入任何 agent。
 * DRAKVUF 提供 Windows EPROCESS / Linux task_struct 解析 + 系统调用陷阱。
 */
#pragma once

#include <sec/sandbox/monitor.hpp>
#include <sec/sandbox/types.hpp>

#include <atomic>
#include <string>
#include <vector>

namespace sec::sandbox
{
    /**
     * @brief VMI 监控配置
     */
    struct vmi_config
    {
        /** @brief DRAKVUF 可执行路径 */
        std::string drakvuf_path{"drakvuf"};
        /** @brief Windows 内核符号文件路径（ Rekall profile） */
        std::string rekall_profile;
        /** @brief 分析超时（秒） */
        std::uint32_t timeout_seconds{120};
    };

    /**
     * @brief DRAKVUF VMI 行为监控
     * @details 通过子进程调用 DRAKVUF CLI，从 Xen/KVM hypervisor 层
     * 读取 Guest 内存，hook 系统调用（不注入 Guest），输出 JSON 行为日志。
     */
    class vmi_monitor : public monitor
    {
    public:
        explicit vmi_monitor(vmi_config cfg);
        ~vmi_monitor() override;

        auto start(std::string_view vm_name, std::error_code &ec) -> void override;
        auto stop() -> void override;
        [[nodiscard]] auto events() const -> const std::vector<behavior_event> & override;
        [[nodiscard]] auto is_running() const -> bool override;

    private:
        /**
         * @brief 解析 DRAKVUF JSON 输出行，转换为 behavior_event
         */
        auto parse_drakvuf_line(std::string_view line) -> void;

        vmi_config cfg_;
        std::atomic<bool> running_{false};
        std::vector<behavior_event> events_;
        std::string raw_output_;
    };

} // namespace sec::sandbox
