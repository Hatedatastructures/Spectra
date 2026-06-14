/**
 * @file vm_backend.hpp
 * @brief VM 后端抽象接口
 * @details 定义 VirtualBox/QEMU/Hyper-V 共用的 VM 管理接口。
 * 各后端实现快照恢复、启动/关机、文件复制、Guest 内执行等操作。
 */
#pragma once

#include <boost/asio.hpp>

#include <string>
#include <string_view>
#include <system_error>

namespace net = boost::asio;

namespace sec::sandbox
{
    /**
     * @brief VM 后端抽象接口
     * @details 所有方法都是协程（返回 awaitable），通过 engine::context 的 io_context 调度。
     */
    class vm_backend
    {
    public:
        virtual ~vm_backend() = default;

        /**
         * @brief 恢复 VM 到指定快照（分析前的清洁状态）
         */
        virtual auto restore_snapshot(std::string_view vm_name,
                                      std::string_view snapshot_name,
                                      std::error_code &ec) -> net::awaitable<void> = 0;

        /**
         * @brief 启动 VM（无头模式）
         */
        virtual auto start(std::string_view vm_name, std::error_code &ec) -> net::awaitable<void> = 0;

        /**
         * @brief 强制关机（不等待 Guest 内关机流程）
         */
        virtual auto stop(std::string_view vm_name, std::error_code &ec) -> net::awaitable<void> = 0;

        /**
         * @brief 查询 VM 是否正在运行
         */
        [[nodiscard]] virtual auto is_running(std::string_view vm_name) -> bool = 0;

        /**
         * @brief 等待 VM 启动完成（Guest 内网络可达）
         * @param timeout_ms 超时毫秒
         */
        virtual auto wait_for_guest(std::string_view vm_name,
                                     std::uint32_t timeout_ms,
                                     std::error_code &ec) -> net::awaitable<void> = 0;

        /**
         * @brief 复制文件到 Guest
         */
        virtual auto copy_to_guest(std::string_view vm_name,
                                    std::string_view local_path,
                                    std::string_view remote_path,
                                    std::error_code &ec) -> net::awaitable<void> = 0;

        /**
         * @brief 在 Guest 内执行命令
         * @return 命令的 stdout 输出
         */
        virtual auto exec_in_guest(std::string_view vm_name,
                                    std::string_view command,
                                    std::error_code &ec) -> net::awaitable<std::string> = 0;
    };

} // namespace sec::sandbox
