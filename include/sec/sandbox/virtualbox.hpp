/**
 * @file virtualbox.hpp
 * @brief VirtualBox VM 后端
 * @details 通过 VBoxManage CLI 管理 VM（快照/启动/关机/文件复制/Guest 执行），
 * 不链接 VirtualBox SDK，降低依赖。
 */
#pragma once

#include <sec/sandbox/vm_backend.hpp>
#include <sec/sandbox/types.hpp>

namespace sec::sandbox
{
    /**
     * @brief VirtualBox VM 后端实现
     */
    class virtualbox_backend : public vm_backend
    {
    public:
        explicit virtualbox_backend(sandbox_config cfg);

        auto restore_snapshot(std::string_view vm_name,
                              std::string_view snapshot_name,
                              std::error_code &ec) -> net::awaitable<void> override;
        auto start(std::string_view vm_name, std::error_code &ec) -> net::awaitable<void> override;
        auto stop(std::string_view vm_name, std::error_code &ec) -> net::awaitable<void> override;
        [[nodiscard]] auto is_running(std::string_view vm_name) -> bool override;
        auto wait_for_guest(std::string_view vm_name,
                             std::uint32_t timeout_ms,
                             std::error_code &ec) -> net::awaitable<void> override;
        auto copy_to_guest(std::string_view vm_name,
                            std::string_view local_path,
                            std::string_view remote_path,
                            std::error_code &ec) -> net::awaitable<void> override;
        auto exec_in_guest(std::string_view vm_name,
                            std::string_view command,
                            std::error_code &ec) -> net::awaitable<std::string> override;

    private:
        /**
         * @brief 执行 VBoxManage 命令并返回 stdout
         */
        auto run_vboxmanage(std::string_view args, std::error_code &ec) -> std::string;

        /**
         * @brief 获取 VBoxManage 可执行路径
         */
        [[nodiscard]] auto resolve_vboxmanage() const -> std::string;

        sandbox_config cfg_;
        std::string vboxmanage_cache_;
    };

} // namespace sec::sandbox
