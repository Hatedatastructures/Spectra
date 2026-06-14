/**
 * @file qemu.hpp
 * @brief QEMU/KVM VM 后端
 * @details 通过 libvirt virsh CLI 管理 QEMU/KVM 虚拟机。
 */
#pragma once

#include <sec/sandbox/vm_backend.hpp>
#include <sec/sandbox/types.hpp>

namespace sec::sandbox
{
    class qemu_backend : public vm_backend
    {
    public:
        explicit qemu_backend(sandbox_config cfg);

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
        auto run_virsh(std::string_view args, std::error_code &ec) -> std::string;
        sandbox_config cfg_;
    };

} // namespace sec::sandbox
