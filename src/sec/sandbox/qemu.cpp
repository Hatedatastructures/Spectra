// QEMU/KVM VM 后端实现 — 通过 libvirt virsh CLI 操作

#include <sec/sandbox/qemu.hpp>

#include <sec/fault/code.hpp>
#include <sec/fault/compatible.hpp>

#include <spdlog/spdlog.h>

#ifdef _WIN32
#include <windows.h>
#endif

#include <chrono>
#include <cstdlib>
#include <string>
#include <thread>

namespace sec::sandbox
{
    namespace
    {
#ifdef _WIN32
        auto exec_capture(std::string_view cmd) -> std::pair<int, std::string>
        {
            auto pipe_read = HANDLE{};
            auto pipe_write = HANDLE{};
            auto sa = SECURITY_ATTRIBUTES{};
            sa.nLength = sizeof(SECURITY_ATTRIBUTES);
            sa.bInheritHandle = TRUE;
            if (!CreatePipe(&pipe_read, &pipe_write, &sa, 0)) return {-1, {}};
            SetHandleInformation(pipe_read, HANDLE_FLAG_INHERIT, 0);
            auto startup = STARTUPINFOA{};
            startup.cb = sizeof(STARTUPINFOA);
            startup.hStdOutput = pipe_write;
            startup.hStdError = pipe_write;
            startup.dwFlags |= STARTF_USESTDHANDLES;
            auto process = PROCESS_INFORMATION{};
            auto cmd_str = std::string{cmd};
            if (!CreateProcessA(nullptr, cmd_str.data(), nullptr, nullptr, TRUE,
                                CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process))
            {
                CloseHandle(pipe_write);
                CloseHandle(pipe_read);
                return {-1, {}};
            }
            CloseHandle(pipe_write);
            auto buf = std::string{};
            char tmp[4096];
            DWORD bytes_read = 0;
            while (ReadFile(pipe_read, tmp, sizeof(tmp), &bytes_read, nullptr) && bytes_read > 0)
            {
                buf.append(tmp, bytes_read);
            }
            CloseHandle(pipe_read);
            WaitForSingleObject(process.hProcess, INFINITE);
            DWORD exit_code = 0;
            GetExitCodeProcess(process.hProcess, &exit_code);
            CloseHandle(process.hProcess);
            CloseHandle(process.hThread);
            return {static_cast<int>(exit_code), buf};
        }
#else
        auto exec_capture(std::string_view cmd) -> std::pair<int, std::string>
        {
            auto pipe = popen(std::string{cmd}.c_str(), "r");
            if (!pipe) return {-1, {}};
            auto buf = std::string{};
            char tmp[4096];
            while (fgets(tmp, sizeof(tmp), pipe)) buf += tmp;
            auto rc = pclose(pipe);
            return {rc, buf};
        }
#endif
    } // anonymous namespace


    qemu_backend::qemu_backend(sandbox_config cfg)
        : cfg_{std::move(cfg)}
    {
    }


    auto qemu_backend::run_virsh(std::string_view args, std::error_code &ec) -> std::string
    {
        auto cmd = std::string{"virsh "} + std::string{args};
        spdlog::debug("virsh: {}", cmd);
        auto [rc, output] = exec_capture(cmd);
        if (rc != 0)
        {
            spdlog::warn("virsh failed (rc={}): {}", rc, output);
            ec = sec::fault::make_error_code(sec::fault::code::sandbox_error);
            return {};
        }
        ec.clear();
        return output;
    }


    auto qemu_backend::restore_snapshot(std::string_view vm_name,
                                         std::string_view snapshot_name,
                                         std::error_code &ec) -> net::awaitable<void>
    {
        run_virsh(std::string{"snapshot-revert --domain "} + std::string{vm_name} +
                  " --snapshotname " + std::string{snapshot_name}, ec);
        co_return;
    }


    auto qemu_backend::start(std::string_view vm_name, std::error_code &ec) -> net::awaitable<void>
    {
        run_virsh(std::string{"start "} + std::string{vm_name}, ec);
        co_return;
    }


    auto qemu_backend::stop(std::string_view vm_name, std::error_code &ec) -> net::awaitable<void>
    {
        run_virsh(std::string{"destroy "} + std::string{vm_name}, ec);
        co_return;
    }


    auto qemu_backend::is_running(std::string_view vm_name) -> bool
    {
        auto ec = std::error_code{};
        auto output = run_virsh(std::string{"domstate "} + std::string{vm_name}, ec);
        if (ec) return false;
        return output.find("running") != std::string::npos;
    }


    auto qemu_backend::wait_for_guest(std::string_view vm_name,
                                       std::uint32_t timeout_ms,
                                       std::error_code &ec) -> net::awaitable<void>
    {
        auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::milliseconds{timeout_ms};
        while (std::chrono::steady_clock::now() < deadline)
        {
            auto ec2 = std::error_code{};
            auto output = run_virsh(
                std::string{"domifaddr "} + std::string{vm_name}, ec2);
            if (!ec2 && !output.empty() &&
                output.find("error") == std::string::npos)
            {
                ec.clear();
                co_return;
            }
            std::this_thread::sleep_for(std::chrono::seconds{3});
        }
        ec = sec::fault::make_error_code(sec::fault::code::sandbox_error);
        co_return;
    }


    auto qemu_backend::copy_to_guest(std::string_view vm_name,
                                      std::string_view local_path,
                                      std::string_view remote_path,
                                      std::error_code &ec) -> net::awaitable<void>
    {
        // QEMU 用 virtio-copy 或 scp 传输，此处用 scp（简化）
        // 需要 Guest 内 ssh 服务运行
        auto cmd = std::string{"scp "} + std::string{local_path} + " " +
                   std::string{vm_name} + ":" + std::string{remote_path};
        spdlog::debug("scp: {}", cmd);
        auto [rc, output] = exec_capture(cmd);
        if (rc != 0)
        {
            ec = sec::fault::make_error_code(sec::fault::code::sandbox_error);
        }
        ec.clear();
        co_return;
    }


    auto qemu_backend::exec_in_guest(std::string_view vm_name,
                                      std::string_view command,
                                      std::error_code &ec) -> net::awaitable<std::string>
    {
        auto output = run_virsh(
            std::string{"exec --domain "} + std::string{vm_name} +
            " -- " + std::string{command}, ec);
        co_return output;
    }

} // namespace sec::sandbox
