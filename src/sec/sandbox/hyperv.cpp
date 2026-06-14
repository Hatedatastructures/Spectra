// Hyper-V VM 后端实现 — 通过 PowerShell Hyper-V 模块操作

#include <sec/sandbox/hyperv.hpp>

#include <sec/fault/code.hpp>
#include <sec/fault/compatible.hpp>

#include <spdlog/spdlog.h>

#ifdef _WIN32
#include <windows.h>
#endif

#include <chrono>
#include <string>
#include <thread>

namespace sec::sandbox
{
    namespace
    {
#ifdef _WIN32
        auto exec_powershell(std::string_view script) -> std::pair<int, std::string>
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

            // 用 powershell.exe -Command 执行脚本
            auto cmd = std::string{"powershell.exe -NoProfile -Command \""} +
                       std::string{script} + "\"";

            if (!CreateProcessA(nullptr, cmd.data(), nullptr, nullptr, TRUE,
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
        // Hyper-V 仅 Windows，POSIX 桩
        auto exec_powershell(std::string_view) -> std::pair<int, std::string>
        {
            return {-1, "Hyper-V is Windows-only"};
        }
#endif
    } // anonymous namespace


    hyperv_backend::hyperv_backend(sandbox_config cfg)
        : cfg_{std::move(cfg)}
    {
    }


    auto hyperv_backend::run_powershell(std::string_view script, std::error_code &ec) -> std::string
    {
        spdlog::debug("PowerShell: {}", script);
        auto [rc, output] = exec_powershell(script);
        if (rc != 0)
        {
            spdlog::warn("PowerShell failed (rc={}): {}", rc, output);
            ec = sec::fault::make_error_code(sec::fault::code::sandbox_error);
            return {};
        }
        ec.clear();
        return output;
    }


    auto hyperv_backend::restore_snapshot(std::string_view vm_name,
                                           std::string_view snapshot_name,
                                           std::error_code &ec) -> net::awaitable<void>
    {
        run_powershell(std::string{"Restore-VMSnapshot -VMName '"} +
                       std::string{vm_name} + "' -Name '" +
                       std::string{snapshot_name} + "' -Confirm:$false", ec);
        co_return;
    }


    auto hyperv_backend::start(std::string_view vm_name, std::error_code &ec) -> net::awaitable<void>
    {
        run_powershell(std::string{"Start-VM -Name '"} + std::string{vm_name} + "'", ec);
        co_return;
    }


    auto hyperv_backend::stop(std::string_view vm_name, std::error_code &ec) -> net::awaitable<void>
    {
        run_powershell(std::string{"Stop-VM -Name '"} + std::string{vm_name} +
                       "' -TurnOff", ec);
        co_return;
    }


    auto hyperv_backend::is_running(std::string_view vm_name) -> bool
    {
        auto ec = std::error_code{};
        auto output = run_powershell(
            std::string{"(Get-VM -Name '"} + std::string{vm_name} + "').State", ec);
        if (ec) return false;
        return output.find("Running") != std::string::npos;
    }


    auto hyperv_backend::wait_for_guest(std::string_view vm_name,
                                         std::uint32_t timeout_ms,
                                         std::error_code &ec) -> net::awaitable<void>
    {
        auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::milliseconds{timeout_ms};
        while (std::chrono::steady_clock::now() < deadline)
        {
            auto ec2 = std::error_code{};
            auto output = run_powershell(
                std::string{"(Get-VMIntegrationService -VMName '"} +
                std::string{vm_name} + "' -Name 'Key-Value Pair Exchange').Enabled", ec2);
            if (!ec2 && output.find("True") != std::string::npos)
            {
                ec.clear();
                co_return;
            }
            std::this_thread::sleep_for(std::chrono::seconds{3});
        }
        ec = sec::fault::make_error_code(sec::fault::code::sandbox_error);
        co_return;
    }


    auto hyperv_backend::copy_to_guest(std::string_view vm_name,
                                        std::string_view local_path,
                                        std::string_view remote_path,
                                        std::error_code &ec) -> net::awaitable<void>
    {
        run_powershell(
            std::string{"Copy-VMFile -Name '"} + std::string{vm_name} +
            "' -SourcePath '" + std::string{local_path} +
            "' -DestinationPath '" + std::string{remote_path} +
            "' -FileSource Host -CreateFullPath", ec);
        co_return;
    }


    auto hyperv_backend::exec_in_guest(std::string_view vm_name,
                                        std::string_view command,
                                        std::error_code &ec) -> net::awaitable<std::string>
    {
        // Hyper-V 的 Invoke-Command 需要 Guest 配置 PowerShell Direct
        auto output = run_powershell(
            std::string{"Invoke-Command -VMName '"} + std::string{vm_name} +
            "' -ScriptBlock { " + std::string{command} + " }", ec);
        co_return output;
    }

} // namespace sec::sandbox
