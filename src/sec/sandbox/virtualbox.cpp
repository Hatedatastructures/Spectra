// VirtualBox VM 后端实现 — 通过 VBoxManage CLI 操作

#include <sec/sandbox/virtualbox.hpp>

#include <sec/fault/code.hpp>
#include <sec/fault/compatible.hpp>

#include <spdlog/spdlog.h>

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#else
#include <cstdio>
#endif

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <sstream>
#include <thread>

namespace sec::sandbox
{
    namespace
    {
#ifdef _WIN32
        // Windows: 用 CreateProcess 捕获 stdout
        auto exec_capture(std::string_view cmd) -> std::pair<int, std::string>
        {
            auto pipe_read = HANDLE{};
            auto pipe_write = HANDLE{};
            auto sa = SECURITY_ATTRIBUTES{};
            sa.nLength = sizeof(SECURITY_ATTRIBUTES);
            sa.bInheritHandle = TRUE;
            sa.lpSecurityDescriptor = nullptr;

            if (!CreatePipe(&pipe_read, &pipe_write, &sa, 0))
            {
                return {-1, {}};
            }
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
        // POSIX: popen
        auto exec_capture(std::string_view cmd) -> std::pair<int, std::string>
        {
            auto pipe = popen(std::string{cmd}.c_str(), "r");
            if (!pipe) return {-1, {}};
            auto buf = std::string{};
            auto tmp = char[4096]{};
            while (fgets(tmp, sizeof(tmp), pipe))
            {
                buf += tmp;
            }
            auto rc = pclose(pipe);
            return {rc, buf};
        }
#endif
    } // anonymous namespace


    virtualbox_backend::virtualbox_backend(sandbox_config cfg)
        : cfg_{std::move(cfg)}
    {
    }


    auto virtualbox_backend::resolve_vboxmanage() const -> std::string
    {
        if (!cfg_.vboxmanage_path.empty())
        {
            return cfg_.vboxmanage_path;
        }

#ifdef _WIN32
        // 搜索常见安装路径
        const auto candidates = std::vector<std::string>{
            "C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.exe",
            "C:\\Program Files (x86)\\Oracle\\VirtualBox\\VBoxManage.exe",
        };
        namespace fs = std::filesystem;
        for (const auto &p : candidates)
        {
            if (fs::exists(p)) return p;
        }
        return "VBoxManage"; // 退到 PATH 搜索
#else
        return "VBoxManage";
#endif
    }


    auto virtualbox_backend::run_vboxmanage(std::string_view args, std::error_code &ec) -> std::string
    {
        auto exe = resolve_vboxmanage();
        auto cmd = "\"" + exe + "\" " + std::string{args};
        spdlog::debug("VBoxManage: {}", cmd);

        auto [rc, output] = exec_capture(cmd);
        if (rc != 0)
        {
            spdlog::warn("VBoxManage failed (rc={}): {}", rc, output);
            ec = sec::fault::make_error_code(sec::fault::code::sandbox_error);
            return {};
        }
        ec.clear();
        return output;
    }


    auto virtualbox_backend::restore_snapshot(std::string_view vm_name,
                                               std::string_view snapshot_name,
                                               std::error_code &ec) -> net::awaitable<void>
    {
        auto args = std::string{"snapshot \""} + std::string{vm_name} +
                    "\" restore \"" + std::string{snapshot_name} + "\"";
        run_vboxmanage(args, ec);
        co_return;
    }


    auto virtualbox_backend::start(std::string_view vm_name, std::error_code &ec) -> net::awaitable<void>
    {
        auto args = std::string{"startvm \""} + std::string{vm_name} + "\" --type headless";
        run_vboxmanage(args, ec);
        co_return;
    }


    auto virtualbox_backend::stop(std::string_view vm_name, std::error_code &ec) -> net::awaitable<void>
    {
        auto args = std::string{"controlvm \""} + std::string{vm_name} + "\" poweroff";
        run_vboxmanage(args, ec);
        co_return;
    }


    auto virtualbox_backend::is_running(std::string_view vm_name) -> bool
    {
        auto ec = std::error_code{};
        auto output = run_vboxmanage(
            std::string{"showvminfo \""} + std::string{vm_name} + "\" --machinereadable", ec);
        if (ec) return false;
        // 输出含 VMState="running"
        return output.find("VMState=\"running\"") != std::string::npos;
    }


    auto virtualbox_backend::wait_for_guest(std::string_view vm_name,
                                             std::uint32_t timeout_ms,
                                             std::error_code &ec) -> net::awaitable<void>
    {
        auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::milliseconds{timeout_ms};
        while (std::chrono::steady_clock::now() < deadline)
        {
            auto ec2 = std::error_code{};
            auto output = run_vboxmanage(
                std::string{"guestcontrol \""} + std::string{vm_name} +
                "\" run --exe \"C:\\Windows\\System32\\cmd.exe\" -- /c echo ok", ec2);
            if (!ec2 && output.find("ok") != std::string::npos)
            {
                ec.clear();
                co_return;
            }
            std::this_thread::sleep_for(std::chrono::seconds{2});
        }
        ec = sec::fault::make_error_code(sec::fault::code::sandbox_error);
        co_return;
    }


    auto virtualbox_backend::copy_to_guest(std::string_view vm_name,
                                            std::string_view local_path,
                                            std::string_view remote_path,
                                            std::error_code &ec) -> net::awaitable<void>
    {
        auto args = std::string{"guestcontrol \""} + std::string{vm_name} +
                    "\" copyto --target-directory \"" + std::string{remote_path} +
                    "\" \"" + std::string{local_path} + "\"";
        run_vboxmanage(args, ec);
        co_return;
    }


    auto virtualbox_backend::exec_in_guest(std::string_view vm_name,
                                            std::string_view command,
                                            std::error_code &ec) -> net::awaitable<std::string>
    {
        auto args = std::string{"guestcontrol \""} + std::string{vm_name} +
                    "\" run --exe \"C:\\Windows\\System32\\cmd.exe\" --wait-stdout -- /c " +
                    std::string{command};
        auto output = run_vboxmanage(args, ec);
        co_return output;
    }

} // namespace sec::sandbox
