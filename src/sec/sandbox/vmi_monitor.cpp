// DRAKVUF VMI 行为监控实现
// 通过子进程调用 DRAKVUF CLI，从 hypervisor 层监控 Guest 行为

#include <sec/sandbox/vmi_monitor.hpp>

#include <sec/fault/code.hpp>
#include <sec/fault/compatible.hpp>

#include <spdlog/spdlog.h>

#ifdef _WIN32
#include <windows.h>
#endif

#include <chrono>
#include <cstring>
#include <sstream>
#include <string>

namespace sec::sandbox
{
    namespace
    {
#ifdef _WIN32
        auto exec_capture(std::string_view cmd, std::uint32_t timeout_s) -> std::pair<int, std::string>
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
            char tmp[8192];
            DWORD bytes_read = 0;
            while (ReadFile(pipe_read, tmp, sizeof(tmp), &bytes_read, nullptr) && bytes_read > 0)
            {
                buf.append(tmp, bytes_read);
            }
            CloseHandle(pipe_read);
            auto timeout_ms = static_cast<DWORD>(timeout_s * 1000);
            WaitForSingleObject(process.hProcess, timeout_ms);
            DWORD exit_code = 0;
            GetExitCodeProcess(process.hProcess, &exit_code);
            if (exit_code == STILL_ACTIVE)
            {
                TerminateProcess(process.hProcess, 1);
                WaitForSingleObject(process.hProcess, 5000);
                GetExitCodeProcess(process.hProcess, &exit_code);
            }
            CloseHandle(process.hProcess);
            CloseHandle(process.hThread);
            return {static_cast<int>(exit_code), buf};
        }
#else
        auto exec_capture(std::string_view cmd, std::uint32_t) -> std::pair<int, std::string>
        {
            auto pipe = popen(std::string{cmd}.c_str(), "r");
            if (!pipe) return {-1, {}};
            auto buf = std::string{};
            char tmp[8192];
            while (fgets(tmp, sizeof(tmp), pipe)) buf += tmp;
            auto rc = pclose(pipe);
            return {rc, buf};
        }
#endif

        // 从字符串中提取 JSON 字段值（简化版 JSON 解析）
        auto extract_json_value(std::string_view json, std::string_view key) -> std::string
        {
            auto search = std::string{"\""} + std::string{key} + "\":";
            auto pos = json.find(search);
            if (pos == std::string_view::npos) return {};
            pos += search.size();
            // 跳过空白
            while (pos < json.size() && (json[pos] == ' ' || json[pos] == '"')) ++pos;
            auto start = pos;
            while (pos < json.size() && json[pos] != '"' && json[pos] != ',' &&
                   json[pos] != '}' && json[pos] != '\n')
            {
                ++pos;
            }
            return std::string{json.substr(start, pos - start)};
        }
    } // anonymous namespace


    vmi_monitor::vmi_monitor(vmi_config cfg)
        : cfg_{std::move(cfg)}
    {
    }


    vmi_monitor::~vmi_monitor()
    {
        stop();
    }


    auto vmi_monitor::start(std::string_view vm_name, std::error_code &ec) -> void
    {
        if (running_) return;
        running_ = true;
        events_.clear();
        raw_output_.clear();

        // 构建 DRAKVUF 命令
        // drakvuf -r <rekall_profile> -d <vm_domain> -e <payload> -t <timeout>
        // -j 输出 JSON 格式
        auto cmd = std::string{"\""} + cfg_.drakvuf_path + "\" -r \"" +
                   cfg_.rekall_profile + "\" -d " + std::string{vm_name} +
                   " -j -t " + std::to_string(cfg_.timeout_seconds);

        spdlog::info("DRAKVUF: {}", cmd);

        auto [rc, output] = exec_capture(cmd, cfg_.timeout_seconds);
        raw_output_ = output;

        if (rc != 0 && rc != 1)
        {
            spdlog::warn("DRAKVUF exited with rc={}", rc);
        }

        // 解析输出（每行一个 JSON 对象）
        auto ss = std::istringstream{raw_output_};
        auto line = std::string{};
        while (std::getline(ss, line))
        {
            if (line.empty() || line[0] != '{') continue;
            parse_drakvuf_line(line);
        }

        spdlog::info("DRAKVUF monitor: {} events parsed", events_.size());
        ec.clear();
    }


    auto vmi_monitor::stop() -> void
    {
        running_ = false;
    }


    [[nodiscard]] auto vmi_monitor::events() const -> const std::vector<behavior_event> &
    {
        return events_;
    }


    [[nodiscard]] auto vmi_monitor::is_running() const -> bool
    {
        return running_;
    }


    auto vmi_monitor::parse_drakvuf_line(std::string_view line) -> void
    {
        // DRAKVUF JSON 输出格式（简化）：
        // {"Plugin":"syscalls","EventName":"NtCreateFile","PID":1234,
        //  "ProcName":"malware.exe","Arguments":"\\??\\C:\\test.txt"}

        auto event = behavior_event{};
        event.timestamp = std::chrono::steady_clock::now();

        auto plugin = extract_json_value(line, "Plugin");
        auto event_name = extract_json_value(line, "EventName");
        auto proc_name = extract_json_value(line, "ProcName");
        auto arguments = extract_json_value(line, "Arguments");

        if (plugin.empty() && event_name.empty()) return;

        // 按 DRAKVUF 插件/事件名分类
        if (event_name.find("CreateFile") != std::string::npos ||
            event_name.find("WriteFile") != std::string::npos ||
            event_name.find("DeleteFile") != std::string::npos)
        {
            event.kind = event_kind::file;
            event.operation = event_name;
            event.target = arguments;
        }
        else if (event_name.find("CreateProcess") != std::string::npos ||
                 event_name.find("TerminateProcess") != std::string::npos ||
                 event_name.find("OpenProcess") != std::string::npos)
        {
            event.kind = event_kind::process;
            event.operation = event_name;
            event.target = proc_name;
            event.detail = arguments;
        }
        else if (event_name.find("RegSetValue") != std::string::npos ||
                 event_name.find("RegCreateKey") != std::string::npos ||
                 event_name.find("RegDeleteKey") != std::string::npos)
        {
            event.kind = event_kind::registry;
            event.operation = event_name;
            event.target = arguments;
        }
        else if (event_name.find("Connect") != std::string::npos ||
                 event_name.find("Socket") != std::string::npos)
        {
            event.kind = event_kind::network;
            event.operation = event_name;
            event.target = arguments;
        }
        else if (event_name.find("DnsQuery") != std::string::npos)
        {
            event.kind = event_kind::dns;
            event.operation = event_name;
            event.target = arguments;
        }
        else
        {
            // 未分类的系统调用，记为 process
            event.kind = event_kind::process;
            event.operation = event_name;
            event.target = proc_name;
            event.detail = arguments;
        }

        events_.push_back(std::move(event));
    }

} // namespace sec::sandbox
