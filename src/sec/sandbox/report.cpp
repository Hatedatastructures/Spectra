// JSON 报告生成实现

#include <sec/sandbox/report.hpp>

#include <spdlog/spdlog.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace sec::sandbox::report
{
    namespace
    {
        auto escape_json(std::string_view s) -> std::string
        {
            auto out = std::string{};
            out.reserve(s.size() + 8);
            for (auto c : s)
            {
                switch (c)
                {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if (static_cast<unsigned char>(c) < 0x20)
                    {
                        out += "\\u00";
                        char hex[3];
                        std::snprintf(hex, sizeof(hex), "%02x", static_cast<unsigned>(c));
                        out += hex;
                    }
                    else
                    {
                        out += c;
                    }
                }
            }
            return out;
        }

        auto event_kind_str(event_kind k) -> std::string_view
        {
            switch (k)
            {
            case event_kind::process: return "process";
            case event_kind::file: return "file";
            case event_kind::registry: return "registry";
            case event_kind::network: return "network";
            case event_kind::dns: return "dns";
            }
            return "unknown";
        }

        auto status_str(analysis_status s) -> std::string_view
        {
            switch (s)
            {
            case analysis_status::pending: return "pending";
            case analysis_status::running: return "running";
            case analysis_status::completed: return "completed";
            case analysis_status::failed: return "failed";
            }
            return "unknown";
        }
    } // anonymous namespace


    auto generate(const analysis_target &target,
                  const analysis_result &result,
                  const sandbox_config &cfg) -> std::string
    {
        auto ss = std::ostringstream{};
        ss << "{\n";
        ss << "  \"target\": {\n";
        ss << "    \"filename\": \"" << escape_json(target.filename) << "\",\n";
        ss << "    \"sha256\": \"" << escape_json(target.sha256) << "\",\n";
        ss << "    \"local_path\": \"" << escape_json(target.local_path) << "\"\n";
        ss << "  },\n";
        ss << "  \"status\": \"" << status_str(result.status) << "\",\n";
        ss << "  \"score\": " << static_cast<int>(result.score) << ",\n";
        ss << "  \"summary\": \"" << escape_json(result.summary) << "\",\n";
        ss << "  \"submitted_at\": " << result.submitted_at << ",\n";
        ss << "  \"completed_at\": " << result.completed_at << ",\n";
        ss << "  \"vm\": \"" << escape_json(cfg.vm_name) << "\",\n";
        ss << "  \"snapshot\": \"" << escape_json(cfg.snapshot_name) << "\",\n";
        ss << "  \"events\": [\n";

        auto first = true;
        for (const auto &ev : result.events)
        {
            if (!first) ss << ",\n";
            first = false;
            ss << "    {";
            ss << "\"kind\": \"" << event_kind_str(ev.kind) << "\"";
            ss << ", \"operation\": \"" << escape_json(ev.operation) << "\"";
            ss << ", \"target\": \"" << escape_json(ev.target) << "\"";
            ss << ", \"detail\": \"" << escape_json(ev.detail) << "\"";
            ss << "}";
        }

        ss << "\n  ]\n";
        ss << "}\n";

        // 写入文件
        namespace fs = std::filesystem;
        auto reports_dir = fs::path{"reports"};
        fs::create_directories(reports_dir);

        auto now = std::chrono::system_clock::now();
        auto ts = std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch()).count();
        auto report_file = reports_dir / (std::to_string(ts) + "_" +
                                          target.filename + ".json");

        auto ofs = std::ofstream{report_file};
        if (ofs)
        {
            ofs << ss.str();
            ofs.close();
            spdlog::info("Report written to {}", report_file.string());
            return report_file.string();
        }
        spdlog::warn("Failed to write report to {}", report_file.string());
        return {};
    }

} // namespace sec::sandbox::report
