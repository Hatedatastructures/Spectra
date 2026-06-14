    // DNS 劫持检测器实现

#include <sec/mitm/dns.hpp>

#include <chrono>


namespace sec::mitm
{

    namespace
    {

        // 极低 TTL 阈值（秒），低于此值可能为 DNS 缓存投毒
        constexpr std::uint32_t low_ttl_threshold{60};

    } // anonymous namespace


    [[nodiscard]] auto dns_detector::check(const decoder::dns_info &dns_info)
        -> std::optional<dns_alert>
    {
        // 仅检查 DNS 响应
        if (!dns_info.is_response)
        {
            return std::nullopt;
        }

        // 遍历回答段，检查可疑情况
        for (const auto &entry : dns_info.answers)
        {
            // 检查极低 TTL
            if (entry.ttl > 0 && entry.ttl < low_ttl_threshold)
            {
                dns_alert alert;
                alert.query_name = entry.name;
                alert.actual_ip = entry.data;
                alert.ttl = entry.ttl;
                alert.reason = "DNS 响应 TTL 异常低 (" + std::to_string(entry.ttl) + "s)";
                alert.detected_at = std::chrono::steady_clock::now();
                return alert;
            }

            // 检查已知域名的解析结果
            auto it = known_bindings_.find(entry.name);
            if (it != known_bindings_.end())
            {
                if (!entry.data.empty() && entry.data != it->second)
                {
                    dns_alert alert;
                    alert.query_name = entry.name;
                    alert.expected_ip = it->second;
                    alert.actual_ip = entry.data;
                    alert.ttl = entry.ttl;
                    alert.reason = "域名 " + entry.name + " 解析异常";
                    alert.detected_at = std::chrono::steady_clock::now();
                    return alert;
                }
            }

            // 检查可疑 IP
            if (suspicious_ips_.count(entry.data) > 0)
            {
                dns_alert alert;
                alert.query_name = entry.name;
                alert.actual_ip = entry.data;
                alert.ttl = entry.ttl;
                alert.reason = "解析到可疑 IP: " + entry.data;
                alert.detected_at = std::chrono::steady_clock::now();
                return alert;
            }
        }

        return std::nullopt;
    }


} // namespace sec::mitm
