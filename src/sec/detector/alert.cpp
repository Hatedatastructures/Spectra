// 告警数据模型实现

#include <sec/detector/alert.hpp>


namespace sec::detector
{


    [[nodiscard]] auto to_string(severity sev) -> std::string_view
    {
        switch (sev)
        {
        case severity::info:
            return "info";
        case severity::low:
            return "low";
        case severity::medium:
            return "medium";
        case severity::high:
            return "high";
        case severity::critical:
            return "critical";
        }
        return "unknown";
    }


    [[nodiscard]] auto to_string(category cat) -> std::string_view
    {
        switch (cat)
        {
        case category::arp_spoofing:
            return "arp_spoofing";
        case category::dns_hijack:
            return "dns_hijack";
        case category::tls_stripping:
            return "tls_stripping";
        case category::port_scan:
            return "port_scan";
        case category::brute_force:
            return "brute_force";
        case category::data_exfiltration:
            return "data_exfiltration";
        case category::malware_communication:
            return "malware_communication";
        case category::suspicious_traffic:
            return "suspicious_traffic";
        case category::ai_anomaly:
            return "ai_anomaly";
        case category::custom:
            return "custom";
        }
        return "unknown";
    }


} // namespace sec::detector
