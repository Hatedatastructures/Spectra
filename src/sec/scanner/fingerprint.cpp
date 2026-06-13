// 设备指纹识别实现 — 通过 MAC OUI 前缀匹配 IEEE 数据库识别厂商

#include <sec/scanner/fingerprint.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <string_view>


namespace sec::scanner
{

    namespace
    {

        struct oui_entry
        {
            std::string_view prefix;
            std::string_view vendor;
        };

        constexpr std::array oui_table{
            oui_entry{"00:0C:29", "VMware"},
            oui_entry{"00:50:56", "VMware"},
            oui_entry{"00:05:69", "VMware"},
            oui_entry{"08:00:27", "VirtualBox (Oracle)"},
            oui_entry{"0A:00:27", "VirtualBox (Oracle)"},
            oui_entry{"00:1A:A0", "Intel"},
            oui_entry{"70:5A:0F", "Intel"},
            oui_entry{"3C:97:0E", "Intel"},
            oui_entry{"F8:B1:56", "Intel"},
            oui_entry{"B4:D5:BD", "Intel"},
            oui_entry{"A4:4C:C8", "Intel"},
            oui_entry{"00:1B:21", "Intel"},
            oui_entry{"DC:A6:32", "Raspberry Pi"},
            oui_entry{"B8:27:EB", "Raspberry Pi"},
            oui_entry{"E4:5F:01", "Raspberry Pi"},
            oui_entry{"00:03:93", "Apple"},
            oui_entry{"00:05:02", "Apple"},
            oui_entry{"00:0A:95", "Apple"},
            oui_entry{"00:0D:93", "Apple"},
            oui_entry{"AC:DE:48", "Apple"},
            oui_entry{"A4:B1:97", "Apple"},
            oui_entry{"78:CA:39", "Apple"},
            oui_entry{"D4:90:9C", "Apple"},
            oui_entry{"00:26:B0", "Apple"},
            oui_entry{"48:A1:95", "Apple"},
            oui_entry{"64:9A:BE", "Apple"},
            oui_entry{"F0:18:98", "Apple"},
            oui_entry{"C8:BC:C8", "Apple"},
            oui_entry{"28:F0:76", "Apple"},
            oui_entry{"3C:22:FB", "Apple"},
            oui_entry{"A8:60:B6", "Apple"},
            oui_entry{"00:15:5D", "Microsoft"},
            oui_entry{"7C:ED:8D", "Microsoft"},
            oui_entry{"28:18:78", "Microsoft"},
            oui_entry{"00:0F:E2", "Huawei"},
            oui_entry{"48:5B:39", "Huawei"},
            oui_entry{"70:A8:D3", "Huawei"},
            oui_entry{"CC:96:A0", "Huawei"},
            oui_entry{"E0:19:1D", "Huawei"},
            oui_entry{"B0:F1:EC", "Huawei"},
            oui_entry{"A4:56:02", "Huawei"},
            oui_entry{"00:E0:FC", "Huawei"},
            oui_entry{"50:D2:F5", "Huawei"},
            oui_entry{"00:1E:73", "Huawei"},
            oui_entry{"20:A6:CD", "Huawei"},
            oui_entry{"E8:4E:CE", "Huawei"},
            oui_entry{"78:AF:B8", "Huawei"},
            oui_entry{"5C:7D:5E", "Huawei"},
            oui_entry{"B4:43:5E", "Huawei"},
            oui_entry{"44:39:C4", "Huawei"},
            oui_entry{"2C:7D:46", "Huawei"},
            oui_entry{"88:28:B3", "Samsung"},
            oui_entry{"34:23:BA", "Samsung"},
            oui_entry{"A0:CB:FD", "Samsung"},
            oui_entry{"50:02:91", "Samsung"},
            oui_entry{"40:D3:2D", "Samsung"},
            oui_entry{"D8:BB:2C", "Samsung"},
            oui_entry{"9C:3A:AF", "Samsung"},
            oui_entry{"E8:50:8B", "Samsung"},
            oui_entry{"00:12:FB", "Samsung"},
            oui_entry{"C8:BA:94", "Samsung"},
            oui_entry{"F4:09:D8", "Samsung"},
            oui_entry{"E4:BE:ED", "Samsung"},
            oui_entry{"DC:2B:2A", "Google"},
            oui_entry{"3C:5A:B4", "Google"},
            oui_entry{"A4:CF:12", "Google"},
            oui_entry{"54:60:09", "Amazon"},
            oui_entry{"40:B4:CD", "Amazon"},
            oui_entry{"F0:27:2D", "Amazon"},
            oui_entry{"A0:02:DC", "Amazon"},
            oui_entry{"FC:65:DE", "Amazon"},
            oui_entry{"00:FC:21", "Cisco"},
            oui_entry{"00:1B:54", "Cisco"},
            oui_entry{"00:26:0B", "Cisco"},
            oui_entry{"00:26:99", "Cisco"},
            oui_entry{"5C:5A:C7", "Cisco"},
            oui_entry{"A0:E0:AF", "Cisco"},
            oui_entry{"B0:AA:77", "Cisco"},
            oui_entry{"E4:D3:F1", "Netgear"},
            oui_entry{"A0:21:B7", "Netgear"},
            oui_entry{"9C:3D:CF", "Netgear"},
            oui_entry{"60:38:E0", "Netgear"},
            oui_entry{"00:8E:F2", "Netgear"},
            oui_entry{"A4:6B:B8", "Netgear"},
            oui_entry{"24:B2:DE", "Espressif (IoT)"},
            oui_entry{"30:AE:A4", "Espressif (IoT)"},
            oui_entry{"BC:DD:C2", "Espressif (IoT)"},
            oui_entry{"24:0A:C4", "Espressif (IoT)"},
            oui_entry{"7C:9E:BD", "Espressif (IoT)"},
            oui_entry{"EC:FA:BC", "Espressif (IoT)"},
            oui_entry{"A4:CF:11", "Espressif (IoT)"},
            oui_entry{"30:83:98", "Shenzhen (IoT)"},
            oui_entry{"DC:4F:22", "Espressif (IoT)"},
            oui_entry{"D8:BB:C1", "Xiaomi"},
            oui_entry{"78:11:DC", "Xiaomi"},
            oui_entry{"9C:99:A0", "Xiaomi"},
            oui_entry{"0C:1D:AF", "Xiaomi"},
            oui_entry{"28:E3:1F", "Xiaomi"},
            oui_entry{"64:B4:73", "Xiaomi"},
            oui_entry{"F8:A4:5F", "Xiaomi"},
            oui_entry{"50:64:2B", "Xiaomi"},
            oui_entry{"AC:23:3F", "Xiaomi"},
            oui_entry{"74:A3:E4", "TP-Link"},
            oui_entry{"5C:62:8B", "TP-Link"},
            oui_entry{"EC:08:6B", "TP-Link"},
            oui_entry{"B0:4E:26", "TP-Link"},
            oui_entry{"E8:48:B8", "TP-Link"},
            oui_entry{"60:32:B1", "TP-Link"},
            oui_entry{"A8:42:A1", "TP-Link"},
            oui_entry{"F4:F2:6D", "TP-Link"},
            oui_entry{"C0:06:C3", "TP-Link"},
            oui_entry{"10:82:86", "TP-Link"},
            oui_entry{"50:C7:BF", "TP-Link"},
            oui_entry{"B0:A7:B9", "TP-Link"},
            oui_entry{"98:DE:D0", "TP-Link"},
        };

        // 将 MAC 地址中的分隔符统一为冒号，字母转大写
        auto normalize_mac(std::string_view mac) -> std::string
        {
            std::string result;
            result.reserve(mac.size());
            for (auto c : mac)
            {
                if (c == ':' || c == '-' || c == '.')
                    result += ':';
                else if (std::isalpha(static_cast<unsigned char>(c)))
                    result += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
                else
                    result += c;
            }
            return result;
        }

        struct port_service
        {
            std::uint16_t port;
            std::string_view service;
            std::string_view os_hint;
        };

        constexpr std::array port_table{
            port_service{21, "FTP", ""},
            port_service{22, "SSH", "Linux/Unix"},
            port_service{23, "Telnet", "Embedded/IoT"},
            port_service{25, "SMTP", ""},
            port_service{53, "DNS", ""},
            port_service{80, "HTTP", ""},
            port_service{110, "POP3", ""},
            port_service{143, "IMAP", ""},
            port_service{443, "HTTPS", ""},
            port_service{445, "SMB", "Windows"},
            port_service{993, "IMAPS", ""},
            port_service{995, "POP3S", ""},
            port_service{1433, "MSSQL", "Windows"},
            port_service{3306, "MySQL", "Linux"},
            port_service{3389, "RDP", "Windows"},
            port_service{5432, "PostgreSQL", "Linux"},
            port_service{5900, "VNC", ""},
            port_service{6379, "Redis", "Linux"},
            port_service{8080, "HTTP-Alt", ""},
            port_service{8443, "HTTPS-Alt", ""},
            port_service{9200, "Elasticsearch", "Linux"},
            port_service{27017, "MongoDB", "Linux"},
        };

    } // anonymous namespace


    // 通过 MAC OUI 前缀查询 IEEE 厂商数据库
    auto fingerprint::lookup_vendor(std::string_view mac_address) -> std::string
    {
        if (mac_address.size() < 8)
        {
            return "Unknown";
        }

        auto normalized = normalize_mac(mac_address);
        auto oui_prefix = normalized.substr(0, 8);

        for (const auto &entry : oui_table)
        {
            if (entry.prefix == oui_prefix)
            {
                return std::string(entry.vendor);
            }
        }

        return "Unknown";
    }


    // 根据厂商和开放端口推测设备操作系统
    auto fingerprint::guess_os(const device &dev) -> std::string
    {
        auto vendor = lookup_vendor(dev.mac_address);

        if (vendor.find("Microsoft") != std::string::npos)
            return "Windows";
        if (vendor.find("Apple") != std::string::npos)
            return "macOS/iOS";
        if (vendor.find("Raspberry") != std::string::npos)
            return "Linux (Raspbian)";
        if (vendor.find("Espressif") != std::string::npos ||
            vendor.find("Shenzhen") != std::string::npos)
            return "Embedded (ESP32/ESP8266)";

        bool has_windows_port{false};
        bool has_linux_port{false};

        for (auto port : dev.open_ports)
        {
            if (port == 445 || port == 3389 || port == 1433)
                has_windows_port = true;
            if (port == 22 || port == 3306 || port == 5432 ||
                port == 6379 || port == 9200 || port == 27017)
                has_linux_port = true;
        }

        if (has_windows_port && !has_linux_port)
            return "Windows";
        if (has_linux_port && !has_windows_port)
            return "Linux";
        if (has_windows_port && has_linux_port)
            return "Mixed/Linux";

        if (!dev.open_ports.empty())
            return "Unknown";

        if (vendor.find("Huawei") != std::string::npos)
            return "Android/HarmonyOS";
        if (vendor.find("Samsung") != std::string::npos)
            return "Android";
        if (vendor.find("Google") != std::string::npos)
            return "Android/ChromeOS";
        if (vendor.find("Amazon") != std::string::npos)
            return "Fire OS/Linux";
        if (vendor.find("Xiaomi") != std::string::npos)
            return "Android/MIUI";
        if (vendor.find("TP-Link") != std::string::npos)
            return "Embedded (Router)";
        if (vendor.find("Netgear") != std::string::npos)
            return "Embedded (Router)";
        if (vendor.find("Cisco") != std::string::npos)
            return "IOS/NX-OS";

        return "Unknown";
    }


    // 综合识别设备指纹（厂商 + 操作系统）
    void fingerprint::identify(device &dev)
    {
        if (dev.vendor.empty() || dev.vendor == "Unknown")
        {
            dev.vendor = lookup_vendor(dev.mac_address);
        }

        if (dev.os_guess.empty())
        {
            dev.os_guess = guess_os(dev);
        }
    }


} // namespace sec::scanner
