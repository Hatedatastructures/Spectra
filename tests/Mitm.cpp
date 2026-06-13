/**
 * @file Mitm.cpp
 * @brief MITM 检测模块测试
 */

#include <sec/mitm/arp_detect.hpp>
#include <sec/mitm/dns_detect.hpp>
#include <sec/mitm/tls_detect.hpp>
#include <sec/decoder/frame.hpp>
#include <sec/decoder/dns.hpp>
#include <sec/decoder/tls.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#define CHECK(cond)                                        \
    do                                                     \
    {                                                      \
        if (!(cond))                                       \
        {                                                  \
            std::cerr << "FAIL: " #cond "\n"               \
                      << "  at " __FILE__ ":" << __LINE__  \
                      << "\n";                             \
            return 1;                                      \
        }                                                  \
    } while (0)


// --- 辅助函数 ---

static auto make_arp_reply(
    std::uint32_t sender_ip, const std::string &sender_mac_hex,
    std::uint32_t target_ip, const std::string &target_mac_hex) -> std::vector<std::byte>
{
    // 构造 ARP Reply 载荷：HTYPE(2) PTYPE(2) HLEN(1) PLEN(1) OPER(2) SHA(6) SPA(4) THA(6) TPA(4)
    std::vector<std::byte> pkt(28, std::byte{0});
    auto *p = pkt.data();

    // HTYPE = 1 (Ethernet)
    p[0] = std::byte{0x00}; p[1] = std::byte{0x01};
    // PTYPE = 0x0800 (IPv4)
    p[2] = std::byte{0x08}; p[3] = std::byte{0x00};
    // HLEN = 6, PLEN = 4
    p[4] = std::byte{0x06}; p[5] = std::byte{0x04};
    // OPER = 2 (Reply)
    p[6] = std::byte{0x00}; p[7] = std::byte{0x02};

    // SHA (sender MAC) — 从 hex 字符串解析
    auto parse_mac = [](const std::string &hex) -> std::array<std::byte, 6>
    {
        std::array<std::byte, 6> mac{};
        unsigned int vals[6];
        std::sscanf(hex.c_str(), "%02X:%02X:%02X:%02X:%02X:%02X",
            &vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5]);
        for (int i = 0; i < 6; ++i)
        {
            mac[i] = static_cast<std::byte>(static_cast<unsigned char>(vals[i]));
        }
        return mac;
    };

    auto sha = parse_mac(sender_mac_hex);
    std::memcpy(p + 8, sha.data(), 6);

    // SPA (sender IP)
    p[14] = static_cast<std::byte>((sender_ip >> 24) & 0xFF);
    p[15] = static_cast<std::byte>((sender_ip >> 16) & 0xFF);
    p[16] = static_cast<std::byte>((sender_ip >> 8) & 0xFF);
    p[17] = static_cast<std::byte>(sender_ip & 0xFF);

    // THA (target MAC)
    auto tha = parse_mac(target_mac_hex);
    std::memcpy(p + 18, tha.data(), 6);

    // TPA (target IP)
    p[24] = static_cast<std::byte>((target_ip >> 24) & 0xFF);
    p[25] = static_cast<std::byte>((target_ip >> 16) & 0xFF);
    p[26] = static_cast<std::byte>((target_ip >> 8) & 0xFF);
    p[27] = static_cast<std::byte>(target_ip & 0xFF);

    return pkt;
}


// --- ARP 检测辅助：构造完整 Ethernet+ARP 帧 ---

static auto make_arp_frame(
    std::uint16_t opcode,
    const std::string &sender_mac_hex, std::uint32_t sender_ip,
    const std::string &target_mac_hex, std::uint32_t target_ip) -> std::vector<std::byte>
{
    // 14(Ethernet) + 28(ARP) = 42 bytes
    std::vector<std::byte> frame(42, std::byte{0});
    auto *p = frame.data();

    auto parse_mac = [](const std::string &hex) -> std::array<std::byte, 6>
    {
        std::array<std::byte, 6> mac{};
        unsigned int vals[6];
        std::sscanf(hex.c_str(), "%02X:%02X:%02X:%02X:%02X:%02X",
            &vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5]);
        for (int i = 0; i < 6; ++i)
        {
            mac[i] = static_cast<std::byte>(static_cast<unsigned char>(vals[i]));
        }
        return mac;
    };

    auto sha = parse_mac(sender_mac_hex);
    auto tha = parse_mac(target_mac_hex);

    // Ethernet header: dst=tha, src=sha, ethertype=0x0806
    std::memcpy(p, tha.data(), 6);
    std::memcpy(p + 6, sha.data(), 6);
    p[12] = std::byte{0x08};
    p[13] = std::byte{0x06};

    // ARP payload (offsets within ARP packet, after Ethernet header):
    // HTYPE(0-1) PTYPE(2-3) HLEN(4) PLEN(5) OPER(6-7) SHA(8-13) SPA(14-17) THA(18-23) TPA(24-27)
    auto *arp = p + 14;
    arp[0] = std::byte{0x00}; arp[1] = std::byte{0x01}; // HTYPE=Ethernet
    arp[2] = std::byte{0x08}; arp[3] = std::byte{0x00}; // PTYPE=IPv4
    arp[4] = std::byte{0x06}; // HLEN
    arp[5] = std::byte{0x04}; // PLEN
    arp[6] = std::byte(static_cast<unsigned char>((opcode >> 8) & 0xFF));
    arp[7] = std::byte(static_cast<unsigned char>(opcode & 0xFF));
    std::memcpy(arp + 8, sha.data(), 6);
    arp[14] = static_cast<std::byte>((sender_ip >> 24) & 0xFF);
    arp[15] = static_cast<std::byte>((sender_ip >> 16) & 0xFF);
    arp[16] = static_cast<std::byte>((sender_ip >> 8) & 0xFF);
    arp[17] = static_cast<std::byte>(sender_ip & 0xFF);
    std::memcpy(arp + 18, tha.data(), 6);
    arp[24] = static_cast<std::byte>((target_ip >> 24) & 0xFF);
    arp[25] = static_cast<std::byte>((target_ip >> 16) & 0xFF);
    arp[26] = static_cast<std::byte>((target_ip >> 8) & 0xFF);
    arp[27] = static_cast<std::byte>(target_ip & 0xFF);

    return frame;
}


// --- ARP 检测测试 ---

static auto TestArpDetectFirstBinding() -> int
{
    sec::decoder::frame_parser parser;
    sec::mitm::arp_detector detector;

    auto frame = make_arp_frame(2, "AA:BB:CC:DD:EE:01", 0xC0A80101,
                                    "AA:BB:CC:DD:EE:02", 0xC0A80102);
    std::error_code ec;
    auto info = parser.parse(frame, ec);
    CHECK(info.has_value());
    CHECK(info->arp.has_value());

    auto result = detector.check(*info);
    CHECK(!result.has_value());

    auto table = detector.arp_table();
    CHECK(table.size() == 1);
    CHECK(table.count(0xC0A80101) == 1);
    CHECK(table.at(0xC0A80101) == "AA:BB:CC:DD:EE:01");
    return 0;
}

static auto TestArpDetectConflict() -> int
{
    sec::decoder::frame_parser parser;
    sec::mitm::arp_detector detector;
    std::error_code ec;

    // 第一次绑定
    auto frame1 = make_arp_frame(2, "AA:BB:CC:DD:EE:01", 0xC0A80101,
                                     "AA:BB:CC:DD:EE:02", 0xC0A80102);
    auto info1 = parser.parse(frame1, ec);
    CHECK(info1.has_value());
    (void)detector.check(*info1);

    // 同一 IP 不同 MAC -> 告警
    auto frame2 = make_arp_frame(2, "AA:BB:CC:DD:EE:FF", 0xC0A80101,
                                     "AA:BB:CC:DD:EE:02", 0xC0A80102);
    auto info2 = parser.parse(frame2, ec);
    CHECK(info2.has_value());

    auto result = detector.check(*info2);
    CHECK(result.has_value());
    CHECK(result->ip == 0xC0A80101);
    CHECK(result->original_mac == "AA:BB:CC:DD:EE:01");
    CHECK(result->conflict_mac == "AA:BB:CC:DD:EE:FF");
    return 0;
}

static auto TestArpDetectSameMac() -> int
{
    sec::decoder::frame_parser parser;
    sec::mitm::arp_detector detector;
    std::error_code ec;

    auto frame = make_arp_frame(2, "AA:BB:CC:DD:EE:01", 0xC0A80101,
                                    "AA:BB:CC:DD:EE:02", 0xC0A80102);
    auto info = parser.parse(frame, ec);
    CHECK(info.has_value());

    (void)detector.check(*info);
    auto result = detector.check(*info);
    CHECK(!result.has_value());
    return 0;
}

static auto TestArpDetectTooShort() -> int
{
    sec::decoder::frame_parser parser;
    sec::mitm::arp_detector detector;
    std::error_code ec;

    // 10 字节不足以构成有效的 ARP 帧
    std::array<std::byte, 10> short_data{};
    auto info = parser.parse(short_data, ec);
    // frame parser 会返回 nullopt，无法传给 detector
    CHECK(!info.has_value());
    return 0;
}

static auto TestArpDetectNonReply() -> int
{
    sec::decoder::frame_parser parser;
    sec::mitm::arp_detector detector;
    std::error_code ec;

    // ARP Request: OPER=1
    auto frame = make_arp_frame(1, "AA:BB:CC:DD:EE:01", 0xC0A80101,
                                    "AA:BB:CC:DD:EE:02", 0xC0A80102);
    auto info = parser.parse(frame, ec);
    CHECK(info.has_value());

    // ARP Request 不应触发 IP-MAC 冲突告警
    auto result = detector.check(*info);
    CHECK(!result.has_value());
    return 0;
}


// --- DNS 检测测试 ---

static auto TestDnsDetectLowTtl() -> int
{
    sec::mitm::dns_detector detector;

    sec::decoder::dns_info dns;
    dns.is_response = true;
    dns.transaction_id = 0x1234;

    sec::decoder::dns_entry entry;
    entry.name = "example.com";
    entry.data = "1.2.3.4";
    entry.ttl = 10;
    dns.answers.push_back(entry);

    auto result = detector.check(dns);
    CHECK(result.has_value());
    CHECK(result->query_name == "example.com");
    CHECK(result->ttl == 10);
    CHECK(!result->reason.empty());
    return 0;
}

static auto TestDnsDetectKnownBindingMismatch() -> int
{
    sec::mitm::dns_detector detector;
    detector.add_known_binding("safe.example.com", "93.184.216.34");

    sec::decoder::dns_info dns;
    dns.is_response = true;

    sec::decoder::dns_entry entry;
    entry.name = "safe.example.com";
    entry.data = "6.6.6.6";
    entry.ttl = 300;
    dns.answers.push_back(entry);

    auto result = detector.check(dns);
    CHECK(result.has_value());
    CHECK(result->expected_ip == "93.184.216.34");
    CHECK(result->actual_ip == "6.6.6.6");
    return 0;
}

static auto TestDnsDetectSuspiciousIp() -> int
{
    sec::mitm::dns_detector detector;
    detector.add_suspicious_ip("6.6.6.6");

    sec::decoder::dns_info dns;
    dns.is_response = true;

    sec::decoder::dns_entry entry;
    entry.name = "test.com";
    entry.data = "6.6.6.6";
    entry.ttl = 300;
    dns.answers.push_back(entry);

    auto result = detector.check(dns);
    CHECK(result.has_value());
    CHECK(result->actual_ip == "6.6.6.6");
    return 0;
}

static auto TestDnsDetectQueryNoAlert() -> int
{
    sec::mitm::dns_detector detector;

    sec::decoder::dns_info dns;
    dns.is_response = false;

    sec::decoder::dns_entry entry;
    entry.name = "example.com";
    entry.data = "1.2.3.4";
    entry.ttl = 10;
    dns.questions.push_back(entry);

    auto result = detector.check(dns);
    CHECK(!result.has_value());
    return 0;
}

static auto TestDnsDetectNormalResponse() -> int
{
    sec::mitm::dns_detector detector;

    sec::decoder::dns_info dns;
    dns.is_response = true;

    sec::decoder::dns_entry entry;
    entry.name = "example.com";
    entry.data = "93.184.216.34";
    entry.ttl = 300;
    dns.answers.push_back(entry);

    auto result = detector.check(dns);
    CHECK(!result.has_value());
    return 0;
}


// --- TLS 检测测试 ---

static auto TestTlsDetectStripping() -> int
{
    sec::mitm::tls_detector detector;

    sec::decoder::tls_info tls;
    tls.client_version = 0x0303;

    detector.observe_client_hello(0xC0A80101, 0xC0A80102, tls);

    // 非 TLS 响应 -> 告警
    auto result = detector.check_response(0xC0A80101, 0xC0A80102, false);
    CHECK(result.has_value());
    CHECK(result->type == sec::mitm::tls_alert_type::stripping);
    CHECK(result->client_ip == 0xC0A80101);
    CHECK(result->server_ip == 0xC0A80102);
    return 0;
}

static auto TestTlsDetectNormalResponse() -> int
{
    sec::mitm::tls_detector detector;

    sec::decoder::tls_info tls;
    tls.client_version = 0x0303;

    detector.observe_client_hello(0xC0A80101, 0xC0A80102, tls);

    // 正常 TLS 响应 -> 无告警
    auto result = detector.check_response(0xC0A80101, 0xC0A80102, true);
    CHECK(!result.has_value());
    return 0;
}

static auto TestTlsDetectNoPendingSession() -> int
{
    sec::mitm::tls_detector detector;

    // 没有 ClientHello 记录 -> 无告警
    auto result = detector.check_response(0xC0A80101, 0xC0A80102, false);
    CHECK(!result.has_value());
    return 0;
}


// --- 主函数 ---

auto main() -> int
{
    int failures = 0;

    if (auto r = TestArpDetectFirstBinding(); r) { ++failures; }
    if (auto r = TestArpDetectConflict(); r) { ++failures; }
    if (auto r = TestArpDetectSameMac(); r) { ++failures; }
    if (auto r = TestArpDetectTooShort(); r) { ++failures; }
    if (auto r = TestArpDetectNonReply(); r) { ++failures; }
    if (auto r = TestDnsDetectLowTtl(); r) { ++failures; }
    if (auto r = TestDnsDetectKnownBindingMismatch(); r) { ++failures; }
    if (auto r = TestDnsDetectSuspiciousIp(); r) { ++failures; }
    if (auto r = TestDnsDetectQueryNoAlert(); r) { ++failures; }
    if (auto r = TestDnsDetectNormalResponse(); r) { ++failures; }
    if (auto r = TestTlsDetectStripping(); r) { ++failures; }
    if (auto r = TestTlsDetectNormalResponse(); r) { ++failures; }
    if (auto r = TestTlsDetectNoPendingSession(); r) { ++failures; }

    if (failures == 0)
    {
        std::cout << "Mitm: ALL PASSED\n";
    }
    else
    {
        std::cerr << "Mitm: " << failures << " test(s) FAILED\n";
    }
    return failures;
}
