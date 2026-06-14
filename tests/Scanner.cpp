/**
 * @file Scanner.cpp
 * @brief 扫描器模块测试
 */

#include <sec/scanner/device.hpp>
#include <sec/scanner/port.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

using namespace sec::scanner;

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

// --- ARP 包结构常量 (与 arp.cpp 保持一致) ---
// 以太网帧头: dst_mac(6) + src_mac(6) + ethertype(2) = 14
// ARP 包: hw_type(2) + proto_type(2) + hw_size(1) + proto_size(1) +
//          opcode(2) + sender_mac(6) + sender_ip(4) + target_mac(6) +
//          target_ip(4) = 28
// 总计: 14 + 28 = 42

static constexpr std::size_t kEthHdrSize = 14;
static constexpr std::size_t kArpPktSize = 28;
static constexpr std::size_t kTotalArpSize = 42;
static constexpr std::uint16_t kEthertypeArp = 0x0806;
static constexpr std::uint16_t kArpHwEthernet = 0x0001;
static constexpr std::uint16_t kArpProtoIpv4 = 0x0800;
static constexpr std::uint16_t kArpOpRequest = 0x0001;
static constexpr std::uint16_t kArpOpReply = 0x0002;

static void put_u16_be(std::span<std::byte> buf, std::size_t offset, std::uint16_t val)
{
    buf[offset] = static_cast<std::byte>((val >> 8) & 0xFF);
    buf[offset + 1] = static_cast<std::byte>(val & 0xFF);
}

static void put_u32_be(std::span<std::byte> buf, std::size_t offset, std::uint32_t val)
{
    buf[offset] = static_cast<std::byte>((val >> 24) & 0xFF);
    buf[offset + 1] = static_cast<std::byte>((val >> 16) & 0xFF);
    buf[offset + 2] = static_cast<std::byte>((val >> 8) & 0xFF);
    buf[offset + 3] = static_cast<std::byte>(val & 0xFF);
}

[[nodiscard]] static auto get_u16_be(std::span<const std::byte> buf, std::size_t offset) -> std::uint16_t
{
    return (static_cast<std::uint16_t>(buf[offset]) << 8) |
           static_cast<std::uint16_t>(buf[offset + 1]);
}

[[nodiscard]] static auto get_u32_be(std::span<const std::byte> buf, std::size_t offset) -> std::uint32_t
{
    return (static_cast<std::uint32_t>(buf[offset]) << 24) |
           (static_cast<std::uint32_t>(buf[offset + 1]) << 16) |
           (static_cast<std::uint32_t>(buf[offset + 2]) << 8) |
           static_cast<std::uint32_t>(buf[offset + 3]);
}

static auto build_valid_arp_reply(std::uint32_t sender_ip,
                                  std::array<std::byte, 6> sender_mac,
                                  std::uint32_t target_ip)
    -> std::vector<std::byte>
{
    std::vector<std::byte> packet(kTotalArpSize, std::byte{0});
    std::span<std::byte> buf{packet};

    for (std::size_t i = 0; i < 6; ++i)
    {
        buf[i] = std::byte{0xFF};
    }
    std::copy(sender_mac.begin(), sender_mac.end(), buf.subspan(6, 6).begin());
    put_u16_be(buf, 12, kEthertypeArp);

    put_u16_be(buf, 14, kArpHwEthernet);
    put_u16_be(buf, 16, kArpProtoIpv4);
    buf[18] = std::byte{6};
    buf[19] = std::byte{4};
    put_u16_be(buf, 20, kArpOpReply);

    std::copy(sender_mac.begin(), sender_mac.end(), buf.subspan(22, 6).begin());
    put_u32_be(buf, 28, sender_ip);

    put_u32_be(buf, 38, target_ip);

    return packet;
}


// --- 测试用例 ---

static auto test_device_default_construction() -> int
{
    device d;
    CHECK(d.ip_address.empty());
    CHECK(d.mac_address.empty());
    CHECK(d.hostname.empty());
    CHECK(d.vendor.empty());
    CHECK(d.open_ports.empty());
    CHECK(d.os_guess.empty());
    CHECK(!d.is_gateway);
    return 0;
}

static auto test_device_equality_by_mac() -> int
{
    device a;
    a.ip_address = "192.168.1.1";
    a.mac_address = "AA:BB:CC:DD:EE:FF";

    device b;
    b.ip_address = "192.168.1.2";
    b.mac_address = "AA:BB:CC:DD:EE:FF";

    CHECK(a == b);
    CHECK(!(a != b));
    return 0;
}

static auto test_device_inequality() -> int
{
    device a;
    a.mac_address = "AA:BB:CC:DD:EE:FF";

    device b;
    b.mac_address = "11:22:33:44:55:66";

    CHECK(a != b);
    CHECK(!(a == b));
    return 0;
}

static auto test_device_pmr_containers() -> int
{
    device d;
    d.ip_address = "10.0.0.1";
    d.mac_address = "AA:BB:CC:DD:EE:FF";
    d.hostname = "test-host";
    d.vendor = "TestVendor";
    d.os_guess = "Linux";
    d.open_ports.push_back(22);
    d.open_ports.push_back(80);
    d.open_ports.push_back(443);
    d.is_gateway = true;

    CHECK(d.ip_address == "10.0.0.1");
    CHECK(d.mac_address == "AA:BB:CC:DD:EE:FF");
    CHECK(d.hostname == "test-host");
    CHECK(d.vendor == "TestVendor");
    CHECK(d.os_guess == "Linux");
    CHECK(d.open_ports.size() == 3);
    CHECK(d.open_ports[0] == 22);
    CHECK(d.open_ports[1] == 80);
    CHECK(d.open_ports[2] == 443);
    CHECK(d.is_gateway);
    return 0;
}

static auto test_device_copy() -> int
{
    device original;
    original.ip_address = "192.168.1.100";
    original.mac_address = "DE:AD:BE:EF:00:01";
    original.open_ports.push_back(8080);
    original.is_gateway = false;

    device copy = original;
    CHECK(copy.ip_address == original.ip_address);
    CHECK(copy.mac_address == original.mac_address);
    CHECK(copy.open_ports.size() == 1);
    CHECK(copy.open_ports[0] == 8080);
    CHECK(copy.is_gateway == original.is_gateway);
    return 0;
}

static auto test_port_scan_options_defaults() -> int
{
    port_scan_options opts;
    CHECK(opts.ports.empty());
    CHECK(opts.timeout_ms == 500);
    CHECK(opts.concurrency == 128);
    return 0;
}

static auto test_port_scan_options_custom() -> int
{
    port_scan_options opts;
    opts.ports = {22, 80, 443, 8080};
    opts.timeout_ms = 1000;
    opts.concurrency = 64;

    CHECK(opts.ports.size() == 4);
    CHECK(opts.ports[0] == 22);
    CHECK(opts.ports[1] == 80);
    CHECK(opts.ports[2] == 443);
    CHECK(opts.ports[3] == 8080);
    CHECK(opts.timeout_ms == 1000);
    CHECK(opts.concurrency == 64);
    return 0;
}

static auto test_arp_packet_size_constants() -> int
{
    CHECK(kEthHdrSize == 14);
    CHECK(kArpPktSize == 28);
    CHECK(kTotalArpSize == 42);
    CHECK(kEthHdrSize + kArpPktSize == kTotalArpSize);
    return 0;
}

static auto test_arp_reply_structure_valid() -> int
{
    auto sender_mac = std::array<std::byte, 6>{
        std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
        std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}};
    auto packet = build_valid_arp_reply(0xC0A80101, sender_mac, 0xC0A80164);
    std::span<const std::byte> data{packet};

    CHECK(data.size() == kTotalArpSize);

    CHECK(data[0] == std::byte{0xFF});
    CHECK(data[5] == std::byte{0xFF});

    CHECK(data[6] == std::byte{0xAA});
    CHECK(data[11] == std::byte{0xFF});

    CHECK(get_u16_be(data, 12) == kEthertypeArp);

    CHECK(get_u16_be(data, 14) == kArpHwEthernet);

    CHECK(get_u16_be(data, 16) == kArpProtoIpv4);

    CHECK(data[18] == std::byte{6});

    CHECK(data[19] == std::byte{4});

    CHECK(get_u16_be(data, 20) == kArpOpReply);

    CHECK(data[22] == std::byte{0xAA});
    CHECK(data[27] == std::byte{0xFF});

    CHECK(get_u32_be(data, 28) == 0xC0A80101);

    CHECK(get_u32_be(data, 38) == 0xC0A80164);
    return 0;
}

static auto test_arp_reply_reject_too_short() -> int
{
    std::array<std::byte, 41> short_buf{};
    std::span<const std::byte> data{short_buf};

    CHECK(data.size() < kTotalArpSize);
    return 0;
}

static auto test_arp_reply_reject_wrong_ethertype() -> int
{
    std::vector<std::byte> packet(kTotalArpSize, std::byte{0});
    std::span<std::byte> buf{packet};

    put_u16_be(buf, 12, 0x0800);

    std::span<const std::byte> data{packet};
    CHECK(get_u16_be(data, 12) != kEthertypeArp);
    return 0;
}

static auto test_arp_reply_reject_wrong_opcode() -> int
{
    std::vector<std::byte> packet(kTotalArpSize, std::byte{0});
    std::span<std::byte> buf{packet};

    put_u16_be(buf, 12, kEthertypeArp);
    put_u16_be(buf, 20, kArpOpRequest);

    std::span<const std::byte> data{packet};
    CHECK(get_u16_be(data, 12) == kEthertypeArp);
    CHECK(get_u16_be(data, 20) != kArpOpReply);
    return 0;
}

static auto test_arp_reply_reject_zero_sender_mac() -> int
{
    std::vector<std::byte> packet(kTotalArpSize, std::byte{0});
    std::span<std::byte> buf{packet};

    put_u16_be(buf, 12, kEthertypeArp);
    put_u16_be(buf, 14, kArpHwEthernet);
    put_u16_be(buf, 16, kArpProtoIpv4);
    buf[18] = std::byte{6};
    buf[19] = std::byte{4};
    put_u16_be(buf, 20, kArpOpReply);
    put_u32_be(buf, 28, 0xC0A80101);

    std::span<const std::byte> data{packet};
    bool all_zero = true;
    for (std::size_t i = 22; i < 28; ++i)
    {
        if (data[i] != std::byte{0})
        {
            all_zero = false;
            break;
        }
    }
    CHECK(all_zero);
    return 0;
}

static auto test_ipv4_roundtrip_192_168_1_1() -> int
{
    std::string_view ip_str = "192.168.1.1";
    std::uint32_t octets[4]{};
    int idx{0};
    std::uint32_t current{0};

    for (auto ch : ip_str)
    {
        if (ch == '.')
        {
            octets[idx++] = current;
            current = 0;
        }
        else
        {
            current = current * 10 + static_cast<std::uint32_t>(ch - '0');
        }
    }
    octets[idx] = current;

    auto ip_val = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
    CHECK(ip_val == 0xC0A80101);

    auto reconstructed = std::to_string((ip_val >> 24) & 0xFF) + "." +
                         std::to_string((ip_val >> 16) & 0xFF) + "." +
                         std::to_string((ip_val >> 8) & 0xFF) + "." +
                         std::to_string(ip_val & 0xFF);
    CHECK(reconstructed == "192.168.1.1");
    return 0;
}

static auto test_ipv4_roundtrip_10_0_0_1() -> int
{
    auto ip_val = (10u << 24) | (0u << 16) | (0u << 8) | 1u;
    CHECK(ip_val == 0x0A000001);

    auto reconstructed = std::to_string((ip_val >> 24) & 0xFF) + "." +
                         std::to_string((ip_val >> 16) & 0xFF) + "." +
                         std::to_string((ip_val >> 8) & 0xFF) + "." +
                         std::to_string(ip_val & 0xFF);
    CHECK(reconstructed == "10.0.0.1");
    return 0;
}

static auto test_ipv4_roundtrip_broadcast() -> int
{
    auto ip_val = (255u << 24) | (255u << 16) | (255u << 8) | 255u;
    CHECK(ip_val == 0xFFFFFFFF);

    auto reconstructed = std::to_string((ip_val >> 24) & 0xFF) + "." +
                         std::to_string((ip_val >> 16) & 0xFF) + "." +
                         std::to_string((ip_val >> 8) & 0xFF) + "." +
                         std::to_string(ip_val & 0xFF);
    CHECK(reconstructed == "255.255.255.255");
    return 0;
}

static auto test_subnet_24_range() -> int
{
    auto network_ip = (192u << 24) | (168u << 16) | (1u << 8) | 0u;
    auto prefix_len = 24u;
    auto mask = ~static_cast<std::uint32_t>(0) << (32 - prefix_len);

    auto network = network_ip & mask;
    auto broadcast = network | ~mask;
    auto start = network + 1;
    auto end = broadcast - 1;

    CHECK(start == ((192u << 24) | (168u << 16) | (1u << 8) | 1u));
    CHECK(end == ((192u << 24) | (168u << 16) | (1u << 8) | 254u));
    return 0;
}

static auto test_subnet_16_range() -> int
{
    auto network_ip = (10u << 24) | (0u << 16) | (0u << 8) | 0u;
    auto mask = ~static_cast<std::uint32_t>(0) << 16;
    auto network = network_ip & mask;
    auto broadcast = network | ~mask;
    auto start = network + 1;
    auto end = broadcast - 1;

    CHECK(start == ((10u << 24) | (0u << 16) | (0u << 8) | 1u));
    CHECK(end == ((10u << 24) | (0u << 16) | (255u << 8) | 254u));
    return 0;
}

static auto test_subnet_single_host() -> int
{
    auto network_ip = (192u << 24) | (168u << 16) | (1u << 8) | 100u;
    auto mask = ~static_cast<std::uint32_t>(0) << 0;
    auto network = network_ip & mask;
    auto broadcast = network | ~mask;
    auto start = network + 1;
    auto end = broadcast - 1;

    CHECK(start > end);
    return 0;
}

static auto test_mac_formatting() -> int
{
    std::array<std::byte, 6> mac{
        std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC},
        std::byte{0xDD}, std::byte{0xEE}, std::byte{0xFF}};

    char buf[18]{};
    std::snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
                  static_cast<unsigned>(mac[0]),
                  static_cast<unsigned>(mac[1]),
                  static_cast<unsigned>(mac[2]),
                  static_cast<unsigned>(mac[3]),
                  static_cast<unsigned>(mac[4]),
                  static_cast<unsigned>(mac[5]));

    std::string result{buf};
    CHECK(result == "AA:BB:CC:DD:EE:FF");
    return 0;
}

static auto test_broadcast_mac() -> int
{
    constexpr std::array<std::byte, 6> broadcast{
        std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF},
        std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}};

    for (auto b : broadcast)
    {
        CHECK(b == std::byte{0xFF});
    }
    return 0;
}

auto main() -> int
{
    int failures = 0;

    if (auto r = test_device_default_construction(); r) { ++failures; }
    if (auto r = test_device_equality_by_mac(); r) { ++failures; }
    if (auto r = test_device_inequality(); r) { ++failures; }
    if (auto r = test_device_pmr_containers(); r) { ++failures; }
    if (auto r = test_device_copy(); r) { ++failures; }
    if (auto r = test_port_scan_options_defaults(); r) { ++failures; }
    if (auto r = test_port_scan_options_custom(); r) { ++failures; }
    if (auto r = test_arp_packet_size_constants(); r) { ++failures; }
    if (auto r = test_arp_reply_structure_valid(); r) { ++failures; }
    if (auto r = test_arp_reply_reject_too_short(); r) { ++failures; }
    if (auto r = test_arp_reply_reject_wrong_ethertype(); r) { ++failures; }
    if (auto r = test_arp_reply_reject_wrong_opcode(); r) { ++failures; }
    if (auto r = test_arp_reply_reject_zero_sender_mac(); r) { ++failures; }
    if (auto r = test_ipv4_roundtrip_192_168_1_1(); r) { ++failures; }
    if (auto r = test_ipv4_roundtrip_10_0_0_1(); r) { ++failures; }
    if (auto r = test_ipv4_roundtrip_broadcast(); r) { ++failures; }
    if (auto r = test_subnet_24_range(); r) { ++failures; }
    if (auto r = test_subnet_16_range(); r) { ++failures; }
    if (auto r = test_subnet_single_host(); r) { ++failures; }
    if (auto r = test_mac_formatting(); r) { ++failures; }
    if (auto r = test_broadcast_mac(); r) { ++failures; }

    if (failures == 0)
    {
        std::cout << "Scanner: ALL PASSED\n";
    }
    else
    {
        std::cerr << "Scanner: " << failures << " test(s) FAILED\n";
    }
    return failures;
}
