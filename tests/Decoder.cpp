/**
 * @file Decoder.cpp
 * @brief 协议解码器模块测试
 */

#include <sec/decoder/frame.hpp>
#include <sec/decoder/http.hpp>
#include <sec/decoder/dns.hpp>
#include <sec/decoder/tls.hpp>
#include <sec/decoder/socks5.hpp>
#include <sec/decoder/ssh.hpp>
#include <sec/decoder/ftp.hpp>
#include <sec/decoder/smtp.hpp>
#include <sec/decoder/pipeline.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <string_view>
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

static auto to_bytes(std::string_view sv) -> std::vector<std::byte>
{
    auto v = std::vector<std::byte>(sv.size());
    for (std::size_t i = 0; i < sv.size(); ++i)
    {
        v[i] = static_cast<std::byte>(static_cast<unsigned char>(sv[i]));
    }
    return v;
}

static auto span_eq(std::span<const std::byte> span, std::string_view sv) -> bool
{
    if (span.size() != sv.size())
    {
        return false;
    }
    for (std::size_t i = 0; i < sv.size(); ++i)
    {
        if (span[i] != static_cast<std::byte>(static_cast<unsigned char>(sv[i])))
        {
            return false;
        }
    }
    return true;
}

static auto make_ipv4_tcp_packet(
    std::uint32_t src_ip, std::uint32_t dst_ip,
    std::uint16_t src_port, std::uint16_t dst_port,
    std::string_view payload) -> std::vector<std::byte>
{
    // Ethernet(14) + IPv4(20) + TCP(20) + payload
    constexpr std::size_t eth_len = 14;
    constexpr std::size_t ip_len = 20;
    constexpr std::size_t tcp_len = 20;
    const std::size_t total = eth_len + ip_len + tcp_len + payload.size();

    std::vector<std::byte> pkt(total, std::byte{0});
    auto *p = pkt.data();

    // Ethernet: dst=FF:FF:FF:FF:FF:FF, src=AA:BB:CC:DD:EE:FF, type=0x0800
    for (int i = 0; i < 6; ++i) p[i] = std::byte{0xFF};
    p[6] = std::byte{0xAA}; p[7] = std::byte{0xBB}; p[8] = std::byte{0xCC};
    p[9] = std::byte{0xDD}; p[10] = std::byte{0xEE}; p[11] = std::byte{0xFF};
    p[12] = std::byte{0x08}; p[13] = std::byte{0x00};

    // IPv4 header
    auto *ip = p + eth_len;
    ip[0] = std::byte{0x45};  // version=4, IHL=5
    ip[1] = std::byte{0};
    auto total_len = static_cast<std::uint16_t>(ip_len + tcp_len + payload.size());
    ip[2] = static_cast<std::byte>((total_len >> 8) & 0xFF);
    ip[3] = static_cast<std::byte>(total_len & 0xFF);
    ip[9] = std::byte{6};  // TCP
    ip[12] = static_cast<std::byte>((src_ip >> 24) & 0xFF);
    ip[13] = static_cast<std::byte>((src_ip >> 16) & 0xFF);
    ip[14] = static_cast<std::byte>((src_ip >> 8) & 0xFF);
    ip[15] = static_cast<std::byte>(src_ip & 0xFF);
    ip[16] = static_cast<std::byte>((dst_ip >> 24) & 0xFF);
    ip[17] = static_cast<std::byte>((dst_ip >> 16) & 0xFF);
    ip[18] = static_cast<std::byte>((dst_ip >> 8) & 0xFF);
    ip[19] = static_cast<std::byte>(dst_ip & 0xFF);

    // TCP header
    auto *tcp = ip + ip_len;
    tcp[0] = static_cast<std::byte>((src_port >> 8) & 0xFF);
    tcp[1] = static_cast<std::byte>(src_port & 0xFF);
    tcp[2] = static_cast<std::byte>((dst_port >> 8) & 0xFF);
    tcp[3] = static_cast<std::byte>(dst_port & 0xFF);
    tcp[12] = std::byte{0x50};  // data offset = 5 (20 bytes)

    // Payload
    if (!payload.empty())
    {
        std::memcpy(tcp + tcp_len, payload.data(), payload.size());
    }

    return pkt;
}


// --- Frame Parser Tests ---

static auto TestFrameParserRejectsTooShort() -> int
{
    sec::decoder::frame_parser parser;
    std::error_code ec;
    std::array<std::byte, 10> short_data{};
    auto result = parser.parse(short_data, ec);
    CHECK(!result.has_value());
    CHECK(ec);
    return 0;
}

static auto TestFrameParserParsesTcpPacket() -> int
{
    auto pkt = make_ipv4_tcp_packet(
        0xC0A80101, 0xC0A80102, 12345, 80,
        "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");

    sec::decoder::frame_parser parser;
    std::error_code ec;
    auto result = parser.parse(pkt, ec);
    CHECK(result.has_value());
    CHECK(!ec);
    CHECK(result->src_ip == 0xC0A80101);
    CHECK(result->dst_ip == 0xC0A80102);
    CHECK(result->src_port == 12345);
    CHECK(result->dst_port == 80);
    CHECK(result->protocol == 6);
    CHECK(!result->payload.empty());
    return 0;
}

static auto TestIpToString() -> int
{
    auto s = sec::decoder::ip_to_string(0xC0A80101);
    CHECK(s == "192.168.1.1");

    auto s2 = sec::decoder::ip_to_string(0x0A000001);
    CHECK(s2 == "10.0.0.1");
    return 0;
}


// --- HTTP Decoder Tests ---

static auto TestHttpRequestDecode() -> int
{
    sec::decoder::http_decoder decoder;
    auto data = to_bytes("GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: TestAgent\r\n\r\nbody");
    auto result = decoder.decode(data);
    CHECK(result.has_value());
    CHECK(result->type == sec::decoder::http_message_type::request);
    CHECK(result->method == "GET");
    CHECK(result->uri == "/index.html");
    CHECK(result->host == "example.com");
    CHECK(result->user_agent == "TestAgent");
    CHECK(span_eq(result->body, "body"));
    return 0;
}

static auto TestHttpResponseDecode() -> int
{
    sec::decoder::http_decoder decoder;
    auto data = to_bytes("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nhello");
    auto result = decoder.decode(data);
    CHECK(result.has_value());
    CHECK(result->type == sec::decoder::http_message_type::response);
    CHECK(result->status_code == 200);
    CHECK(result->content_type == "text/html");
    CHECK(span_eq(result->body, "hello"));
    return 0;
}

static auto TestHttpRejectsGarbage() -> int
{
    sec::decoder::http_decoder decoder;
    auto data = to_bytes("XYZ random data\r\n");
    auto result = decoder.decode(data);
    CHECK(!result.has_value());
    return 0;
}


// --- DNS Decoder Tests ---

static auto TestDnsResponseDecode() -> int
{
    // 构造一个最小 DNS 响应包
    // Header(12) + Question(8) + Answer(16)
    std::vector<std::byte> pkt(36, std::byte{0});
    auto *p = pkt.data();

    // Transaction ID
    p[0] = std::byte{0x12}; p[1] = std::byte{0x34};
    // Flags: QR=1 (response), OPCODE=0, RCODE=0
    p[2] = std::byte{0x80}; p[3] = std::byte{0x00};
    // QDCOUNT=1
    p[4] = std::byte{0x00}; p[5] = std::byte{0x01};
    // ANCOUNT=1
    p[6] = std::byte{0x00}; p[7] = std::byte{0x01};
    // NSCOUNT=0, ARCOUNT=0
    p[8] = std::byte{0x00}; p[9] = std::byte{0x00};
    p[10] = std::byte{0x00}; p[11] = std::byte{0x00};

    // Question section: label "a" (1 byte label + root)
    p[12] = std::byte{0x01}; p[13] = std::byte{'a'}; p[14] = std::byte{0x00};
    // QTYPE=A(1), QCLASS=IN(1)
    p[15] = std::byte{0x00}; p[16] = std::byte{0x01};
    p[17] = std::byte{0x00}; p[18] = std::byte{0x01};

    // Answer section: pointer to question name
    p[19] = std::byte{0xC0}; p[20] = std::byte{0x0C};
    // TYPE=A(1), CLASS=IN(1)
    p[21] = std::byte{0x00}; p[22] = std::byte{0x01};
    p[23] = std::byte{0x00}; p[24] = std::byte{0x01};
    // TTL=300
    p[25] = std::byte{0x00}; p[26] = std::byte{0x00};
    p[27] = std::byte{0x01}; p[28] = std::byte{0x2C};
    // RDLENGTH=4
    p[29] = std::byte{0x00}; p[30] = std::byte{0x04};
    // RDATA: 1.2.3.4
    p[31] = std::byte{0x01}; p[32] = std::byte{0x02};
    p[33] = std::byte{0x03}; p[34] = std::byte{0x04};
    // Need one more byte to make 35 bytes... actually we need exactly 35
    pkt.resize(35);

    sec::decoder::dns_decoder decoder;
    auto result = decoder.decode(pkt);
    CHECK(result.has_value());
    CHECK(result->transaction_id == 0x1234);
    CHECK(result->is_response);
    CHECK(result->answers.size() == 1);
    CHECK(result->answers[0].data == "1.2.3.4");
    CHECK(result->answers[0].ttl == 300);
    return 0;
}

static auto TestDnsRejectsTooShort() -> int
{
    sec::decoder::dns_decoder decoder;
    std::array<std::byte, 10> short_data{};
    auto result = decoder.decode(short_data);
    CHECK(!result.has_value());
    return 0;
}


// --- TLS Decoder Tests ---

static auto TestTlsClientHelloDecode() -> int
{
    // 构造最小 TLS ClientHello
    // TLS Record: type=22, version=0x0301, length
    // Handshake: type=1, length
    // ClientVersion: 0x0303
    // Random: 32 bytes
    // SessionID: 0 length
    // CipherSuites: 2 suites (4 bytes)
    // Compression: 1 method (2 bytes)

    std::vector<std::byte> pkt;
    pkt.push_back(std::byte{0x16});  // Handshake
    pkt.push_back(std::byte{0x03}); pkt.push_back(std::byte{0x01});  // TLS 1.0 record version

    // Calculate payload size after record header
    // Handshake header(4) + version(2) + random(32) + session_len(1) +
    // cipher_len(2) + cipher_data(4) + comp_len(1) + comp_data(1) = 47
    std::uint16_t record_len = 47;
    pkt.push_back(static_cast<std::byte>((record_len >> 8) & 0xFF));
    pkt.push_back(static_cast<std::byte>(record_len & 0xFF));

    // Handshake header
    pkt.push_back(std::byte{0x01});  // ClientHello
    std::uint8_t hs_len[3] = {0, 0, 43};  // 47 - 4 = 43
    pkt.push_back(std::byte{hs_len[0]});
    pkt.push_back(std::byte{hs_len[1]});
    pkt.push_back(std::byte{hs_len[2]});

    // Client version TLS 1.2
    pkt.push_back(std::byte{0x03}); pkt.push_back(std::byte{0x03});

    // Random (32 bytes of 0x42)
    for (int i = 0; i < 32; ++i) pkt.push_back(std::byte{0x42});

    // Session ID length = 0
    pkt.push_back(std::byte{0x00});

    // Cipher suites: 2 suites = 4 bytes
    pkt.push_back(std::byte{0x00}); pkt.push_back(std::byte{0x04});
    pkt.push_back(std::byte{0x00}); pkt.push_back(std::byte{0x2F});  // TLS_RSA_WITH_AES_128_CBC_SHA
    pkt.push_back(std::byte{0x00}); pkt.push_back(std::byte{0x35});  // TLS_RSA_WITH_AES_256_CBC_SHA

    // Wait, that's 3 suites (6 bytes). Let me fix: length=4 means 2 suites
    // Actually length=4 = 2 cipher suites (each is 2 bytes)
    // Fix: already have 4 bytes of cipher data (00 2F 00 35) and length field says 00 04.
    // That's correct.

    // Compression methods: length=1, method=0 (null)
    pkt.push_back(std::byte{0x01}); pkt.push_back(std::byte{0x00});

    sec::decoder::tls_decoder decoder;
    auto result = decoder.decode(pkt);
    CHECK(result.has_value());
    CHECK(result->client_version == 0x0303);
    CHECK(result->cipher_suites.size() == 2);
    return 0;
}

static auto TestTlsRejectsNonHandshake() -> int
{
    sec::decoder::tls_decoder decoder;
    auto data = to_bytes("GET / HTTP/1.1\r\n\r\n");
    auto result = decoder.decode(data);
    CHECK(!result.has_value());
    return 0;
}


// --- SSH Decoder Tests ---

static auto TestSshBannerDecode() -> int
{
    sec::decoder::ssh_decoder decoder;
    auto data = to_bytes("SSH-2.0-OpenSSH_9.0\r\n");
    auto result = decoder.decode(data);
    CHECK(result.has_value());
    CHECK(result->protocol_version == "2.0");
    CHECK(result->software_version == "OpenSSH_9.0");
    CHECK(result->is_server);
    return 0;
}

static auto TestSshRejectsNonSsh() -> int
{
    sec::decoder::ssh_decoder decoder;
    auto data = to_bytes("Welcome to server\r\n");
    auto result = decoder.decode(data);
    CHECK(!result.has_value());
    return 0;
}


// --- FTP Decoder Tests ---

static auto TestFtpCommandDecode() -> int
{
    sec::decoder::ftp_decoder decoder;
    auto data = to_bytes("USER admin\r\n");
    auto result = decoder.decode(data);
    CHECK(result.has_value());
    CHECK(result->type == sec::decoder::ftp_message_type::command);
    CHECK(result->command == "USER");
    CHECK(result->argument == "admin");
    return 0;
}

static auto TestFtpResponseDecode() -> int
{
    sec::decoder::ftp_decoder decoder;
    auto data = to_bytes("220 Welcome to FTP Server\r\n");
    auto result = decoder.decode(data);
    CHECK(result.has_value());
    CHECK(result->type == sec::decoder::ftp_message_type::response);
    CHECK(result->status_code == 220);
    return 0;
}


// --- SMTP Decoder Tests ---

static auto TestSmtpCommandDecode() -> int
{
    sec::decoder::smtp_decoder decoder;
    auto data = to_bytes("EHLO client.example.com\r\n");
    auto result = decoder.decode(data);
    CHECK(result.has_value());
    CHECK(result->type == sec::decoder::smtp_message_type::command);
    CHECK(result->command == "EHLO");
    CHECK(result->argument == "client.example.com");
    return 0;
}

static auto TestSmtpResponseDecode() -> int
{
    sec::decoder::smtp_decoder decoder;
    auto data = to_bytes("250 OK\r\n");
    auto result = decoder.decode(data);
    CHECK(result.has_value());
    CHECK(result->type == sec::decoder::smtp_message_type::response);
    CHECK(result->status_code == 250);
    return 0;
}


// --- SOCKS5 Decoder Tests ---

static auto TestSocks5MethodNegotiation() -> int
{
    sec::decoder::socks5_decoder decoder;
    // VER=5, NMETHODS=2, METHODS=0x00,0x02
    std::array<std::byte, 4> data{
        std::byte{0x05}, std::byte{0x02},
        std::byte{0x00}, std::byte{0x02}};
    auto result = decoder.decode(data);
    CHECK(result.has_value());
    CHECK(result->version == 0x05);
    return 0;
}

static auto TestSocks5RejectsNonSocks5() -> int
{
    sec::decoder::socks5_decoder decoder;
    std::array<std::byte, 2> data{std::byte{0x04}, std::byte{0x01}};
    auto result = decoder.decode(data);
    CHECK(!result.has_value());
    return 0;
}


// --- Pipeline Tests ---

static auto TestPipelineHttpPacket() -> int
{
    sec::decoder::pipeline pipe;
    auto pkt = make_ipv4_tcp_packet(
        0xC0A80101, 0xC0A80102, 54321, 80,
        "GET /test HTTP/1.1\r\nHost: test.com\r\n\r\n");

    std::error_code ec;
    auto result = pipe.process(pkt, ec);
    CHECK(result.has_value());
    CHECK(!ec);
    CHECK(result->frame.dst_port == 80);
    CHECK(std::holds_alternative<sec::decoder::http_info>(result->protocol));

    auto &http = std::get<sec::decoder::http_info>(result->protocol);
    CHECK(http.method == "GET");
    CHECK(http.uri == "/test");
    return 0;
}

static auto TestPipelineSubscribe() -> int
{
    sec::decoder::pipeline pipe;
    int call_count = 0;
    auto handle = pipe.subscribe([&](const sec::decoder::decoded_packet &p)
    {
        (void)p;
        ++call_count;
    });

    auto pkt = make_ipv4_tcp_packet(
        0xC0A80101, 0xC0A80102, 1234, 80,
        "GET / HTTP/1.1\r\n\r\n");

    std::error_code ec;
    (void)pipe.process(pkt, ec);
    CHECK(call_count == 1);

    pipe.unsubscribe(handle);
    (void)pipe.process(pkt, ec);
    CHECK(call_count == 1);
    return 0;
}


auto main() -> int
{
    int failures = 0;

    if (auto r = TestFrameParserRejectsTooShort(); r) { ++failures; }
    if (auto r = TestFrameParserParsesTcpPacket(); r) { ++failures; }
    if (auto r = TestIpToString(); r) { ++failures; }
    if (auto r = TestHttpRequestDecode(); r) { ++failures; }
    if (auto r = TestHttpResponseDecode(); r) { ++failures; }
    if (auto r = TestHttpRejectsGarbage(); r) { ++failures; }
    if (auto r = TestDnsResponseDecode(); r) { ++failures; }
    if (auto r = TestDnsRejectsTooShort(); r) { ++failures; }
    if (auto r = TestTlsClientHelloDecode(); r) { ++failures; }
    if (auto r = TestTlsRejectsNonHandshake(); r) { ++failures; }
    if (auto r = TestSshBannerDecode(); r) { ++failures; }
    if (auto r = TestSshRejectsNonSsh(); r) { ++failures; }
    if (auto r = TestFtpCommandDecode(); r) { ++failures; }
    if (auto r = TestFtpResponseDecode(); r) { ++failures; }
    if (auto r = TestSmtpCommandDecode(); r) { ++failures; }
    if (auto r = TestSmtpResponseDecode(); r) { ++failures; }
    if (auto r = TestSocks5MethodNegotiation(); r) { ++failures; }
    if (auto r = TestSocks5RejectsNonSocks5(); r) { ++failures; }
    if (auto r = TestPipelineHttpPacket(); r) { ++failures; }
    if (auto r = TestPipelineSubscribe(); r) { ++failures; }

    if (failures == 0)
    {
        std::cout << "Decoder: ALL PASSED\n";
    }
    else
    {
        std::cerr << "Decoder: " << failures << " test(s) FAILED\n";
    }
    return failures;
}
