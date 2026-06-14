/**
 * @file Detector.cpp
 * @brief 检测器模块测试（规则引擎 + 统计异常 + 特征提取）
 */

#include <sec/detector/alert.hpp>
#include <sec/detector/rule.hpp>
#include <sec/detector/anomaly.hpp>
#include <sec/detector/forest.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <random>
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

static auto to_bytes(std::string_view sv) -> std::vector<std::byte>
{
    std::vector<std::byte> result(sv.size());
    for (std::size_t i = 0; i < sv.size(); ++i)
    {
        result[i] = static_cast<std::byte>(sv[i]);
    }
    return result;
}


// --- 测试用例 ---

auto TestAlertToString() -> int
{
    using namespace sec::detector;

    CHECK(to_string(severity::info) == "info");
    CHECK(to_string(severity::low) == "low");
    CHECK(to_string(severity::medium) == "medium");
    CHECK(to_string(severity::high) == "high");
    CHECK(to_string(severity::critical) == "critical");

    CHECK(to_string(category::arp_spoofing) == "arp_spoofing");
    CHECK(to_string(category::dns_hijack) == "dns_hijack");
    CHECK(to_string(category::ai_anomaly) == "ai_anomaly");
    CHECK(to_string(category::custom) == "custom");

    std::cout << "  PASS: AlertToString\n";
    return 0;
}


auto TestRuleEngineBasic() -> int
{
    using namespace sec::detector;

    rule_engine engine;
    CHECK(engine.rule_count() == 0);

    // 添加一条 TCP 规则：匹配端口 80 的 HTTP GET
    rule r;
    r.id = "RULE_001";
    r.action = rule_action::alert;
    r.protocol = rule_protocol::tcp;
    r.source.any = true;
    r.destination.any = false;
    r.destination.port = 80;
    r.message = "HTTP GET detected";
    r.level = severity::low;
    r.type = category::custom;

    content_option opt;
    opt.pattern = "GET";
    opt.nocase = true;
    r.contents.push_back(opt);

    engine.add_rule(std::move(r));
    CHECK(engine.rule_count() == 1);

    // 构造匹配的数据包
    sec::decoder::packet_info frame;
    frame.src_ip = 0x01010101; // 1.1.1.1
    frame.dst_ip = 0x02020202; // 2.2.2.2
    frame.src_port = 12345;
    frame.dst_port = 80;
    frame.protocol = 6; // TCP

    auto payload = to_bytes("GET /index.html HTTP/1.1\r\n");
    auto alerts = engine.match(frame,
        {payload.data(), payload.size()});

    CHECK(alerts.size() == 1);
    CHECK(alerts[0].rule_id == "RULE_001");
    CHECK(alerts[0].type == category::custom);

    std::cout << "  PASS: RuleEngineBasic\n";
    return 0;
}


auto TestRuleEngineNoMatch() -> int
{
    using namespace sec::detector;

    rule_engine engine;

    rule r;
    r.id = "RULE_002";
    r.protocol = rule_protocol::tcp;
    r.destination.any = false;
    r.destination.port = 443;
    r.message = "TLS pattern";
    r.contents.push_back({"TLS", false, -1, -1});

    engine.add_rule(std::move(r));

    // 端口不匹配
    sec::decoder::packet_info frame;
    frame.dst_port = 80;
    frame.protocol = 6;

    auto payload = to_bytes("TLS something");
    auto alerts = engine.match(frame,
        {payload.data(), payload.size()});
    CHECK(alerts.empty());

    std::cout << "  PASS: RuleEngineNoMatch\n";
    return 0;
}


auto TestRuleEngineRemove() -> int
{
    using namespace sec::detector;

    rule_engine engine;
    rule r;
    r.id = "RULE_003";
    engine.add_rule(std::move(r));
    CHECK(engine.rule_count() == 1);

    CHECK(engine.remove_rule("RULE_003"));
    CHECK(engine.rule_count() == 0);

    CHECK(!engine.remove_rule("RULE_003"));

    engine.clear();
    CHECK(engine.rule_count() == 0);

    std::cout << "  PASS: RuleEngineRemove\n";
    return 0;
}


auto TestRuleEngineCaseInsensitive() -> int
{
    using namespace sec::detector;

    rule_engine engine;

    rule r;
    r.id = "RULE_004";
    r.protocol = rule_protocol::ip;
    r.source.any = true;
    r.destination.any = true;
    r.contents.push_back({"get", true, -1, -1});

    engine.add_rule(std::move(r));

    sec::decoder::packet_info frame;
    frame.protocol = 6;

    auto payload = to_bytes("GeT /path HTTP/1.1");
    auto alerts = engine.match(frame,
        {payload.data(), payload.size()});
    CHECK(alerts.size() == 1);

    std::cout << "  PASS: RuleEngineCaseInsensitive\n";
    return 0;
}


auto TestAnomalyBasic() -> int
{
    namespace dec = sec::decoder;
    using namespace sec::detector;

    anomaly_config cfg;
    cfg.alpha = 0.1;
    cfg.sigma_threshold = 2.0;
    cfg.min_observations = 5;

    anomaly_detector det(cfg);
    CHECK(det.tracked_count() == 0);

    // 喂入正常流量建立基线
    std::uint32_t ip = 0xC0A80101; // 192.168.1.1
    for (int i = 0; i < 10; ++i)
    {
        dec::packet_info frame;
        frame.src_ip = ip;
        frame.dst_ip = 0xC0A80102;
        frame.payload = {};

        auto result = det.observe(frame);
        // 前 min_observations 次不应产生告警
        if (i < static_cast<int>(cfg.min_observations))
        {
            CHECK(!result.has_value());
        }
    }

    CHECK(det.tracked_count() == 1);

    auto *stats = det.get_stats(ip);
    CHECK(stats != nullptr);
    CHECK(stats->packet_count == 10);

    std::cout << "  PASS: AnomalyBasic\n";
    return 0;
}


auto TestAnomalyReset() -> int
{
    namespace dec = sec::decoder;
    using namespace sec::detector;

    anomaly_detector det;
    CHECK(det.tracked_count() == 0);

    dec::packet_info frame;
    frame.src_ip = 0x01020304;
    frame.dst_ip = 0x05060708;
    frame.payload = {};

    (void)det.observe(frame);
    CHECK(det.tracked_count() == 1);

    det.reset();
    CHECK(det.tracked_count() == 0);

    std::cout << "  PASS: AnomalyReset\n";
    return 0;
}


auto TestRuleEngineMultiPort() -> int
{
    using namespace sec::detector;

    rule_engine engine;

    rule r_ssh;
    r_ssh.id = "brute_ssh";
    r_ssh.protocol = rule_protocol::tcp;
    r_ssh.destination.any = false;
    r_ssh.destination.port = 22;
    r_ssh.type = category::brute_force;
    r_ssh.threshold_count = 3;
    r_ssh.threshold_seconds = 60;
    engine.add_rule(std::move(r_ssh));

    rule r_ftp;
    r_ftp.id = "brute_ftp";
    r_ftp.protocol = rule_protocol::tcp;
    r_ftp.destination.any = false;
    r_ftp.destination.port = 21;
    r_ftp.type = category::brute_force;
    r_ftp.threshold_count = 3;
    r_ftp.threshold_seconds = 60;
    engine.add_rule(std::move(r_ftp));

    CHECK(engine.rule_count() == 2);

    sec::decoder::packet_info frame;
    frame.src_ip = 0xC0A80101;
    frame.dst_ip = 0xC0A80102;
    frame.dst_port = 22;
    frame.protocol = 6;
    frame.payload = std::span<const std::byte>{};

    // 触发 SSH 阈值（threshold_count=3，发 4 次确保超过）
    auto alerts = std::vector<alert>{};
    for (auto i = 0; i < 4; ++i)
    {
        auto result = engine.match(frame, frame.payload);
        for (auto &a : result) alerts.push_back(std::move(a));
    }
    CHECK(!alerts.empty());

    // FTP 端口匹配（threshold_count=3，发 4 次）
    frame.dst_port = 21;
    alerts.clear();
    for (auto i = 0; i < 4; ++i)
    {
        auto result = engine.match(frame, frame.payload);
        for (auto &a : result) alerts.push_back(std::move(a));
    }
    CHECK(!alerts.empty());

    // 不匹配的端口
    frame.dst_port = 8080;
    alerts.clear();
    for (auto i = 0; i < 4; ++i)
    {
        auto result = engine.match(frame, frame.payload);
        for (auto &a : result) alerts.push_back(std::move(a));
    }
    CHECK(alerts.empty());

    std::cout << "  PASS: RuleEngineMultiPort\n";
    return 0;
}


auto TestAnomalyDestinationTracking() -> int
{
    using namespace sec::detector;

    anomaly_detector det{{}};

    sec::decoder::packet_info frame;
    frame.src_ip = 0x0A000001;
    frame.protocol = 6;
    frame.payload = std::span<const std::byte>{};

    frame.dst_ip = 0x0A000002;
    frame.dst_port = 80;
    (void)det.observe(frame);
    (void)det.observe(frame);

    frame.dst_ip = 0x0A000003;
    (void)det.observe(frame);

    frame.dst_ip = 0x0A000004;
    (void)det.observe(frame);

    auto *stats = det.get_stats(0x0A000001);
    CHECK(stats != nullptr);
    CHECK(stats->packet_count == 4);
    CHECK(stats->unique_destinations == 3);

    std::cout << "  PASS: AnomalyDestinationTracking\n";
    return 0;
}


auto TestIsolationForest() -> int
{
    using namespace sec::detector;

    isolation_forest forest{100, 128};

    CHECK(!forest.is_trained());

    // 生成正常样本：模拟典型网络流量
    auto rng = std::mt19937{42};
    auto normal_ports = std::array<int, 5>{80, 443, 22, 53, 25};
    auto size_dist = std::uniform_real_distribution<double>(200, 1400);

    auto normal = std::vector<std::vector<double>>{};
    for (auto i = 0; i < 300; ++i)
    {
        auto port = normal_ports[std::uniform_int_distribution<int>(0, 4)(rng)];
        normal.push_back({
            static_cast<double>(std::uniform_int_distribution<int>(1024, 65535)(rng)),
            static_cast<double>(port),
            6.0,                              // TCP
            size_dist(rng),
            static_cast<double>(std::uniform_int_distribution<int>(0, 3)(rng)),
            static_cast<double>(std::uniform_int_distribution<int>(1, 254)(rng)),
            static_cast<double>(std::uniform_int_distribution<int>(1, 254)(rng)),
        });
    }

    forest.train(normal);
    CHECK(forest.is_trained());
    CHECK(forest.feature_count() == 7);

    // 正常样本应该低分
    auto normal_feat = std::vector<double>{50000, 443, 6, 800, 2, 192, 168};
    auto normal_score = forest.score(normal_feat);
    std::cout << "  Normal sample score: " << normal_score << "\n";

    // 异常样本（端口 4444 + UDP + 零载荷 + 异常 tcp_flags）
    auto anomaly_feat = std::vector<double>{33333, 4444, 17, 0, 255, 1, 1};
    auto anomaly_score = forest.score(anomaly_feat);
    std::cout << "  Anomaly sample score: " << anomaly_score << "\n";

    // 核心断言：异常分必须高于正常分
    CHECK(anomaly_score > normal_score);

    std::cout << "  PASS: IsolationForest\n";
    return 0;
}


// --- main ---

auto main() -> int
{
    int rc = 0;

    std::cout << "[Detector + AI Feature Tests]\n";

    rc |= TestAlertToString();
    rc |= TestRuleEngineBasic();
    rc |= TestRuleEngineNoMatch();
    rc |= TestRuleEngineRemove();
    rc |= TestRuleEngineCaseInsensitive();
    rc |= TestAnomalyBasic();
    rc |= TestAnomalyReset();
    rc |= TestRuleEngineMultiPort();
    rc |= TestAnomalyDestinationTracking();
    rc |= TestIsolationForest();

    if (rc == 0)
    {
        std::cout << "All tests passed.\n";
    }

    return rc;
}
