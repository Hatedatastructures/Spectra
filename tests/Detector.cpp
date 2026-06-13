/**
 * @file Detector.cpp
 * @brief 检测器模块测试（规则引擎 + 统计异常 + 特征提取）
 */

#include <sec/detector/alert.hpp>
#include <sec/detector/rule_engine.hpp>
#include <sec/detector/anomaly.hpp>
#include <sec/ai/feature.hpp>

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


auto TestFeatureExtractor() -> int
{
    namespace dec = sec::decoder;
    using namespace sec::ai;

    feature_extractor ext(60);
    CHECK(ext.tracked_ips().empty());

    // 喂入数据包
    std::uint32_t ip1 = 0xC0A80101;
    std::uint32_t ip2 = 0xC0A80102;

    dec::packet_info frame1;
    frame1.src_ip = ip1;
    frame1.dst_ip = ip2;
    frame1.src_port = 12345;
    frame1.dst_port = 80;
    frame1.protocol = 6;
    frame1.payload = std::span<const std::byte>{};

    ext.observe(frame1);

    dec::packet_info frame2;
    frame2.src_ip = ip1;
    frame2.dst_ip = 0xC0A80103;
    frame2.src_port = 12346;
    frame2.dst_port = 443;
    frame2.protocol = 6;
    frame2.payload = std::span<const std::byte>{};

    ext.observe(frame2);

    auto ips = ext.tracked_ips();
    CHECK(ips.size() == 1);
    CHECK(ips[0] == ip1);

    auto feat = ext.extract(ip1);
    // 检查特征向量维度
    CHECK(feat.size() == feature_dim);

    // 2 个包
    CHECK(feat[static_cast<std::size_t>(feature_index::total_packets)] == 2.0);
    // TCP 占比 = 1.0
    CHECK(feat[static_cast<std::size_t>(feature_index::tcp_ratio)] == 1.0);
    // UDP 占比 = 0.0
    CHECK(feat[static_cast<std::size_t>(feature_index::udp_ratio)] == 0.0);
    // 唯一目标 IP 数 = 2
    CHECK(feat[static_cast<std::size_t>(feature_index::unique_destinations)] == 2.0);
    // 唯一目标端口数 = 2
    CHECK(feat[static_cast<std::size_t>(feature_index::unique_ports)] == 2.0);

    // 不存在的 IP 返回零向量
    auto feat_empty = ext.extract(0xFFFFFFFF);
    for (std::size_t i = 0; i < feature_dim; ++i)
    {
        CHECK(feat_empty[i] == 0.0);
    }

    std::cout << "  PASS: FeatureExtractor\n";
    return 0;
}


auto TestFeatureExtractorRemove() -> int
{
    namespace dec = sec::decoder;
    using namespace sec::ai;

    feature_extractor ext;

    dec::packet_info frame;
    frame.src_ip = 0x01020304;
    frame.dst_ip = 0x05060708;
    frame.src_port = 1234;
    frame.dst_port = 80;
    frame.protocol = 6;
    frame.payload = {};

    ext.observe(frame);
    CHECK(ext.tracked_ips().size() == 1);

    ext.remove(0x01020304);
    CHECK(ext.tracked_ips().empty());

    // 清除所有
    ext.observe(frame);
    ext.reset();
    CHECK(ext.tracked_ips().empty());

    std::cout << "  PASS: FeatureExtractorRemove\n";
    return 0;
}


auto TestFeatureExtractorUdp() -> int
{
    namespace dec = sec::decoder;
    using namespace sec::ai;

    feature_extractor ext;

    dec::packet_info frame;
    frame.src_ip = 0xC0A80101;
    frame.dst_ip = 0xC0A80102;
    frame.src_port = 54321;
    frame.dst_port = 53;
    frame.protocol = 17; // UDP
    frame.payload = {};

    ext.observe(frame);

    auto feat = ext.extract(0xC0A80101);
    CHECK(feat[static_cast<std::size_t>(feature_index::tcp_ratio)] == 0.0);
    CHECK(feat[static_cast<std::size_t>(feature_index::udp_ratio)] == 1.0);
    CHECK(feat[static_cast<std::size_t>(feature_index::total_packets)] == 1.0);

    std::cout << "  PASS: FeatureExtractorUdp\n";
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
    rc |= TestFeatureExtractor();
    rc |= TestFeatureExtractorRemove();
    rc |= TestFeatureExtractorUdp();

    if (rc == 0)
    {
        std::cout << "All tests passed.\n";
    }

    return rc;
}
