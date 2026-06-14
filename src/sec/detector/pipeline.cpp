// 检测管线实现

#include <sec/detector/pipeline.hpp>

#include <sec/decoder/dns.hpp>
#include <sec/decoder/frame.hpp>
#include <sec/decoder/ftp.hpp>
#include <sec/decoder/http.hpp>
#include <sec/decoder/smtp.hpp>

#include <cctype>



namespace sec::detector
{


    detection_pipeline::detection_pipeline(
        decoder::pipeline &decoder) noexcept
        : decoder_{decoder}
    {
        load_default_rules();
    }


    detection_pipeline::~detection_pipeline() noexcept
    {
        stop();
    }


    void detection_pipeline::start()
    {
        if (running_)
        {
            return;
        }

        decoder_handle_ = decoder_.subscribe(
            [this](const decoder::decoded_packet &pkt)
            {
                on_decoded(pkt);
            });

        running_ = true;
    }


    void detection_pipeline::stop()
    {
        if (!running_)
        {
            return;
        }

        decoder_.unsubscribe(decoder_handle_);
        decoder_handle_ = 0;
        running_ = false;
    }


    [[nodiscard]] auto detection_pipeline::subscribe(
        detection_callback cb) -> std::size_t
    {
        auto handle = sub_next_;
        ++sub_next_;
        subscribers_.push_back(std::move(cb));
        return handle;
    }


    void detection_pipeline::unsubscribe(std::size_t handle)
    {
        if (handle < subscribers_.size())
        {
            subscribers_[handle] = nullptr;
        }
    }


    void detection_pipeline::on_decoded(
        const decoder::decoded_packet &pkt)
    {
        // 规则引擎匹配
        auto rule_alerts = rules_.match(pkt.frame, pkt.frame.payload);
        for (auto &a : rule_alerts)
        {
            emit_alert(std::move(a));
        }

        // 统计异常检测
        auto anomaly_result = anomaly_.observe(pkt.frame);
        if (anomaly_result.has_value())
        {
            emit_alert(std::move(anomaly_result.value()));
        }

        // 端口扫描检测
        auto ps_result = port_scan_.check(pkt.frame);
        if (ps_result.has_value())
        {
            alert a;
            a.level = severity::medium;
            a.type = category::port_scan;
            a.source_ip = decoder::ip_to_string(ps_result->source_ip);
            a.description = ps_result->scan_type + ": " + std::to_string(ps_result->target_count) + " targets";
            a.detected_at = ps_result->detected_at;
            emit_alert(std::move(a));
        }

        // DNS 隧道检测
        auto *dns = std::get_if<decoder::dns_info>(&pkt.protocol);
        if (dns != nullptr && !dns->is_response)
        {
            for (const auto &q : dns->questions)
            {
                // 域名超长（正常域名 < 30 字符，DNS 隧道编码后通常 > 50）
                if (q.name.size() > 50)
                {
                    alert a;
                    a.level = severity::high;
                    a.type = category::data_exfiltration;
                    a.source_ip = decoder::ip_to_string(pkt.frame.src_ip);
                    a.description = "DNS tunneling suspected: long query (" +
                        std::to_string(q.name.size()) + " chars): " +
                        q.name.substr(0, 30) + "...";
                    a.detected_at = std::chrono::steady_clock::now();
                    emit_alert(std::move(a));
                }

                // TXT 记录查询（DNS 隧道常用 TXT 做数据外泄）
                if (q.type == decoder::dns_record_type::txt)
                {
                    alert a;
                    a.level = severity::medium;
                    a.type = category::suspicious_traffic;
                    a.source_ip = decoder::ip_to_string(pkt.frame.src_ip);
                    a.description = "DNS TXT query (potential tunneling): " + q.name;
                    a.detected_at = std::chrono::steady_clock::now();
                    emit_alert(std::move(a));
                }
            }
        }

        // 明文凭据检测
        auto src = decoder::ip_to_string(pkt.frame.src_ip);

        // FTP PASS 命令（密码明文传输）
        auto *ftp = std::get_if<decoder::ftp_info>(&pkt.protocol);
        if (ftp != nullptr && ftp->type == decoder::ftp_message_type::command)
        {
            if (ftp->command == "PASS")
            {
                alert a;
                a.level = severity::medium;
                a.type = category::suspicious_traffic;
                a.source_ip = src;
                a.description = "FTP password transmitted in cleartext";
                a.detected_at = std::chrono::steady_clock::now();
                emit_alert(std::move(a));
            }
        }

        // SMTP AUTH 命令（认证信息明文传输）
        auto *smtp = std::get_if<decoder::smtp_info>(&pkt.protocol);
        if (smtp != nullptr && smtp->type == decoder::smtp_message_type::command)
        {
            if (smtp->command.find("AUTH") != std::string::npos)
            {
                alert a;
                a.level = severity::medium;
                a.type = category::suspicious_traffic;
                a.source_ip = src;
                a.description = "SMTP authentication over cleartext";
                a.detected_at = std::chrono::steady_clock::now();
                emit_alert(std::move(a));
            }
        }

        // HTTP URI 含凭据参数
        auto *http = std::get_if<decoder::http_info>(&pkt.protocol);
        if (http != nullptr && http->type == decoder::http_message_type::request)
        {
            auto uri_lower = http->uri;
            for (auto &c : uri_lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (uri_lower.find("password=") != std::string::npos ||
                uri_lower.find("passwd=") != std::string::npos ||
                uri_lower.find("token=") != std::string::npos ||
                uri_lower.find("secret=") != std::string::npos)
            {
                alert a;
                a.level = severity::high;
                a.type = category::data_exfiltration;
                a.source_ip = src;
                a.description = "Credentials in HTTP URI (cleartext): " + http->uri.substr(0, 60);
                a.detected_at = std::chrono::steady_clock::now();
                emit_alert(std::move(a));
            }
        }
    }


    void detection_pipeline::emit_alert(alert a)
    {
        if (!should_emit(a))
        {
            return;
        }

        // 记录到最近告警缓存
        recent_alerts_.push_back(a);
        if (recent_alerts_.size() > max_recent)
        {
            recent_alerts_.erase(recent_alerts_.begin());
        }

        // 告警关联检查
        auto correlated = check_correlation(a);
        if (correlated.has_value())
        {
            for (auto &cb : subscribers_)
            {
                if (cb)
                {
                    cb(*correlated);
                }
            }
        }

        for (auto &cb : subscribers_)
        {
            if (cb)
            {
                cb(a);
            }
        }
    }


    auto detection_pipeline::should_emit(const alert &a) -> bool
    {
        // 构建 dedup key：source_ip + category
        auto key = a.source_ip + "|" + std::to_string(static_cast<std::uint32_t>(a.type));
        auto now = std::chrono::steady_clock::now();

        auto it = dedup_cache_.find(key);
        if (it != dedup_cache_.end())
        {
            constexpr auto dedup_window = std::chrono::seconds{60};
            if (now - it->second < dedup_window)
            {
                return false;
            }
        }
        dedup_cache_[key] = now;
        return true;
    }


    auto detection_pipeline::check_correlation(const alert &a) -> std::optional<alert>
    {
        constexpr auto correlation_window = std::chrono::seconds{30};
        auto now = std::chrono::steady_clock::now();

        // 关联规则 1: ARP 欺骗 + DNS 劫持（同 IP，30s 内）= MITM 确认
        if (a.type == category::dns_hijack || a.type == category::arp_spoofing)
        {
            for (const auto &recent : recent_alerts_)
            {
                if (recent.source_ip != a.source_ip) continue;
                if (now - recent.detected_at > correlation_window) continue;

                auto is_mitm_pair =
                    (a.type == category::dns_hijack && recent.type == category::arp_spoofing) ||
                    (a.type == category::arp_spoofing && recent.type == category::dns_hijack);

                if (is_mitm_pair)
                {
                    alert correlated;
                    correlated.level = severity::critical;
                    correlated.type = category::custom;
                    correlated.source_ip = a.source_ip;
                    correlated.description = "**MITM ATTACK CONFIRMED**: ARP spoofing + DNS hijack from " +
                        a.source_ip + " within 30s window";
                    correlated.detected_at = now;
                    return correlated;
                }
            }
        }

        // 关联规则 2: 端口扫描 + 暴力破解（同 IP，60s 内）= 入侵确认
        if (a.type == category::brute_force || a.type == category::port_scan)
        {
            constexpr auto scan_window = std::chrono::seconds{60};
            for (const auto &recent : recent_alerts_)
            {
                if (recent.source_ip != a.source_ip) continue;
                if (now - recent.detected_at > scan_window) continue;

                auto is_intrusion_pair =
                    (a.type == category::brute_force && recent.type == category::port_scan) ||
                    (a.type == category::port_scan && recent.type == category::brute_force);

                if (is_intrusion_pair)
                {
                    alert correlated;
                    correlated.level = severity::critical;
                    correlated.type = category::custom;
                    correlated.source_ip = a.source_ip;
                    correlated.description = "**INTRUSION CONFIRMED**: Port scan + brute force from " +
                        a.source_ip + " within 60s window";
                    correlated.detected_at = now;
                    return correlated;
                }
            }
        }

        return std::nullopt;
    }


    void detection_pipeline::load_default_rules()
    {
        // ARP 欺骗阈值规则
        rule r_arp;
        r_arp.id = "default_arp_spoof";
        r_arp.protocol = rule_protocol::ip;
        r_arp.level = severity::high;
        r_arp.type = category::arp_spoofing;
        r_arp.message = "ARP spoofing detected";
        r_arp.threshold_count = 3;
        r_arp.threshold_seconds = 10;
        rules_.add_rule(std::move(r_arp));

        // 暴力破解规则 — SSH
        rule r_brute;
        r_brute.id = "default_brute_ssh";
        r_brute.protocol = rule_protocol::tcp;
        r_brute.destination.port = 22;
        r_brute.level = severity::high;
        r_brute.type = category::brute_force;
        r_brute.message = "Possible SSH brute force";
        r_brute.threshold_count = 10;
        r_brute.threshold_seconds = 60;
        rules_.add_rule(std::move(r_brute));

        // 暴力破解规则 — FTP
        rule r_ftp_brute;
        r_ftp_brute.id = "default_brute_ftp";
        r_ftp_brute.protocol = rule_protocol::tcp;
        r_ftp_brute.destination.port = 21;
        r_ftp_brute.level = severity::medium;
        r_ftp_brute.type = category::brute_force;
        r_ftp_brute.message = "Possible FTP brute force";
        r_ftp_brute.threshold_count = 10;
        r_ftp_brute.threshold_seconds = 60;
        rules_.add_rule(std::move(r_ftp_brute));

        // 暴力破解规则 — SMTP
        rule r_smtp_brute;
        r_smtp_brute.id = "default_brute_smtp";
        r_smtp_brute.protocol = rule_protocol::tcp;
        r_smtp_brute.destination.port = 25;
        r_smtp_brute.level = severity::medium;
        r_smtp_brute.type = category::brute_force;
        r_smtp_brute.message = "Possible SMTP brute force";
        r_smtp_brute.threshold_count = 10;
        r_smtp_brute.threshold_seconds = 60;
        rules_.add_rule(std::move(r_smtp_brute));

        // 数据外泄规则
        rule r_exfil;
        r_exfil.id = "default_data_exfil";
        r_exfil.protocol = rule_protocol::tcp;
        r_exfil.level = severity::high;
        r_exfil.type = category::data_exfiltration;
        r_exfil.message = "Large outbound transfer detected";
        r_exfil.threshold_count = 100;
        r_exfil.threshold_seconds = 30;
        rules_.add_rule(std::move(r_exfil));
    }


} // namespace sec::detector
