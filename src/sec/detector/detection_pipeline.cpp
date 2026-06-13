// 检测管线实现

#include <sec/detector/detection_pipeline.hpp>

#include <sec/decoder/frame.hpp>



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


    auto detection_pipeline::on_decoded(
        const decoder::decoded_packet &pkt) -> void
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
    }


    void detection_pipeline::emit_alert(alert a)
    {
        for (auto &cb : subscribers_)
        {
            if (cb)
            {
                cb(a);
            }
        }
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

        // 暴力破解规则
        rule r_brute;
        r_brute.id = "default_brute_force";
        r_brute.protocol = rule_protocol::tcp;
        r_brute.destination.port = 22; // SSH
        r_brute.level = severity::high;
        r_brute.type = category::brute_force;
        r_brute.message = "Possible SSH brute force";
        r_brute.threshold_count = 10;
        r_brute.threshold_seconds = 60;
        rules_.add_rule(std::move(r_brute));

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
