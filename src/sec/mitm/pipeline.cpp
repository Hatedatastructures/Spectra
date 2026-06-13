// MITM 检测管线实现

#include <sec/mitm/pipeline.hpp>

#include <sec/decoder/frame.hpp>

#include <chrono>


namespace sec::mitm
{


    mitm_pipeline::mitm_pipeline(decoder::pipeline &decoder,
        store::alert_query *alert_q) noexcept
        : decoder_{decoder}
        , alert_q_{alert_q}
    {
    }


    mitm_pipeline::~mitm_pipeline() noexcept
    {
        stop();
    }


    void mitm_pipeline::start()
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


    void mitm_pipeline::stop()
    {
        if (!running_)
        {
            return;
        }

        decoder_.unsubscribe(decoder_handle_);
        decoder_handle_ = 0;
        running_ = false;
    }


    [[nodiscard]] auto mitm_pipeline::subscribe(mitm_callback cb) -> std::size_t
    {
        auto handle = sub_next_;
        ++sub_next_;
        subscribers_.push_back(std::move(cb));
        return handle;
    }


    void mitm_pipeline::unsubscribe(std::size_t handle)
    {
        if (handle < subscribers_.size())
        {
            subscribers_[handle] = nullptr;
        }
    }


    void mitm_pipeline::on_decoded(const decoder::decoded_packet &pkt)
    {
        // ARP 检测：对所有数据包执行
        auto arp_result = arp_.check(pkt.frame);
        if (arp_result.has_value())
        {
            mitm_event event;
            event.category = "arp_spoofing";
            event.severity = "high";
            event.source_ip = decoder::ip_to_string(arp_result->ip);
            event.target_ip = decoder::ip_to_string(pkt.frame.dst_ip);
            event.description = "ARP conflict detected: IP " + event.source_ip +
                " was " + arp_result->original_mac +
                ", now " + arp_result->conflict_mac;
            emit_alert(std::move(event));
        }

        // DNS 劫持检测
        auto *dns = std::get_if<decoder::dns_info>(&pkt.protocol);
        if (dns != nullptr)
        {
            auto dns_result = dns_.check(*dns);
            if (dns_result.has_value())
            {
                mitm_event event;
                event.category = "dns_hijack";
                event.severity = "high";
                event.source_ip = decoder::ip_to_string(pkt.frame.src_ip);
                event.target_ip = decoder::ip_to_string(pkt.frame.dst_ip);
                event.description = "DNS hijack: " + dns_result->query_name +
                    " expected " + dns_result->expected_ip +
                    " got " + dns_result->actual_ip +
                    " (" + dns_result->reason + ")";
                emit_alert(std::move(event));
            }
        }

        // TLS 检测
        auto *tls = std::get_if<decoder::tls_info>(&pkt.protocol);
        if (tls != nullptr)
        {
            // 记录 ClientHello
            tls_.observe_client_hello(pkt.frame.src_ip, pkt.frame.dst_ip, *tls);
        }
        else
        {
            // 非 TLS 包：检查是否有待检测的 TLS 会话
            auto tls_result = tls_.check_response(
                pkt.frame.dst_ip, pkt.frame.src_ip, false);
            if (tls_result.has_value())
            {
                mitm_event event;
                event.category = "tls_stripping";
                event.severity = "critical";
                event.source_ip = decoder::ip_to_string(tls_result->client_ip);
                event.target_ip = decoder::ip_to_string(tls_result->server_ip);
                event.description = "TLS stripping detected: client " +
                    event.source_ip + " sent ClientHello to " +
                    event.target_ip + " but received non-TLS response";
                emit_alert(std::move(event));
            }
        }
    }


    void mitm_pipeline::emit_alert(mitm_event event)
    {
        // 通知所有订阅者
        for (auto &cb : subscribers_)
        {
            if (cb)
            {
                cb(event);
            }
        }

        // 持久化到 store
        if (alert_q_ != nullptr)
        {
            store::alert_record rec;
            rec.category = event.category;
            rec.severity = event.severity;
            rec.source_ip = event.source_ip;
            rec.target_ip = event.target_ip;
            rec.description = event.description;
            rec.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();

            std::error_code ec;
            (void)alert_q_->insert(rec, ec);
        }
    }


} // namespace sec::mitm
