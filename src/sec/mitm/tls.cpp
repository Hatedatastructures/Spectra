// TLS 降级/剥离检测器实现

#include <sec/mitm/tls.hpp>

#include <array>
#include <chrono>


namespace sec::mitm
{

    auto tls_detector::make_key(std::uint32_t client_ip, std::uint32_t server_ip) noexcept
        -> std::uint64_t
    {
        return (static_cast<std::uint64_t>(client_ip) << 32) |
               static_cast<std::uint64_t>(server_ip);
    }


    void tls_detector::observe_client_hello(std::uint32_t client_ip, std::uint32_t server_ip,
        const decoder::tls_info &info)
    {
        auto now = std::chrono::steady_clock::now();

        // 惰性清理超 60 秒的旧 session
        constexpr std::chrono::seconds session_ttl{60};
        for (auto it = pending_sessions_.begin(); it != pending_sessions_.end(); )
        {
            if ((now - it->second.observed_at) > session_ttl)
            {
                it = pending_sessions_.erase(it);
            }
            else
            {
                ++it;
            }
        }

        tls_session session;
        session.client_version = info.client_version;
        session.observed_at = now;

        // 检查弱密码套件（RC4 / 3DES / NULL / EXPORT）
        // 0x0004=RC4_MD5, 0x0005=RC4_SHA, 0x000a=3DES, 0x0001=NULL_MD5,
        // 0x0002=NULL_SHA, 0x0003=EXP_RC4_MD5
        constexpr auto weak_ciphers = std::array<std::uint16_t, 6>{
            0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x000a
        };
        for (auto suite : info.cipher_suites)
        {
            for (auto weak : weak_ciphers)
            {
                if (suite == weak)
                {
                    session.has_weak_cipher = true;
                    break;
                }
            }
            if (session.has_weak_cipher) break;
        }

        pending_sessions_[make_key(client_ip, server_ip)] = std::move(session);
    }


    [[nodiscard]] auto tls_detector::check_response(std::uint32_t client_ip, std::uint32_t server_ip,
        response_protocol protocol) -> std::optional<tls_alert>
    {
        auto now = std::chrono::steady_clock::now();

        // 惰性清理超 60 秒的旧 session
        constexpr std::chrono::seconds session_ttl{60};
        for (auto it = pending_sessions_.begin(); it != pending_sessions_.end(); )
        {
            if ((now - it->second.observed_at) > session_ttl)
            {
                it = pending_sessions_.erase(it);
            }
            else
            {
                ++it;
            }
        }

        auto key = make_key(client_ip, server_ip);
        auto it = pending_sessions_.find(key);
        if (it == pending_sessions_.end())
        {
            return std::nullopt;
        }

        auto session = std::move(it->second);
        pending_sessions_.erase(it);

        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - session.observed_at);
        if (elapsed.count() > 30)
        {
            return std::nullopt;
        }

        // ClientHello 后收到非 TLS 响应 -> TLS 剥离
        if (protocol == response_protocol::plaintext)
        {
            tls_alert alert;
            alert.type = tls_alert_type::stripping;
            alert.client_ip = client_ip;
            alert.server_ip = server_ip;
            alert.client_version = session.client_version;
            alert.reason = "ClientHello 后收到非 TLS 响应，疑似 TLS 剥离攻击";
            alert.detected_at = now;
            return alert;
        }

        // 弱密码套件检测（RC4/3DES/NULL/EXPORT）
        if (session.has_weak_cipher)
        {
            tls_alert alert;
            alert.type = tls_alert_type::weak_cipher;
            alert.client_ip = client_ip;
            alert.server_ip = server_ip;
            alert.client_version = session.client_version;
            alert.reason = "ClientHello 包含弱密码套件（RC4/3DES/NULL/EXPORT）";
            alert.detected_at = now;
            return alert;
        }

        return std::nullopt;
    }


    [[nodiscard]] auto tls_detector::check_version_downgrade(std::uint32_t client_ip,
        std::uint32_t server_ip, const decoder::tls_info &info) -> std::optional<tls_alert>
    {
        auto now = std::chrono::steady_clock::now();

        // TLS 1.0 = 0x0301, SSL 3.0 = 0x0300, SSL 2.0 = 0x0002
        constexpr std::uint16_t tls_1_0 = 0x0301;

        // record_version 低于 TLS 1.0 — 可能是 SSLv2/SSLv3
        if (info.record_version < tls_1_0 && info.record_version != 0)
        {
            tls_alert alert;
            alert.type = tls_alert_type::version_downgrade;
            alert.client_ip = client_ip;
            alert.server_ip = server_ip;
            alert.client_version = std::to_string(info.record_version >> 8) + "." +
                std::to_string(info.record_version & 0xFF);
            alert.reason = "TLS record version " + alert.client_version + " is below TLS 1.0, possible downgrade";
            alert.detected_at = now;
            return alert;
        }

        // ClientHello version 低于 TLS 1.0
        if (info.client_version < tls_1_0 && info.client_version != 0)
        {
            tls_alert alert;
            alert.type = tls_alert_type::version_downgrade;
            alert.client_ip = client_ip;
            alert.server_ip = server_ip;
            alert.client_version = std::to_string(info.client_version >> 8) + "." +
                std::to_string(info.client_version & 0xFF);
            alert.reason = "ClientHello version " + alert.client_version + " is below TLS 1.0, possible downgrade";
            alert.detected_at = now;
            return alert;
        }

        return std::nullopt;
    }


} // namespace sec::mitm
