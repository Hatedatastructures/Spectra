/**
 * @file mitm_pipeline.hpp
 * @brief MITM 检测管线
 * @details 将解码器管线与 MITM 检测器连接，订阅解码结果，
 * 对 ARP/DNS/TLS 流量执行中间人攻击检测，产生告警并持久化。
 */

#pragma once

#include <sec/decoder/pipeline.hpp>
#include <sec/mitm/arp_detect.hpp>
#include <sec/mitm/dns_detect.hpp>
#include <sec/mitm/tls_detect.hpp>
#include <sec/store/query.hpp>

#include <functional>
#include <vector>


namespace sec::mitm
{

    /**
     * @brief MITM 检测告警输出
     */
    struct mitm_event
    {
        /** @brief 告警类别：arp_spoofing、dns_hijack、tls_stripping */
        std::string category;
        /** @brief 严重程度 */
        std::string severity;
        /** @brief 源 IP */
        std::string source_ip;
        /** @brief 目标 IP */
        std::string target_ip;
        /** @brief 告警描述 */
        std::string description;
    };


    using mitm_callback = std::function<void(const mitm_event &)>;


    /**
     * @brief MITM 检测管线
     * @details 订阅解码器管线的输出，对每条解码后的数据包执行
     * ARP 欺骗、DNS 劫持和 TLS 剥离检测。检测到威胁时产生
     * 告警并通过回调通知上层，同时持久化到 store。
     */
    class mitm_pipeline
    {
    public:
        /**
         * @param decoder 解码器管线引用
         * @param alert_q 告警存储查询对象（可选，为 nullptr 则不持久化）
         */
        explicit mitm_pipeline(decoder::pipeline &decoder,
            store::alert_query *alert_q = nullptr) noexcept;

        ~mitm_pipeline() noexcept;

        /**
         * @brief 启动检测管线，订阅解码器输出
         * @return 订阅句柄
         */
        void start();

        /**
         * @brief 停止检测管线，取消订阅
         */
        void stop();

        /**
         * @brief 注册告警回调
         * @param cb 告警回调函数
         * @return 回调句柄
         */
        [[nodiscard]] auto subscribe(mitm_callback cb) -> std::size_t;

        /**
         * @brief 取消告警回调
         * @param handle 回调句柄
         */
        void unsubscribe(std::size_t handle);

        /**
         * @brief 添加已知域名-IP 绑定（用于 DNS 劫持检测）
         */
        void add_known_dns_binding(const std::string &domain, const std::string &ip)
        {
            dns_.add_known_binding(domain, ip);
        }

        /**
         * @brief 添加可疑 IP（用于 DNS 劫持检测）
         */
        void add_suspicious_ip(const std::string &ip)
        {
            dns_.add_suspicious_ip(ip);
        }

        /**
         * @brief 获取 ARP 检测器引用
         */
        [[nodiscard]] auto arp_detector() noexcept -> arp_detector &
        {
            return arp_;
        }

    private:
        void on_decoded(const decoder::decoded_packet &pkt);

        void emit_alert(mitm_event event);

        decoder::pipeline &decoder_;
        store::alert_query *alert_q_;

        class arp_detector arp_;
        class dns_detector dns_;
        class tls_detector tls_;

        std::vector<mitm_callback> subscribers_;
        std::size_t sub_next_{0};

        std::size_t decoder_handle_{0};
        bool running_{false};
    };


} // namespace sec::mitm
