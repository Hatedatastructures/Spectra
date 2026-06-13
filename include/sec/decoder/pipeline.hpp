/**
 * @file pipeline.hpp
 * @brief 解码器管线
 * @details 订阅 capture_session 的原始数据包，经 frame_parser 解析后
 * 根据端口号分发到对应协议解码器，输出解码结果。
 */

#pragma once

#include <sec/decoder/frame.hpp>
#include <sec/decoder/http.hpp>
#include <sec/decoder/dns.hpp>
#include <sec/decoder/tls.hpp>
#include <sec/decoder/socks5.hpp>
#include <sec/decoder/ssh.hpp>
#include <sec/decoder/ftp.hpp>
#include <sec/decoder/smtp.hpp>

#include <functional>
#include <variant>


namespace sec::decoder
{

    /**
     * @brief 协议解码结果变体
     * @details 包含 frame_info 和任意已识别协议的解码结果，
     * 未识别协议仅保留 frame_info。
     */
    struct decoded_packet
    {
        /** @brief 帧解析信息 */
        packet_info frame;
        /** @brief 协议解码结果，未识别时为 std::monostate */
        std::variant<
            std::monostate,
            http_info,
            dns_info,
            tls_info,
            socks5_info,
            ssh_info,
            ftp_info,
            smtp_info
        > protocol;
    };


    /**
     * @brief 解码结果回调类型
     */
    using decoded_callback = std::function<void(const decoded_packet &)>;


    /**
     * @brief 解码器管线
     * @details 接收原始数据包，经帧解析后按端口号分发到
     * 对应协议解码器，将解码结果通过回调输出给订阅者。
     */
    class pipeline
    {
    public:
        pipeline() = default;

        /**
         * @brief 处理单个原始数据包
         * @param raw_packet 从 capture_session 接收的完整帧
         * @param ec 错误码输出
         * @return 解码成功返回 decoded_packet，解析失败返回 std::nullopt
         */
        [[nodiscard]] auto process(std::span<const std::byte> raw_packet, std::error_code &ec) noexcept
            -> std::optional<decoded_packet>;

        /**
         * @brief 注册解码结果回调
         * @param callback 解码结果回调函数
         * @return 回调句柄，用于取消订阅
         */
        [[nodiscard]] auto subscribe(decoded_callback callback)
            -> std::size_t;

        /**
         * @brief 取消解码结果回调
         * @param handle subscribe 返回的句柄
         */
        void unsubscribe(std::size_t handle);

    private:
        void dispatch(decoded_packet &packet);

        frame_parser parser_;
        http_decoder http_;
        dns_decoder dns_;
        tls_decoder tls_;
        socks5_decoder socks5_;
        ssh_decoder ssh_;
        ftp_decoder ftp_;
        smtp_decoder smtp_;

        std::vector<decoded_callback> subscribers_;
        std::size_t next_handle_{0};
    };


} // namespace sec::decoder
