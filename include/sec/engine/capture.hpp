/**
 * @file capture.hpp
 * @brief 数据包捕获编排器
 * @details 管理 pcap 传输层，将捕获的数据包通过 strand 保护的
 * 回调列表分发给订阅者。支持 subscribe/unsubscribe 模式。
 */
#pragma once

#include <sec/engine/context.hpp>
#include <sec/transport/pcap.hpp>

#include <boost/asio.hpp>

#include <cstddef>
#include <functional>
#include <mutex>
#include <span>
#include <system_error>
#include <vector>


namespace sec::engine
{

    using packet_callback = std::function<void(std::span<const std::byte>)>;


    /**
     * @brief 数据包捕获编排器
     * @details 管理 pcap 传输层，将捕获的数据包通过 strand 保护的
     * 回调列表分发给订阅者。支持 subscribe/unsubscribe 模式，
     * 解码器和检测器通过订阅接收实时数据包。
     */
    class capture_session
    {
    public:
        explicit capture_session(context &ctx);

        ~capture_session() noexcept;

        [[nodiscard]] auto start(std::error_code &ec) -> net::awaitable<void>;

        void stop();

        [[nodiscard]] auto subscribe(packet_callback callback)
            -> std::size_t;

        void set_filter(std::string_view bpf_filter, std::error_code &ec);

        [[nodiscard]] auto is_running() const noexcept -> bool;

    private:
        void distribute(std::span<const std::byte> packet);

        context &ctx_;
        std::unique_ptr<transport::pcap_capture> pcap_;

        std::mutex subscribers_mutex_;
        std::vector<packet_callback> subscribers_;
        std::size_t next_handle_{0};

        bool running_{false};
    };


} // namespace sec::engine
