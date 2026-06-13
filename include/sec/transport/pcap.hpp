/**
 * @file pcap.hpp
 * @brief Pcap 数据包捕获传输层
 * @details 基于 libpcap/Npcap 实现网络数据包捕获，通过后台线程 +
 * asio::post 桥接到 io_context 事件循环。
 */
#pragma once

#include <sec/transport/transmission.hpp>

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>


namespace sec::transport
{

    /**
     * @brief Pcap 数据包捕获器
     * @details 基于 libpcap/Npcap 捕获网络数据包，通过后台线程 +
     * asio::post 桥接到 io_context 事件循环。支持 BPF 过滤器设置。
     */
    class pcap_capture final : public transmission
    {
    public:
        /// 抓包回调（在 executor 线程上调用，线程安全）
        using packet_handler = std::function<void(std::span<const std::byte>)>;

        explicit pcap_capture(std::string interface_name, net::any_io_executor executor);

        ~pcap_capture() noexcept override;

        [[nodiscard]] auto transport_type() const noexcept -> type override
        {
            return type::raw;
        }

        [[nodiscard]] auto executor() const -> executor_type override;

        void set_filter(std::string_view bpf_filter, std::error_code &ec);

        [[nodiscard]] auto start_capture(std::error_code &ec) -> net::awaitable<void>;

        void stop_capture();

        /// 安装抓包回调（每次抓到包从 executor 上调用），传 nullptr 清除
        void set_packet_handler(packet_handler handler);

        /// 同步注入一个完整二层帧，返回写入字节数，失败返回 0 并设置 ec
        auto send_packet(std::span<const std::byte> data, std::error_code &ec) -> std::size_t;

        [[nodiscard]] auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        [[nodiscard]] auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;

        void close() override;

        void cancel() override;

    private:
        void capture_loop();

        std::string interface_name_;
        net::any_io_executor executor_;

        // libpcap 句柄与后台线程
        void *pcap_handle_{nullptr}; // pcap_t*
        std::thread capture_thread_;
        std::atomic<bool> capturing_{false};

        // BPF 过滤器（延迟到 start_capture 时编译）
        std::string bpf_filter_;

        // 抓包回调（shared_ptr 让 capture_loop 按值捕获，生命周期安全）
        std::shared_ptr<packet_handler> handler_;
        std::mutex handler_mutex_;
    };


} // namespace sec::transport
