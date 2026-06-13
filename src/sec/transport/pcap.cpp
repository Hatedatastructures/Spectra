// Pcap 数据包捕获传输层实现 — 基于 Npcap/libpcap

#include <sec/transport/pcap.hpp>
#include <sec/fault/compatible.hpp>
#include <sec/fault/code.hpp>

#include <pcap.h>

#include <boost/asio.hpp>
#include <spdlog/spdlog.h>

#include <cstring>
#include <vector>


namespace sec::transport
{

    namespace
    {

        // 将 libpcap 错误统一映射到 capture_error
        auto pcap_to_error(const char *errbuf) -> std::error_code
        {
            return fault::make_error_code(fault::code::capture_error);
        }

    } // anonymous namespace


    // 构造 pcap 捕获器
    pcap_capture::pcap_capture(std::string interface_name, net::any_io_executor executor)
        : interface_name_{std::move(interface_name)}
        , executor_{std::move(executor)}
        , handler_{std::make_shared<packet_handler>()}
    {
    }


    // 析构时停止捕获并释放 pcap 句柄
    pcap_capture::~pcap_capture() noexcept
    {
        stop_capture();
        close();
    }


    // 获取关联的 Asio 执行器
    [[nodiscard]] auto pcap_capture::executor() const -> executor_type
    {
        return executor_;
    }


    // 设置 BPF 过滤器（捕获启动前调用）
    void pcap_capture::set_filter(std::string_view bpf_filter, std::error_code &ec)
    {
        bpf_filter_ = std::string{bpf_filter};
    }


    // 安装抓包回调
    void pcap_capture::set_packet_handler(packet_handler handler)
    {
        auto new_handler = std::make_shared<packet_handler>(std::move(handler));
        std::lock_guard lk{handler_mutex_};
        handler_ = std::move(new_handler);
    }


    // 同步注入一个完整二层帧
    auto pcap_capture::send_packet(std::span<const std::byte> data, std::error_code &ec) -> std::size_t
    {
        if (!pcap_handle_)
        {
            ec = fault::make_error_code(fault::code::capture_stopped);
            return 0;
        }

        auto handle = static_cast<pcap_t *>(pcap_handle_);
        if (pcap_sendpacket(handle,
                reinterpret_cast<const u_char *>(data.data()),
                static_cast<int>(data.size())) != 0)
        {
            spdlog::warn("pcap_sendpacket failed: {}", pcap_geterr(handle));
            ec = fault::make_error_code(fault::code::capture_error);
            return 0;
        }

        return data.size();
    }


    // 启动数据包捕获
    auto pcap_capture::start_capture(std::error_code &ec) -> net::awaitable<void>
    {
        if (capturing_.load())
        {
            co_return;
        }

        char errbuf[PCAP_ERRBUF_SIZE]{};
        auto handle = pcap_open_live(
            interface_name_.c_str(),
            65535,   // snapshot length
            1,       // promiscuous mode
            1000,    // read timeout ms
            errbuf);

        if (!handle)
        {
            spdlog::error("pcap_open_live({}) failed: {}", interface_name_, errbuf);
            ec = pcap_to_error(errbuf);
            co_return;
        }

        // 编译并安装 BPF 过滤器
        if (!bpf_filter_.empty())
        {
            bpf_program prog{};
            if (pcap_compile(handle, &prog, bpf_filter_.c_str(), 1, PCAP_NETMASK_UNKNOWN) != 0)
            {
                spdlog::error("pcap_compile({}) failed: {}", bpf_filter_, pcap_geterr(handle));
                pcap_close(handle);
                ec = pcap_to_error(pcap_geterr(handle));
                co_return;
            }

            if (pcap_setfilter(handle, &prog) != 0)
            {
                spdlog::error("pcap_setfilter failed: {}", pcap_geterr(handle));
                pcap_freecode(&prog);
                pcap_close(handle);
                ec = pcap_to_error(pcap_geterr(handle));
                co_return;
            }
            pcap_freecode(&prog);
        }

        pcap_handle_ = handle;
        capturing_.store(true);

        // 启动后台捕获线程
        capture_thread_ = std::thread{[this]() {
            capture_loop();
        }};

        ec.clear();
        co_return;
    }


    // 停止数据包捕获
    void pcap_capture::stop_capture()
    {
        capturing_.store(false);

        // 先清空 handler，避免 stop 后还有新的 post
        {
            std::lock_guard lk{handler_mutex_};
            if (handler_)
            {
                *handler_ = nullptr;
            }
        }

        if (pcap_handle_)
        {
            pcap_breakloop(static_cast<pcap_t *>(pcap_handle_));
        }

        if (capture_thread_.joinable())
        {
            capture_thread_.join();
        }
    }


    // 后台捕获线程主循环
    void pcap_capture::capture_loop()
    {
        auto handle = static_cast<pcap_t *>(pcap_handle_);
        if (!handle)
        {
            return;
        }

        while (capturing_.load())
        {
            pcap_pkthdr header{};
            const auto *data = pcap_next(handle, &header);
            if (!data)
            {
                // read timeout 或 breakloop，继续检查 capturing_
                continue;
            }

            // 拷贝包到独立缓冲区
            auto packet = std::make_shared<std::vector<std::byte>>(
                reinterpret_cast<const std::byte *>(data),
                reinterpret_cast<const std::byte *>(data) + header.caplen);

            // 取 handler 快照（shared_ptr 按值捕获，生命周期安全）
            std::shared_ptr<packet_handler> handler_snap;
            {
                std::lock_guard lk{handler_mutex_};
                handler_snap = handler_;
            }

            // 投递到 executor，handler 在 executor 线程上执行
            net::post(executor_,
                [packet, handler_snap]() {
                    if (handler_snap && *handler_snap)
                    {
                        (*handler_snap)(std::span<const std::byte>{*packet});
                    }
                });
        }
    }


    // 异步读取数据包（暂未实现队列消费）
    auto pcap_capture::async_read_some(std::span<std::byte> buffer, std::error_code &ec) -> net::awaitable<std::size_t>
    {
        ec = std::make_error_code(std::errc::operation_not_supported);
        co_return 0;
    }


    // 异步写入数据包（pcap 捕获模式通过 send_packet 替代）
    auto pcap_capture::async_write_some(std::span<const std::byte>, std::error_code &ec) -> net::awaitable<std::size_t>
    {
        ec = std::make_error_code(std::errc::operation_not_supported);
        co_return 0;
    }


    // 关闭捕获器
    void pcap_capture::close()
    {
        if (pcap_handle_)
        {
            pcap_close(static_cast<pcap_t *>(pcap_handle_));
            pcap_handle_ = nullptr;
        }
    }


    // 取消异步操作
    void pcap_capture::cancel()
    {
        if (pcap_handle_)
        {
            pcap_breakloop(static_cast<pcap_t *>(pcap_handle_));
        }
    }


} // namespace sec::transport
