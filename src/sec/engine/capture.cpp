// 数据包捕获编排器实现

#include <sec/engine/capture.hpp>

#include <algorithm>
#include <mutex>


namespace sec::engine
{

    // 构造捕获会话
    capture_session::capture_session(context &ctx)
        : ctx_{ctx}
    {
    }


    // 析构时自动停止捕获
    capture_session::~capture_session() noexcept
    {
        try
        {
            stop();
        }
        catch (...)
        {
        }
    }


    // 启动数据包捕获
    auto capture_session::start(std::error_code &ec) -> net::awaitable<void>
    {
        if (running_)
        {
            co_return;
        }

        pcap_ = std::make_unique<transport::pcap_capture>(
            ctx_.config().engine.capture_interface,
            ctx_.executor());

        co_await pcap_->start_capture(ec);
        if (ec)
        {
            pcap_.reset();
            co_return;
        }

        // 将 pcap 抓到的包分发给 capture_session 的订阅者
        pcap_->set_packet_handler([this](std::span<const std::byte> packet) {
            distribute(packet);
        });

        running_ = true;
        co_return;
    }


    // 停止捕获并释放 pcap 资源
    void capture_session::stop()
    {
        if (!running_)
        {
            return;
        }

        running_ = false;

        if (pcap_)
        {
            pcap_->stop_capture();
            pcap_->close();
            pcap_.reset();
        }
    }


    // 注册数据包回调
    [[nodiscard]] auto capture_session::subscribe(packet_callback callback) -> std::size_t
    {
        std::lock_guard lock{subscribers_mutex_};
        auto handle = next_handle_++;
        subscribers_.push_back(std::move(callback));
        return handle;
    }


    // 设置 BPF 过滤器
    void capture_session::set_filter(std::string_view bpf_filter, std::error_code &ec)
    {
        if (pcap_)
        {
            pcap_->set_filter(bpf_filter, ec);
        }
        else
        {
            ec = std::make_error_code(std::errc::not_connected);
        }
    }


    // 查询捕获是否正在运行
    [[nodiscard]] auto capture_session::is_running() const noexcept -> bool
    {
        return running_;
    }


    // 将数据包分发给所有订阅者
    void capture_session::distribute(std::span<const std::byte> packet)
    {
        std::lock_guard lock{subscribers_mutex_};
        for (auto &cb : subscribers_)
        {
            if (cb)
            {
                cb(packet);
            }
        }
    }


} // namespace sec::engine
