/**
 * @file context.hpp
 * @brief 引擎运行时上下文
 * @details 封装 io_context、配置和 strand，作为引擎各组件的
 * 共享运行环境。io_context 运行在专用线程上。
 */
#pragma once

#include <sec/config.hpp>

#include <boost/asio.hpp>

#include <cstdint>
#include <memory>


namespace sec::engine
{

    namespace net = boost::asio;


    /**
     * @brief 引擎运行时上下文
     * @details 封装 io_context、配置和 strand，作为引擎各组件的
     * 共享运行环境。io_context 运行在专用线程上，所有异步操作
     * 通过 strand 序列化以保证线程安全。
     */
    class context
    {
    public:
        explicit context(const sec::config &cfg = {})
            : config_{cfg}
            , io_context_{std::make_shared<net::io_context>(static_cast<int>(1))}
            , strand_{net::make_strand(*io_context_)}
        {
        }

        [[nodiscard]] auto io_context() const noexcept
            -> net::io_context &
        {
            return *io_context_;
        }

        [[nodiscard]] auto io_context_ptr() const noexcept
            -> std::shared_ptr<net::io_context>
        {
            return io_context_;
        }

        [[nodiscard]] auto config() const noexcept
            -> const sec::config &
        {
            return config_;
        }

        [[nodiscard]] auto strand() const noexcept
            -> const net::strand<net::io_context::executor_type> &
        {
            return strand_;
        }

        [[nodiscard]] auto executor() const noexcept
            -> net::any_io_executor
        {
            return strand_;
        }

        [[nodiscard]] auto run() -> std::size_t
        {
            return io_context_->run();
        }

        [[nodiscard]] auto run_one() -> std::size_t
        {
            return io_context_->run_one();
        }

        [[nodiscard]] auto poll() -> std::size_t
        {
            return io_context_->poll();
        }

        void stop()
        {
            io_context_->stop();
        }

        [[nodiscard]] auto stopped() const -> bool
        {
            return io_context_->stopped();
        }

        void restart()
        {
            io_context_->restart();
        }

    private:
        sec::config config_;
        std::shared_ptr<net::io_context> io_context_;
        net::strand<net::io_context::executor_type> strand_;
    };


} // namespace sec::engine
