/**
 * @file scheduler.hpp
 * @brief 协程任务调度器
 * @details 封装 net::co_spawn 和 net::post，提供协程任务的
 * 统一调度接口。所有任务通过 strand 序列化执行。
 */
#pragma once

#include <sec/engine/context.hpp>

#include <boost/asio.hpp>

#include <functional>
#include <utility>


namespace sec::engine
{

    /**
     * @brief 协程任务调度器
     * @details 封装 net::co_spawn 和 net::post，提供协程任务的
     * 统一调度接口。所有任务通过 strand 序列化执行，确保线程安全。
     */
    class scheduler
    {
    public:
        explicit scheduler(context &ctx) noexcept
            : ctx_{ctx}
        {
        }

        template <typename T>
        void spawn(net::awaitable<T> task)
        {
            net::co_spawn(
                ctx_.executor(),
                std::move(task),
                net::detached);
        }

        template <typename T>
        void spawn_with_handler(net::awaitable<T> task, net::any_completion_handler<void(T)> handler)
        {
            net::co_spawn(
                ctx_.executor(),
                std::move(task),
                std::move(handler));
        }

        void post(std::function<void()> func)
        {
            net::post(ctx_.executor(), std::move(func));
        }

        void defer(std::function<void()> func)
        {
            net::defer(ctx_.executor(), std::move(func));
        }

        [[nodiscard]] auto get_context() const noexcept
            -> context &
        {
            return ctx_;
        }

    private:
        context &ctx_;
    };


} // namespace sec::engine
