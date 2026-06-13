/**
 * @file transmission.hpp
 * @brief 传输层流式抽象接口
 * @details 定义异步流的核心概念，参照 Boost.Asio 的 AsyncReadStream/AsyncWriteStream
 * 设计。基类只提供流的基本操作（async_read_some、async_write_some、executor），
 * 不包含组合操作或类型特定操作。
 * 装饰器链通过 next_layer() / lowest_layer<T>() 导航。
 * @note 所有异步操作返回 net::awaitable，错误通过 std::error_code& 参数返回。
 */
#pragma once

#include <sec/fault/compatible.hpp>

#include <boost/asio.hpp>
#include <boost/asio/any_completion_handler.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <system_error>
#include <utility>


namespace sec::transport
{

    namespace net = boost::asio;

    namespace detail
    {

        [[nodiscard]] inline auto to_ec(const std::error_code &ec)
            -> boost::system::error_code
        {
            if (!ec)
                return {};
            if (ec.category() == sec::fault::category())
                return {ec.value(), boost::system::category()};
            return {ec.value(), boost::system::generic_category()};
        }
    } // namespace detail

    /**
     * @brief 传输层流式抽象基类
     * @details 定义异步读写、关闭、取消等核心接口。支持装饰器链模式，
     * 通过 next_layer()/lowest_layer<T>() 导航层叠传输。
     * 所有异步操作返回 net::awaitable，并提供 any_completion_handler 重载。
     */
    class transmission
    {
    public:
        using executor_type = net::any_io_executor;

        enum class type : std::uint8_t
        {
            tcp,
            udp,
            raw
        };

        virtual ~transmission() noexcept = default;

        [[nodiscard]] virtual auto transport_type() const noexcept
            -> type
        {
            auto *n = next_layer();
            if (n)
                return n->transport_type();
            return type::tcp;
        }

        [[nodiscard]] virtual auto executor() const -> executor_type = 0;

        [[nodiscard]] auto get_executor() const
            -> executor_type
        {
            return executor();
        }

        [[nodiscard]] virtual auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> = 0;

        [[nodiscard]] virtual auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> = 0;

        virtual void async_read_some(std::span<std::byte> buffer, net::any_completion_handler<void(boost::system::error_code, std::size_t)> handler)
        {
            auto ex = executor();
            net::co_spawn(ex,
                [this, buffer, h = std::move(handler)]() mutable -> net::awaitable<void>
                {
                    std::error_code ec;
                    const auto n = co_await async_read_some(buffer, ec);
                    std::move(h)(detail::to_ec(ec), n);
                },
                net::detached);
        }

        virtual void async_write_some(std::span<const std::byte> buffer, net::any_completion_handler<void(boost::system::error_code, std::size_t)> handler)
        {
            auto ex = executor();
            net::co_spawn(ex,
                [this, buffer, h = std::move(handler)]() mutable -> net::awaitable<void>
                {
                    std::error_code ec;
                    const auto n = co_await async_write_some(buffer, ec);
                    std::move(h)(detail::to_ec(ec), n);
                },
                net::detached);
        }

        virtual void close() = 0;

        virtual void cancel() = 0;

        [[nodiscard]] virtual auto next_layer() noexcept
            -> transmission *
        {
            return nullptr;
        }

        [[nodiscard]] virtual auto next_layer() const noexcept
            -> const transmission *
        {
            return nullptr;
        }

        template <typename T>
        [[nodiscard]] auto lowest_layer() noexcept
            -> T *
        {
            auto *current = this;
            while (auto *n = current->next_layer())
            {
                current = n;
            }
            return dynamic_cast<T *>(current);
        }

        template <typename T>
        [[nodiscard]] auto lowest_layer() const noexcept
            -> const T *
        {
            const auto *current = this;
            while (const auto *n = current->next_layer())
            {
                current = n;
            }
            return dynamic_cast<const T *>(current);
        }
    };

    using shared_transmission = std::shared_ptr<transmission>;

    [[nodiscard]] inline auto async_write(transmission &t, std::span<const std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        std::size_t total_written = 0;
        while (total_written < buffer.size())
        {
            const auto remaining = buffer.subspan(total_written);
            const auto n = co_await t.async_write_some(remaining, ec);
            if (ec || n == 0)
            {
                co_return total_written;
            }
            total_written += n;
        }
        co_return total_written;
    }

    [[nodiscard]] inline auto async_read(transmission &t, std::span<std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t>
    {
        std::size_t total_read = 0;
        while (total_read < buffer.size())
        {
            const auto remaining = buffer.subspan(total_read);
            const auto n = co_await t.async_read_some(remaining, ec);
            if (ec || n == 0)
            {
                co_return total_read;
            }
            total_read += n;
        }
        co_return total_read;
    }

} // namespace sec::transport
