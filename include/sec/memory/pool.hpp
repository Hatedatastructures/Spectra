/**
 * @file pool.hpp
 * @brief 内存池系统定义
 * @details 提供全局和线程局部的内存池管理，以及基于
 * 内存池的对象分配基类和帧分配器。遵循热路径无分配、
 * 线程封闭和大小分类的设计原则。
 */
#pragma once

#include <sec/memory/container.hpp>

#include <cstdint>


namespace sec::memory
{

    /**
     * @brief 内存池策略参数
     * @details 控制内存池的最大块数和最大分配大小。
     */
    struct policy
    {
        static constexpr std::size_t max_blocks = 256;

        static constexpr std::size_t max_size = 16384;
    }; // struct policy

    /**
     * @brief 内存池管理系统
     * @details 提供全局同步池、线程局部非同步池和热路径池。
     * 全局池线程安全但开销大，局部池线程封闭且无锁。
     */
    class system
    {
    public:
        [[nodiscard]] static auto global_pool() -> synchronized_pool *
        {
            static auto *pool = []()
            {
                std::pmr::pool_options opts;
                opts.largest_required_pool_block = policy::max_size;
                opts.max_blocks_per_chunk = policy::max_blocks;

                return new synchronized_pool(opts, std::pmr::new_delete_resource());
            }();
            return pool;
        }

        [[nodiscard]] static auto local_pool() -> unsynchronized_pool *
        {
            thread_local auto *pool = []()
            {
                std::pmr::pool_options opts;
                opts.largest_required_pool_block = policy::max_size;
                opts.max_blocks_per_chunk = policy::max_blocks;

                return new unsynchronized_pool(opts, std::pmr::new_delete_resource());
            }();
            return pool;
        }

        [[nodiscard]] static auto hot_pool() -> unsynchronized_pool *
        {
            return local_pool();
        }

        static void enable_pooling()
        {
            std::pmr::set_default_resource(global_pool());
        }
    }; // class system

    /**
     * @brief 内存池类型枚举
     * @details 区分全局同步池和线程局部非同步池。
     */
    enum class pool_type : std::uint8_t
    {
        global,
        local
    }; // enum class pool_type

    /**
     * @brief 基于内存池的对象分配基类 (CRTP)
     * @details 继承此类后，new/delete 操作将优先使用内存池分配，
     * 超出策略大小的分配回退到系统默认分配器。
     * @tparam T 派生类类型
     * @tparam Type 池类型，默认为线程局部池
     */
    template <typename T, pool_type Type = pool_type::local>
    class pooled_object
    {
    public:
        [[nodiscard]] static auto target_pool() -> resource_pointer
        {
            if (Type == pool_type::global)
            {
                return system::global_pool();
            }
            return system::local_pool();
        }

        void *operator new(const std::size_t count)
        {
            if (count <= policy::max_size)
            {
                return pooled_object::target_pool()->allocate(count);
            }
            return ::operator new(count);
        }

        void operator delete(void *ptr, const std::size_t count)
        {
            if (count <= policy::max_size)
            {
                pooled_object::target_pool()->deallocate(ptr, count);
            }
            else
            {
                ::operator delete(ptr);
            }
        }

        void *operator new[](const std::size_t count)
        {
            if (count <= policy::max_size)
            {
                return pooled_object::target_pool()->allocate(count);
            }
            return ::operator new[](count);
        }

        void operator delete[](void *ptr, std::size_t count)
        {
            if (count <= policy::max_size)
            {
                pooled_object::target_pool()->deallocate(ptr, count);
            }
            else
            {
                ::operator delete[](ptr);
            }
        }
    }; // class pooled_object

    /**
     * @brief 帧栈分配器
     * @details 基于 512 字节栈缓冲区的单调分配器，适用于单个
     * 协程帧内的临时分配。每帧结束时应调用 reset() 释放。
     */
    class frame_arena
    {
    public:
        explicit frame_arena()
            : resource_(buffer_, sizeof(buffer_), system::local_pool())
        {
        }

        [[nodiscard]] auto get() -> resource_pointer
        {
            return &resource_;
        }

        void reset()
        {
            resource_.release();
        }

    private:
        std::byte buffer_[512];
        monotonic_buffer resource_;

        frame_arena(const frame_arena &) = delete;
        auto operator=(const frame_arena &) -> frame_arena & = delete;
    }; // class frame_arena

} // namespace sec::memory
