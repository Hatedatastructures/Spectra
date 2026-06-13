/**
 * @file application.hpp
 * @brief Qt 应用程序封装
 * @details 管理 Qt 和 Asio 双事件循环，
 * io_context 运行在专用线程，Qt 事件循环运行在主线程。
 */

#pragma once

#include <sec/config.hpp>
#include <sec/engine/context.hpp>
#include <sec/store/database.hpp>
#include <sec/store/migration.hpp>
#include <sec/qt/device_model.hpp>
#include <sec/qt/traffic_model.hpp>
#include <sec/qt/alert_model.hpp>

#include <memory>
#include <string_view>
#include <thread>


namespace sec::qt
{

    /**
     * @brief Qt 应用程序封装
     * @details 管理 Qt 和 Asio 双事件循环的协调。io_context 运行在专用后台线程，
     * Qt 事件循环运行在主线程。通过 request_stop() 安全关闭两个循环。
     */
    class application
    {
    public:
        explicit application(const sec::config &cfg);
        ~application() noexcept;

        application(const application &) = delete;
        auto operator=(const application &) -> application & = delete;

        [[nodiscard]] auto run() -> int;

        void request_stop();

        [[nodiscard]] auto engine_context() noexcept -> engine::context &;
        [[nodiscard]] auto database() noexcept -> store::database &;
        [[nodiscard]] auto devices() noexcept -> device_model &;
        [[nodiscard]] auto traffic() noexcept -> traffic_model &;
        [[nodiscard]] auto alerts() noexcept -> alert_model &;

    private:
        void start_background_thread();
        void stop_background_thread();

        engine::context engine_ctx_;
        std::unique_ptr<store::database> db_;
        device_model devices_;
        traffic_model traffic_;
        alert_model alerts_;
        std::thread bg_thread_;
        bool running_{false};
    };

} // namespace sec::qt
