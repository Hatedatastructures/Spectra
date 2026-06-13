// Qt 应用程序封装实现

#include <sec/qt/application.hpp>

#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QResource>
#include <QUrl>

#include <exception>
#include <iostream>

// QRC 资源初始化（AUTORCC 生成）
extern int qInitResources_qml();


namespace sec::qt
{

    // 构造应用程序并初始化所有子系统，自动启动后台引擎线程
    application::application(const sec::config &cfg)
        : engine_ctx_{cfg}
    {
        db_ = std::make_unique<store::database>(cfg.store.database_path);

        auto ec = std::error_code{};
        store::migration_manager migration{*db_};
        if (!migration.migrate(ec))
        {
            throw std::system_error(ec);
        }

        start_background_thread();
    }


    // 析构时停止后台线程并释放资源
    application::~application() noexcept
    {
        stop_background_thread();
    }


    // 启动 Qt 事件循环并加载 QML 界面
    [[nodiscard]] auto application::run() -> int
    {
        int fake_argc = 1;
        char fake_arg0[] = "Spectra";
        char *fake_argv[] = {fake_arg0, nullptr};

        QGuiApplication qt_app{fake_argc, fake_argv};
        qt_app.setApplicationDisplayName(QStringLiteral("Spectra"));

        // 初始化 QRC 资源（防止被 --gc-sections 裁剪）
        qInitResources_qml();

        QQmlApplicationEngine qml_engine;
        qml_engine.rootContext()->setContextProperty("deviceModel", &devices_);
        qml_engine.rootContext()->setContextProperty("trafficModel", &traffic_);
        qml_engine.rootContext()->setContextProperty("alertModel", &alerts_);

        qml_engine.load(QUrl{QStringLiteral("qrc:/qml/Main.qml")});

        if (qml_engine.rootObjects().isEmpty())
        {
            std::cerr << "Failed to load QML\n";
            return 1;
        }

        running_ = true;
        auto result = qt_app.exec();
        running_ = false;

        stop_background_thread();
        return result;
    }


    // 请求应用程序停止运行
    void application::request_stop()
    {
        running_ = false;
        engine_ctx_.stop();
    }


    // 获取引擎运行时上下文引用
    [[nodiscard]] auto application::engine_context() noexcept -> engine::context &
    {
        return engine_ctx_;
    }


    // 获取数据库连接引用
    [[nodiscard]] auto application::database() noexcept -> store::database &
    {
        return *db_;
    }


    // 获取设备列表模型引用
    [[nodiscard]] auto application::devices() noexcept -> device_model &
    {
        return devices_;
    }


    // 获取流量模型引用
    [[nodiscard]] auto application::traffic() noexcept -> traffic_model &
    {
        return traffic_;
    }


    // 获取告警模型引用
    [[nodiscard]] auto application::alerts() noexcept -> alert_model &
    {
        return alerts_;
    }


    // 启动后台引擎线程运行 io_context 事件循环
    void application::start_background_thread()
    {
        bg_thread_ = std::thread{[this]() {
            static_cast<void>(engine_ctx_.run());
        }};
    }


    // 停止后台引擎线程并等待其退出
    void application::stop_background_thread()
    {
        engine_ctx_.stop();
        if (bg_thread_.joinable())
        {
            bg_thread_.join();
        }
    }


} // namespace sec::qt
