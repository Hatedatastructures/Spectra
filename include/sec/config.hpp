/**
 * @file config.hpp
 * @brief 全局配置定义
 * @details 定义 Spectra 运行时配置结构体，包含引擎、扫描器、
 * 存储、AI 和追踪等子模块的配置项。使用 glaze 库提供
 * JSON 序列化/反序列化支持。
 */
#pragma once

#include <glaze/glaze.hpp>

#include <string>
#include <cstdint>

namespace sec
{

    /**
     * @brief 引擎配置
     * @details 控制抓包引擎的运行参数。
     */
    struct engine_config
    {
        std::string capture_interface{"eth0"};
        std::uint16_t capture_buffer_size{4096};
        bool promiscuous_mode{true};
        std::uint32_t snapshot_length{65535};
    }; // struct engine_config

    /**
     * @brief 扫描器配置
     * @details 控制设备扫描器的超时和并发参数。
     */
    struct scanner_config
    {
        std::uint16_t arp_timeout_ms{1000};
        std::uint16_t port_timeout_ms{500};
        std::uint16_t port_concurrency{128};
        bool enable_mdns{true};
        bool enable_ssdp{true};
    }; // struct scanner_config

    /**
     * @brief 存储配置
     * @details SQLite 数据库路径和维护参数。
     */
    struct store_config
    {
        std::string database_path{"spectra.db"};
        std::uint32_t wal_checkpoint_interval{1000};
        std::uint32_t max_traffic_log_hours{72};
    }; // struct store_config

    /**
     * @brief AI 推理配置
     * @details ONNX 模型路径和异常检测阈值。
     */
    struct ai_config
    {
        std::string model_path{"models/anomaly_detection.onnx"};
        float anomaly_threshold{0.85f};
        std::uint32_t feature_window_size{100};
        bool enable_inference{true};
        std::string remote_endpoint;
        std::string remote_api_key;
        std::string remote_model{"gpt-4o"};
        std::string remote_protocol{"openai"};
    }; // struct ai_config

    /**
     * @brief 日志追踪配置
     * @details spdlog 日志级别、路径和控制台输出开关。
     */
    struct trace_config
    {
        std::string log_level{"info"};
        std::string log_path{"logs/"};
        bool console_output{true};
    }; // struct trace_config

    /**
     * @brief TUI 界面配置
     * @details 控制终端界面主题（dark/light/auto）。
     */
    struct tui_config
    {
        std::string theme{"auto"};
    }; // struct tui_config

    /**
     * @brief 全局配置聚合
     * @details 聚合所有子模块配置，支持 JSON 序列化。
     */
    struct config
    {
        engine_config engine{};
        scanner_config scanner{};
        store_config store{};
        ai_config ai{};
        trace_config trace{};
        tui_config tui{};
    }; // struct config

    /**
     * @brief 从 JSON 文件加载配置
     * @param path JSON 文件路径
     * @return 解析后的配置对象
     */
    [[nodiscard]] auto load_config(const std::string &path) -> config;

    /**
     * @brief 将配置保存到 JSON 文件
     * @param cfg 配置对象
     * @param path 目标文件路径
     */
    void save_config(const config &cfg, const std::string &path);

} // namespace sec

template <>
struct glz::meta<sec::engine_config>
{
    using T = sec::engine_config;
    static constexpr auto value = glz::object(
        "capture_interface", &T::capture_interface,
        "capture_buffer_size", &T::capture_buffer_size,
        "promiscuous_mode", &T::promiscuous_mode,
        "snapshot_length", &T::snapshot_length
    );
};

template <>
struct glz::meta<sec::scanner_config>
{
    using T = sec::scanner_config;
    static constexpr auto value = glz::object(
        "arp_timeout_ms", &T::arp_timeout_ms,
        "port_timeout_ms", &T::port_timeout_ms,
        "port_concurrency", &T::port_concurrency,
        "enable_mdns", &T::enable_mdns,
        "enable_ssdp", &T::enable_ssdp
    );
};

template <>
struct glz::meta<sec::store_config>
{
    using T = sec::store_config;
    static constexpr auto value = glz::object(
        "database_path", &T::database_path,
        "wal_checkpoint_interval", &T::wal_checkpoint_interval,
        "max_traffic_log_hours", &T::max_traffic_log_hours
    );
};

template <>
struct glz::meta<sec::ai_config>
{
    using T = sec::ai_config;
    static constexpr auto value = glz::object(
        "model_path", &T::model_path,
        "anomaly_threshold", &T::anomaly_threshold,
        "feature_window_size", &T::feature_window_size,
        "enable_inference", &T::enable_inference,
        "remote_endpoint", &T::remote_endpoint,
        "remote_api_key", &T::remote_api_key,
        "remote_model", &T::remote_model,
        "remote_protocol", &T::remote_protocol
    );
};

template <>
struct glz::meta<sec::trace_config>
{
    using T = sec::trace_config;
    static constexpr auto value = glz::object(
        "log_level", &T::log_level,
        "log_path", &T::log_path,
        "console_output", &T::console_output
    );
};

template <>
struct glz::meta<sec::tui_config>
{
    using T = sec::tui_config;
    static constexpr auto value = glz::object(
        "theme", &T::theme
    );
};

template <>
struct glz::meta<sec::config>
{
    using T = sec::config;
    static constexpr auto value = glz::object(
        "engine", &T::engine,
        "scanner", &T::scanner,
        "store", &T::store,
        "ai", &T::ai,
        "trace", &T::trace,
        "tui", &T::tui
    );
};
