/**
 * @file application.hpp
 * @brief 命令行应用封装
 * @details 管理所有子系统生命周期，提供交互式命令行界面。
 * io_context 运行在后台线程，CLI 命令循环在主线程。
 */

#pragma once

#include <sec/config.hpp>
#include <sec/engine/context.hpp>
#include <sec/engine/capture.hpp>
#include <sec/scanner/arp.hpp>
#include <sec/scanner/mdns.hpp>
#include <sec/scanner/port.hpp>
#include <sec/scanner/ssdp.hpp>
#include <sec/decoder/pipeline.hpp>
#include <sec/detector/pipeline.hpp>
#include <sec/mitm/pipeline.hpp>
#include <sec/store/database.hpp>
#include <sec/store/migration.hpp>
#include <sec/store/query.hpp>
#include <sec/store/persist.hpp>

#include <atomic>
#include <memory>
#include <optional>
#include <string>
#include <thread>


namespace sec::cli
{

    /**
     * @brief 命令行应用
     * @details 串联引擎、扫描器、解码器、检测器和存储层，
     * 提供交互式命令行操作界面。
     */
    class application
    {
    public:
        explicit application(const sec::config &cfg);

        ~application() noexcept;

        [[nodiscard]] auto run(int argc, char *argv[]) -> int;

    private:
        void start_background_thread();
        void stop_background_thread();

        // 命令处理
        void command_loop();
        void print_help() const;
        void print_banner() const;
        void print_usage() const;

        // 调度子命令，返回退出码（0=成功 / 1=调度错误）
        [[nodiscard]] auto dispatch_command(const std::vector<std::string> &tokens) -> int;

        void cmd_scan_arp(std::string_view subnet);
        void cmd_scan_mdns();
        void cmd_scan_ssdp();
        void cmd_scan_port(const std::string &ip, const std::string &range);
        void cmd_devices();
        void cmd_device(const std::string &ip);
        void cmd_alerts();
        void cmd_alert_ack(std::int64_t id);
        void cmd_scans();
        void cmd_traffic();
        void cmd_pentest();

        void start_capture();
        void stop_capture();

        // 将 scanner::device 转为 store::device_record 并持久化
        void persist_devices(std::vector<scanner::device> &devices, std::string_view scan_type, std::string_view subnet);

        // 解析端口范围字符串，如 "1-1024" 或 "22,80,443"
        [[nodiscard]] static auto parse_port_range(const std::string &range) -> std::vector<std::uint16_t>;

        sec::config config_;
        engine::context context_;

        std::unique_ptr<store::database> db_;
        std::unique_ptr<store::device_query> device_q_;
        std::unique_ptr<store::scan_query> scan_q_;
        std::unique_ptr<store::traffic_query> traffic_q_;
        std::unique_ptr<store::alert_query> alert_q_;
        std::unique_ptr<store::scan_persister> persister_;

        decoder::pipeline decoder_;
        std::unique_ptr<detector::detection_pipeline> detection_;
        std::unique_ptr<mitm::mitm_pipeline> mitm_;
        std::unique_ptr<engine::capture_session> capture_;

        scanner::arp_scanner arp_;
        scanner::mdns_scanner mdns_;
        scanner::ssdp_scanner ssdp_;
        scanner::port_scanner port_;

        std::thread bg_thread_;
        std::atomic<bool> running_{false};
        std::atomic<bool> capture_active_{false};
        std::optional<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>> work_guard_;
    };


} // namespace sec::cli
