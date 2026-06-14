/**
 * @file command.hpp
 * @brief 命令注册表
 * @details 管理所有可用命令，提供补全和分发。
 * 每个命令的 execute 回调返回 Markdown 格式字符串。
 */
#pragma once

#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace sec::tui
{
    class application;

    /**
     * @brief 命令描述
     */
    struct command_entry
    {
        std::string name;
        std::string usage;
        std::string description;
        std::function<std::string(const std::vector<std::string> &)> execute;
    };

    /**
     * @brief 命令注册表
     */
    class command_registry
    {
    public:
        explicit command_registry(application &app);

        /**
         * @brief 分发命令
         * @param input 用户输入（命令 + 参数）
         * @return Markdown 格式输出
         */
        [[nodiscard]] auto dispatch(const std::string &input) -> std::string;

        /**
         * @brief 命令补全
         * @param partial 部分输入
         * @return 匹配的候选列表
         */
        [[nodiscard]] auto complete(std::string_view partial) const -> std::vector<std::string>;

        /**
         * @brief 获取所有命令
         */
        [[nodiscard]] auto commands() const noexcept -> const std::vector<command_entry> &;

    private:
        void register_builtin_commands();

        void register_help();
        void register_arp();
        void register_mdns();
        void register_ssdp();
        void register_port();
        void register_devices();
        void register_device();
        void register_alerts();
        void register_ack();
        void register_scans();
        void register_traffic();
        void register_ai();
        void register_api();
        void register_sandbox();
        void register_analyses();

        application &app_;
        std::vector<command_entry> entries_;
    };

} // namespace sec::tui
