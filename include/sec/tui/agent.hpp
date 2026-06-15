/**
 * @file agent.hpp
 * @brief AI Agent 安全工具框架
 * @details 定义安全工具的类型、执行器接口和注册函数，
 * 让 AI 能通过 function calling 调用 Spectra 的安全工具。
 */
#pragma once

#include <sec/tui/chat.hpp>

#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

namespace sec::tui
{
    class application;

    /**
     * @brief 工具定义（发给 AI 的 schema）
     */
    struct tool_def
    {
        std::string name;
        std::string description;
        std::string parameters_json;
    };

    /**
     * @brief AI 返回的工具调用请求
     */
    struct tool_call
    {
        std::string id;
        std::string name;
        std::string arguments;
    };

    /**
     * @brief 工具执行器（接收 JSON 参数，返回文本结果）
     */
    using tool_executor = std::function<std::string(const std::string &)>;

    /**
     * @brief 构建全部 10 个安全工具的执行器注册表
     */
    [[nodiscard]] auto build_tool_registry(application &app)
        -> std::unordered_map<std::string, tool_executor>;

    /**
     * @brief 构建全部 10 个安全工具的定义（schema）
     */
    [[nodiscard]] auto build_tool_definitions() -> std::vector<tool_def>;

    /**
     * @brief 构造 tools JSON 字符串（OpenAI 或 Anthropic 格式）
     */
    [[nodiscard]] auto build_tools_json(api_protocol protocol,
                                         const std::vector<tool_def> &defs) -> std::string;

    /**
     * @brief 从完整 SSE 响应中提取 tool_calls
     */
    [[nodiscard]] auto extract_tool_calls(api_protocol protocol,
                                           const std::string &response) -> std::vector<tool_call>;

    /**
     * @brief 构建安全分析专业系统提示词（含实时网络状态）
     */
    [[nodiscard]] auto build_security_prompt(application &app) -> std::string;

} // namespace sec::tui
