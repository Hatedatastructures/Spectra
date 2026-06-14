/**
 * @file types.hpp
 * @brief 沙箱引擎基础数据类型
 * @details 定义分析目标、行为事件、分析结果等核心数据结构，
 * 供 VM 后端、监控器、分析编排器和报告生成器共用。
 */
#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace sec::sandbox
{
    /**
     * @brief 行为事件类型
     */
    enum class event_kind : std::uint8_t
    {
        /** @brief 进程操作（创建/退出/注入） */
        process,
        /** @brief 文件操作（创建/写入/删除） */
        file,
        /** @brief 注册表操作 */
        registry,
        /** @brief 网络连接 */
        network,
        /** @brief DNS 解析 */
        dns
    };

    /**
     * @brief 单条行为事件
     */
    struct behavior_event
    {
        /** @brief 事件类型 */
        event_kind kind{event_kind::process};
        /** @brief 相对分析启动的时间戳 */
        std::chrono::steady_clock::time_point timestamp{};
        /** @brief 操作名（"create"/"write"/"connect"/"resolve" 等） */
        std::string operation;
        /** @brief 操作目标（文件路径/IP/域名/进程名） */
        std::string target;
        /** @brief 额外信息（命令行参数/端口/注册表值等） */
        std::string detail;
    };

    /**
     * @brief 分析目标（待分析的文件）
     */
    struct analysis_target
    {
        /** @brief 本地文件路径 */
        std::string local_path;
        /** @brief SHA256 哈希（可选，未计算时为空） */
        std::string sha256;
        /** @brief 文件名（Guest 内的执行名） */
        std::string filename;
        /** @brief 目标 Guest 内的执行参数（可选） */
        std::string arguments;
    };

    /**
     * @brief 分析状态
     */
    enum class analysis_status : std::uint8_t
    {
        /** @brief 排队中 */
        pending,
        /** @brief 正在分析 */
        running,
        /** @brief 分析完成 */
        completed,
        /** @brief 分析失败 */
        failed
    };

    /**
     * @brief 分析结果
     */
    struct analysis_result
    {
        /** @brief 数据库行 ID（0 表示未入库） */
        std::int64_t id{0};
        /** @brief 分析状态 */
        analysis_status status{analysis_status::pending};
        /** @brief 威胁评分 [0-100]，0=无威胁，100=确定恶意 */
        std::uint8_t score{0};
        /** @brief 摘要描述 */
        std::string summary;
        /** @brief JSON 报告文件路径 */
        std::string report_path;
        /** @brief 收集到的行为事件列表 */
        std::vector<behavior_event> events;
        /** @brief 提交时间戳（Unix epoch 秒） */
        std::int64_t submitted_at{0};
        /** @brief 完成时间戳（Unix epoch 秒，0=未完成） */
        std::int64_t completed_at{0};
    };

    /**
     * @brief 沙箱配置
     */
    struct sandbox_config
    {
        /** @brief VirtualBox VM 名称 */
        std::string vm_name{"Win10-Analyze"};
        /** @brief 快照名称（分析前恢复到此快照） */
        std::string snapshot_name{"clean"};
        /** @brief 分析超时（秒），超时后强制关机 */
        std::uint32_t timeout_seconds{120};
        /** @brief Guest 内执行目录 */
        std::string guest_workdir{"C:\\Users\\Public"};
        /** @brief VBoxManage 路径（空=自动搜索 PATH） */
        std::string vboxmanage_path;
    };

} // namespace sec::sandbox
