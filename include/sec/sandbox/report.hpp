/**
 * @file report.hpp
 * @brief JSON 报告生成
 */
#pragma once

#include <sec/sandbox/types.hpp>

#include <string>

namespace sec::sandbox::report
{
    /**
     * @brief 生成 JSON 格式分析报告并写入文件
     * @param target 分析目标
     * @param result 分析结果
     * @param cfg 沙箱配置
     * @return 报告文件路径
     */
    [[nodiscard]] auto generate(const analysis_target &target,
                                 const analysis_result &result,
                                 const sandbox_config &cfg) -> std::string;

} // namespace sec::sandbox::report
