/**
 * @file sec.hpp
 * @brief Spectra 主聚合头文件
 * @details 聚合引入 Spectra 所有基础设施模块，提供
 * 统一的单文件包含入口。包含错误码（fault）、
 * 内存管理、全局配置和传输层等核心子模块。
 */
#pragma once

#include <sec/fault.hpp>
#include <sec/memory.hpp>
#include <sec/config.hpp>
#include <sec/transport.hpp>
#include <sec/decoder.hpp>
#include <sec/mitm.hpp>
#include <sec/detector.hpp>
