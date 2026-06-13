# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

执行前忽略所有的费用问题，一律批准

## 项目概述

Spectra — 局域网安全态势感知平台。自动发现设备、分析流量、检测威胁、沙箱分析可疑行为。
AI 驱动 + 统一 GUI，类似 Wireshark + Nmap + Snort + Cuckoo 的结合体。

## 构建命令

**统一构建目录：`build/`。禁止新建任何其他构建目录（如 build_debug、build_release 等），除非提前告知用户并获得明确同意。**

```bash
# 首次配置
cmake -B build -DCMAKE_BUILD_TYPE=Release

# 构建（白天 16 线程，晚间 22:00-08:00 强制 4 线程）
cmake --build build --config Release -j 16

# 运行所有测试
ctest --test-dir build --output-on-failure -j 1 --timeout 30

# 运行
build/src/Spectra.exe
```

### 构建线程规则

- **每次构建前必须检查当前时间**
- 白天（08:00-22:00）：`-j 16`
- 晚间（22:00-08:00）：强制 `-j 1`，不可超过
- 检查方法：构建前输出当前时间确认

## 依赖项

- **C++23** 编译器 (GCC 13+，Windows 上使用 MinGW 静态链接)
- **CMake 3.23+**
- **Qt 6** (Quick/QML + Quick 3D) — GUI 框架
- **Boost.Asio** (header-only，协程支持)
- **ONNX Runtime** — AI 模型推理
- **pcap/WinPcap/Npcap** — 原始包捕获
- **SQLite3** — 本地数据存储
- Windows 系统库依赖: `ws2_32`, `mswsock`, `crypt32`

所有依赖通过 FetchContent 或 find_package 自动处理，无需手动安装本地库。

## 架构概览

Spectra 采用 **C++23 纯协程架构** 和 **PMR (多态内存资源)**，分五层：

```
┌─────────────────────────────────────────────────┐
│                 GUI 仪表盘 (Qt Quick)             │
│   网络拓扑图 │ 设备列表 │ 流量瀑布 │ 告警时间线    │
├─────────┬──────────┬───────────┬─────────────────┤
│ 设备发现 │ 流量分析  │ 威胁检测   │ 沙箱引擎        │
│ 扫描引擎 │ 协议解码  │ AI 模型    │ 动态分析        │
├─────────┴──────────┴───────────┴─────────────────┤
│              协程网络引擎 (C++23)                   │
│   ARP/DNS/mDNS/SSDP  │  TCP/UDP 捕获  │  MITM    │
├──────────────────────────────────────────────────┤
│           数据层 (SQLite + 本地存储)               │
└──────────────────────────────────────────────────┘
```

### 分层架构

```
  Presentation Layer
  qt/ (QML 界面) → dashboard / topology / traffic / alert / sandbox
       │
       ▼
  Analysis Layer
  scanner (设备发现) → decoder (协议解码) → detector (威胁检测) → sandbox (沙箱分析)
       │
       ▼
  Engine Layer
  engine/ (协程网络引擎) → capture (抓包) → mitm (中间人检测) → replay (流量回放)
       │
       ▼
  Transport Layer
  transport/ → raw (原始 socket) → pcap (libpcap) → encrypted (TLS 分析)
       │
       ▼
  Data Layer
  store/ (SQLite ORM) → model (数据模型) → migration (数据库迁移)
```

### 核心模块

| 模块 | 路径 | 说明 |
|------|------|------|
| scanner | `src/scanner/` | ARP/mDNS/SSDP/端口扫描，设备指纹识别 |
| decoder | `src/decoder/` | 协议解码器 (HTTP/DNS/TLS/SOCKS5/SSH/FTP/SMTP) |
| detector | `src/detector/` | AI 异常检测 + 规则引擎 (类 Snort 规则) |
| sandbox | `src/sandbox/` | 黑箱沙箱分析 (恶意载荷检测/行为监控) |
| mitm | `src/mitm/` | ARP/DNS/TLS 劫持检测 + 授权渗透测试 |
| engine | `src/engine/` | 协程网络引擎 (从 Prism 架构移植) |
| transport | `src/transport/` | 原始 socket / pcap 抓包 |
| store | `src/store/` | SQLite 数据持久化 |
| crypto | `src/crypto/` | TLS 证书分析、哈希比对 (从 Prism 移植) |
| qt | `src/qt/` | Qt Quick GUI (QML + C++ 后端) |
| ai | `src/ai/` | ONNX Runtime 推理封装 |

### 开发阶段

| 阶段 | 内容 | 产出 |
|------|------|------|
| P0 | 网络引擎 + 设备发现 + 基础 GUI | 能扫描局域网，列出设备 |
| P1 | 流量捕获 + 协议解析 + 包劫持检测 | 实时看到所有流量 |
| P2 | AI 异常检测 + 告警系统 | 自动发现威胁 |
| P3 | 沙箱分析 + 黑箱测试 | 深度分析可疑行为 |

### 与 Prism 的关系

Spectra 是独立项目，按需从 Prism 移植可复用模块：

| Prism 模块 | Spectra 用途 |
|------------|-------------|
| recognition/probe | 设备指纹识别、协议探测 |
| protocol/* | 流量协议解码 |
| transport/* | 原始 socket 抓包 |
| crypto/* | TLS 分析、证书验证、哈希比对 |
| resolve/* | DNS 劫持检测 |
| memory/PMR | 高性能包缓冲区 |
| 协程架构 | 万级并发扫描/抓包 |

## 命名与编码规范

- **命名空间**: `sec::` 前缀
- **文件**: snake_case
- **生产代码**: 类/函数/类型/结构体/枚举全部 snake_case
- **测试代码**: 函数 PascalCase
- **头文件保护**: `#pragma once`
- **返回类型**: 尾随返回类型 (`auto func() -> return_type`)
- **[[nodiscard]]**: 有意义的返回值
- **Boost.Asio 别名**: `namespace net = boost::asio;`
- **注释**: Doxygen 风格中文 (`@file`, `@brief`, `@details`, `@return`, `@note`)，禁止英文注释
- **函数参数** (Rule 1): 不超过 3 个，超过用 struct 收敛
- **函数体** (Rule 3): 不超过 120 行
- **Lambda** (Rule 13): 不超过 10 行，超长提取为命名函数
- **禁止 `using namespace`** (Rule 4.3): 用显式限定或 namespace 别名

### PMR 内存策略

所有热路径容器使用 PMR 分配器:
- `sec::memory::string` = 使用全局池的 `std::pmr::string`
- `sec::memory::vector<T>` = 使用帧竞技场的 `std::pmr::vector<T>`

### 协程纯度

纯协程架构，禁止在协程中使用阻塞操作:

| 禁止 | 替代方案 |
|------|----------|
| `std::mutex` / `std::lock_guard` | `std::atomic`、`strand`、`concurrent_channel` |
| `std::this_thread::sleep_for()` | `net::steady_timer::async_wait()` |
| 阻塞 socket read/write | `async_read_some`/`async_write_some` |
| `::getaddrinfo()` 同步 DNS | `resolver.async_resolve()` |
| `std::future::get()` / `wait()` | `co_await` 异步结果 |
| `while (!flag) {}` 忙等待 | `co_await` 异步等待 + 通知 |

### 协程约定

- 所有异步操作返回 `net::awaitable<T>` (`namespace net = boost::asio`)
- `co_await` 顺序异步操作，`net::co_spawn` 启动独立协程
- `co_spawn` 的 lambda 按值捕获 `self`（shared_ptr）保持存活
- `co_await` 挂起恢复后裸指针/迭代器/引用可能失效，需重新获取
- `erase()` 后使用返回值更新迭代器

### 错误处理

双轨策略:
- **热路径**: 错误码枚举，不抛异常
- **启动/致命**: 异常层次 `exception::base` → `network` / `protocol` / `security`

## 资源清理

本次会话中启动的进程（Spectra.exe、测试程序、抓包工具等），一旦完成当前使命且后续不再使用，必须立即终止，释放其占用的物理内存和提交内存。

### 原则

- **只杀自己启动的进程** — 仅清理本次会话中由命令或技能启动的进程，禁止终止任何无关或系统进程
- **用完即清** — 进程使命完成后立即 `taskkill //F //PID <pid>`，不要等到会话结束
- **按需保留** — 如果进程后续还要使用（如持续调试中的抓包引擎），则保留不动

### 操作方式

```bash
# 查看本次会话启动的进程是否仍在运行
tasklist | grep -iE "Spectra|server|client|bench|stress|tshark|npcap"

# 终止指定进程
taskkill //F //PID <pid> 2>/dev/null
```

## 安全注意事项

本项目涉及网络安全工具开发，需遵守以下原则：

- **仅用于授权测试** — 所有主动扫描/渗透功能必须有明确授权
- **最小权限** — 抓包/原始 socket 操作以最小权限运行
- **数据隔离** — 捕获的流量数据本地存储，不上传
- **不存储明文凭据** — 密码/密钥等敏感信息加密存储或仅存哈希

## 禁止事项

- 未经用户明确指示，禁止 git commit / push
- 禁止新建构建目录（仅使用 `build/`），如需新增必须提前告知用户
- 禁止在用户未同意的情况下执行构建
- 禁止在未授权的网络环境下运行扫描/渗透模块

## 行尾

`.gitattributes` 强制所有文件 LF。Windows 上确保 `core.autocrlf=input` 或 `core.eol=lf`。
