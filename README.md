<div align="center">

# Spectra


![C++23](https://img.shields.io/badge/C%2B%2B-23-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-informational)
![Status](https://img.shields.io/badge/status-active-success)
![License](https://img.shields.io/badge/license-MIT-green)

**看见你网络里的每一台设备，每一字节流量，每一次可疑握手。**

</div>

---

## 这是什么

Spectra 是一个跑在你局域网网关或镜像端口上的安全监听站。它持续抓包、解码、
检测，把"看不见的网络"变成"看得见的事件流"——并通过 TUI 或 AI 对话告诉你
刚刚发生了什么。

底层用 C++23 协程 + PMR，万级并发扫描/抓包零阻塞；不依赖 Qt，单二进制可跑。

> ⚠️ **仅用于授权网络**。在未授权环境下运行抓包/扫描模块可能违反当地法律。

---

## 核心能力

### 谁在我的网络里？

主动询问局域网每一台设备，连不响应 ping 的"沉默"主机也无处遁形。

| 手段 | 看见什么 |
|------|----------|
| ARP 主动扫描 | 所有 IPv4 设备（绕过 ping 屏蔽） |
| mDNS | Bonjour/Avahi 服务（打印机、AirPlay、HomeKit） |
| SSDP | UPnP 设备（路由器、智能电视、NAS） |
| TCP 端口扫描 | 开放端口（高并发 connect，速率可配置） |
| 设备指纹 | MAC OUI 厂商识别 + 端口服务推断 |

### 它们在说什么？

7 个协议解码器逐字节解析，提取关键字段而非简单正则匹配。

| 协议 | 提取字段 |
|------|----------|
| HTTP | method / path / headers / body |
| DNS | A/AAAA/CNAME/TXT/MX/SRV + 压缩指针处理 |
| TLS | ClientHello SNI + **JA3 指纹** |
| SOCKS5 | CONNECT / UDP ASSOCIATE |
| SSH | 版本协商 / 服务端软件标识 |
| FTP / SMTP | 命令通道 + 响应码 |

### 哪些行为可疑？

规则引擎 + 统计异常 + 协议层特征三路并行，命中即生成告警落库。

**内置 3 条默认规则**（`detector/pipeline.cpp::load_default_rules`）：

| 规则 ID | 检测 | 严重等级 |
|---------|------|:--------:|
| `default_arp_spoofing` | 短时间内同一 IP 出现多个 MAC | high |
| `default_brute_force` | SSH (22/TCP) 频繁连接尝试 | high |
| `default_data_exfiltration` | 大流量出站传输 | high |

**统计异常检测**：EMA + z-score 流量基线，识别突发端口扫描。

**端口扫描识别**：TCP SYN 模式 + 时间窗口阈值。

**MITM 检测**：

| 检测器 | 当前覆盖 |
|--------|----------|
| ARP 欺骗 | 网关 MAC 突变 / IP-MAC 绑定冲突 |
| DNS 劫持 | 同域名回答/TTL 突变 + 伪造响应特征 |
| TLS 降级 | ClientHello 版本回退识别 |

> 弱套件检测 / JA3 恶意指纹 / FTP-SMTP 暴力破解已实现，告警自动去重（60s 窗口）。

### 怎么理解这些？

不是简单的 ChatGPT 套壳——Spectra 把网络事件喂给 AI，可以直接问：

- *"刚才 192.168.1.50 在做什么？"*
- *"最近的告警有没有关联性？"*
- *"解释一下这个 TLS ClientHello 的 JA3 指纹含义"*

AI 回复支持完整 Markdown：表格、代码块（语法高亮）、嵌套列表、引用块、emoji。
底层用图元簇宽度算法，正确处理中文 / ZWJ 序列 / VS16 / skin tone，不重叠不错位。

支持任意 OpenAI 或 Anthropic 协议兼容端点（OpenAI / Claude / 智谱 GLM / Moonshot / DeepSeek 等）。

---

## 架构

四层分工，每层只做一件事。协程贯穿全链路，热路径零阻塞。

| 层 | 模块 | 职责 |
|:----|:-----|:-----|
| **表现** | TUI · CLI · AI 助手 | cpp-terminal 渲染 · Markdown · SSE 流式对话 |
| **分析** | Scanner · Decoder · Detector · MITM | 设备发现 · 协议解码 · 威胁检测 · 劫持识别 |
| **引擎** | engine · transport | C++23 协程 · `capture_session` · raw socket · libpcap |
| **数据** | store | SQLite + WAL 持久化 |

**数据流向**：

```
用户输入命令
    ↓
Scanner 触发 → Transport 抓包 → Decoder 解析帧
    ↓
Detector 比对规则 / MITM 检查指纹 → 命中则告警
    ↓
告警落 store → TUI 实时刷新 / AI 助手按需查询
```

**SQLite 表结构**（`store/migration.cpp`）：`devices` · `scan_results` · `traffic_logs` · `alerts` · `schema_versions`

**关键设计**：

- **C++23 协程纯度** — 热路径禁用 `std::mutex` / 阻塞 I/O，全 `co_await`
- **PMR 内存模型** — `sec::memory::string` / `sec::memory::vector` 零堆分配
- **错误双轨** — 热路径用 `fault::code` 错误码（零开销），启动期用异常

---

## 15 分钟上手

```bash
# 1. 克隆
git clone https://github.com/Hatedatastructures/Spectra.git
cd Spectra

# 2. 构建（白天 -j 16；22:00-08:00 强制 -j 1 避免扰民）
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release -j 16

# 3. 配置（复制模板，填入 AI API key；不需要 AI 可留空）
cp spectra.json.example spectra.json
# 编辑 spectra.json，把 remote_api_key 换成你的实际 key

# 4. 运行（管理员权限，需要 Npcap 抓包）
./build/src/Spectra.exe
```

**TUI 命令速查**（chat 模式输入）：

| 命令 | 作用 |
|------|------|
| `arp <subnet>` | ARP 扫描子网（如 `arp 192.168.1.0/24`） |
| `mdns` / `ssdp` | mDNS / SSDP 服务发现 |
| `port <ip> [range]` | TCP 端口扫描 |
| `devices` / `device <ip>` | 列出 / 查看设备详情 |
| `alerts` / `ack <id>` | 查看告警 / 确认告警 |
| `scans` / `traffic` | 扫描历史 / 最近流量 |
| `sandbox <filepath>` | 提交文件到沙箱分析 |
| `analyses` | 查看沙箱分析历史 |
| `ai [on/off/remote]` | AI 模式切换 |
| `api <endpoint> <key> [model] [protocol]` | 在线配置远程 AI |

**快捷键**：`Ctrl+T` 切换 cmd/chat · `Ctrl+B` 折叠侧栏 · `Ctrl+F` 切换主题 · 鼠标滚轮 / `PageUp Down` 滚动聊天

---

## 检测能力矩阵

| 攻击类型 | 检测方式 | 状态 |
|----------|----------|:----:|
| ARP 欺骗 | 默认规则（IP-MAC 突变） | ✅ |
| DNS 劫持 | 回答突变 + 伪造响应特征 | ✅ |
| TLS 版本降级 | ClientHello 版本检查 | ✅ |
| TCP 端口扫描 | SYN 模式 + 时间窗口 | ✅ |
| SSH 暴力破解 | 默认规则（22/TCP 频次） | ✅ |
| 数据外泄 | 默认规则（大流量出站） | ✅ |
| 流量统计异常 | EMA + z-score | ✅ |
| 自定义规则 | 类 Snort 语法（IP/端口/协议/正则） | ✅ |
| TLS 弱套件 / 证书异常 | RC4/3DES/NULL/EXPORT 检测 | ✅ |
| FTP/SMTP 暴力破解 | 默认规则（21/25/TCP 频次） | ✅ |
| JA3 恶意指纹库 | 6 个已知 C2 工具指纹 | ✅ |
| 告警去重 | 60s 窗口 source_ip + category 去重 | ✅ |
| DNS 隧道检测 | 超长域名 + TXT 记录告警 | ✅ |
| 明文凭据检测 | FTP PASS / SMTP AUTH / HTTP URI 凭据参数 | ✅ |
| C2 信标检测 | 周期性连接变异系数分析（CV < 0.3） | ✅ |
| 沙箱动态分析 | 3 后端（VirtualBox/QEMU/Hyper-V）+ 3 监控（ETW/strace/VMI） | ✅ |

---

## 依赖

CMake `FetchContent` 自动拉取，首次构建约 8 分钟。

| 库 | 角色 |
|:---|:-----|
| **Boost.Asio** | 协程异步 I/O 基础设施 |
| **cpp-terminal** | TUI 渲染（带 CJK 宽字符补丁） |
| **cmark-gfm** | Markdown 解析（GFM 表格 / 任务列表） |
| **spdlog** | 异步日志 |
| **glaze** | JSON 配置序列化 |
| **SQLite3** | 设备 / 流量 / 告警持久化 |

Windows 系统库：`ws2_32` / `mswsock` / `crypt32` / `wininet`（AI HTTPS 走 WinINet，避免 OpenSSL 触发 Defender 误报）

---

## 路线

**已完成（P0-P1）**

- 协程网络引擎 + raw socket / libpcap 抓包
- 4 种设备发现（ARP / mDNS / SSDP / 端口扫描）+ 设备指纹
- 7 协议解码器（HTTP/DNS/TLS/SOCKS5/SSH/FTP/SMTP）+ JA3
- 规则引擎 + 5 条默认规则（ARP/SSH/FTP/SMTP 暴力 + 数据外泄） + 告警去重
- ARP / DNS / TLS MITM 检测
- SQLite 持久化 + migration
- TUI（Markdown 渲染 + 表格 + 代码块语法高亮 + 鼠标滚轮）
- AI 远程流式（OpenAI / Anthropic SSE，WinINet HTTPS）
- CLI 交互模式 + 13 个内置命令

**进行中（P2）**

- 沙箱引擎（VirtualBox + QEMU + Hyper-V 三后端 + ETW/strace/VMI 三监控）
- AI 异常检测模型接入（ONNX Runtime）
- 告警关联与去重（60s 窗口去重已实现，关联分析后续）
- JA3 恶意指纹库（6 个 C2 工具已入库，威胁情报定期更新）
- TLS 弱套件 / 证书异常 / 证书透明度检查

**规划中（P3）**

- Qt Quick GUI（目前以 TUI 为主）
- 分布式部署 + 中心聚合
- 自定义规则编辑器

---

## 项目结构

```
src/sec/
├── engine/      # 协程引擎 + capture_session
├── scanner/     # ARP / mDNS / SSDP / 端口 + 指纹
├── decoder/     # 7 协议 + pipeline + util.hpp（ip/mac/read_uN_be）
├── detector/    # 规则 + 异常 + 端口扫描 + 默认规则加载
├── mitm/        # ARP / DNS / TLS 劫持检测
├── transport/   # raw socket + pcap
├── store/       # SQLite + migration + query
├── tui/         # application + chat + markdown + components/{chat,input,side,status}
└── cli/         # 交互式 CLI
```

详细开发规范见 [CLAUDE.md](CLAUDE.md)。

---

## 合规与许可

- **仅用于授权测试** — 在你拥有合法权限的网络中运行
- **数据本地存储** — 流量、设备、告警全部写入本地 SQLite，不上传
- **不存储明文凭据** — 配置中的 API key 仅用于 AI 远程调用，不写日志

[MIT](LICENSE) · Copyright © 2026 Hatedatastructures
