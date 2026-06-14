# 类型与格式化规则

## 24. struct vs class

**规则：按语义区分。** 纯数据聚合用 `struct`，有不变量/私有成员/行为用 `class`。

```cpp
// struct：纯数据，无不变量，无私有成员
struct packet_info
{
    std::uint32_t src_ip = 0;
    std::uint32_t dst_ip = 0;
    std::uint16_t src_port = 0;
    std::uint16_t dst_port = 0;
    protocol proto = protocol::tcp;
    bool valid = false;
};

// class：有不变量、私有成员、或非平凡行为
class capture_session final : public std::enable_shared_from_this<capture_session>
{
public:
    // ...
private:
    void *raw_handle_ = nullptr;
    // ...
};
```

**How to apply**: 如果去掉所有成员函数后只剩下数据且没有不变量要保护，用 `struct`。否则用 `class`。

## 25. enum class + 底层类型

**规则：所有枚举必须使用 `enum class` 并指定底层类型。**

```cpp
// 正确
enum class protocol : std::uint8_t
{ tcp, udp, icmp, arp };
enum class severity : std::uint8_t
{ info, low, medium, high, critical };

// 禁止：无作用域枚举
enum protocol { tcp, udp, icmp, arp };

// 禁止：未指定底层类型
enum class protocol
{ tcp, udp, icmp, arp };
```

**例外**：
- C 库兼容的枚举（如第三方库常量映射）

## 26. 智能指针

**规则：按场景灵活选择。** 遵循以下语义指引：

- `std::unique_ptr`：独占所有权，不可复制（如 `std::unique_ptr<store::database> db_`）
- `std::shared_ptr`：共享所有权，协程中按值捕获保持对象存活（如 `auto self = shared_from_this()`）
- 裸指针/引用：非拥有关系（如 `this`、外部管理的对象）

协程中 `co_spawn` 的 lambda 必须按值捕获 `shared_ptr`（`self` 模式）保持对象存活。

## 27. noexcept

**规则：析构函数和移动构造/移动赋值必须标注 `noexcept`。** PMR 容器的移动构造 noexcept 依赖上游分配器，按实际情况标注。

```cpp
// 正确：析构函数 noexcept（若默认则编译器自动生成）
~capture_session() noexcept;

// 正确：移动构造 noexcept
capture_session(capture_session &&other) noexcept;

// 注意：PMR 容器的移动构造依赖 allocator 是否 propagate_on_container_move_assignment
// 如果上游分配器不是 noexcept，不要强行标注
```

**不强制**：其他场景按需判断。

## 28. 特殊成员函数

**规则：按资源所有权和协程捕获需求决定 copy/move 策略。** PMR 容器需要特殊处理。

- PMR 容器（`sec::memory::vector` 等）的 copy 需要显式传递 memory resource
- 持有独占资源（raw socket、pcap handle、SQLite connection）的类应 delete copy，提供 move
- 纯数据 struct 通常 `= default` 即可
- 如果自定义了析构函数，检查是否需要同步自定义 copy/move

## 29. nullptr

**规则：禁止使用 `NULL` 或 `0` 表示空指针。必须使用 `nullptr`。**

```cpp
// 正确
void *raw_handle_ = nullptr;
auto db = std::unique_ptr<store::database>{};

// 禁止
void *raw_handle_ = NULL;   // 禁止
void *raw_handle_ = 0;      // 禁止
```

## 30. constexpr / consteval

**规则：积极使用 `constexpr`。** 编译期能计算的都应标注。

```cpp
// 正确：常量
constexpr std::uint32_t max_packet_size = 65535;
constexpr std::uint16_t dns_default_port = 53;

// 正确：辅助函数
[[nodiscard]] constexpr auto to_protocol_id(protocol p) noexcept
    -> std::uint8_t
{
    return static_cast<std::uint8_t>(p);
}

// 正确：枚举转换
[[nodiscard]] constexpr auto tcp_header_size(std::uint8_t flags) noexcept
    -> std::size_t
{
    return static_cast<std::size_t>((flags & 0xF0) >> 4) * 4;
}
```

## 31. 初始化风格

**规则：混合使用 `=` 和 `{}`，按上下文选择最清晰的方式。**

```cpp
// = 初始化：简单值、类内默认值
std::uint16_t port = 0;
bool capturing = false;
void *raw_handle_ = nullptr;

// {} 初始化：容器初始化、避免 narrowing conversion
sec::memory::vector<std::byte> buf{4096};
std::array<std::uint8_t, 4> header{0x45, 0x00, 0x00, 0x00};
```

## 32. static 成员变量

**规则：`.hpp` 中声明，`.cpp` 中定义。** 不使用 `inline static`。

```cpp
// arp_scanner.hpp
class arp_scanner final
{
    static constexpr std::uint32_t default_timeout_ms = 1000;
    // ...
};

// arp_scanner.cpp（如果需要取地址或 ODR 使用）
// constexpr 成员不需要额外定义，但非 constexpr static 成员需要：
// std::uint32_t arp_scanner::default_timeout_ms = 1000;
```

## 33. 模板实现风格

**规则：模板实现放在 `.tpp` 文件中分离。** `.hpp` 声明，`.tpp` 实现，`.hpp` 末尾 include `.tpp`。

```cpp
// query.hpp
#pragma once

template <typename Row>
class query
{
public:
    [[nodiscard]] auto find_all(std::error_code &ec) const
        -> std::vector<Row>;

private:
    database &db_;
};

#include <sec/store/query.tpp>  // 末尾 include 实现
```

```cpp
// query.tpp
#pragma once

template <typename Row>
auto query<Row>::find_all(std::error_code &ec) const
    -> std::vector<Row>
{
    // 实现...
}
```

**小模板**（< 20 行）可直接 inline 在 `.hpp` 中，不需要 `.tpp`。

## 34. std::move vs std::forward

**规则：严格区分 `std::move` 和 `std::forward`。**

- `std::move`：无条件右值转换，用于已知要转移所有权的场景
- `std::forward`：仅在完美转发模板参数时使用，保持值类别

```cpp
// 正确：std::move — 转移所有权
auto pkt = std::move(pending_.at(id));
co_await decode(std::move(payload));

// 正确：std::forward — 完美转发
template <typename T>
void subscribe(T &&callback)
{
    subscribers_.emplace_back(std::forward<T>(callback));
}

// 禁止：用 forward 代替 move
co_await decode(std::forward<sec::memory::vector<std::byte>>(payload));  // 禁止，用 std::move

// 禁止：用 move 做完美转发
template <typename T>
void subscribe(T &&callback)
{
    subscribers_.emplace_back(std::move(callback));  // 禁止，左值会被意外移动，用 std::forward<T>
}
```

## 35. 代码格式化

### 35.1 行宽

**规则：每行不超过 200 字，这个不是绝对的，具体看上下文来做决策来换行具备美观性。**

### 35.2 缩进

**规则：统一 4 空格缩进，禁止 Tab。**

### 35.3 花括号风格

**规则：Allman 风格。** 所有开括号 `{` 独占一行，包括函数/类/结构体/命名空间和控制结构（`if`/`for`/`while`/`switch`）。

```cpp
// 函数：开括号独占一行
auto scanner::run()
    -> net::awaitable<void>
{
    // ...
}


if (capturing)
{
    dispatch(pkt);
}

for (const auto &device : discovered_)
{
    co_await probe(device);
}
```

### 35.4 函数声明换行

**规则：返回类型独占一行。** 尾随返回类型换行后固定缩进 4 空格。

```cpp
// 非 void：返回类型独占一行 + 尾随返回换行缩进 4 空格
auto scanner::send_arp(std::uint32_t target_ip, mac_addr sender_mac)
    -> net::awaitable<result>
{
    // ...
}

// void：直接写 void，不换行
void scanner::start()
{
    // ...
}
```

### 35.5 函数参数不换行

**规则：参数不换行。**

```cpp
auto parse_arp(const std::byte *raw, std::size_t len, std::error_code &ec)
    -> std::optional<arp_packet>
{
    // ...
}
```

### 35.6 命名空间格式

**规则：命名空间关键字后换行，开括号独占一行。** 括号后空 1 行。**项目惯例：命名空间内部代码额外缩进 4 空格**（与 Spectra 现有代码一致，提升层次可读性）。

```cpp
namespace sec::scanner::detail
{

    auto arp_scanner::run()
        -> net::awaitable<void>
    {
        // ...
    }

} // namespace sec::scanner::detail
```

### 35.7 空行规则

| 位置 | 空行数 |
|------|--------|
| 函数/方法之间 | 2 行 |
| 逻辑段落之间（函数内） | 1 行 |
| 访问限定符前 | 1 行 |
| `#include` 块与代码之间 | 2 行 |
| 命名空间开括号后 | 1 行 |
| 命名空间闭括号前 | 1 行 |

### 35.8 switch/case 缩进

**规则：`case` 与 `switch` 同级，不额外缩进。** `case` 内代码缩进 4 空格。

```cpp
switch (proto)
{
case protocol::tcp:
    co_await handle_tcp(pkt);
    break;
case protocol::udp:
    co_await handle_udp(pkt);
    break;
default:
    break;
}
```

### 35.9 单行 if/else

**规则：单行 `if`/`else` 可以不加花括号。** 但多行体必须加。

```cpp
// OK：单行不加
if (!capturing) return;

// OK：多行必须加
if (auto it = sessions_.find(id); it != sessions_.end())
{
    co_await close(std::move(it->second));
    sessions_.erase(it);
}
```

### 35.10 const 位置

**规则：`const` 在类型左侧。** `const T&` 而非 `T const&`。

```cpp
// 正确
const auto &device = discovered_.at(id);
void process(const sec::memory::string &input);

// 禁止
auto &device = const auto(discovered_.at(id));  // 禁止
auto process(sec::memory::string const &input) -> void;  // 禁止
```

### 35.11 初始化列表尾随逗号

**规则：初始化列表、枚举最后一个元素后不加尾随逗号。**

```cpp
// 正确
std::array<std::uint8_t, 3> mac{0xAA, 0xBB, 0xCC};
enum class protocol : std::uint8_t
{ tcp, udp, icmp };

// 禁止
std::array<std::uint8_t, 3> mac{0xAA, 0xBB, 0xCC,};  // 禁止
enum class protocol : std::uint8_t
{ tcp, udp, icmp, };  // 禁止
```

### 35.12 函数间空行

**规则：函数和函数中间头文件空一行，源文件空两行**

**例外**：匿名 namespace 内连续小工具函数（< 10 行）允许仅 1 空行分隔（紧凑写法，提升局部可读性）。

```cpp
// 正确
void func1()
{
    // ...
}


void func2()
{
    // ...
}

// 例外：匿名 ns 内紧凑小工具群
namespace
{

auto parse_ipv4(std::string_view s) -> std::uint32_t { /* ... */ }

auto ipv4_to_string(std::uint32_t ip) -> std::string { /* ... */ }

auto mac_to_string(std::span<const std::byte, 6> mac) -> std::string { /* ... */ }

} // namespace

// 禁止
void func1() {}
void func2() {}
```
