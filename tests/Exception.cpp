/**
 * @file Exception.cpp
 * @brief 异常模块测试
 */

#include <sec/exception/deviant.hpp>
#include <sec/exception/network.hpp>
#include <sec/exception/protocol.hpp>
#include <sec/exception/security.hpp>

#include <iostream>
#include <string>
#include <string_view>

using namespace sec::exception;

#define CHECK(cond)                                        \
    do                                                     \
    {                                                      \
        if (!(cond))                                       \
        {                                                  \
            std::cerr << "FAIL: " #cond "\n"               \
                      << "  at " __FILE__ ":" << __LINE__  \
                      << "\n";                             \
            return 1;                                      \
        }                                                  \
    } while (0)

static auto test_deviant_error_code_ctor() -> int
{
    auto ec = sec::fault::make_error_code(sec::fault::code::generic_error);
    network ex{sec::fault::code::generic_error, "test description"};
    CHECK(ex.error_code().value() == ec.value());
    CHECK(ex.what() != nullptr);
    CHECK(std::string_view(ex.what()).find("test description") != std::string_view::npos);
    return 0;
}

static auto test_deviant_string_ctor() -> int
{
    network ex{std::string{"custom message"}};
    CHECK(ex.error_code().value() == static_cast<int>(sec::fault::code::generic_error));
    CHECK(std::string_view(ex.what()).find("custom message") != std::string_view::npos);
    CHECK(!ex.filename().empty());
    CHECK(ex.location().line() > 0);
    return 0;
}

static auto test_deviant_format_ctor() -> int
{
    network ex{"value {} and {}", 42, "hello"};
    CHECK(std::string_view(ex.what()).find("42") != std::string_view::npos);
    CHECK(std::string_view(ex.what()).find("hello") != std::string_view::npos);
    return 0;
}

static auto test_deviant_dump() -> int
{
    network ex{sec::fault::code::timeout, "dump test"};
    auto dump = ex.dump();
    CHECK(!dump.empty());
    CHECK(dump.find("Exception.cpp") != std::string::npos);
    CHECK(dump.find("generic_error") != std::string::npos || dump.find("timeout") != std::string::npos);
    return 0;
}

static auto test_deviant_no_description() -> int
{
    network ex{sec::fault::code::connection_refused};
    CHECK(ex.error_code().value() == static_cast<int>(sec::fault::code::connection_refused));
    CHECK(std::string_view(ex.what()).find("connection_refused") != std::string_view::npos);
    return 0;
}

static auto test_network_basic() -> int
{
    network ex{sec::fault::code::connection_refused};
    CHECK(ex.error_code().value() == static_cast<int>(sec::fault::code::connection_refused));
    CHECK(std::string_view(ex.error_code().category().name()) == "sec::fault");
    return 0;
}

static auto test_network_with_desc() -> int
{
    network ex{sec::fault::code::dns_failed, "lookup failed for example.com"};
    CHECK(std::string_view(ex.what()).find("lookup failed for example.com") != std::string_view::npos);
    return 0;
}

static auto test_network_string_ctor() -> int
{
    network ex{std::string{"socket error"}};
    CHECK(std::string_view(ex.what()).find("socket error") != std::string_view::npos);
    return 0;
}

static auto test_network_format_ctor() -> int
{
    network ex{"port {} unreachable", 8080};
    auto msg = std::string_view(ex.what());
    CHECK(msg.find("8080") != std::string_view::npos);
    return 0;
}

static auto test_network_catch_as_deviant() -> int
{
    try
    {
        throw network{sec::fault::code::host_noreply, "no response"};
    }
    catch (const deviant &e)
    {
        CHECK(e.error_code().value() == static_cast<int>(sec::fault::code::host_noreply));
        return 0;
    }
    CHECK(false);
    return 1;
}

static auto test_network_catch_as_runtime() -> int
{
    try
    {
        throw network{sec::fault::code::unreachable};
    }
    catch (const std::runtime_error &e)
    {
        CHECK(e.what() != nullptr);
        return 0;
    }
    CHECK(false);
    return 1;
}

static auto test_protocol_basic() -> int
{
    protocol ex{sec::fault::code::http_parse_error};
    CHECK(ex.error_code().value() == static_cast<int>(sec::fault::code::http_parse_error));
    return 0;
}

static auto test_protocol_with_desc() -> int
{
    protocol ex{sec::fault::code::bad_message, "invalid header"};
    CHECK(std::string_view(ex.what()).find("invalid header") != std::string_view::npos);
    return 0;
}

static auto test_protocol_format_ctor() -> int
{
    protocol ex{"malformed {} at offset {}", "packet", 128};
    auto msg = std::string_view(ex.what());
    CHECK(msg.find("packet") != std::string_view::npos);
    CHECK(msg.find("128") != std::string_view::npos);
    return 0;
}

static auto test_protocol_catch_as_deviant() -> int
{
    try
    {
        throw protocol{sec::fault::code::tls_hsfail, "handshake failed"};
    }
    catch (const deviant &e)
    {
        CHECK(e.error_code().value() == static_cast<int>(sec::fault::code::tls_hsfail));
        return 0;
    }
    CHECK(false);
    return 1;
}

static auto test_security_basic() -> int
{
    security ex{sec::fault::code::arp_spoofing};
    CHECK(ex.error_code().value() == static_cast<int>(sec::fault::code::arp_spoofing));
    return 0;
}

static auto test_security_with_desc() -> int
{
    security ex{sec::fault::code::malware_detected, "trojan.sigmatch"};
    CHECK(std::string_view(ex.what()).find("trojan.sigmatch") != std::string_view::npos);
    return 0;
}

static auto test_security_format_ctor() -> int
{
    security ex{"detected {} from {}", "port scan", "192.168.1.100"};
    auto msg = std::string_view(ex.what());
    CHECK(msg.find("port scan") != std::string_view::npos);
    CHECK(msg.find("192.168.1.100") != std::string_view::npos);
    return 0;
}

static auto test_security_catch_as_deviant() -> int
{
    try
    {
        throw security{sec::fault::code::brute_force, "ssh login attempts"};
    }
    catch (const deviant &e)
    {
        CHECK(e.error_code().value() == static_cast<int>(sec::fault::code::brute_force));
        return 0;
    }
    CHECK(false);
    return 1;
}

static auto test_source_location_capture() -> int
{
    network ex{sec::fault::code::connection_reset, "loc test"};
    CHECK(ex.location().line() > 0);
    CHECK(ex.location().file_name() != nullptr);
    CHECK(std::string_view(ex.location().file_name()).find("Exception.cpp") != std::string_view::npos);
    return 0;
}

static auto test_exception_hierarchy() -> int
{
    bool caught_deviant = false;
    bool caught_runtime = false;
    bool caught_exception = false;

    try
    {
        throw security{sec::fault::code::data_exfiltration};
    }
    catch (const deviant &)
    {
        caught_deviant = true;
    }

    try
    {
        throw protocol{sec::fault::code::dns_parse_error};
    }
    catch (const std::runtime_error &)
    {
        caught_runtime = true;
    }

    try
    {
        throw network{sec::fault::code::forbidden};
    }
    catch (const std::exception &)
    {
        caught_exception = true;
    }

    CHECK(caught_deviant);
    CHECK(caught_runtime);
    CHECK(caught_exception);
    return 0;
}

auto main() -> int
{
    std::cout << "Exception test starting...\n" << std::flush;

    int failures = 0;

    std::cout << "  test_deviant_error_code_ctor..." << std::flush;
    if (auto r = test_deviant_error_code_ctor(); r) { ++failures; std::cout << "FAIL\n"; } else { std::cout << "ok\n"; }

    std::cout << "  test_deviant_string_ctor..." << std::flush;
    if (auto r = test_deviant_string_ctor(); r) { ++failures; std::cout << "FAIL\n"; } else { std::cout << "ok\n"; }

    std::cout << "  test_deviant_format_ctor..." << std::flush;
    if (auto r = test_deviant_format_ctor(); r) { ++failures; std::cout << "FAIL\n"; } else { std::cout << "ok\n"; }

    std::cout << "  test_deviant_dump..." << std::flush;
    if (auto r = test_deviant_dump(); r) { ++failures; std::cout << "FAIL\n"; } else { std::cout << "ok\n"; }

    std::cout << "  test_deviant_no_description..." << std::flush;
    if (auto r = test_deviant_no_description(); r) { ++failures; std::cout << "FAIL\n"; } else { std::cout << "ok\n"; }

    std::cout << "  test_network_basic..." << std::flush;
    if (auto r = test_network_basic(); r) { ++failures; std::cout << "FAIL\n"; } else { std::cout << "ok\n"; }

    std::cout << "  test_network_with_desc..." << std::flush;
    if (auto r = test_network_with_desc(); r) { ++failures; std::cout << "FAIL\n"; } else { std::cout << "ok\n"; }

    std::cout << "  test_network_string_ctor..." << std::flush;
    if (auto r = test_network_string_ctor(); r) { ++failures; std::cout << "FAIL\n"; } else { std::cout << "ok\n"; }

    std::cout << "  test_network_format_ctor..." << std::flush;
    if (auto r = test_network_format_ctor(); r) { ++failures; std::cout << "FAIL\n"; } else { std::cout << "ok\n"; }

    std::cout << "  test_network_catch_as_deviant..." << std::flush;
    if (auto r = test_network_catch_as_deviant(); r) { ++failures; std::cout << "FAIL\n"; } else { std::cout << "ok\n"; }

    std::cout << "  test_network_catch_as_runtime..." << std::flush;
    if (auto r = test_network_catch_as_runtime(); r) { ++failures; std::cout << "FAIL\n"; } else { std::cout << "ok\n"; }

    std::cout << "  test_protocol_basic..." << std::flush;
    if (auto r = test_protocol_basic(); r) { ++failures; std::cout << "FAIL\n"; } else { std::cout << "ok\n"; }

    std::cout << "  test_protocol_with_desc..." << std::flush;
    if (auto r = test_protocol_with_desc(); r) { ++failures; std::cout << "FAIL\n"; } else { std::cout << "ok\n"; }

    std::cout << "  test_protocol_format_ctor..." << std::flush;
    if (auto r = test_protocol_format_ctor(); r) { ++failures; std::cout << "FAIL\n"; } else { std::cout << "ok\n"; }

    std::cout << "  test_protocol_catch_as_deviant..." << std::flush;
    if (auto r = test_protocol_catch_as_deviant(); r) { ++failures; std::cout << "FAIL\n"; } else { std::cout << "ok\n"; }

    std::cout << "  test_security_basic..." << std::flush;
    if (auto r = test_security_basic(); r) { ++failures; std::cout << "FAIL\n"; } else { std::cout << "ok\n"; }

    std::cout << "  test_security_with_desc..." << std::flush;
    if (auto r = test_security_with_desc(); r) { ++failures; std::cout << "FAIL\n"; } else { std::cout << "ok\n"; }

    std::cout << "  test_security_format_ctor..." << std::flush;
    if (auto r = test_security_format_ctor(); r) { ++failures; std::cout << "FAIL\n"; } else { std::cout << "ok\n"; }

    std::cout << "  test_security_catch_as_deviant..." << std::flush;
    if (auto r = test_security_catch_as_deviant(); r) { ++failures; std::cout << "FAIL\n"; } else { std::cout << "ok\n"; }

    std::cout << "  test_source_location_capture..." << std::flush;
    if (auto r = test_source_location_capture(); r) { ++failures; std::cout << "FAIL\n"; } else { std::cout << "ok\n"; }

    std::cout << "  test_exception_hierarchy..." << std::flush;
    if (auto r = test_exception_hierarchy(); r) { ++failures; std::cout << "FAIL\n"; } else { std::cout << "ok\n"; }

    if (failures == 0)
    {
        std::cout << "Exception: ALL PASSED\n";
    }
    else
    {
        std::cerr << "Exception: " << failures << " test(s) FAILED\n";
    }
    return failures;
}
