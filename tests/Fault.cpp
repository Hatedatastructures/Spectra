/**
 * @file Fault.cpp
 * @brief 错误码模块测试
 */

#include <sec/fault/code.hpp>
#include <sec/fault/compatible.hpp>
#include <sec/fault/handling.hpp>

#include <boost/system/error_code.hpp>

#include <cstdlib>
#include <iostream>
#include <string_view>

using namespace sec::fault;

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

static auto test_code_describe() -> int
{
    CHECK(describe(code::success) == "success");
    CHECK(describe(code::generic_error) == "generic_error");
    CHECK(describe(code::connection_refused) == "connection_refused");
    CHECK(describe(code::pcap_open_failed) == "pcap_open_failed");
    CHECK(describe(code::protocol_error) == "protocol_error");
    CHECK(describe(code::arp_spoofing) == "arp_spoofing");
    CHECK(describe(code::scan_failed) == "scan_failed");
    CHECK(describe(code::db_error) == "db_error");
    CHECK(describe(code::ai_error) == "ai_error");
    CHECK(describe(code::sandbox_error) == "sandbox_error");
    return 0;
}

static auto test_code_succeeded_failed() -> int
{
    CHECK(succeeded(code::success));
    CHECK(!failed(code::success));
    CHECK(!succeeded(code::generic_error));
    CHECK(failed(code::generic_error));
    CHECK(!succeeded(code::timeout));
    CHECK(failed(code::timeout));
    return 0;
}

static auto test_std_error_code_interop() -> int
{
    auto ec = make_error_code(code::connection_refused);
    CHECK(ec);
    CHECK(ec.value() == static_cast<int>(code::connection_refused));
    CHECK(std::string_view(ec.category().name()) == "sec::fault");
    CHECK(ec.message() == "connection_refused");

    auto ec_ok = make_error_code(code::success);
    CHECK(!ec_ok);
    CHECK(ec_ok.value() == 0);
    return 0;
}

static auto test_boost_error_code_interop() -> int
{
    auto ec = boost::system::make_error_code(code::dns_failed);
    CHECK(ec);
    CHECK(ec.value() == static_cast<int>(code::dns_failed));
    CHECK(std::string_view(ec.category().name()) == "sec::fault");
    return 0;
}

static auto test_cached_message() -> int
{
    CHECK(cached_message(code::success) == "success");
    CHECK(cached_message(code::host_noreply) == "host_noreply");
    CHECK(cached_message(code::malware_detected) == "malware_detected");
    CHECK(cached_message(code::hash_lookup_failed) == "hash_lookup_failed");
    return 0;
}

static auto test_handling_code() -> int
{
    CHECK(succeeded(code::success));
    CHECK(!succeeded(code::io_error));
    CHECK(!failed(code::success));
    CHECK(failed(code::io_error));
    return 0;
}

static auto test_handling_std_error_code() -> int
{
    auto ec_ok = make_error_code(code::success);
    auto ec_err = make_error_code(code::timeout);
    CHECK(succeeded(ec_ok));
    CHECK(!succeeded(ec_err));
    CHECK(!failed(ec_ok));
    CHECK(failed(ec_err));
    return 0;
}

static auto test_handling_boost_error_code() -> int
{
    auto ec_ok = boost::system::make_error_code(code::success);
    auto ec_err = boost::system::make_error_code(code::eof);
    CHECK(succeeded(ec_ok));
    CHECK(!succeeded(ec_err));
    CHECK(!failed(ec_ok));
    CHECK(failed(ec_err));
    return 0;
}

static auto test_to_code_from_boost() -> int
{
    CHECK(to_code(boost::system::error_code{}) == code::success);

    CHECK(to_code(boost::asio::error::eof) == code::eof);
    CHECK(to_code(boost::asio::error::operation_aborted) == code::canceled);
    CHECK(to_code(boost::asio::error::timed_out) == code::timeout);
    CHECK(to_code(boost::asio::error::connection_refused) == code::connection_refused);
    CHECK(to_code(boost::asio::error::connection_reset) == code::connection_reset);
    CHECK(to_code(boost::asio::error::connection_aborted) == code::connection_aborted);
    CHECK(to_code(boost::asio::error::host_unreachable) == code::host_noreply);
    CHECK(to_code(boost::asio::error::network_unreachable) == code::net_noreply);
    CHECK(to_code(boost::asio::error::no_buffer_space) == code::resource_unavailable);

    auto sec_ec = boost::system::make_error_code(code::db_open_failed);
    CHECK(to_code(sec_ec) == code::db_open_failed);
    return 0;
}

static auto test_to_code_from_std() -> int
{
    CHECK(to_code(std::error_code{}) == code::success);

    auto sec_ec = make_error_code(code::arp_failed);
    CHECK(to_code(sec_ec) == code::arp_failed);

    CHECK(to_code(std::make_error_code(std::errc::connection_refused)) == code::connection_refused);
    CHECK(to_code(std::make_error_code(std::errc::connection_reset)) == code::connection_reset);
    CHECK(to_code(std::make_error_code(std::errc::connection_aborted)) == code::connection_aborted);
    CHECK(to_code(std::make_error_code(std::errc::timed_out)) == code::timeout);
    CHECK(to_code(std::make_error_code(std::errc::host_unreachable)) == code::host_noreply);
    CHECK(to_code(std::make_error_code(std::errc::network_unreachable)) == code::net_noreply);
    CHECK(to_code(std::make_error_code(std::errc::operation_canceled)) == code::canceled);
    return 0;
}

auto main() -> int
{
    int failures = 0;

    if (auto r = test_code_describe(); r) { ++failures; }
    if (auto r = test_code_succeeded_failed(); r) { ++failures; }
    if (auto r = test_std_error_code_interop(); r) { ++failures; }
    if (auto r = test_boost_error_code_interop(); r) { ++failures; }
    if (auto r = test_cached_message(); r) { ++failures; }
    if (auto r = test_handling_code(); r) { ++failures; }
    if (auto r = test_handling_std_error_code(); r) { ++failures; }
    if (auto r = test_handling_boost_error_code(); r) { ++failures; }
    if (auto r = test_to_code_from_boost(); r) { ++failures; }
    if (auto r = test_to_code_from_std(); r) { ++failures; }

    if (failures == 0)
    {
        std::cout << "Fault: ALL PASSED\n";
    }
    else
    {
        std::cerr << "Fault: " << failures << " test(s) FAILED\n";
    }
    return failures;
}
