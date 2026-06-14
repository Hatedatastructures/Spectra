/**
 * @file database.hpp
 * @brief SQLite 数据库连接管理器
 * @details RAII 封装 sqlite3 连接，提供语句准备、
 * 事务管理和错误码返回。热路径使用 error_code，
 * 启动失败使用异常。
 */

#pragma once

#include <sec/fault/code.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <variant>

struct sqlite3;
struct sqlite3_stmt;


namespace sec::store
{

    class statement;

    /**
     * @brief SQLite 数据库 RAII 连接管理
     */
    class database
    {
    public:
        explicit database(std::string_view path);
        ~database() noexcept;

        database(const database &) = delete;
        auto operator=(const database &) -> database & = delete;
        database(database &&) noexcept;
        auto operator=(database &&) noexcept -> database &;

        [[nodiscard]] auto is_open() const noexcept -> bool;

        void close() noexcept;

        [[nodiscard]] auto execute(std::string_view sql,
                                   std::error_code &ec) noexcept -> bool;

        [[nodiscard]] auto prepare(std::string_view sql,
                                   std::error_code &ec) noexcept -> statement;

        [[nodiscard]] auto begin_transaction(std::error_code &ec) noexcept -> bool;
        [[nodiscard]] auto commit(std::error_code &ec) noexcept -> bool;
        [[nodiscard]] auto rollback(std::error_code &ec) noexcept -> bool;

        [[nodiscard]] auto last_insert_rowid() const noexcept -> std::int64_t;
        [[nodiscard]] auto changes_count() const noexcept -> int;

        [[nodiscard]] auto raw_handle() noexcept -> sqlite3 *;

    private:
        sqlite3 *handle_{nullptr};
    };


    /**
     * @brief SQLite 语句 RAII 包装
     */
    class statement
    {
    public:
        statement() noexcept = default;
        ~statement() noexcept;

        statement(const statement &) = delete;
        auto operator=(const statement &) -> statement & = delete;
        statement(statement &&) noexcept;
        auto operator=(statement &&) noexcept -> statement &;

        [[nodiscard]] auto is_valid() const noexcept -> bool;

        [[nodiscard]] auto bind(int index, std::int64_t value) noexcept -> bool;
        [[nodiscard]] auto bind(int index, int value) noexcept -> bool;
        [[nodiscard]] auto bind(int index, double value) noexcept -> bool;
        [[nodiscard]] auto bind(int index, std::string_view value) noexcept -> bool;
        [[nodiscard]] auto bind(int index, std::span<const std::byte> value) noexcept -> bool;
        [[nodiscard]] auto bind_null(int index) noexcept -> bool;

        [[nodiscard]] auto step() noexcept -> int;

        [[nodiscard]] auto column_int(int col) const noexcept -> int;
        [[nodiscard]] auto column_int64(int col) const noexcept -> std::int64_t;
        [[nodiscard]] auto column_double(int col) const noexcept -> double;
        [[nodiscard]] auto column_string(int col) const noexcept -> std::string;

        void reset() noexcept;
        void clear_bindings() noexcept;

        void close() noexcept;

    private:
        friend class database;

        explicit statement(sqlite3_stmt *stmt) noexcept;

        sqlite3_stmt *stmt_{nullptr};
    };


    /**
     * @brief 事务 RAII 守卫，析构时自动回滚未提交事务
     */
    class transaction_guard
    {
    public:
        explicit transaction_guard(database &db) noexcept;
        ~transaction_guard() noexcept;

        transaction_guard(const transaction_guard &) = delete;
        auto operator=(const transaction_guard &) -> transaction_guard & = delete;

        [[nodiscard]] auto commit() noexcept -> bool;
        [[nodiscard]] auto is_committed() const noexcept -> bool;

    private:
        database &db_;
        bool committed_{false};
    };

} // namespace sec::store
