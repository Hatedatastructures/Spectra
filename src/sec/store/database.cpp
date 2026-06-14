// SQLite 数据库连接管理器实现

#include <sec/store/database.hpp>
#include <sec/fault/compatible.hpp>
#include <sec/fault/code.hpp>

#include <sqlite3.h>

#include <cstring>


namespace sec::store
{

    namespace
    {

        // 将 SQLite 返回码转换为 std::error_code
        auto to_error_code(int rc) noexcept -> std::error_code
        {
            if (rc == SQLITE_OK || rc == SQLITE_DONE)
                return {};

            fault::code code{fault::code::db_error};
            if (rc == SQLITE_BUSY || rc == SQLITE_LOCKED)
                code = fault::code::db_constraint;
            else if (rc == SQLITE_CORRUPT || rc == SQLITE_NOTADB)
                code = fault::code::db_open_failed;

            return fault::make_error_code(code);
        }

    } // anonymous namespace


    // 打开 SQLite 数据库连接，自动启用 WAL 模式和外键约束
    database::database(std::string_view path)
    {
        auto rc = sqlite3_open(std::string(path).c_str(), &handle_);
        if (rc != SQLITE_OK)
        {
            if (handle_)
            {
                sqlite3_close(handle_);
                handle_ = nullptr;
            }
            throw std::system_error(to_error_code(rc));
        }

        sqlite3_exec(handle_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
        sqlite3_exec(handle_, "PRAGMA foreign_keys=ON;", nullptr, nullptr, nullptr);
    }


    // 析构时自动关闭数据库连接
    database::~database() noexcept
    {
        close();
    }


    // 移动构造数据库连接
    database::database(database &&other) noexcept
        : handle_{other.handle_}
    {
        other.handle_ = nullptr;
    }


    // 移动赋值数据库连接
    auto database::operator=(database &&other) noexcept -> database &
    {
        if (this != &other)
        {
            close();
            handle_ = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }


    // 查询数据库连接是否有效
    [[nodiscard]] auto database::is_open() const noexcept -> bool
    {
        return handle_ != nullptr;
    }


    // 关闭数据库连接并释放句柄
    void database::close() noexcept
    {
        if (handle_)
        {
            sqlite3_close(handle_);
            handle_ = nullptr;
        }
    }


    // 执行原始 SQL 语句
    [[nodiscard]] auto database::execute(std::string_view sql, std::error_code &ec) noexcept -> bool
    {
        if (!handle_)
        {
            ec = fault::make_error_code(fault::code::db_open_failed);
            return false;
        }

        auto rc = sqlite3_exec(handle_, std::string(sql).c_str(),
                               nullptr, nullptr, nullptr);
        if (rc != SQLITE_OK)
        {
            ec = to_error_code(rc);
            return false;
        }

        ec.clear();
        return true;
    }


    // 预编译 SQL 语句
    [[nodiscard]] auto database::prepare(std::string_view sql, std::error_code &ec) noexcept -> statement
    {
        if (!handle_)
        {
            ec = fault::make_error_code(fault::code::db_open_failed);
            return statement{};
        }

        sqlite3_stmt *stmt{nullptr};
        auto rc = sqlite3_prepare_v2(handle_, std::string(sql).c_str(),
                                     static_cast<int>(sql.size()), &stmt, nullptr);
        if (rc != SQLITE_OK)
        {
            ec = to_error_code(rc);
            return statement{};
        }

        ec.clear();
        return statement{stmt};
    }


    // 开始数据库事务
    auto database::begin_transaction(std::error_code &ec) noexcept -> bool
    {
        return execute("BEGIN TRANSACTION;", ec);
    }


    // 提交当前事务
    auto database::commit(std::error_code &ec) noexcept -> bool
    {
        return execute("COMMIT;", ec);
    }


    // 回滚当前事务
    auto database::rollback(std::error_code &ec) noexcept -> bool
    {
        return execute("ROLLBACK;", ec);
    }


    // 获取最近一次插入行的 ROWID
    [[nodiscard]] auto database::last_insert_rowid() const noexcept -> std::int64_t
    {
        if (!handle_) return 0;
        return sqlite3_last_insert_rowid(handle_);
    }


    // 获取最近一次操作影响的行数
    [[nodiscard]] auto database::changes_count() const noexcept -> int
    {
        if (!handle_) return 0;
        return sqlite3_changes(handle_);
    }


    // 获取底层 SQLite 原始句柄
    [[nodiscard]] auto database::raw_handle() noexcept -> sqlite3 *
    {
        return handle_;
    }


    // ---- statement ----

    // 从预编译语句构造 statement 对象
    statement::statement(sqlite3_stmt *stmt) noexcept
        : stmt_{stmt}
    {
    }


    // 析构时自动释放预编译语句
    statement::~statement() noexcept
    {
        close();
    }


    // 移动构造预编译语句
    statement::statement(statement &&other) noexcept
        : stmt_{other.stmt_}
    {
        other.stmt_ = nullptr;
    }


    // 移动赋值预编译语句
    auto statement::operator=(statement &&other) noexcept -> statement &
    {
        if (this != &other)
        {
            close();
            stmt_ = other.stmt_;
            other.stmt_ = nullptr;
        }
        return *this;
    }


    // 查询预编译语句是否有效
    [[nodiscard]] auto statement::is_valid() const noexcept -> bool
    {
        return stmt_ != nullptr;
    }


    // 绑定 64 位整数值到指定参数位置
    auto statement::bind(int index, std::int64_t value) noexcept -> bool
    {
        if (!stmt_) return false;
        return sqlite3_bind_int64(stmt_, index, value) == SQLITE_OK;
    }


    // 绑定 32 位整数值到指定参数位置
    auto statement::bind(int index, int value) noexcept -> bool
    {
        if (!stmt_) return false;
        return sqlite3_bind_int(stmt_, index, value) == SQLITE_OK;
    }


    // 绑定双精度浮点值到指定参数位置
    auto statement::bind(int index, double value) noexcept -> bool
    {
        if (!stmt_) return false;
        return sqlite3_bind_double(stmt_, index, value) == SQLITE_OK;
    }


    // 绑定文本字符串到指定参数位置
    auto statement::bind(int index, std::string_view value) noexcept -> bool
    {
        if (!stmt_) return false;
        return sqlite3_bind_text(stmt_, index, value.data(),
                                 static_cast<int>(value.size()),
                                 SQLITE_TRANSIENT) == SQLITE_OK;
    }


    // 绑定二进制 BLOB 到指定参数位置
    auto statement::bind(int index, std::span<const std::byte> value) noexcept -> bool
    {
        if (!stmt_) return false;
        return sqlite3_bind_blob(stmt_, index, value.data(),
                                 static_cast<int>(value.size()),
                                 SQLITE_TRANSIENT) == SQLITE_OK;
    }


    // 绑定 NULL 值到指定参数位置
    auto statement::bind_null(int index) noexcept -> bool
    {
        if (!stmt_) return false;
        return sqlite3_bind_null(stmt_, index) == SQLITE_OK;
    }


    // 执行一步预编译语句
    [[nodiscard]] auto statement::step() noexcept -> int
    {
        if (!stmt_) return SQLITE_ERROR;
        return sqlite3_step(stmt_);
    }


    // 读取当前行的 32 位整数列值
    [[nodiscard]] auto statement::column_int(int col) const noexcept -> int
    {
        if (!stmt_) return 0;
        return sqlite3_column_int(stmt_, col);
    }


    // 读取当前行的 64 位整数列值
    [[nodiscard]] auto statement::column_int64(int col) const noexcept -> std::int64_t
    {
        if (!stmt_) return 0;
        return sqlite3_column_int64(stmt_, col);
    }


    // 读取当前行的双精度浮点列值
    [[nodiscard]] auto statement::column_double(int col) const noexcept -> double
    {
        if (!stmt_) return 0.0;
        return sqlite3_column_double(stmt_, col);
    }


    // 读取当前行的文本列值
    [[nodiscard]] auto statement::column_string(int col) const noexcept -> std::string
    {
        if (!stmt_) return {};
        auto *text = sqlite3_column_text(stmt_, col);
        if (!text) return {};
        return reinterpret_cast<const char *>(text);
    }


    // 重置预编译语句以便重新执行
    void statement::reset() noexcept
    {
        if (stmt_) sqlite3_reset(stmt_);
    }


    // 清除所有参数绑定
    void statement::clear_bindings() noexcept
    {
        if (stmt_) sqlite3_clear_bindings(stmt_);
    }


    // 关闭并释放预编译语句
    void statement::close() noexcept
    {
        if (stmt_)
        {
            sqlite3_finalize(stmt_);
            stmt_ = nullptr;
        }
    }


    // ---- transaction_guard ----

    // 构造事务守卫并自动开始事务
    transaction_guard::transaction_guard(database &db) noexcept
        : db_{db}
    {
        auto ec = std::error_code{};
        db_.begin_transaction(ec);
    }


    // 析构时若未提交则自动回滚事务
    transaction_guard::~transaction_guard() noexcept
    {
        if (!committed_)
        {
            auto ec = std::error_code{};
            db_.rollback(ec);
        }
    }


    // 提交当前事务（重复调用安全）
    [[nodiscard]] auto transaction_guard::commit() noexcept -> bool
    {
        if (committed_) return true;
        auto ec = std::error_code{};
        if (db_.commit(ec))
        {
            committed_ = true;
            return true;
        }
        return false;
    }


    // 查询事务是否已提交
    [[nodiscard]] auto transaction_guard::is_committed() const noexcept -> bool
    {
        return committed_;
    }


} // namespace sec::store
