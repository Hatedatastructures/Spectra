// AI 对话管理器实现 — 远程 SSE 流式（OpenAI / Anthropic）
// Windows: 使用 WinINet 实现 HTTPS，避免链接 OpenSSL 触发 Defender
// POSIX: 使用 OpenSSL

#include <sec/tui/ai_chat.hpp>

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <spdlog/spdlog.h>

#ifdef _WIN32
#include <wininet.h>
#pragma comment(lib, "wininet.lib")
#else
#include <boost/asio/ssl.hpp>
#include <boost/beast/ssl.hpp>
#endif

#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <iomanip>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>


namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = boost::beast::http;
using tcp = boost::asio::ip::tcp;

#ifndef _WIN32
namespace ssl = boost::asio::ssl;
#endif


namespace sec::tui
{

    namespace
    {

        auto url_decode(const std::string &s) -> std::string
        {
            auto out = std::string{};
            for (std::size_t i = 0; i < s.size(); ++i)
            {
                if (s[i] == '%' && i + 2 < s.size())
                {
                    auto hex = s.substr(i + 1, 2);
                    auto val = static_cast<char>(std::stoi(hex, nullptr, 16));
                    out.push_back(val);
                    i += 2;
                }
                else
                {
                    out.push_back(s[i]);
                }
            }
            return out;
        }

        struct parsed_url
        {
            std::string scheme;
            std::string host;
            std::string port;
            std::string path;
        };

        auto parse_url(const std::string &url) -> parsed_url
        {
            auto p = parsed_url{};
            auto pos = url.find("://");
            if (pos != std::string::npos)
            {
                p.scheme = url.substr(0, pos);
                pos += 3;
            }
            else
            {
                p.scheme = "http";
                pos = 0;
            }

            auto rest = url.substr(pos);
            auto slash = rest.find('/');
            auto host_port = slash != std::string::npos ? rest.substr(0, slash) : rest;
            p.path = slash != std::string::npos ? rest.substr(slash) : "/";

            auto colon = host_port.find(':');
            if (colon != std::string::npos)
            {
                p.host = host_port.substr(0, colon);
                p.port = host_port.substr(colon + 1);
            }
            else
            {
                p.host = host_port;
                p.port = p.scheme == "https" ? "443" : "80";
            }

            return p;
        }

        auto json_escape(const std::string &s) -> std::string
        {
            auto out = std::string{};
            out.reserve(s.size() + 8);
            for (auto c : s)
            {
                switch (c)
                {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if (static_cast<unsigned char>(c) < 0x20)
                    {
                        auto ss = std::ostringstream{};
                        ss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
                        out += ss.str();
                    }
                    else
                    {
                        out.push_back(c);
                    }
                }
            }
            return out;
        }

        auto extract_json_string(const std::string &json, const std::string &key) -> std::string
        {
            auto needle = "\"" + key + "\"";
            auto pos = json.find(needle);
            if (pos == std::string::npos) return {};
            pos += needle.size();
            while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':')) ++pos;
            if (pos >= json.size() || json[pos] != '"') return {};
            ++pos;
            auto out = std::string{};
            while (pos < json.size() && json[pos] != '"')
            {
                if (json[pos] == '\\' && pos + 1 < json.size())
                {
                    auto next = json[pos + 1];
                    if (next == '"') { out.push_back('"'); pos += 2; continue; }
                    if (next == '\\') { out.push_back('\\'); pos += 2; continue; }
                    if (next == 'n') { out.push_back('\n'); pos += 2; continue; }
                    if (next == 'r') { out.push_back('\r'); pos += 2; continue; }
                    if (next == 't') { out.push_back('\t'); pos += 2; continue; }
                    if (next == 'u' && pos + 5 < json.size())
                    {
                        auto hex = json.substr(pos + 2, 4);
                        auto cp = static_cast<unsigned int>(std::stoul(hex, nullptr, 16));
                        if (cp < 0x80) out.push_back(static_cast<char>(cp));
                        else if (cp < 0x800)
                        {
                            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
                            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                        }
                        else
                        {
                            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
                            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                        }
                        pos += 6;
                        continue;
                    }
                }
                out.push_back(json[pos]);
                ++pos;
            }
            return out;
        }

        auto extract_delta_content(const std::string &line) -> std::string
        {
            static const std::string needle = "\"content\"";
            auto pos = line.find(needle);
            if (pos == std::string::npos)
            {
                return {};
            }
            pos += needle.size();
            while (pos < line.size() && (line[pos] == ' ' || line[pos] == ':')) ++pos;
            if (pos >= line.size() || line[pos] != '"') return {};
            ++pos;
            auto out = std::string{};
            while (pos < line.size() && line[pos] != '"')
            {
                if (line[pos] == '\\' && pos + 1 < line.size())
                {
                    auto next = line[pos + 1];
                    if (next == '"') { out.push_back('"'); pos += 2; continue; }
                    if (next == '\\') { out.push_back('\\'); pos += 2; continue; }
                    if (next == 'n') { out.push_back('\n'); pos += 2; continue; }
                    if (next == 'r') { out.push_back('\r'); pos += 2; continue; }
                    if (next == 't') { out.push_back('\t'); pos += 2; continue; }
                }
                out.push_back(line[pos]);
                ++pos;
            }
            return out;
        }

        auto build_request_body(const std::string &model, const std::string &system_prompt,
            const std::vector<chat_message> &history, int max_tokens, double temperature) -> std::string
        {
            auto body = std::string{};
            body += "{\"model\":\"" + json_escape(model) + "\",";
            body += "\"stream\":true,";
            body += "\"max_tokens\":" + std::to_string(max_tokens) + ",";
            body += "\"temperature\":" + std::to_string(temperature) + ",";
            body += "\"messages\":[";
            body += "{\"role\":\"system\",\"content\":\"" + json_escape(system_prompt) + "\"},";
            auto count = std::size_t{0};
            for (const auto &m : history)
            {
                if (count >= 8) break;
                if (count > 0) body += ",";
                auto role = std::string{"user"};
                if (m.who == chat_message::role::assistant) role = "assistant";
                else if (m.who == chat_message::role::system) continue;
                body += "{\"role\":\"" + role + "\",\"content\":\"" + json_escape(m.content) + "\"}";
                ++count;
            }
            body += "]}";
            return body;
        }

        auto build_request_body_anthropic(const std::string &model, const std::string &system_prompt,
            const std::vector<chat_message> &history, int max_tokens, double temperature) -> std::string
        {
            auto body = std::string{};
            body += "{\"model\":\"" + json_escape(model) + "\",";
            body += "\"stream\":true,";
            body += "\"max_tokens\":" + std::to_string(max_tokens) + ",";
            body += "\"temperature\":" + std::to_string(temperature) + ",";
            body += "\"system\":\"" + json_escape(system_prompt) + "\",";
            body += "\"messages\":[";
            auto count = std::size_t{0};
            for (const auto &m : history)
            {
                if (count >= 8) break;
                if (m.who == chat_message::role::system) continue;
                if (count > 0) body += ",";
                auto role = std::string{"user"};
                if (m.who == chat_message::role::assistant) role = "assistant";
                body += "{\"role\":\"" + role + "\",\"content\":\"" + json_escape(m.content) + "\"}";
                ++count;
            }
            body += "]}";
            return body;
        }

        auto extract_delta_content_anthropic(const std::string &line) -> std::string
        {
            static const std::string needle = "\"text\"";
            auto pos = line.find(needle);
            if (pos == std::string::npos)
            {
                return {};
            }
            pos += needle.size();
            while (pos < line.size() && (line[pos] == ' ' || line[pos] == ':')) ++pos;
            if (pos >= line.size() || line[pos] != '"') return {};
            ++pos;
            auto out = std::string{};
            while (pos < line.size() && line[pos] != '"')
            {
                if (line[pos] == '\\' && pos + 1 < line.size())
                {
                    auto next = line[pos + 1];
                    if (next == '"') { out.push_back('"'); pos += 2; continue; }
                    if (next == '\\') { out.push_back('\\'); pos += 2; continue; }
                    if (next == 'n') { out.push_back('\n'); pos += 2; continue; }
                    if (next == 'r') { out.push_back('\r'); pos += 2; continue; }
                    if (next == 't') { out.push_back('\t'); pos += 2; continue; }
                }
                out.push_back(line[pos]);
                ++pos;
            }
            return out;
        }

        void parse_sse_chunk(const std::string &chunk,
            std::string &sse_buffer, std::string &total_response,
            std::function<void(std::string_view)> &on_chunk,
            std::atomic<bool> &abort_flag, api_protocol protocol)
        {
            auto last_event = std::string{};
            auto pos = std::size_t{0};
            while (pos < chunk.size())
            {
                auto nl = chunk.find('\n', pos);
                if (nl == std::string::npos)
                {
                    sse_buffer = chunk.substr(pos);
                    break;
                }
                auto line = chunk.substr(pos, nl - pos);
                pos = nl + 1;

                if (!line.empty() && line.back() == '\r')
                {
                    line.pop_back();
                }

                if (protocol == api_protocol::openai)
                {
                    if (line.rfind("data:", 0) == 0)
                    {
                        auto payload = line.substr(5);
                        while (!payload.empty() && payload.front() == ' ') payload.erase(0, 1);
                        if (payload == "[DONE]")
                        {
                            abort_flag = true;
                            break;
                        }
                        auto delta = extract_delta_content(payload);
                        if (!delta.empty())
                        {
                            total_response += delta;
                            if (on_chunk) on_chunk(delta);
                        }
                    }
                }
                else
                {
                    // Anthropic SSE: event: content_block_delta → data: {"delta":{"text":"..."}}
                    if (line.rfind("event:", 0) == 0)
                    {
                        auto evt = line.substr(6);
                        while (!evt.empty() && evt.front() == ' ') evt.erase(0, 1);
                        last_event = evt;
                        if (evt == "message_stop")
                        {
                            abort_flag = true;
                            break;
                        }
                    }
                    else if (line.rfind("data:", 0) == 0)
                    {
                        auto payload = line.substr(5);
                        while (!payload.empty() && payload.front() == ' ') payload.erase(0, 1);

                        // 错误事件：提取 message 字段显示给用户
                        if (last_event == "error" || payload.find("\"type\":\"error\"") != std::string::npos)
                        {
                            auto msg = extract_json_string(payload, "message");
                            if (msg.empty()) msg = payload;
                            auto err = std::string{"**API 错误：** "} + msg + "\n";
                            total_response += err;
                            if (on_chunk) on_chunk(err);
                            abort_flag = true;
                            break;
                        }

                        auto delta = extract_delta_content_anthropic(payload);
                        if (!delta.empty())
                        {
                            total_response += delta;
                            if (on_chunk) on_chunk(delta);
                        }
                    }
                }
            }
        }

    } // anonymous namespace


    ai_chat::ai_chat(const sec::ai_config &ai_cfg)
        : system_prompt_{"你是 Spectra 安全分析助手，专门分析局域网安全态势。\n"
                          "请用 Markdown 格式回复，可以使用表格、列表、代码块。\n"
                          "当前监控数据由系统自动注入。"}
        , remote_ioc_{}
    {
        (void)ai_cfg;  // 配置字段通过 set_remote() 注入，构造参数保留以维持接口稳定
        remote_work_.emplace(asio::make_work_guard(remote_ioc_.get_executor()));
        remote_thread_ = std::thread{[this]()
        {
            try
            {
                remote_ioc_.run();
            }
            catch (const std::exception &e)
            {
                spdlog::error("AI remote io_context exited: {}", e.what());
            }
        }};
    }


    ai_chat::~ai_chat() noexcept
    {
        abort_flag_ = true;
        remote_ioc_.stop();
        if (remote_work_)
        {
            remote_work_.reset();
        }
        if (remote_thread_.joinable())
        {
            remote_thread_.join();
        }
    }


    void ai_chat::set_remote(const remote_config &cfg)
    {
        auto lock = std::lock_guard<std::mutex>{history_mutex_};
        remote_cfg_ = cfg;
    }


    void ai_chat::set_mode(ai_mode mode)
    {
        mode_ = mode;
    }


    auto ai_chat::mode() const noexcept -> ai_mode
    {
        return mode_;
    }


    auto ai_chat::send(const std::string &text,
                       std::function<void(std::string_view)> on_chunk,
                       std::function<void()> on_done) -> void
    {
        if (generating_.exchange(true))
        {
            if (on_chunk) on_chunk("**Already generating.**\n");
            if (on_done) on_done();
            return;
        }

        abort_flag_ = false;

        {
            auto lock = std::lock_guard<std::mutex>{history_mutex_};
            auto msg = chat_message{};
            msg.who = chat_message::role::user;
            msg.content = text;
            history_.push_back(std::move(msg));
        }

        if (mode_ == ai_mode::remote)
        {
            do_remote_request(text, std::move(on_chunk), std::move(on_done));
        }
        else
        {
            if (on_chunk) on_chunk("AI is **off**. Press `Ctrl+T` to switch mode and use `ai remote`.\n");
            generating_ = false;
            if (on_done) on_done();
        }
    }


    void ai_chat::abort()
    {
        abort_flag_ = true;
    }


    auto ai_chat::history() const -> const std::vector<chat_message> &
    {
        return history_;
    }


    void ai_chat::clear_history()
    {
        auto lock = std::lock_guard<std::mutex>{history_mutex_};
        history_.clear();
    }


    void ai_chat::set_system_prompt(std::string prompt)
    {
        auto lock = std::lock_guard<std::mutex>{history_mutex_};
        system_prompt_ = std::move(prompt);
    }


    auto ai_chat::is_generating() const noexcept -> bool
    {
        return generating_;
    }


    // Windows 实现：WinINet HTTPS + SSE 流式
#ifdef _WIN32
    static auto wide(const std::string &s) -> std::wstring
    {
        if (s.empty()) return {};
        auto len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
        auto ws = std::wstring{};
        ws.resize(len - 1);
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, ws.data(), len);
        return ws;
    }

    static auto wininet_https_streaming(
        const std::string &host, int port, const std::string &path,
        const std::string &body, const std::string &api_key,
        api_protocol protocol,
        std::function<void(std::string_view)> &on_chunk,
        std::atomic<bool> &abort_flag) -> std::string
    {
        auto whost = wide(host);
        auto wpath = wide(path);
        auto total = std::string{};

        auto hInternet = InternetOpenW(L"Spectra/0.1", INTERNET_OPEN_TYPE_DIRECT, nullptr, nullptr, 0);
        if (!hInternet)
        {
            throw std::runtime_error("InternetOpen failed: " + std::to_string(GetLastError()));
        }

        auto hConnect = InternetConnectW(hInternet, whost.c_str(),
            static_cast<INTERNET_PORT>(port), nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, 0);
        if (!hConnect)
        {
            InternetCloseHandle(hInternet);
            throw std::runtime_error("InternetConnect failed: " + std::to_string(GetLastError()));
        }

        auto flags = INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_RELOAD;
        if (port == 443) flags |= INTERNET_FLAG_SECURE;

        auto headers = std::string{"Content-Type: application/json\r\n"};
        if (!api_key.empty())
        {
            if (protocol == api_protocol::anthropic)
            {
                headers += "x-api-key: " + api_key + "\r\n";
                headers += "anthropic-version: 2023-06-01\r\n";
            }
            else
            {
                headers += "Authorization: Bearer " + api_key + "\r\n";
            }
        }

        auto wheaders = wide(headers);
        auto wmethod = wide("POST");

        auto hRequest = HttpOpenRequestW(hConnect, wmethod.c_str(), wpath.c_str(),
            nullptr, nullptr, nullptr, flags, 0);
        if (!hRequest)
        {
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            throw std::runtime_error("HttpOpenRequest failed: " + std::to_string(GetLastError()));
        }

        // 超时设置
        auto timeout = DWORD{30000};
        InternetSetOptionW(hRequest, INTERNET_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
        InternetSetOptionW(hRequest, INTERNET_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
        InternetSetOptionW(hRequest, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));

        auto ok = HttpSendRequestW(hRequest, wheaders.c_str(),
            static_cast<DWORD>(wheaders.size()),
            const_cast<char *>(body.data()), static_cast<DWORD>(body.size()));
        if (!ok)
        {
            auto err = GetLastError();
            InternetCloseHandle(hRequest);
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            throw std::runtime_error("HttpSendRequest failed: " + std::to_string(err));
        }

        // 检查 HTTP 状态码
        auto status_code = DWORD{0};
        auto status_len = DWORD{sizeof(status_code)};
        HttpQueryInfoW(hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
            &status_code, &status_len, nullptr);
        spdlog::info("AI request: {}:{}{}  HTTP {}  body={} bytes",
            host, port, path, status_code, body.size());

        if (status_code != 200)
        {
            auto err_buf = std::vector<char>(4096);
            auto bytes_read = DWORD{0};
            InternetReadFile(hRequest, err_buf.data(), 4096, &bytes_read);
            auto err_msg = std::string{err_buf.data(), bytes_read};
            spdlog::error("AI error response: {}", err_msg);
            InternetCloseHandle(hRequest);
            InternetCloseHandle(hConnect);
            InternetCloseHandle(hInternet);
            throw std::runtime_error("HTTP " + std::to_string(status_code) + ": " + err_msg);
        }

        // 读取 SSE 流式响应
        auto read_buf = std::vector<char>(4096);
        auto sse_buffer = std::string{};
        while (!abort_flag)
        {
            auto bytes_read = DWORD{0};
            auto result = InternetReadFile(hRequest, read_buf.data(),
                static_cast<DWORD>(read_buf.size()), &bytes_read);
            if (!result || bytes_read == 0) break;

            auto chunk_str = std::string{read_buf.data(), bytes_read};
            spdlog::debug("AI SSE chunk ({} bytes): {}", bytes_read, chunk_str.substr(0, 200));

            parse_sse_chunk(chunk_str, sse_buffer, total, on_chunk, abort_flag, protocol);
        }

        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);

        return total;
    }
#endif

    auto ai_chat::do_remote_request(const std::string &text,
                                     std::function<void(std::string_view)> on_chunk,
                                     std::function<void()> on_done) -> void
    {
#ifdef _WIN32
        // Windows: WinINet HTTPS 流式（不链接 OpenSSL）
        std::thread{[this, text, on_chunk = std::move(on_chunk), on_done = std::move(on_done)]() mutable
        {
            try
            {
                auto parsed = parse_url(remote_cfg_.endpoint);
                auto port = std::stoi(parsed.port);

                // 智谱/Anthropic 兼容端点：base 是 /api/anthropic，实际请求 /api/anthropic/v1/messages
                // OpenAI 兼容端点：base 是 /v1，实际请求 /v1/chat/completions
                auto api_path = parsed.path;
                if (remote_cfg_.protocol == api_protocol::anthropic)
                {
                    if (api_path.find("/v1") == std::string::npos)
                        api_path += "/v1";
                    api_path += "/messages";
                }
                else
                {
                    api_path += "/chat/completions";
                }

                auto body = std::string{};
                if (remote_cfg_.protocol == api_protocol::anthropic)
                {
                    body = build_request_body_anthropic(
                        remote_cfg_.model, system_prompt_, history_,
                        remote_cfg_.max_tokens, remote_cfg_.temperature);
                }
                else
                {
                    body = build_request_body(
                        remote_cfg_.model, system_prompt_, history_,
                        remote_cfg_.max_tokens, remote_cfg_.temperature);
                }

                spdlog::info("AI request body: {}", body);

                auto total = wininet_https_streaming(
                    parsed.host, port, api_path, body,
                    remote_cfg_.api_key, remote_cfg_.protocol,
                    on_chunk, abort_flag_);

                {
                    auto lock = std::lock_guard<std::mutex>{history_mutex_};
                    auto msg = chat_message{};
                    msg.who = chat_message::role::assistant;
                    msg.content = total;
                    history_.push_back(std::move(msg));
                }
            }
            catch (const std::exception &e)
            {
                auto err = std::string{"**远程请求失败：** "} + e.what() + "\n";
                spdlog::error("AI remote request failed: {}", e.what());
                if (on_chunk) on_chunk(err);
            }

            generating_ = false;
            if (on_done) on_done();
        }}.detach();
#else
        // POSIX: Beast + OpenSSL
        asio::co_spawn(remote_ioc_,
            [this, text, on_chunk = std::move(on_chunk), on_done = std::move(on_done)]() mutable -> asio::awaitable<void>
            {
                try
                {
                    auto parsed = parse_url(remote_cfg_.endpoint);
                    auto use_ssl = (parsed.scheme == "https");

                    auto api_path = parsed.path;
                    if (remote_cfg_.protocol == api_protocol::anthropic)
                    {
                        if (api_path.find("/v1") == std::string::npos)
                            api_path += "/v1";
                        api_path += "/messages";
                    }
                    else
                    {
                        api_path += "/chat/completions";
                    }

                    auto resolver = tcp::resolver{co_await asio::this_coro::executor};
                    auto const results = co_await resolver.async_resolve(parsed.host, parsed.port, asio::use_awaitable);

                    auto body = std::string{};
                    if (remote_cfg_.protocol == api_protocol::anthropic)
                    {
                        body = build_request_body_anthropic(
                            remote_cfg_.model, system_prompt_, history_,
                            remote_cfg_.max_tokens, remote_cfg_.temperature);
                    }
                    else
                    {
                        body = build_request_body(
                            remote_cfg_.model, system_prompt_, history_,
                            remote_cfg_.max_tokens, remote_cfg_.temperature);
                    }

                    auto req = http::request<http::string_body>{http::verb::post, api_path, 11};
                    req.set(http::field::host, parsed.host);
                    req.set(http::field::user_agent, "Spectra/0.1");
                    req.set(http::field::content_type, "application/json");
                    if (!remote_cfg_.api_key.empty())
                    {
                        if (remote_cfg_.protocol == api_protocol::anthropic)
                        {
                            req.set("x-api-key", remote_cfg_.api_key);
                            req.set("anthropic-version", "2023-06-01");
                        }
                        else
                        {
                            req.set(http::field::authorization, "Bearer " + remote_cfg_.api_key);
                        }
                    }
                    req.body() = std::move(body);
                    req.prepare_payload();

                    auto buffer = beast::flat_buffer{};
                    auto total_response = std::string{};
                    auto sse_buffer = std::string{};

                    if (use_ssl)
                    {
                        auto ssl_ctx = ssl::context{ssl::context::tls_client};
                        ssl_ctx.set_default_verify_paths();
                        ssl_ctx.set_verify_mode(ssl::verify_peer);

                        auto stream = beast::ssl_stream<beast::tcp_stream>{
                            co_await asio::this_coro::executor, ssl_ctx};
                        SSL_set_tlsext_host_name(stream.native_handle(), parsed.host.c_str());

                        co_await beast::get_lowest_layer(stream).async_connect(results, asio::use_awaitable);
                        co_await stream.async_handshake(ssl::stream_base::client, asio::use_awaitable);
                        co_await http::async_write(stream, req, asio::use_awaitable);

                        while (!abort_flag_)
                        {
                            auto resp = http::response<http::string_body>{};
                            try { co_await http::async_read(stream, buffer, resp, asio::use_awaitable); }
                            catch (const std::exception &e) { spdlog::debug("SSE read done: {}", e.what()); break; }
                            auto chunk = resp.body();
                            parse_sse_chunk(chunk, sse_buffer, total_response, on_chunk, abort_flag_, remote_cfg_.protocol);
                            if (abort_flag_) break;
                        }

                        beast::error_code ignore_ec;
                        stream.async_shutdown([&ignore_ec](beast::error_code ec) { ignore_ec = ec; });
                    }
                    else
                    {
                        auto stream = beast::tcp_stream{co_await asio::this_coro::executor};
                        co_await stream.async_connect(results, asio::use_awaitable);
                        co_await http::async_write(stream, req, asio::use_awaitable);

                        while (!abort_flag_)
                        {
                            auto resp = http::response<http::string_body>{};
                            try { co_await http::async_read(stream, buffer, resp, asio::use_awaitable); }
                            catch (const std::exception &e) { spdlog::debug("SSE read done: {}", e.what()); break; }
                            auto chunk = resp.body();
                            parse_sse_chunk(chunk, sse_buffer, total_response, on_chunk, abort_flag_, remote_cfg_.protocol);
                            if (abort_flag_) break;
                        }

                        beast::error_code ignore_ec;
                        stream.socket().shutdown(tcp::socket::shutdown_both, ignore_ec);
                    }

                    {
                        auto lock = std::lock_guard<std::mutex>{history_mutex_};
                        auto msg = chat_message{};
                        msg.who = chat_message::role::assistant;
                        msg.content = total_response;
                        history_.push_back(std::move(msg));
                    }
                }
                catch (const std::exception &e)
                {
                    auto err = std::string{"**远程请求失败：** "} + e.what() + "\n";
                    spdlog::error("AI remote request failed: {}", e.what());
                    if (on_chunk) on_chunk(err);
                }

                generating_ = false;
                if (on_done) on_done();
            },
            asio::detached);
#endif
    }


} // namespace sec::tui
