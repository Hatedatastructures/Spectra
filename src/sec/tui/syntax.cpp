// 简易语法高亮 — 单遍状态机，支持常见语言关键字/字符串/注释/数字

#include <sec/tui/syntax.hpp>

#include <cctype>
#include <string>
#include <string_view>
#include <unordered_set>

namespace sec::tui
{

    namespace
    {
        auto is_ident_start(char c) -> bool
        {
            return std::isalpha(static_cast<unsigned char>(c)) || c == '_' || static_cast<unsigned char>(c) >= 0x80;
        }

        auto is_ident_char(char c) -> bool
        {
            return std::isalnum(static_cast<unsigned char>(c)) || c == '_' || static_cast<unsigned char>(c) >= 0x80;
        }

        auto is_digit(char c) -> bool
        {
            return std::isdigit(static_cast<unsigned char>(c));
        }

        auto is_operator(char c) -> bool
        {
            static const char ops[] = "+-*/=<>!&|% ^~";
            for (auto o : ops) if (c == o) return true;
            return false;
        }

        auto is_punct(char c) -> bool
        {
            static const char p[] = ".,;:()[]{}?";
            for (auto x : p) if (c == x) return true;
            return false;
        }

        auto normalize_lang(std::string_view lang) -> std::string
        {
            auto out = std::string{};
            for (auto c : lang)
            {
                if (c == ' ' || c == '\t') continue;
                out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
            }
            if (out == "c++" || out == "cxx" || out == "cc" || out == "hpp" || out == "h") return "cpp";
            if (out == "typescript" || out == "tsx" || out == "jsx") return "js";
            if (out == "py" || out == "python3") return "python";
            if (out == "sh" || out == "shell" || out == "zsh" || out == "ksh") return "bash";
            if (out == "golang") return "go";
            return out;
        }

        const std::unordered_set<std::string> &keywords_for(const std::string &lang)
        {
            static const std::unordered_set<std::string> cpp_kw = {
                "alignas","alignof","and","auto","bool","break","case","catch","char","class","const","constexpr",
                "continue","decltype","default","delete","do","double","else","enum","explicit","export","extern",
                "false","float","for","friend","goto","if","inline","int","long","mutable","namespace","new","noexcept",
                "nullptr","operator","or","private","protected","public","register","reinterpret_cast","return","short",
                "signed","sizeof","static","static_cast","struct","switch","template","this","throw","true","try",
                "typedef","typename","union","unsigned","using","virtual","void","volatile","while","std","string",
                "vector","map","size_t","uint8_t","uint16_t","uint32_t","uint64_t","int8_t","int16_t","int32_t","int64_t",
                "co_await","co_return","co_spawn","awaitable"
            };
            static const std::unordered_set<std::string> py_kw = {
                "False","None","True","and","as","assert","async","await","break","class","continue","def","del","elif",
                "else","except","finally","for","from","global","if","import","in","is","lambda","nonlocal","not","or",
                "pass","raise","return","try","while","with","yield","self","print","len","range","str","int","float",
                "list","dict","tuple","set","bool"
            };
            static const std::unordered_set<std::string> bash_kw = {
                "if","then","else","elif","fi","for","while","do","done","case","esac","function","in","select",
                "until","echo","printf","read","local","export","unset","source","return","exit","set","unset",
                "alias","declare","typeset","let","eval","exec","trap","test","cd","pwd","ls","cat","grep","sed","awk"
            };
            static const std::unordered_set<std::string> js_kw = {
                "abstract","arguments","async","await","break","case","catch","class","const","continue","debugger",
                "default","delete","do","else","enum","eval","export","extends","false","finally","for","from","function",
                "if","implements","import","in","instanceof","interface","let","new","null","package","private","protected",
                "public","return","static","super","switch","this","throw","true","try","typeof","undefined","var","void",
                "while","with","yield","console","log","require","module","exports"
            };
            static const std::unordered_set<std::string> rust_kw = {
                "as","async","await","break","const","continue","crate","dyn","else","enum","extern","false","fn","for",
                "if","impl","in","let","loop","match","mod","move","mut","pub","ref","return","self","Self","static",
                "struct","super","trait","true","type","unsafe","use","where","while","Vec","String","Option","Result",
                "Some","None","Ok","Err","Box","Rc","Arc"
            };
            static const std::unordered_set<std::string> go_kw = {
                "break","case","chan","const","continue","default","defer","else","fallthrough","for","func","go","goto",
                "if","import","interface","map","package","range","return","select","struct","switch","type","var",
                "true","false","nil","iota","make","len","cap","append","copy","delete","panic","recover","print","println"
            };
            static const std::unordered_set<std::string> empty;

            if (lang == "cpp" || lang == "c") return cpp_kw;
            if (lang == "python") return py_kw;
            if (lang == "bash") return bash_kw;
            if (lang == "js") return js_kw;
            if (lang == "rust" || lang == "rs") return rust_kw;
            if (lang == "go") return go_kw;
            return empty;
        }

        auto line_comment_prefix(const std::string &lang) -> std::string_view
        {
            if (lang == "python" || lang == "bash") return "#";
            if (lang == "sql") return "--";
            return "//";
        }

        auto emit_seg(styled_line &out, std::string &buf,
                      const Term::Color &color, const theme_palette &th,
                      bool is_default = false)
        {
            if (buf.empty()) return;
            auto seg = styled_segment{};
            seg.text = std::move(buf);
            seg.fg = is_default ? th.code_text : color;
            out.push_back(std::move(seg));
            buf.clear();
        }
    }


    auto highlight_line(std::string_view line, std::string_view lang, const theme_palette &th) -> styled_line
    {
        auto norm = normalize_lang(lang);
        const auto &kw = keywords_for(norm);
        auto lc_prefix = line_comment_prefix(norm);

        auto out = styled_line{};
        auto buf = std::string{};
        auto i = std::size_t{0};
        auto n = line.size();
        auto default_color = th.code_text;

        auto flush_default = [&]() { emit_seg(out, buf, default_color, th, true); };

        // 行注释：消耗到行尾，命中后整体返回
        auto try_line_comment = [&]() -> bool
        {
            if (lc_prefix.empty() || i + lc_prefix.size() > n ||
                line.substr(i, lc_prefix.size()) != lc_prefix)
            {
                return false;
            }
            flush_default();
            auto seg = styled_segment{};
            seg.text = std::string{line.substr(i)};
            seg.fg = th.syn_comment;
            seg.italic = true;
            out.push_back(std::move(seg));
            return true;
        };

        // 块注释 /* */ — 仅处理单行内的
        auto try_block_comment = [&]() -> bool
        {
            if (line[i] != '/' || i + 1 >= n || line[i + 1] != '*') return false;
            flush_default();
            auto end = line.find("*/", i + 2);
            auto seg = styled_segment{};
            seg.text = std::string{line.substr(i, (end == std::string_view::npos ? n : end + 2) - i)};
            seg.fg = th.syn_comment;
            seg.italic = true;
            out.push_back(std::move(seg));
            i = (end == std::string_view::npos ? n : end + 2);
            return true;
        };

        // 字符串字面量
        auto try_string = [&]() -> bool
        {
            auto c = line[i];
            if (c != '"' && c != '\'' && c != '`') return false;
            flush_default();
            auto quote = c;
            auto start = i;
            ++i;
            while (i < n)
            {
                if (line[i] == '\\' && i + 1 < n) { i += 2; continue; }
                if (line[i] == quote) { ++i; break; }
                ++i;
            }
            auto seg = styled_segment{};
            seg.text = std::string{line.substr(start, i - start)};
            seg.fg = th.syn_string;
            out.push_back(std::move(seg));
            return true;
        };

        // 数字字面量
        auto try_number = [&]() -> bool
        {
            if (!is_digit(line[i]) || !buf.empty()) return false;
            flush_default();
            auto start = i;
            ++i;
            while (i < n && (is_digit(line[i]) || line[i] == '.' || line[i] == 'x' || line[i] == 'X' ||
                   std::isxdigit(static_cast<unsigned char>(line[i])) || line[i] == 'f' || line[i] == 'F' ||
                   line[i] == 'l' || line[i] == 'L' || line[i] == 'u' || line[i] == 'U'))
            {
                ++i;
            }
            auto seg = styled_segment{};
            seg.text = std::string{line.substr(start, i - start)};
            seg.fg = th.syn_number;
            out.push_back(std::move(seg));
            return true;
        };

        // 标识符 / 关键字 / 函数名
        auto try_identifier = [&]() -> bool
        {
            if (!is_ident_start(line[i])) return false;
            flush_default();
            auto start = i;
            while (i < n && is_ident_char(line[i])) ++i;
            auto word = std::string{line.substr(start, i - start)};

            auto seg = styled_segment{};
            seg.text = word;
            // 查找下一个非空白字符判断是否函数调用
            auto j = i;
            while (j < n && std::isspace(static_cast<unsigned char>(line[j]))) ++j;

            if (kw.count(word) > 0)
            {
                seg.fg = th.syn_keyword;
                seg.bold = true;
            }
            else if (j < n && line[j] == '(')
            {
                seg.fg = th.syn_function;
            }
            else
            {
                seg.fg = th.code_text;
            }
            out.push_back(std::move(seg));
            return true;
        };

        // 运算符
        auto try_operator = [&]() -> bool
        {
            if (!is_operator(line[i])) return false;
            flush_default();
            auto start = i;
            while (i < n && is_operator(line[i])) ++i;
            auto seg = styled_segment{};
            seg.text = std::string{line.substr(start, i - start)};
            seg.fg = th.syn_operator;
            out.push_back(std::move(seg));
            return true;
        };

        // 标点
        auto try_punct = [&]() -> bool
        {
            auto c = line[i];
            if (!is_punct(c)) return false;
            flush_default();
            auto seg = styled_segment{};
            seg.text = std::string{1, c};
            seg.fg = th.syn_punct;
            out.push_back(std::move(seg));
            ++i;
            return true;
        };

        while (i < n)
        {
            if (try_line_comment()) return out;
            if (try_block_comment()) continue;
            if (try_string()) continue;
            if (try_number()) continue;
            if (try_identifier()) continue;
            if (try_operator()) continue;
            if (try_punct()) continue;

            // 默认（含空白）
            buf.push_back(line[i]);
            ++i;
        }

        flush_default();
        return out;
    }

} // namespace sec::tui
