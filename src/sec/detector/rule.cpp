// 规则引擎实现

#include <sec/detector/rule.hpp>

#include <algorithm>
#include <cctype>


namespace sec::detector
{


    void rule_engine::add_rule(rule r)
    {
        rules_.push_back(std::move(r));
    }


    auto rule_engine::remove_rule(const std::string &id) -> bool
    {
        auto it = std::find_if(rules_.begin(), rules_.end(),
            [&id](const rule &r) { return r.id == id; });

        if (it != rules_.end())
        {
            rules_.erase(it);
            threshold_counters_.erase(id);
            cooldown_.erase(id);
            return true;
        }
        return false;
    }


    [[nodiscard]] auto rule_engine::match(const decoder::packet_info &frame,
        std::span<const std::byte> payload) -> std::vector<alert>
    {
        std::vector<alert> result;

        for (const auto &r : rules_)
        {
            if (!r.enabled)
            {
                continue;
            }

            // 协议匹配
            bool proto_match = false;
            switch (r.protocol)
            {
            case rule_protocol::tcp:
                proto_match = (frame.protocol == 6);
                break;
            case rule_protocol::udp:
                proto_match = (frame.protocol == 17);
                break;
            case rule_protocol::icmp:
                proto_match = (frame.protocol == 1);
                break;
            case rule_protocol::ip:
                proto_match = true;
                break;
            }

            if (!proto_match)
            {
                continue;
            }

            // 地址和端口匹配
            if (!match_address(r.source, frame.src_ip, frame.src_port))
            {
                continue;
            }

            if (!match_address(r.destination, frame.dst_ip, frame.dst_port))
            {
                continue;
            }

            // 内容匹配
            bool content_match = true;
            for (const auto &opt : r.contents)
            {
                if (!match_content(opt, payload))
                {
                    content_match = false;
                    break;
                }
            }

            if (!content_match)
            {
                continue;
            }

            // 规则匹配成功，检查阈值
            if (!check_threshold(r))
            {
                continue;
            }

            // 产生告警
            alert a;
            a.level = r.level;
            a.type = r.type;
            a.source_ip = decoder::ip_to_string(frame.src_ip);
            a.target_ip = decoder::ip_to_string(frame.dst_ip);
            a.description = r.message;
            a.rule_id = r.id;
            a.detected_at = std::chrono::steady_clock::now();
            result.push_back(std::move(a));
        }

        return result;
    }


    [[nodiscard]] auto rule_engine::rule_count() const noexcept -> std::size_t
    {
        return rules_.size();
    }


    void rule_engine::clear()
    {
        rules_.clear();
        threshold_counters_.clear();
    }


    auto rule_engine::check_threshold(const rule &r) -> bool
    {
        // 阈值为 0 表示立即触发
        if (r.threshold_count <= 0 || r.threshold_seconds <= 0)
        {
            return true;
        }

        auto now = std::chrono::steady_clock::now();

        // 冷却期检查：60 秒内不重复触发同一规则
        constexpr std::chrono::seconds cooldown_period{60};
        auto cd_it = cooldown_.find(r.id);
        if (cd_it != cooldown_.end() && (now - cd_it->second) < cooldown_period)
        {
            return false;
        }

        auto &deque = threshold_counters_[r.id];

        // 清理超出时间窗口的旧记录
        const std::chrono::seconds window{r.threshold_seconds};
        while (!deque.empty() && (now - deque.front().when) > window)
        {
            deque.pop_front();
        }

        // 记录本次匹配
        deque.push_back({now});

        // 达到阈值才触发
        if (deque.size() < r.threshold_count)
        {
            return false;
        }

        // 触发后清空计数器并进入冷却期
        deque.clear();
        cooldown_[r.id] = now;
        return true;
    }


    auto rule_engine::match_address(const rule_address &addr, std::uint32_t ip,
        std::uint16_t port) const -> bool
    {
        if (addr.any)
        {
            return true;
        }

        // IP 匹配
        if (addr.mask > 0 && addr.mask < 32)
        {
            auto mask = static_cast<std::uint32_t>(
                ~((1ULL << (32 - addr.mask)) - 1));
            if ((ip & mask) != (addr.ip & mask))
            {
                return false;
            }
        }
        else if (addr.ip != 0 && addr.ip != ip)
        {
            return false;
        }

        // 端口匹配
        if (addr.port != 0 && addr.port != port)
        {
            return false;
        }

        return true;
    }


    auto rule_engine::match_content(const content_option &opt,
        std::span<const std::byte> payload) const -> bool
    {
        if (opt.pattern.empty())
        {
            return true;
        }

        // 确定搜索范围
        auto start = std::size_t{0};
        auto end = payload.size();

        if (opt.offset >= 0)
        {
            start = static_cast<std::size_t>(opt.offset);
        }

        if (opt.depth >= 0)
        {
            end = std::min(end, start + static_cast<std::size_t>(opt.depth));
        }

        if (start >= payload.size() || end <= start)
        {
            return false;
        }

        auto search_len = end - start;
        auto pat_len = opt.pattern.size();

        if (pat_len > search_len)
        {
            return false;
        }

        // 简单字节搜索
        for (std::size_t i = start; i + pat_len <= end; ++i)
        {
            bool found = true;
            for (std::size_t j = 0; j < pat_len; ++j)
            {
                auto pkt_byte = static_cast<char>(payload[i + j]);
                auto pat_byte = opt.pattern[j];

                if (opt.nocase)
                {
                    if (std::tolower(static_cast<unsigned char>(pkt_byte)) !=
                        std::tolower(static_cast<unsigned char>(pat_byte)))
                    {
                        found = false;
                        break;
                    }
                }
                else
                {
                    if (pkt_byte != pat_byte)
                    {
                        found = false;
                        break;
                    }
                }
            }
            if (found)
            {
                return true;
            }
        }

        return false;
    }


} // namespace sec::detector
