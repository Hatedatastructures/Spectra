// 告警时间线 QML 模型实现

#include <sec/qt/alert_model.hpp>

#include <algorithm>


namespace sec::qt
{


    // 严重程度排序权重（越高越严重）
    static auto severity_rank(const QString &sev) -> int
    {
        if (sev == QStringLiteral("critical")) { return 4; }
        if (sev == QStringLiteral("high"))     { return 3; }
        if (sev == QStringLiteral("medium"))   { return 2; }
        if (sev == QStringLiteral("low"))      { return 1; }
        if (sev == QStringLiteral("info"))     { return 0; }
        return -1;
    }


    // 构造告警模型，设定最大保留条目数
    alert_model::alert_model(QObject *parent, int max_entries)
        : QAbstractListModel{parent}
        , max_entries_{max_entries}
    {
    }


    // 返回告警条目行数
    [[nodiscard]] auto alert_model::rowCount(const QModelIndex &parent) const -> int
    {
        if (parent.isValid())
        {
            return 0;
        }
        auto lock = std::lock_guard{mutex_};
        return entries_.size();
    }


    // 根据角色返回指定索引的告警数据
    [[nodiscard]] auto alert_model::data(const QModelIndex &index, int role) const -> QVariant
    {
        if (!index.isValid())
        {
            return {};
        }

        auto lock = std::lock_guard{mutex_};
        if (index.row() < 0 || index.row() >= entries_.size())
        {
            return {};
        }

        const auto &entry = entries_[index.row()];

        switch (role)
        {
        case category:
            return entry.category;
        case severity:
            return entry.severity;
        case source_ip:
            return entry.source_ip;
        case target_ip:
            return entry.target_ip;
        case description:
            return entry.description;
        case rule_id:
            return entry.rule_id;
        case confidence:
            return entry.confidence;
        case timestamp:
            return static_cast<qint64>(entry.timestamp);
        case acknowledged:
            return entry.acknowledged;
        default:
            return {};
        }
    }


    // 返回 QML 可用的角色名称映射
    [[nodiscard]] auto alert_model::roleNames() const -> QHash<int, QByteArray>
    {
        return {
            {category,     "category"},
            {severity,     "severity"},
            {source_ip,    "source_ip"},
            {target_ip,    "target_ip"},
            {description,  "description"},
            {rule_id,      "rule_id"},
            {confidence,   "confidence"},
            {timestamp,    "timestamp"},
            {acknowledged, "acknowledged"},
        };
    }


    // 返回当前告警总数
    [[nodiscard]] auto alert_model::alertCount() const -> int
    {
        auto lock = std::lock_guard{mutex_};
        return entries_.size();
    }


    // 返回未确认告警数
    [[nodiscard]] auto alert_model::unacknowledgedCount() const -> int
    {
        auto lock = std::lock_guard{mutex_};
        return unacknowledged_count_;
    }


    // 返回最高严重程度字符串
    [[nodiscard]] auto alert_model::highestSeverity() const -> QString
    {
        auto lock = std::lock_guard{mutex_};
        return highest_severity_;
    }


    // 追加一个告警条目（线程安全槽）
    void alert_model::appendAlert(alert_entry entry)
    {
        auto lock = std::lock_guard{mutex_};

        beginInsertRows(QModelIndex(), 0, 0);
        entries_.prepend(std::move(entry));
        endInsertRows();

        // 超出容量时移除尾部（最旧）条目
        while (entries_.size() > max_entries_)
        {
            beginRemoveRows(QModelIndex(), entries_.size() - 1, entries_.size() - 1);
            if (!entries_.last().acknowledged)
            {
                --unacknowledged_count_;
            }
            entries_.removeLast();
            endRemoveRows();
        }

        recalc_stats();
    }


    // 确认指定索引的告警
    void alert_model::acknowledge(int row)
    {
        auto lock = std::lock_guard{mutex_};

        if (row < 0 || row >= entries_.size())
        {
            return;
        }

        if (!entries_[row].acknowledged)
        {
            entries_[row].acknowledged = true;
            --unacknowledged_count_;
            auto idx = index(row);
            emit dataChanged(idx, idx, {acknowledged});
            emit unacknowledgedCountChanged();
        }
    }


    // 确认所有告警
    void alert_model::acknowledgeAll()
    {
        auto lock = std::lock_guard{mutex_};

        for (auto &entry : entries_)
        {
            entry.acknowledged = true;
        }
        unacknowledged_count_ = 0;

        if (!entries_.isEmpty())
        {
            emit dataChanged(index(0), index(entries_.size() - 1), {acknowledged});
        }
        emit unacknowledgedCountChanged();
    }


    // 清除所有告警
    void alert_model::clear()
    {
        auto lock = std::lock_guard{mutex_};

        beginResetModel();
        entries_.clear();
        endResetModel();

        unacknowledged_count_ = 0;
        highest_severity_ = QStringLiteral("none");
        emit alertCountChanged();
        emit unacknowledgedCountChanged();
        emit highestSeverityChanged();
    }


    // 重新计算统计信息
    void alert_model::recalc_stats()
    {
        int unack = 0;
        int max_rank = -1;
        QString max_sev = QStringLiteral("none");

        for (const auto &entry : entries_)
        {
            if (!entry.acknowledged)
            {
                ++unack;
            }
            auto rank = severity_rank(entry.severity);
            if (rank > max_rank)
            {
                max_rank = rank;
                max_sev = entry.severity;
            }
        }

        auto old_unack = unacknowledged_count_;
        auto old_sev = highest_severity_;

        unacknowledged_count_ = unack;
        highest_severity_ = max_sev;

        if (old_unack != unacknowledged_count_)
        {
            emit unacknowledgedCountChanged();
        }
        if (old_sev != highest_severity_)
        {
            emit highestSeverityChanged();
        }
        emit alertCountChanged();
    }


} // namespace sec::qt
