// 流量数据包 QML 模型实现

#include <sec/qt/traffic_model.hpp>

#include <algorithm>


namespace sec::qt
{


    // 构造流量模型，设定最大保留条目数
    traffic_model::traffic_model(QObject *parent, int max_entries)
        : QAbstractListModel{parent}
        , max_entries_{max_entries}
    {
    }


    // 返回流量条目行数
    [[nodiscard]] auto traffic_model::rowCount(const QModelIndex &parent) const -> int
    {
        if (parent.isValid())
        {
            return 0;
        }
        auto lock = std::lock_guard{mutex_};
        return entries_.size();
    }


    // 根据角色返回指定索引的流量数据
    [[nodiscard]] auto traffic_model::data(const QModelIndex &index, int role) const -> QVariant
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
        case src_ip:
            return entry.src_ip;
        case dst_ip:
            return entry.dst_ip;
        case src_port:
            return static_cast<int>(entry.src_port);
        case dst_port:
            return static_cast<int>(entry.dst_port);
        case protocol:
            return static_cast<int>(entry.protocol);
        case protocol_name:
            return entry.protocol_name;
        case timestamp:
            return static_cast<qint64>(entry.timestamp);
        case payload_size:
            return entry.payload_size;
        case info:
            return entry.info;
        default:
            return {};
        }
    }


    // 返回 QML 可用的角色名称映射
    [[nodiscard]] auto traffic_model::roleNames() const -> QHash<int, QByteArray>
    {
        return {
            {src_ip,         "src_ip"},
            {dst_ip,         "dst_ip"},
            {src_port,       "src_port"},
            {dst_port,       "dst_port"},
            {protocol,       "protocol"},
            {protocol_name,  "protocol_name"},
            {timestamp,      "timestamp"},
            {payload_size,   "payload_size"},
            {info,           "info"},
        };
    }


    // 返回当前包总数
    [[nodiscard]] auto traffic_model::packetCount() const -> int
    {
        auto lock = std::lock_guard{mutex_};
        return entries_.size();
    }


    // 返回是否暂停捕获
    [[nodiscard]] auto traffic_model::paused() const -> bool
    {
        return paused_;
    }


    // 设置暂停状态
    void traffic_model::setPaused(bool paused)
    {
        if (paused_ == paused)
        {
            return;
        }
        paused_ = paused;
        emit pausedChanged();
    }


    // 追加一个数据包条目（线程安全槽）
    void traffic_model::appendEntry(traffic_entry entry)
    {
        do_append(std::move(entry));
    }


    // 清除所有数据包
    void traffic_model::clear()
    {
        auto lock = std::lock_guard{mutex_};
        beginResetModel();
        entries_.clear();
        endResetModel();
        emit packetCountChanged();
    }


    // 内部追加实现，在列表头部插入并限制容量
    void traffic_model::do_append(traffic_entry entry)
    {
        auto lock = std::lock_guard{mutex_};

        if (paused_)
        {
            return;
        }

        beginInsertRows(QModelIndex(), 0, 0);
        entries_.prepend(std::move(entry));
        endInsertRows();

        // 超出容量时移除尾部（最旧）条目
        while (entries_.size() > max_entries_)
        {
            beginRemoveRows(QModelIndex(), entries_.size() - 1, entries_.size() - 1);
            entries_.removeLast();
            endRemoveRows();
        }

        emit packetCountChanged();
    }


} // namespace sec::qt
