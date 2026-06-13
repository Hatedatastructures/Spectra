// 设备列表 QML 模型实现

#include <sec/qt/device_model.hpp>

#include <QDateTime>

#include <algorithm>


namespace sec::qt
{

    // 构造设备列表模型
    device_model::device_model(QObject *parent)
        : QAbstractListModel{parent}
    {
    }


    // 返回设备列表行数
    [[nodiscard]] auto device_model::rowCount(const QModelIndex &parent) const -> int
    {
        if (parent.isValid())
        {
            return 0;
        }
        auto lock = std::lock_guard{mutex_};
        return static_cast<int>(devices_.size());
    }


    // 根据角色返回指定索引的设备数据
    [[nodiscard]] auto device_model::data(const QModelIndex &index, int role) const -> QVariant
    {
        if (!index.isValid())
        {
            return {};
        }

        auto lock = std::lock_guard{mutex_};
        if (index.row() < 0 || index.row() >= static_cast<int>(devices_.size()))
        {
            return {};
        }

        const auto &dev = devices_[static_cast<std::size_t>(index.row())];

        switch (role)
        {
        case ip_address:
            return QString::fromStdString(dev.ip_address);
        case mac_address:
            return QString::fromStdString(dev.mac_address);
        case hostname:
            return QString::fromStdString(dev.hostname);
        case vendor:
            return QString::fromStdString(dev.vendor);
        case os_guess:
            return QString::fromStdString(dev.os_guess);
        case open_ports:
            return QString::fromStdString(dev.open_ports);
        case first_seen:
            return QDateTime::fromSecsSinceEpoch(dev.first_seen);
        case last_seen:
            return QDateTime::fromSecsSinceEpoch(dev.last_seen);
        case is_gateway:
            return dev.is_gateway;
        default:
            return {};
        }
    }


    // 返回 QML 可用的角色名称映射
    [[nodiscard]] auto device_model::roleNames() const -> QHash<int, QByteArray>
    {
        return {
            {ip_address,  "ip_address"},
            {mac_address, "mac_address"},
            {hostname,    "hostname"},
            {vendor,      "vendor"},
            {os_guess,    "os_guess"},
            {open_ports,  "open_ports"},
            {first_seen,  "first_seen"},
            {last_seen,   "last_seen"},
            {is_gateway,  "is_gateway"},
        };
    }


    // 替换当前设备列表数据并通知 QML 刷新
    void device_model::update_devices(std::vector<store::device_record> devices)
    {
        auto lock = std::lock_guard{mutex_};

        beginResetModel();
        devices_ = std::move(devices);
        endResetModel();
    }


} // namespace sec::qt
