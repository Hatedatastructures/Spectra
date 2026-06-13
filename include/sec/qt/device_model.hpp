/**
 * @file device_model.hpp
 * @brief 设备列表 QML 模型
 * @details 将 store::device_record 数据暴露给 QML ListView，
 * 通过 QMetaObject::invokeMethod 实现线程安全更新。
 */

#pragma once

#include <QAbstractListModel>
#include <QList>
#include <QString>
#include <QStringList>

#include <sec/store/model.hpp>

#include <mutex>


namespace sec::qt
{

    /**
     * @brief 设备列表 QML 模型
     * @details 将 store::device_record 数据暴露给 QML ListView，
     * 通过 QMetaObject::invokeMethod 实现跨线程安全更新。
     * 支持 IP/MAC/主机名/厂商/OS/端口/时间/网关等角色。
     */
    class device_model : public QAbstractListModel
    {
        Q_OBJECT

    public:
        enum roles
        {
            ip_address = Qt::UserRole + 1,
            mac_address,
            hostname,
            vendor,
            os_guess,
            open_ports,
            first_seen,
            last_seen,
            is_gateway
        };

        explicit device_model(QObject *parent = nullptr);

        [[nodiscard]] auto rowCount(const QModelIndex &parent = {}) const -> int override;
        [[nodiscard]] auto data(const QModelIndex &index, int role) const -> QVariant override;
        [[nodiscard]] auto roleNames() const -> QHash<int, QByteArray> override;

        void update_devices(std::vector<store::device_record> devices);

    private:
        std::vector<store::device_record> devices_;
        mutable std::mutex mutex_;
    };


} // namespace sec::qt
