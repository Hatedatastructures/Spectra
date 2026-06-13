/**
 * @file traffic_model.hpp
 * @brief 流量数据包 QML 模型
 * @details 将解码后的数据包信息暴露给 QML ListView，
 * 支持实时追加和容量限制的环形缓冲。
 */

#pragma once

#include <QAbstractListModel>
#include <QList>
#include <QString>

#include <chrono>
#include <cstdint>
#include <mutex>


namespace sec::qt
{

    /**
     * @brief 流量数据包条目
     * @details 存储单个数据包的显示信息，
     * 由解码管线回调填充。
     */
    struct traffic_entry
    {
        /** @brief 源 IP */
        QString src_ip;
        /** @brief 目的 IP */
        QString dst_ip;
        /** @brief 源端口 */
        std::uint16_t src_port{0};
        /** @brief 目的端口 */
        std::uint16_t dst_port{0};
        /** @brief 协议号 */
        std::uint8_t protocol{0};
        /** @brief 协议名称，如 "TCP"、"UDP"、"HTTP" */
        QString protocol_name;
        /** @brief 捕获时间戳，Unix 纪元微秒 */
        std::int64_t timestamp{0};
        /** @brief 载荷大小（字节） */
        std::int32_t payload_size{0};
        /** @brief 解码信息，如 HTTP host、DNS query */
        QString info;
    };


    /**
     * @brief 流量数据包 QML 列表模型
     * @details 环形缓冲区实现，支持实时追加数据包并限制最大条目数。
     * 通过 QMetaObject::invokeMethod 实现跨线程安全更新。
     * 新数据包插入到列表头部（最新在前）。
     */
    class traffic_model : public QAbstractListModel
    {
        Q_OBJECT

        /** @brief 当前包总数（QML 绑定） */
        Q_PROPERTY(int packetCount READ packetCount NOTIFY packetCountChanged)
        /** @brief 是否暂停捕获（QML 绑定） */
        Q_PROPERTY(bool paused READ paused WRITE setPaused NOTIFY pausedChanged)

    public:
        enum roles
        {
            src_ip = Qt::UserRole + 1,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            protocol_name,
            timestamp,
            payload_size,
            info
        };

        /**
         * @brief 构造流量模型
         * @param parent 父对象
         * @param max_entries 最大保留条目数，默认 2000
         */
        explicit traffic_model(QObject *parent = nullptr, int max_entries = 2000);

        [[nodiscard]] auto rowCount(const QModelIndex &parent = {}) const -> int override;
        [[nodiscard]] auto data(const QModelIndex &index, int role) const -> QVariant override;
        [[nodiscard]] auto roleNames() const -> QHash<int, QByteArray> override;

        /** @brief 返回当前包总数 */
        [[nodiscard]] auto packetCount() const -> int;

        /** @brief 返回是否暂停 */
        [[nodiscard]] auto paused() const -> bool;

        /** @brief 设置暂停状态 */
        void setPaused(bool paused);

        /**
         * @brief 追加一个数据包条目
         * @param entry 数据包信息
         * @note 线程安全，通过 QMetaObject::invokeMethod 调用
         */
        Q_SLOT void appendEntry(traffic_entry entry);

        /** @brief 清除所有数据包 */
        Q_SLOT void clear();

    signals:
        void packetCountChanged();
        void pausedChanged();

    private:
        void do_append(traffic_entry entry);

        QList<traffic_entry> entries_;
        int max_entries_;
        bool paused_{false};
        mutable std::mutex mutex_;
    };


} // namespace sec::qt
