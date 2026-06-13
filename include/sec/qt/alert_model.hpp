/**
 * @file alert_model.hpp
 * @brief 告警时间线 QML 模型
 * @details 将威胁告警数据暴露给 QML ListView，
 * 支持实时追加、严重程度过滤和确认操作。
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
     * @brief 告警条目
     * @details 存储单个告警的显示信息，
     * 由检测管线回调填充。
     */
    struct alert_entry
    {
        /** @brief 告警类别，如 "arp_spoofing"、"dns_hijack" */
        QString category;
        /** @brief 严重程度，如 "info"、"low"、"medium"、"high"、"critical" */
        QString severity;
        /** @brief 源 IP */
        QString source_ip;
        /** @brief 目标 IP */
        QString target_ip;
        /** @brief 告警描述 */
        QString description;
        /** @brief 匹配的规则 ID */
        QString rule_id;
        /** @brief 置信度 [0.0, 1.0] */
        double confidence{0.0};
        /** @brief 检测时间戳，Unix 纪元微秒 */
        std::int64_t timestamp{0};
        /** @brief 是否已确认 */
        bool acknowledged{false};
    };


    /**
     * @brief 告警时间线 QML 列表模型
     * @details 环形缓冲区实现，支持实时追加告警、按严重程度过滤。
     * 通过 QMetaObject::invokeMethod 实现跨线程安全更新。
     * 新告警插入到列表头部（最新在前）。
     */
    class alert_model : public QAbstractListModel
    {
        Q_OBJECT

        /** @brief 当前告警总数（QML 绑定） */
        Q_PROPERTY(int alertCount READ alertCount NOTIFY alertCountChanged)
        /** @brief 未确认告警数（QML 绑定） */
        Q_PROPERTY(int unacknowledgedCount READ unacknowledgedCount NOTIFY unacknowledgedCountChanged)
        /** @brief 最高严重程度（QML 绑定） */
        Q_PROPERTY(QString highestSeverity READ highestSeverity NOTIFY highestSeverityChanged)

    public:
        enum roles
        {
            category = Qt::UserRole + 1,
            severity,
            source_ip,
            target_ip,
            description,
            rule_id,
            confidence,
            timestamp,
            acknowledged
        };

        /**
         * @brief 构造告警模型
         * @param parent 父对象
         * @param max_entries 最大保留条目数，默认 500
         */
        explicit alert_model(QObject *parent = nullptr, int max_entries = 500);

        [[nodiscard]] auto rowCount(const QModelIndex &parent = {}) const -> int override;
        [[nodiscard]] auto data(const QModelIndex &index, int role) const -> QVariant override;
        [[nodiscard]] auto roleNames() const -> QHash<int, QByteArray> override;

        /** @brief 返回当前告警总数 */
        [[nodiscard]] auto alertCount() const -> int;

        /** @brief 返回未确认告警数 */
        [[nodiscard]] auto unacknowledgedCount() const -> int;

        /** @brief 返回最高严重程度字符串 */
        [[nodiscard]] auto highestSeverity() const -> QString;

        /**
         * @brief 追加一个告警条目
         * @param entry 告警信息
         * @note 线程安全，通过 QMetaObject::invokeMethod 调用
         */
        Q_SLOT void appendAlert(alert_entry entry);

        /**
         * @brief 确认指定索引的告警
         * @param row 行索引
         */
        Q_SLOT void acknowledge(int row);

        /** @brief 确认所有告警 */
        Q_SLOT void acknowledgeAll();

        /** @brief 清除所有告警 */
        Q_SLOT void clear();

    signals:
        void alertCountChanged();
        void unacknowledgedCountChanged();
        void highestSeverityChanged();

    private:
        void recalc_stats();

        QList<alert_entry> entries_;
        int max_entries_;
        int unacknowledged_count_{0};
        QString highest_severity_{QStringLiteral("none")};
        mutable std::mutex mutex_;
    };


} // namespace sec::qt
