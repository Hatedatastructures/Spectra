/**
 * @file AlertTimeline.qml
 * @brief 告警时间线视图
 */

import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

Rectangle {
    id: root
    color: "#1a1a2e"

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 16
        spacing: 8

        // 工具栏
        RowLayout {
            Layout.fillWidth: true

            Label {
                text: qsTr("Alert Timeline")
                font.pixelSize: 18
                font.bold: true
                color: "#e0e0e0"
            }

            Item { Layout.fillWidth: true }

            Rectangle {
                width: 12
                height: 12
                radius: 6
                color: {
                    var sev = alertModel.highestSeverity;
                    if (sev === "critical") return "#ff1744";
                    if (sev === "high")     return "#e94560";
                    if (sev === "medium")   return "#ff9800";
                    if (sev === "low")      return "#ffeb3b";
                    return "#53d769";
                }
                Layout.alignment: Qt.AlignVCenter
            }

            Label {
                text: qsTr("Alerts: ") + alertModel.alertCount +
                      qsTr("  Unacked: ") + alertModel.unacknowledgedCount
                font.pixelSize: 12
                color: "#a0a0a0"
            }

            Button {
                text: qsTr("Ack All")
                flat: true
                palette.buttonText: "#53d769"
                onClicked: alertModel.acknowledgeAll()
            }

            Button {
                text: qsTr("Clear")
                flat: true
                palette.buttonText: "#e94560"
                onClicked: alertModel.clear()
            }
        }

        // 告警列表
        ListView {
            id: alertList
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            spacing: 4
            model: alertModel

            delegate: Rectangle {
                width: alertList.width
                height: 72
                radius: 6
                color: {
                    if (model.acknowledged) return "#1a1a2e";
                    var sev = model.severity;
                    if (sev === "critical") return "#3d0011";
                    if (sev === "high")     return "#2d0a1e";
                    if (sev === "medium")   return "#2d1f0a";
                    if (sev === "low")      return "#2d2d0a";
                    return "#0a2d1f";
                }
                border.color: {
                    if (model.acknowledged) return "transparent";
                    var sev = model.severity;
                    if (sev === "critical") return "#ff1744";
                    if (sev === "high")     return "#e94560";
                    if (sev === "medium")   return "#ff9800";
                    if (sev === "low")      return "#ffeb3b";
                    return "#53d769";
                }
                border.width: model.acknowledged ? 0 : 1
                opacity: model.acknowledged ? 0.5 : 1.0

                RowLayout {
                    anchors.fill: parent
                    anchors.leftMargin: 16
                    anchors.rightMargin: 16

                    // 严重程度指示条
                    Rectangle {
                        width: 4
                        height: parent.height - 16
                        radius: 2
                        color: {
                            var sev = model.severity;
                            if (sev === "critical") return "#ff1744";
                            if (sev === "high")     return "#e94560";
                            if (sev === "medium")   return "#ff9800";
                            if (sev === "low")      return "#ffeb3b";
                            return "#53d769";
                        }
                        Layout.alignment: Qt.AlignVCenter
                    }

                    ColumnLayout {
                        spacing: 4
                        Layout.fillWidth: true

                        RowLayout {
                            spacing: 8

                            Label {
                                text: model.severity.toUpperCase()
                                font.pixelSize: 11
                                font.bold: true
                                color: {
                                    var sev = model.severity;
                                    if (sev === "critical") return "#ff1744";
                                    if (sev === "high")     return "#e94560";
                                    if (sev === "medium")   return "#ff9800";
                                    if (sev === "low")      return "#ffeb3b";
                                    return "#53d769";
                                }
                            }

                            Label {
                                text: model.category
                                font.pixelSize: 11
                                color: "#4fc3f7"
                            }

                            Label {
                                text: model.rule_id || ""
                                font.pixelSize: 11
                                color: "#a0a0a0"
                                visible: model.rule_id.length > 0
                            }

                            Item { Layout.fillWidth: true }

                            Label {
                                text: {
                                    var ts = model.timestamp / 1000000;
                                    return ts.toFixed(3);
                                }
                                font.pixelSize: 10
                                color: "#707070"
                            }
                        }

                        Label {
                            text: model.description
                            font.pixelSize: 12
                            color: "#e0e0e0"
                            Layout.fillWidth: true
                            elide: Text.ElideRight
                        }

                        RowLayout {
                            spacing: 16

                            Label {
                                text: qsTr("Source: ") + model.source_ip
                                font.pixelSize: 10
                                color: "#a0a0a0"
                            }

                            Label {
                                text: qsTr("Target: ") + model.target_ip
                                font.pixelSize: 10
                                color: "#a0a0a0"
                            }

                            Label {
                                text: model.confidence > 0 ?
                                    qsTr("Confidence: ") + (model.confidence * 100).toFixed(1) + "%" : ""
                                font.pixelSize: 10
                                color: "#a0a0a0"
                                visible: model.confidence > 0
                            }
                        }
                    }

                    Button {
                        text: model.acknowledged ? qsTr("Done") : qsTr("Ack")
                        flat: true
                        font.pixelSize: 10
                        palette.buttonText: model.acknowledged ? "#707070" : "#53d769"
                        enabled: !model.acknowledged
                        onClicked: alertModel.acknowledge(index)
                        Layout.alignment: Qt.AlignVCenter
                    }
                }
            }

            Label {
                anchors.centerIn: parent
                text: qsTr("No alerts")
                font.pixelSize: 16
                color: "#a0a0a0"
                visible: alertList.count === 0
            }
        }
    }
}
