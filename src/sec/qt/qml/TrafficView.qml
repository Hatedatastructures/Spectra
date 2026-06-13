/**
 * @file TrafficView.qml
 * @brief 实时流量数据包视图
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
                text: qsTr("Traffic Monitor")
                font.pixelSize: 18
                font.bold: true
                color: "#e0e0e0"
            }

            Item { Layout.fillWidth: true }

            Label {
                text: qsTr("Packets: ") + trafficModel.packetCount
                font.pixelSize: 12
                color: "#a0a0a0"
            }

            Switch {
                id: pauseSwitch
                text: qsTr("Pause")
                checked: trafficModel.paused
                onCheckedChanged: trafficModel.paused = checked
                palette.text: "#e0e0e0"
            }

            Button {
                text: qsTr("Clear")
                flat: true
                palette.buttonText: "#e94560"
                onClicked: trafficModel.clear()
            }
        }

        // 表头
        Rectangle {
            Layout.fillWidth: true
            height: 32
            radius: 4
            color: "#16213e"

            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: 12
                anchors.rightMargin: 12

                Label {
                    text: qsTr("No.")
                    font.pixelSize: 11
                    font.bold: true
                    color: "#a0a0a0"
                    Layout.preferredWidth: 50
                }
                Label {
                    text: qsTr("Time")
                    font.pixelSize: 11
                    font.bold: true
                    color: "#a0a0a0"
                    Layout.preferredWidth: 80
                }
                Label {
                    text: qsTr("Source")
                    font.pixelSize: 11
                    font.bold: true
                    color: "#a0a0a0"
                    Layout.preferredWidth: 180
                }
                Label {
                    text: qsTr("Destination")
                    font.pixelSize: 11
                    font.bold: true
                    color: "#a0a0a0"
                    Layout.preferredWidth: 180
                }
                Label {
                    text: qsTr("Protocol")
                    font.pixelSize: 11
                    font.bold: true
                    color: "#a0a0a0"
                    Layout.preferredWidth: 70
                }
                Label {
                    text: qsTr("Size")
                    font.pixelSize: 11
                    font.bold: true
                    color: "#a0a0a0"
                    Layout.preferredWidth: 60
                }
                Label {
                    text: qsTr("Info")
                    font.pixelSize: 11
                    font.bold: true
                    color: "#a0a0a0"
                    Layout.fillWidth: true
                }
            }
        }

        // 数据包列表
        ListView {
            id: trafficList
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            spacing: 2
            model: trafficModel

            delegate: Rectangle {
                width: trafficList.width
                height: 28
                radius: 3
                color: index % 2 === 0 ? "#0f3460" : "#16213e"
                opacity: 0.9

                RowLayout {
                    anchors.fill: parent
                    anchors.leftMargin: 12
                    anchors.rightMargin: 12

                    Label {
                        text: index + 1
                        font.pixelSize: 11
                        color: "#a0a0a0"
                        Layout.preferredWidth: 50
                    }
                    Label {
                        text: {
                            var ts = model.timestamp / 1000000;
                            return ts.toFixed(3);
                        }
                        font.pixelSize: 11
                        color: "#a0a0a0"
                        Layout.preferredWidth: 80
                    }
                    Label {
                        text: model.src_ip + ":" + model.src_port
                        font.pixelSize: 11
                        color: "#53d769"
                        Layout.preferredWidth: 180
                    }
                    Label {
                        text: model.dst_ip + ":" + model.dst_port
                        font.pixelSize: 11
                        color: "#4fc3f7"
                        Layout.preferredWidth: 180
                    }
                    Label {
                        text: model.protocol_name
                        font.pixelSize: 11
                        font.bold: true
                        color: model.protocol_name === "TCP" ? "#ff9800" :
                               model.protocol_name === "UDP" ? "#2196f3" :
                               model.protocol_name === "HTTP" ? "#e94560" :
                               model.protocol_name === "DNS" ? "#ab47bc" : "#e0e0e0"
                        Layout.preferredWidth: 70
                    }
                    Label {
                        text: model.payload_size + " B"
                        font.pixelSize: 11
                        color: "#a0a0a0"
                        Layout.preferredWidth: 60
                    }
                    Label {
                        text: model.info || ""
                        font.pixelSize: 11
                        color: "#a0a0a0"
                        Layout.fillWidth: true
                        elide: Text.ElideRight
                    }
                }
            }

            Label {
                anchors.centerIn: parent
                text: qsTr("No traffic captured")
                font.pixelSize: 16
                color: "#a0a0a0"
                visible: trafficList.count === 0
            }
        }
    }
}
