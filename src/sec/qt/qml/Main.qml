/**
 * @file Main.qml
 * @brief Spectra 主窗口
 */

import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

ApplicationWindow {
    id: root
    visible: true
    width: 1280
    height: 800
    title: "Spectra"
    color: "#1a1a2e"

    header: ToolBar {
        background: Rectangle {
            color: "#16213e"
        }

        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: 16
            anchors.rightMargin: 16

            Label {
                text: "Spectra"
                font.pixelSize: 20
                font.bold: true
                color: "#e94560"
            }

            Label {
                text: qsTr("LAN Security Situational Awareness")
                font.pixelSize: 12
                color: "#a0a0a0"
                Layout.leftMargin: 8
            }

            Item { Layout.fillWidth: true }

            Button {
                text: qsTr("Devices")
                flat: true
                palette.buttonText: stackView.currentItem === devicePage ? "#e94560" : "#e0e0e0"
                onClicked: stackView.replace(devicePage)
            }
            Button {
                text: qsTr("Traffic")
                flat: true
                palette.buttonText: stackView.currentItem === trafficPage ? "#e94560" : "#e0e0e0"
                onClicked: stackView.replace(trafficPage)
            }
            Button {
                text: qsTr("Alerts")
                flat: true
                palette.buttonText: stackView.currentItem === alertPage ? "#e94560" : "#e0e0e0"
                onClicked: stackView.replace(alertPage)

                Rectangle {
                    anchors.top: parent.top
                    anchors.right: parent.right
                    width: 8
                    height: 8
                    radius: 4
                    color: "#e94560"
                    visible: alertModel.unacknowledgedCount > 0
                }
            }
        }
    }

    StackView {
        id: stackView
        anchors.fill: parent
        initialItem: devicePage
    }

    Component {
        id: devicePage

        Rectangle {
            color: "#1a1a2e"

            ListView {
                id: deviceList
                anchors.fill: parent
                anchors.margins: 16
                spacing: 4
                clip: true
                model: deviceModel

                delegate: Rectangle {
                    width: deviceList.width
                    height: 64
                    radius: 6
                    color: mouseArea.containsMouse ? "#16213e" : "#0f3460"
                    opacity: 0.9

                    MouseArea {
                        id: mouseArea
                        anchors.fill: parent
                        hoverEnabled: true
                    }

                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: 16
                        anchors.rightMargin: 16

                        Rectangle {
                            width: 8
                            height: 8
                            radius: 4
                            color: model.is_gateway ? "#e94560" : "#53d769"
                            Layout.alignment: Qt.AlignVCenter
                        }

                        ColumnLayout {
                            spacing: 2
                            Layout.fillWidth: true

                            Label {
                                text: model.hostname || model.ip_address
                                font.pixelSize: 14
                                font.bold: true
                                color: "#e0e0e0"
                            }

                            Label {
                                text: model.ip_address + "  |  " + model.mac_address
                                font.pixelSize: 11
                                color: "#a0a0a0"
                            }
                        }

                        Label {
                            text: model.vendor
                            font.pixelSize: 11
                            color: "#a0a0a0"
                            Layout.alignment: Qt.AlignVCenter
                        }

                        Label {
                            text: model.os_guess
                            font.pixelSize: 11
                            color: "#a0a0a0"
                            Layout.alignment: Qt.AlignVCenter
                        }

                        Label {
                            text: model.open_ports
                            font.pixelSize: 11
                            color: "#e94560"
                            Layout.alignment: Qt.AlignVCenter
                        }
                    }
                }

                Label {
                    anchors.centerIn: parent
                    text: qsTr("No devices discovered")
                    font.pixelSize: 16
                    color: "#a0a0a0"
                    visible: deviceList.count === 0
                }
            }
        }
    }

    Component {
        id: trafficPage
        TrafficView {}
    }

    Component {
        id: alertPage
        AlertTimeline {}
    }

    footer: ToolBar {
        background: Rectangle {
            color: "#16213e"
        }

        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: 16
            anchors.rightMargin: 16

            Label {
                text: qsTr("Ready")
                font.pixelSize: 11
                color: "#a0a0a0"
            }

            Item { Layout.fillWidth: true }

            Label {
                text: qsTr("Packets: ") + trafficModel.packetCount +
                      qsTr("  |  Alerts: ") + alertModel.alertCount
                font.pixelSize: 11
                color: "#a0a0a0"
            }
        }
    }
}
