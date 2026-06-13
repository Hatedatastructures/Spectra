if(Qt6_FOUND)
    target_sources(${PROJECT_NAME}_static_library
        PUBLIC FILE_SET public_headers TYPE HEADERS
        BASE_DIRS ${PROJECT_SOURCE_DIR}/include
        FILES
            ${PROJECT_SOURCE_DIR}/include/sec/qt.hpp
            ${PROJECT_SOURCE_DIR}/include/sec/qt/application.hpp
            ${PROJECT_SOURCE_DIR}/include/sec/qt/device_model.hpp
            ${PROJECT_SOURCE_DIR}/include/sec/qt/traffic_model.hpp
            ${PROJECT_SOURCE_DIR}/include/sec/qt/alert_model.hpp
        PRIVATE
            application.cpp
            device_model.cpp
            traffic_model.cpp
            alert_model.cpp
            qml/qml.qrc
    )
endif()
