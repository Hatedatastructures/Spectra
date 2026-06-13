target_sources(${PROJECT_NAME}_static_library
    PUBLIC FILE_SET public_headers TYPE HEADERS
    BASE_DIRS ${PROJECT_SOURCE_DIR}/include
    FILES
        ${PROJECT_SOURCE_DIR}/include/sec/detector.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/detector/alert.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/detector/rule_engine.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/detector/anomaly.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/detector/detection_pipeline.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/detector/port_scan_detector.hpp
    PRIVATE
        alert.cpp
        rule_engine.cpp
        anomaly.cpp
        detection_pipeline.cpp
        port_scan_detector.cpp
)
