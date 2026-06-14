target_sources(${PROJECT_NAME}_static_library
    PUBLIC FILE_SET public_headers TYPE HEADERS
    BASE_DIRS ${PROJECT_SOURCE_DIR}/include
    FILES
        ${PROJECT_SOURCE_DIR}/include/sec/detector.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/detector/alert.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/detector/rule.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/detector/anomaly.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/detector/forest.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/detector/pipeline.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/detector/port_scan.hpp
    PRIVATE
        alert.cpp
        rule.cpp
        anomaly.cpp
        forest.cpp
        pipeline.cpp
        port_scan.cpp
)
