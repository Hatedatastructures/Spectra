target_sources(${PROJECT_NAME}_static_library
    PUBLIC FILE_SET public_headers TYPE HEADERS
    BASE_DIRS ${PROJECT_SOURCE_DIR}/include
    FILES
        ${PROJECT_SOURCE_DIR}/include/sec/engine.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/engine/context.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/engine/scheduler.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/engine/capture.hpp
    PRIVATE
        capture.cpp
)
