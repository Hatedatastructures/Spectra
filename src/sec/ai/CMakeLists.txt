target_sources(${PROJECT_NAME}_static_library
    PUBLIC FILE_SET public_headers TYPE HEADERS
    BASE_DIRS ${PROJECT_SOURCE_DIR}/include
    FILES
        ${PROJECT_SOURCE_DIR}/include/sec/ai.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/ai/feature.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/ai/runtime.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/ai/model.hpp
    PRIVATE
        feature.cpp
        runtime.cpp
        model.cpp
)
