target_sources(${PROJECT_NAME}_static_library
    PUBLIC FILE_SET public_headers TYPE HEADERS
    BASE_DIRS ${PROJECT_SOURCE_DIR}/include
    FILES
        ${PROJECT_SOURCE_DIR}/include/sec/store.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/store/database.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/store/model.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/store/migration.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/store/query.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/store/persist.hpp
    PRIVATE
        database.cpp
        migration.cpp
        query.cpp
        persist.cpp
)
