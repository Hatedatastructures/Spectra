target_sources(${PROJECT_NAME}_static_library
    PUBLIC FILE_SET public_headers TYPE HEADERS
    BASE_DIRS ${PROJECT_SOURCE_DIR}/include
    FILES
        ${PROJECT_SOURCE_DIR}/include/sec/sec.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/fault.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/fault/code.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/fault/compatible.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/fault/handling.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/exception.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/exception/deviant.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/exception/network.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/exception/protocol.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/exception/security.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/memory.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/memory/container.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/memory/pool.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/config.hpp
    PRIVATE
        config.cpp
)

add_subdirectory(transport)
add_subdirectory(engine)
add_subdirectory(decoder)
add_subdirectory(mitm)
add_subdirectory(detector)
add_subdirectory(ai)
add_subdirectory(scanner)
add_subdirectory(store)
add_subdirectory(tests)
add_subdirectory(cli)
add_subdirectory(tui)
