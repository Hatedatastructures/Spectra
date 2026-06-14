target_sources(${PROJECT_NAME}_static_library
    PUBLIC FILE_SET public_headers TYPE HEADERS
    BASE_DIRS ${PROJECT_SOURCE_DIR}/include
    FILES
        ${PROJECT_SOURCE_DIR}/include/sec/mitm.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/mitm/arp.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/mitm/dns.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/mitm/tls.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/mitm/pipeline.hpp
    PRIVATE
        arp.cpp
        dns.cpp
        tls.cpp
        pipeline.cpp
)
