target_sources(${PROJECT_NAME}_static_library
    PUBLIC FILE_SET public_headers TYPE HEADERS
    BASE_DIRS ${PROJECT_SOURCE_DIR}/include
    FILES
        ${PROJECT_SOURCE_DIR}/include/sec/mitm.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/mitm/arp_detect.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/mitm/dns_detect.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/mitm/tls_detect.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/mitm/pipeline.hpp
    PRIVATE
        arp_detect.cpp
        dns_detect.cpp
        tls_detect.cpp
        pipeline.cpp
)
