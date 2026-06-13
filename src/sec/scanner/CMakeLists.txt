target_sources(${PROJECT_NAME}_static_library
    PUBLIC FILE_SET public_headers TYPE HEADERS
    BASE_DIRS ${PROJECT_SOURCE_DIR}/include
    FILES
        ${PROJECT_SOURCE_DIR}/include/sec/scanner.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/scanner/device.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/scanner/arp_scanner.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/scanner/mdns_scanner.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/scanner/ssdp_scanner.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/scanner/port_scanner.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/scanner/fingerprint.hpp
    PRIVATE
        arp_scanner.cpp
        mdns_scanner.cpp
        ssdp_scanner.cpp
        port_scanner.cpp
        fingerprint.cpp
)

if(WIN32)
    target_link_libraries(${PROJECT_NAME}_static_library PUBLIC iphlpapi)
endif()
