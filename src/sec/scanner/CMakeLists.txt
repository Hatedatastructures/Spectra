target_sources(${PROJECT_NAME}_static_library
    PUBLIC FILE_SET public_headers TYPE HEADERS
    BASE_DIRS ${PROJECT_SOURCE_DIR}/include
    FILES
        ${PROJECT_SOURCE_DIR}/include/sec/scanner.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/scanner/device.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/scanner/arp.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/scanner/mdns.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/scanner/ssdp.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/scanner/port.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/scanner/fingerprint.hpp
    PRIVATE
        arp.cpp
        mdns.cpp
        ssdp.cpp
        port.cpp
        fingerprint.cpp
)

if(WIN32)
    target_link_libraries(${PROJECT_NAME}_static_library PUBLIC iphlpapi)
endif()
