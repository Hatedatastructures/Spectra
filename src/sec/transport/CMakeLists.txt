target_sources(${PROJECT_NAME}_static_library
    PUBLIC FILE_SET public_headers TYPE HEADERS
    BASE_DIRS ${PROJECT_SOURCE_DIR}/include
    FILES
        ${PROJECT_SOURCE_DIR}/include/sec/transport.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/transport/transmission.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/transport/raw.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/transport/pcap.hpp
    PRIVATE
        raw.cpp
        pcap.cpp
)

if(WIN32)
    target_include_directories(${PROJECT_NAME}_static_library
        PRIVATE ${NPCAP_INCLUDE_DIR}
    )
    target_link_libraries(${PROJECT_NAME}_static_library
        PRIVATE ${NPCAP_LIB_DIR}/wpcap.lib ${NPCAP_LIB_DIR}/Packet.lib
    )
endif()
