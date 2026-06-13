target_sources(${PROJECT_NAME}_static_library
    PUBLIC FILE_SET public_headers TYPE HEADERS
    BASE_DIRS ${PROJECT_SOURCE_DIR}/include
    FILES
        ${PROJECT_SOURCE_DIR}/include/sec/decoder.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/decoder/frame.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/decoder/util.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/decoder/http.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/decoder/dns.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/decoder/tls.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/decoder/socks5.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/decoder/ssh.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/decoder/ftp.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/decoder/smtp.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/decoder/pipeline.hpp
    PRIVATE
        frame.cpp
        http.cpp
        dns.cpp
        tls.cpp
        socks5.cpp
        ssh.cpp
        ftp.cpp
        smtp.cpp
        pipeline.cpp
)
