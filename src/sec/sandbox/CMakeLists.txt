target_sources(${PROJECT_NAME}_static_library
    PUBLIC FILE_SET public_headers TYPE HEADERS
    BASE_DIRS ${PROJECT_SOURCE_DIR}/include
    FILES
        ${PROJECT_SOURCE_DIR}/include/sec/sandbox/types.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/sandbox/vm_backend.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/sandbox/virtualbox.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/sandbox/qemu.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/sandbox/hyperv.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/sandbox/monitor.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/sandbox/etw_monitor.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/sandbox/strace_monitor.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/sandbox/vmi_monitor.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/sandbox/analyzer.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/sandbox/report.hpp
    PRIVATE
        virtualbox.cpp
        qemu.cpp
        hyperv.cpp
        etw_monitor.cpp
        strace_monitor.cpp
        vmi_monitor.cpp
        analyzer.cpp
        report.cpp
)
