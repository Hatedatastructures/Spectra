target_sources(${PROJECT_NAME}_static_library
    PUBLIC FILE_SET public_headers TYPE HEADERS
    BASE_DIRS ${PROJECT_SOURCE_DIR}/include
    FILES
        ${PROJECT_SOURCE_DIR}/include/sec/tui/tui.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/tui/application.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/tui/chat.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/tui/markdown.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/tui/command.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/tui/components/chat.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/tui/components/input.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/tui/components/side.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/tui/components/status.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/tui/layout.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/tui/event.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/tui/input.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/tui/terminal.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/tui/theme.hpp
        ${PROJECT_SOURCE_DIR}/include/sec/tui/syntax.hpp
    PRIVATE
        application.cpp
        chat.cpp
        markdown.cpp
        syntax.cpp
        command.cpp
        components/chat.cpp
        components/input.cpp
        components/side.cpp
        components/status.cpp
        layout.cpp
        event.cpp
        input.cpp
        terminal.cpp
        theme.cpp
)

# cmark-gfm 使用 include_directories() 而非 target_include_directories()，
# 不会自动传递；需要手动添加其头文件路径
target_include_directories(${PROJECT_NAME}_static_library
    PRIVATE
        ${cmark_gfm_SOURCE_DIR}/src
        ${cmark_gfm_BINARY_DIR}/src
        ${cmark_gfm_SOURCE_DIR}/extensions
        ${cmark_gfm_BINARY_DIR}/extensions
)

target_link_libraries(${PROJECT_NAME}_static_library
    PUBLIC
        cpp-terminal::cpp-terminal
        libcmark-gfm-extensions_static
        libcmark-gfm_static
        libcmark-gfm_static
)
