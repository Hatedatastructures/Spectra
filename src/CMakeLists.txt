add_library(${PROJECT_NAME}_static_library STATIC)

target_include_directories(${PROJECT_NAME}_static_library
        PUBLIC
        ${PROJECT_SOURCE_DIR}/include
        ${boost_include_dir}
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(${PROJECT_NAME}_static_library
        PUBLIC
        spdlog::spdlog
        glaze::glaze
        Boost::system
        sqlite3_static
)

if(WIN32)
    target_link_libraries(${PROJECT_NAME}_static_library PUBLIC ws2_32 mswsock crypt32 wininet)
endif()

target_compile_definitions(${PROJECT_NAME}_static_library
        PUBLIC
        BOOST_ASIO_HEADER_ONLY
        BOOST_ASIO_DISABLE_VISIBILITY
)

if(WIN32)
    target_compile_definitions(${PROJECT_NAME}_static_library PUBLIC WIN32_LEAN_AND_MEAN)
endif()

# Qt6 暂时禁用 — 仅使用 CLI + TUI
# if(Qt6_FOUND)
#     target_link_libraries(${PROJECT_NAME}_static_library PUBLIC Qt6::Core Qt6::Gui Qt6::Quick)
# endif()

add_subdirectory(sec)

add_executable(${PROJECT_NAME}
        main.cpp
)

set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME "Spectra")

if(WIN32)
    # 通过 windres 编译资源脚本，嵌入 UAC manifest 实现 requireAdministrator 提权
    set(rc_file "${CMAKE_CURRENT_SOURCE_DIR}/app.rc")
    set(res_file "${CMAKE_CURRENT_BINARY_DIR}/app.res")
    find_program(WINDRES_EXECUTABLE windres HINTS ${_CMAKE_TOOLCHAIN_LOCATION})
    add_custom_command(
        OUTPUT "${res_file}"
        COMMAND ${WINDRES_EXECUTABLE} -o "${res_file}" "${rc_file}"
        DEPENDS "${rc_file}" "${CMAKE_CURRENT_SOURCE_DIR}/app.manifest"
        COMMENT "Compiling UAC manifest resource"
    )
    target_sources(${PROJECT_NAME} PRIVATE "${res_file}")
endif()

if(MINGW)
    target_link_options(${PROJECT_NAME} PRIVATE
            -static-libgcc
    )
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(${PROJECT_NAME} PRIVATE
            -g1
            -O1
    )
endif()

if(MINGW)
    target_compile_options(${PROJECT_NAME} PRIVATE -fno-keep-inline-dllexport)
endif()

target_link_libraries(${PROJECT_NAME}
        PRIVATE
        ${PROJECT_NAME}_static_library
)
