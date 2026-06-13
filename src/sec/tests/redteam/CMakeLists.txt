add_executable(redteam_test
    main.cpp
)

target_compile_options(redteam_test PRIVATE -g1 -Os)
target_link_libraries(redteam_test PRIVATE ${PROJECT_NAME}_static_library)

if(MINGW)
    target_link_options(redteam_test PRIVATE -static-libgcc)
endif()

# 不加入 ctest（红队测试是独立的，需要管理员权限运行主程序，这里只测试检测器逻辑）
# add_test(NAME redteam_test COMMAND redteam_test)
