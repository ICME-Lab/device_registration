cmake_minimum_required(VERSION 3.5.0)
project(add_client VERSION 0.1.0 LANGUAGES C)

option (COMPILE_LIB_SET "Set ioConnectCore compile to a Lib" ON)

include_directories(./libraries/core/src)

add_compile_options(-g -O0)

add_executable(add_client ./src/main.c)

add_subdirectory(./libraries/core)

if (COMPILE_LIB_SET)
    target_link_libraries(add_client ioConnectCore)
else()
    target_sources(add_client PRIVATE ${ioConnectCore_SRC})
endif()