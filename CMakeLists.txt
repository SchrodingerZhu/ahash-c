cmake_minimum_required(VERSION 3.17)
project(ahash C)

set(CMAKE_C_STANDARD 11)
include_directories(.)
if(NOT MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror")
endif()
add_library(ahash ahash.c random_state.c)
add_executable(test_aes tests/test_aes.c)
target_link_libraries(test_aes ahash)
add_test(ahash-test test_aes)
enable_testing()