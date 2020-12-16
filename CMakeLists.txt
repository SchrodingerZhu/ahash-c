cmake_minimum_required(VERSION 3.17)
project(ahash C)

set(CMAKE_C_STANDARD 11)
include_directories(.)
add_library(ahash ahash.c)
add_executable(test_aes tests/test_aes.c)