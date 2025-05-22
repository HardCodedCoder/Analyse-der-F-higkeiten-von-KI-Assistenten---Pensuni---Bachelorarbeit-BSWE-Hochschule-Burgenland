cmake_minimum_required(VERSION 3.10)
project(BachelorThesisDemo VERSION 0.1.0 LANGUAGES C CXX)

include(CTest)
enable_testing()

file(GLOB_RECURSE SRC_FILES 
    src/*.cpp
    src/buffer_overflow/*.cpp
)

set(CMAKE_CXX_CLANG_TIDY "clang-tidy;-checks=*")


add_executable(BachelorThesisDemo ${SRC_FILES})

set_property(TARGET BachelorThesisDemo PROPERTY CXX_STANDARD 20)