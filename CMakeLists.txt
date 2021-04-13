cmake_minimum_required(VERSION 3.17)
project(FileViewer C)

set(CMAKE_C_STANDARD 99)

add_executable(FileViewer cmake-build-debug/PEView/main.c cmake-build-debug/PEView/PE.h cmake-build-debug/PEView/printInfo.c cmake-build-debug/PEView/PEHeader.c)