cmake_minimum_required(VERSION 3.5)
project(chacha
    VERSION 1.0.0
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED 11)

include(CTest)
include(GNUInstallDirs)

add_library(chacha INTERFACE)

target_include_directories(chacha 
    INTERFACE 
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()
