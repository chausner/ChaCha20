cmake_minimum_required(VERSION 3.8)
project(chacha
    VERSION 1.0.0
    LANGUAGES CXX
)

include(CTest)
include(GNUInstallDirs)

add_library(chacha INTERFACE)

target_include_directories(chacha 
    INTERFACE 
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_compile_features(chacha INTERFACE cxx_std_11)

if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()
