cmake_minimum_required(VERSION 3.14)
project(chacha
    VERSION 1.0.0
    LANGUAGES CXX
)

include(CMakePackageConfigHelpers)
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

install(
    DIRECTORY
        "include/"
    DESTINATION
        "${CMAKE_INSTALL_INCLUDEDIR}"
)

install(
    TARGETS
        chacha
    EXPORT
        ChachaTargets
    DESTINATION
        "${CMAKE_INSTALL_LIBDIR}"
)

set(CHACHA_CMAKE_CONFIG_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/Chacha")

install(
    EXPORT
        ChachaTargets
    NAMESPACE
        Chacha::
    DESTINATION
        "${CHACHA_CMAKE_CONFIG_DESTINATION}"
)

configure_package_config_file(
    "${CMAKE_CURRENT_LIST_DIR}/cmake/ChachaConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/ChachaConfig.cmake"
    INSTALL_DESTINATION
        "${CHACHA_CMAKE_CONFIG_DESTINATION}"
)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/ChachaConfigVersion.cmake"
    COMPATIBILITY
        SameMajorVersion
    ARCH_INDEPENDENT
)

install(
    FILES
        "${CMAKE_CURRENT_BINARY_DIR}/ChachaConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/ChachaConfigVersion.cmake"
    DESTINATION
        "${CHACHA_CMAKE_CONFIG_DESTINATION}"
)