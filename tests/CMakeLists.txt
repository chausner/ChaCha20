# tests target

find_package(Catch2 REQUIRED)

add_executable(tests
    src/main.cpp
    src/tests.cpp
)

target_link_libraries(tests
    PRIVATE
        chacha
        Catch2::Catch2
)

include(Catch)
catch_discover_tests(tests)

# benchmark target

add_executable(benchmark
    src/benchmark.cpp
)

target_link_libraries(benchmark
    PRIVATE
        chacha
)