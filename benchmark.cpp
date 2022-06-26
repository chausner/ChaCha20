#include "chacha.hpp"

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <vector>

using namespace chausner;

template<int rounds>
void benchmark(size_t buffer_size, size_t iterations) {
    std::vector<uint8_t> key(32);
    std::vector<uint8_t> nonce(8);
    Chacha<rounds> chacha(key.data(), nonce.data());

    auto start = std::chrono::high_resolution_clock::now();

    std::vector<uint8_t> buffer(buffer_size);

    for (size_t i = 0; i < iterations; i++) {        
        chacha.crypt(buffer.data(), buffer.size());
    }

    auto elapsed = std::chrono::high_resolution_clock::now() - start;
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();

    double mb_per_second = buffer.size() * iterations / 1024.0 / 1024.0 / (elapsed_ms / 1000.0);

    std::cout << "Rounds: " << rounds << std::endl;
    std::cout << "Elapsed: " << elapsed_ms << "ms" << std::endl;
    std::cout << "Speed: " << mb_per_second << "MB/s" << std::endl;
}

void benchmark_all_variants(size_t buffer_size, size_t iterations) {
    benchmark<20>(buffer_size, iterations);
    benchmark<12>(buffer_size, iterations);
    benchmark<8>(buffer_size, iterations);
}

int main() {
    benchmark_all_variants(128 * 1024, 100000);

    return 0;
}
