#include "chacha20.hpp"

#include <stdlib.h>
#include <chrono>
#include <iostream>
#include <vector>

int main(){
    std::vector<uint8_t> key(32);
    std::vector<uint8_t> nonce(8);
    Chacha20 chacha(key.data(), nonce.data());

    auto start = std::chrono::high_resolution_clock::now();

    std::vector<uint8_t> buffer(128 * 1024);
    int iterations = 100000;

    for (int i = 0; i < iterations; i++){        
        chacha.crypt(buffer.data(), buffer.size());
    }

    auto elapsed = std::chrono::high_resolution_clock::now() - start;
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();

    double mb_per_second = buffer.size() * iterations / 1024.0 / 1024.0 / (elapsed_ms / 1000.0);

    std::cout << "Elapsed: " << elapsed_ms << "ms" << std::endl;
    std::cout << "Speed: " << mb_per_second << "MB/s" << std::endl;

    return 0;
}
