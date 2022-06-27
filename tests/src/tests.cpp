#include "chausner/chacha.hpp"

#include "catch2/catch.hpp"
#include <fstream>
#include <random>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

using namespace chausner;
using namespace Catch::Matchers;

typedef std::vector<uint8_t> Bytes;

Bytes hex_to_bytes(const std::string &hex) {
    const char *digits = "0123456789abcdefghijklmnopqrstuvwxyz";
    auto digit_value = [digits](char c) {
        return static_cast<uint8_t>(std::strchr(digits, c) - digits);
    };
    assert(hex.size() % 2 == 0);
    Bytes raw(hex.size() / 2);
    for (size_t i = 0; i < raw.size(); i++) {
        uint8_t high = digit_value(hex[i*2 + 0]);
        uint8_t low = digit_value(hex[i*2 + 1]);
        raw[i] = (high << 4) | low;
    }
    return raw;
}

std::vector<std::tuple<Bytes, Bytes, Bytes>> read_test_vectors(const char *path) {
    std::vector<std::tuple<Bytes, Bytes, Bytes>> test_vectors;
    std::ifstream file(path);
    if (!file.is_open()) {
        throw std::runtime_error(std::string("Could not open file ") + path);
    }
    for (std::string line; std::getline(file, line);) {        
        Bytes key = hex_to_bytes(line.substr(0, 64));
        Bytes nonce = hex_to_bytes(line.substr(65, 16));
        Bytes keystream = hex_to_bytes(line.substr(82));
        test_vectors.push_back(std::make_tuple(std::move(key), std::move(nonce), std::move(keystream)));
    }
    if (file.bad()) {
        throw std::runtime_error(std::string("Error reading from file ") + path);
    }
    return test_vectors;
}

template<typename Chacha>
Bytes get_keystream(bool inplace, const Bytes &key, const Bytes &nonce, size_t n_bytes) {
    Chacha chacha(key.data(), nonce.data());

    // Since Chacha just XORs the plaintext with the keystream,
    // we can feed it zeros and we will get the keystream.
    Bytes zeros(n_bytes, 0);
    Bytes cipher(zeros);    

    if (inplace) {
        chacha.encrypt_inplace(cipher.data(), cipher.size());
    } else {
        chacha.encrypt(zeros.data(), zeros.size(), cipher.data());
    }

    return cipher;
}

TEMPLATE_TEST_CASE("Keystream matches test vectors", "[keystream]", Chacha20, Chacha12, Chacha8) {
    bool inplace = GENERATE(false, true);
    CAPTURE(inplace);

    const char *test_vectors_path;
    if (std::is_same_v<TestType, Chacha20>) {
        test_vectors_path = "tests/res/test-vectors-20.csv";
    } else if (std::is_same_v<TestType, Chacha12>) {
        test_vectors_path = "tests/res/test-vectors-12.csv";
    } else if (std::is_same_v<TestType, Chacha8>) {
        test_vectors_path = "tests/res/test-vectors-8.csv";
    }

    auto test_vectors = read_test_vectors(test_vectors_path);

    Bytes key, nonce, expected_keystream;
    std::tie(key, nonce, expected_keystream) = GENERATE_COPY(from_range(test_vectors));

    Bytes keystream = get_keystream<TestType>(inplace, key, nonce, expected_keystream.size());
    
    REQUIRE_THAT(keystream, Equals(expected_keystream));
}

TEMPLATE_TEST_CASE("Calls to encrypt/encrypt_inplace with different buffer sizes always yield the same ciphertext", "[keystream]", Chacha20, Chacha12, Chacha8) {
    bool inplace = GENERATE(false, true);
    CAPTURE(inplace);

    uint8_t key[32] = {1, 2, 3, 4, 5, 6};
    uint8_t nonce[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    TestType chacha(key, nonce);

    Bytes plain(256, 0);

    Bytes expected_cipher(plain);
    chacha.encrypt_inplace(expected_cipher.data(), expected_cipher.size());

    for (size_t b1 = 0; b1 < plain.size(); b1++) {
        for (size_t b2 = 0; b1 + b2 < plain.size(); b2++) {
            size_t b3 = plain.size() - (b1 + b2);
            
            CAPTURE(b1);
            CAPTURE(b2);
            CAPTURE(b3);

            chacha.set_counter(0);
            Bytes cipher(plain);

            if (inplace) {
                chacha.encrypt_inplace(cipher.data(), b1);
                chacha.encrypt_inplace(cipher.data() + b1, b2);
                chacha.encrypt_inplace(cipher.data() + b1 + b2, b3);
            } else {
                chacha.encrypt(plain.data(), b1, cipher.data());
                chacha.encrypt(plain.data() + b1, b2, cipher.data() + b1);
                chacha.encrypt(plain.data() + b1 + b2, b3, cipher.data() + b1 + b2);
            }

            REQUIRE_THAT(cipher, Equals(expected_cipher));
        }
    }
}

TEMPLATE_TEST_CASE("Encrypting, then decrypting again yields the original plaintext", "[keystream]", Chacha20, Chacha12, Chacha8) {
    bool inplace = GENERATE(false, true);
    CAPTURE(inplace);

    // Generate a megabyte of random data.
    Bytes plain(1024 * 1024);
    std::mt19937 rand;
    std::uniform_int_distribution<int> dist(0, 255);
    for (size_t i = 0; i < plain.size(); i++) {
        plain[i] = static_cast<uint8_t>(dist(rand));
    }

    // Encrypt    
    uint8_t key[32] = {1, 2, 3, 4, 5, 6};
    uint8_t nonce[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    TestType chacha(key, nonce);
    Bytes cipher;
    if (inplace) {
        cipher = plain;
        chacha.encrypt_inplace(cipher.data(), cipher.size());
    } else {
        cipher.resize(plain.size());
        chacha.encrypt(plain.data(), plain.size(), cipher.data());
    }
    
    // Decrypt
    chacha = TestType(key, nonce);
    Bytes plain2;
    if (inplace) {
        plain2 = cipher;
        chacha.decrypt_inplace(plain2.data(), plain2.size());
    } else {
        plain2.resize(cipher.size());
        chacha.decrypt(cipher.data(), cipher.size(), plain2.data());
    }
    
    // Check if decrypt(encrypt(input)) == input.
    REQUIRE_THAT(plain2, Equals(plain));
}

TEMPLATE_TEST_CASE("Keystreams are identical when encrypting in normal and reverse order", "[keystream]", Chacha20, Chacha12, Chacha8) {
    bool inplace = GENERATE(false, true);
    CAPTURE(inplace);

    // Generate a kilobyte of random data.
    Bytes plain(1024);
    std::mt19937 rand;
    std::uniform_int_distribution<int> dist(0, 255);
    for (size_t i = 0; i < plain.size(); i++) {
        plain[i] = static_cast<uint8_t>(dist(rand));
    }

    // Encrypt buffer in normal order
    uint8_t key[32] = {1, 2, 3, 4, 5, 6};
    uint8_t nonce[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    TestType chacha(key, nonce);
    Bytes cipher;
    if (inplace) {
        cipher = plain;
        chacha.encrypt_inplace(cipher.data(), cipher.size());
    } else {
        cipher.resize(plain.size());
        chacha.encrypt(plain.data(), plain.size(), cipher.data());
    }
    
    // Encrypt buffer in reverse order
    chacha = TestType(key, nonce);
    Bytes cipher2;
    if (inplace) {
        cipher2 = plain;
    } else {
        cipher2.resize(plain.size());
    }
    for (int64_t counter = plain.size() / 64 - 1; counter >= 0; counter--) {
        chacha.set_counter(counter);
        size_t offset = counter * 64;
        if (inplace) {
            chacha.encrypt_inplace(cipher2.data() + offset, 64);
        } else {
            chacha.encrypt(plain.data() + offset, 64, cipher2.data() + offset);
        }
    }
    
    // Check if decrypt(encrypt(input)) == input.
    REQUIRE_THAT(cipher2, Equals(cipher));
}