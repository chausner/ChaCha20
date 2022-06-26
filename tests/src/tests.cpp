#include "chausner/chacha.hpp"

#include "catch2/catch.hpp"

using namespace chausner;
using namespace Catch::Matchers;

typedef std::vector<uint8_t> Bytes;

Bytes hex_to_raw(const std::string &hex) {
    const char *digits = "0123456789abcdefghijklmnopqrstuvwxyz";
    auto digit_value = [digits](char c) {
        return static_cast<uint8_t>(std::strchr(digits, c) - digits);
    };
    size_t n = hex.size();
    assert(n % 2 == 0);
    Bytes raw(n/2);
    for (size_t i = 0; i < n/2; i++) {
        uint8_t hi = digit_value(hex[i*2 + 0]);
        uint8_t lo = digit_value(hex[i*2 + 1]);
        raw[i] = (hi << 4) | lo;
    }
    return raw;
}

Bytes operator ""_hex(const char *hex, size_t size) {
    return hex_to_raw(hex);
}

template<typename Chacha>
Bytes get_keystream(bool inplace, const Bytes &key, const Bytes &nonce, size_t n_bytes) {
    Chacha chacha(key.data(), nonce.data());

    // Since Chacha just XORs the plaintext with the keystream,
    // we can feed it zeros and we will get the keystream.
    Bytes zeros(n_bytes, 0);
    Bytes result(zeros);    

    if (inplace) {
        chacha.encrypt_inplace(result.data(), result.size());
    } else {
        chacha.encrypt(zeros.data(), zeros.size(), result.data());
    }

    return result;
}

TEST_CASE("Chacha20: keystream matches test vectors", "[chacha20][keystream]") {
    bool inplace = GENERATE(false, true);
    CAPTURE(inplace);

    auto params = GENERATE(table<Bytes, Bytes, Bytes>({
        { "0000000000000000000000000000000000000000000000000000000000000000"_hex, "0000000000000000"_hex, "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"_hex },
        { "0000000000000000000000000000000000000000000000000000000000000001"_hex, "0000000000000000"_hex, "4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952ed432d41bbe2a0b6ea7566d2a5d1e7e20d42af2c53d792b1c43fea817e9ad275ae546963"_hex },
        { "0000000000000000000000000000000000000000000000000000000000000000"_hex, "0000000000000001"_hex, "de9cba7bf3d69ef5e786dc63973f653a0b49e015adbff7134fcb7df137821031e85a050278a7084527214f73efc7fa5b5277062eb7a0433e445f41e3"_hex },
        { "0000000000000000000000000000000000000000000000000000000000000000"_hex, "0100000000000000"_hex, "ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd138e50d32111e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d6bbdb0041b2f586b"_hex },
        { "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"_hex, "0001020304050607"_hex, "f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53f15916155c2be8241a38008b9a26bc35941e2444177c8ade6689de95264986d95889fb60e84629c9bd9a5acb1cc118be563eb9b3a4a472f82e09a7e778492b562ef7130e88dfe031c79db9d4f7c7a899151b9a475032b63fc385245fe054e3dd5a97a5f576fe064025d3ce042c566ab2c507b138db853e3d6959660996546cc9c4a6eafdc777c040d70eaf46f76dad3979e5c5360c3317166a1c894c94a371876a94df7628fe4eaaf2ccb27d5aaae0ad7ad0f9d4b6ad3b54098746d4524d38407a6deb3ab78fab78c9"_hex }
    }));

    Bytes expected_keystream = std::get<2>(params);
    Bytes keystream = get_keystream<Chacha20>(inplace, std::get<0>(params), std::get<1>(params), expected_keystream.size());
    
    REQUIRE_THAT(keystream, Equals(expected_keystream));
}

/*TEST_CASE("Chacha12: keystream matches test vectors", "[chacha12][keystream]") {
    bool inplace = GENERATE(false, true);
    CAPTURE(inplace);

    auto params = GENERATE(table<Bytes, Bytes, Bytes>({
    }));

    Bytes expected_keystream = std::get<2>(params);
    Bytes keystream = get_keystream<Chacha12>(inplace, std::get<0>(params), std::get<1>(params), expected_keystream.size());
    
    REQUIRE_THAT(keystream, Equals(expected_keystream));
}

TEST_CASE("Chacha8: keystream matches test vectors", "[chacha8][keystream]") {
    bool inplace = GENERATE(false, true);
    CAPTURE(inplace);

    auto params = GENERATE(table<Bytes, Bytes, Bytes>({
    }));

    Bytes expected_keystream = std::get<2>(params);
    Bytes keystream = get_keystream<Chacha8>(inplace, std::get<0>(params), std::get<1>(params), expected_keystream.size());
    
    REQUIRE_THAT(keystream, Equals(expected_keystream));
}*/

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