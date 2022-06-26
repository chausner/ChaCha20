#include "chausner/chacha.hpp"

#include "catch2/catch.hpp"

using namespace chausner;
using namespace Catch::Matchers;

typedef std::vector<uint8_t> Bytes;

Bytes operator ""_hex(const char *hex, size_t size) {
    const char *digits = "0123456789abcdefghijklmnopqrstuvwxyz";
    auto digit_value = [digits](char c) {
        return static_cast<uint8_t>(std::strchr(digits, c) - digits);
    };
    assert(size % 2 == 0);
    Bytes raw(size/2);
    for (size_t i = 0; i < size/2; i++) {
        uint8_t high = digit_value(hex[i*2 + 0]);
        uint8_t low = digit_value(hex[i*2 + 1]);
        raw[i] = (high << 4) | low;
    }
    return raw;
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

// Test vectors have been taken from https://datatracker.ietf.org/doc/html/draft-strombergson-chacha-test-vectors-00
// and are licensed under the Simplified BSD License:
//
// Copyright (c) 2013, Joachim Strömbergson
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
// 
//   Redistributions of source code must retain the above copyright notice, this
//   list of conditions and the following disclaimer.
// 
//   Redistributions in binary form must reproduce the above copyright notice, this
//   list of conditions and the following disclaimer in the documentation and/or
//   other materials provided with the distribution.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
// ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
// ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

TEST_CASE("Chacha20: keystream matches test vectors", "[chacha20][keystream]") {
    bool inplace = GENERATE(false, true);
    CAPTURE(inplace);

    auto params = GENERATE(table<Bytes, Bytes, Bytes>({
        { "0000000000000000000000000000000000000000000000000000000000000000"_hex, "0000000000000000"_hex, "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee65869f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f"_hex },
        { "0100000000000000000000000000000000000000000000000000000000000000"_hex, "0000000000000000"_hex, "c5d30a7ce1ec119378c84f487d775a8542f13ece238a9455e8229e888de85bbd29eb63d0a17a5b999b52da22be4023eb07620a54f6fa6ad8737b71eb0464dac010f656e6d1fd55053e50c4875c9930a33f6d0263bd14dfd6ab8c70521c19338b2308b95cf8d0bb7d202d2102780ea3528f1cb48560f76b20f382b942500fceac"_hex },
        { "0000000000000000000000000000000000000000000000000000000000000000"_hex, "0100000000000000"_hex, "ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd138e50d32111e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d6bbdb0041b2f586b5305e5e44aff19b235936144675efbe4409eb7e8e5f1430f5f5836aeb49bb5328b017c4b9dc11f8a03863fa803dc71d5726b2b6b31aa32708afe5af1d6b69058"_hex },
    }));

    Bytes expected_keystream = std::get<2>(params);
    Bytes keystream = get_keystream<Chacha20>(inplace, std::get<0>(params), std::get<1>(params), expected_keystream.size());
    
    REQUIRE_THAT(keystream, Equals(expected_keystream));
}

TEST_CASE("Chacha12: keystream matches test vectors", "[chacha12][keystream]") {
    bool inplace = GENERATE(false, true);
    CAPTURE(inplace);

    auto params = GENERATE(table<Bytes, Bytes, Bytes>({            
        { "0000000000000000000000000000000000000000000000000000000000000000"_hex, "0000000000000000"_hex, "9bf49a6a0755f953811fce125f2683d50429c3bb49e074147e0089a52eae155f0564f879d27ae3c02ce82834acfa8c793a629f2ca0de6919610be82f411326be0bd58841203e74fe86fc71338ce0173dc628ebb719bdcbcc151585214cc089b442258dcda14cf111c602b8971b8cc843e91e46ca905151c02744a6b017e69316"_hex },
        { "0100000000000000000000000000000000000000000000000000000000000000"_hex, "0000000000000000"_hex, "12056e595d56b0f6eef090f0cd25a20949248c2790525d0f930218ff0b4ddd10a6002239d9a454e29e107a7d06fefdfef0210feba044f9f29b1772c960dc29c00c7366c5cbc604240e665eb02a69372a7af979b26fbb78092ac7c4b88029a7c854513bc217bbfc7d90432e308eba15afc65aeb48ef100d5601e6afba257117a9"_hex },
        { "0000000000000000000000000000000000000000000000000000000000000000"_hex, "0100000000000000"_hex, "64b8bdf87b828c4b6dbaf7ef698de03df8b33f635714418f9836ade59be1296946c953a0f38ecffc9ecb98e81d5d99a5edfc8f9a0a45b9e41ef3b31f028f1d0f559db4a7f222c442fe23b9a2596a88285122ee4f1363896ea77ca150912ac723bff04b026a2f807e03b29c02077d7b06fc1ab9827c13c8013a6d83bd3b52a26f"_hex }
    }));

    Bytes expected_keystream = std::get<2>(params);
    Bytes keystream = get_keystream<Chacha12>(inplace, std::get<0>(params), std::get<1>(params), expected_keystream.size());
    
    REQUIRE_THAT(keystream, Equals(expected_keystream));
}

TEST_CASE("Chacha8: keystream matches test vectors", "[chacha8][keystream]") {
    bool inplace = GENERATE(false, true);
    CAPTURE(inplace);

    auto params = GENERATE(table<Bytes, Bytes, Bytes>({
        { "0000000000000000000000000000000000000000000000000000000000000000"_hex, "0000000000000000"_hex, "3e00ef2f895f40d67f5bb8e81f09a5a12c840ec3ce9a7f3b181be188ef711a1e984ce172b9216f419f445367456d5619314a42a3da86b001387bfdb80e0cfe42d2aefa0deaa5c151bf0adb6c01f2a5adc0fd581259f9a2aadcf20f8fd566a26b5032ec38bbc5da98ee0c6f568b872a65a08abf251deb21bb4b56e5d8821e68aa"_hex },
        { "0100000000000000000000000000000000000000000000000000000000000000"_hex, "0000000000000000"_hex, "cf5ee9a0494aa9613e05d5ed725b804b12f4a465ee635acc3a311de8740489ea289d04f43c7518db56eb4433e498a1238cd8464d3763ddbb9222ee3bd8fae3c8b4355a7d93dd8867089ee643558b95754efa2bd1a8a1e2d75bcdb32015542638291941feb49965587c4fdfe219cf0ec132a6cd4dc067392e67982fe53278c0b4"_hex },
        { "0000000000000000000000000000000000000000000000000000000000000000"_hex, "0100000000000000"_hex, "2b8f4bb3798306ca5130d47c4f8d4ed13aa0edccc1be6942090faeeca0d7599b7ff0fe616bb25aa0153ad6fdc88b954903c22426d478b97b22b8f9b1db00cf06470bdffbc488a8b7c701ebf4061d75c5969186497c95367809afa80bd843b040a79abc6e73a91757f1db73c8eacfa543b38f289d065ab2f3032d377b8c37fe46"_hex }
    }));

    Bytes expected_keystream = std::get<2>(params);
    Bytes keystream = get_keystream<Chacha8>(inplace, std::get<0>(params), std::get<1>(params), expected_keystream.size());
    
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