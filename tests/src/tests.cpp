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
    Bytes cipher(zeros);    

    if (inplace) {
        chacha.encrypt_inplace(cipher.data(), cipher.size());
    } else {
        chacha.encrypt(zeros.data(), zeros.size(), cipher.data());
    }

    return cipher;
}

// Test vectors have been taken from https://datatracker.ietf.org/doc/html/draft-strombergson-chacha-test-vectors-01
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
        // TC1: All zero key and IV.
        { "0000000000000000000000000000000000000000000000000000000000000000"_hex, "0000000000000000"_hex, "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee65869f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f"_hex },
        // TC2: Single bit in key set. All zero IV.
        { "0100000000000000000000000000000000000000000000000000000000000000"_hex, "0000000000000000"_hex, "c5d30a7ce1ec119378c84f487d775a8542f13ece238a9455e8229e888de85bbd29eb63d0a17a5b999b52da22be4023eb07620a54f6fa6ad8737b71eb0464dac010f656e6d1fd55053e50c4875c9930a33f6d0263bd14dfd6ab8c70521c19338b2308b95cf8d0bb7d202d2102780ea3528f1cb48560f76b20f382b942500fceac"_hex },
        // TC3: Single bit in IV set. All zero key.
        { "0000000000000000000000000000000000000000000000000000000000000000"_hex, "0100000000000000"_hex, "ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd138e50d32111e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d6bbdb0041b2f586b5305e5e44aff19b235936144675efbe4409eb7e8e5f1430f5f5836aeb49bb5328b017c4b9dc11f8a03863fa803dc71d5726b2b6b31aa32708afe5af1d6b69058"_hex },
        // TC4: All bits in key and IV are set.
        { "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"_hex, "ffffffffffffffff"_hex, "d9bf3f6bce6ed0b54254557767fb57443dd4778911b606055c39cc25e674b8363feabc57fde54f790c52c8ae43240b79d49042b777bfd6cb80e931270b7f50eb5bac2acd86a836c5dc98c116c1217ec31d3a63a9451319f097f3b4d6dab0778719477d24d24b403a12241d7cca064f790f1d51ccaff6b1667d4bbca1958c4306"_hex }, 
        // TC5: Every even bit set in key and IV.
        { "5555555555555555555555555555555555555555555555555555555555555555"_hex, "5555555555555555"_hex, "bea9411aa453c5434a5ae8c92862f564396855a9ea6e22d6d3b50ae1b3663311a4a3606c671d605ce16c3aece8e61ea145c59775017bee2fa6f88afc758069f7e0b8f676e644216f4d2a3422d7fa36c6c4931aca950e9da42788e6d0b6d1cd838ef652e97b145b14871eae6c6804c7004db5ac2fce4c68c726d004b10fcaba86"_hex }, 
        // TC6: Every odd bit set in key and IV.
        { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"_hex, "aaaaaaaaaaaaaaaa"_hex, "9aa2a9f656efde5aa7591c5fed4b35aea2895dec7cb4543b9e9f21f5e7bcbcf3c43c748a970888f8248393a09d43e0b7e164bc4d0b0fb240a2d72115c480890672184489440545d021d97ef6b693dfe5b2c132d47e6f041c9063651f96b623e62a11999a23b6f7c461b2153026ad5e866a2e597ed07b8401dec63a0934c6b2a9"_hex }, 
        // TC7: Sequence patterns in key and IV.
        { "00112233445566778899aabbccddeeffffeeddccbbaa99887766554433221100"_hex, "0f1e2d3c4b596877"_hex, "87fa92061043ca5e631fedd88e8bfb84ad6b213bdee4bc806e2764935fb89097218a897b7aead10e1b17f6802b2abdd95594903083735613d6b3531b9e0d1b6747908c74f018f6e182138b991b9c5a957c69f23c26c8a2fbb8b0acf8e64222cc251281a61cff673608de6490b41ca1b9f4ab754474f9afc7c35dcd65de3d745f"_hex }, 
        // TC8: Random key and IV.
        { "c46ec1b18ce8a878725a37e780dfb7351f68ed2e194c79fbc6aebee1a667975d"_hex, "1ada31d5cf688221"_hex, "f63a89b75c2271f9368816542ba52f06ed49241792302b00b5e8f80ae9a473afc25b218f519af0fdd406362e8d69de7f54c604a6e00f353f110f771bdca8ab92e5fbc34e60a1d9a9db17345b0a402736853bf910b060bdf1f897b6290f01d138ae2c4c90225ba9ea14d518f55929dea098ca7a6ccfe61227053c84e49a4a3332"_hex }
    }));

    Bytes expected_keystream = std::get<2>(params);
    Bytes keystream = get_keystream<Chacha20>(inplace, std::get<0>(params), std::get<1>(params), expected_keystream.size());
    
    REQUIRE_THAT(keystream, Equals(expected_keystream));
}

TEST_CASE("Chacha12: keystream matches test vectors", "[chacha12][keystream]") {
    bool inplace = GENERATE(false, true);
    CAPTURE(inplace);

    auto params = GENERATE(table<Bytes, Bytes, Bytes>({          
        // TC1: All zero key and IV.  
        { "0000000000000000000000000000000000000000000000000000000000000000"_hex, "0000000000000000"_hex, "9bf49a6a0755f953811fce125f2683d50429c3bb49e074147e0089a52eae155f0564f879d27ae3c02ce82834acfa8c793a629f2ca0de6919610be82f411326be0bd58841203e74fe86fc71338ce0173dc628ebb719bdcbcc151585214cc089b442258dcda14cf111c602b8971b8cc843e91e46ca905151c02744a6b017e69316"_hex },
        // TC2: Single bit in key set. All zero IV.
        { "0100000000000000000000000000000000000000000000000000000000000000"_hex, "0000000000000000"_hex, "12056e595d56b0f6eef090f0cd25a20949248c2790525d0f930218ff0b4ddd10a6002239d9a454e29e107a7d06fefdfef0210feba044f9f29b1772c960dc29c00c7366c5cbc604240e665eb02a69372a7af979b26fbb78092ac7c4b88029a7c854513bc217bbfc7d90432e308eba15afc65aeb48ef100d5601e6afba257117a9"_hex },
        // TC3: Single bit in IV set. All zero key.
        { "0000000000000000000000000000000000000000000000000000000000000000"_hex, "0100000000000000"_hex, "64b8bdf87b828c4b6dbaf7ef698de03df8b33f635714418f9836ade59be1296946c953a0f38ecffc9ecb98e81d5d99a5edfc8f9a0a45b9e41ef3b31f028f1d0f559db4a7f222c442fe23b9a2596a88285122ee4f1363896ea77ca150912ac723bff04b026a2f807e03b29c02077d7b06fc1ab9827c13c8013a6d83bd3b52a26f"_hex },
        // TC4: All bits in key and IV are set.
        { "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"_hex, "ffffffffffffffff"_hex, "04bf88dae8e47a228fa47b7e6379434ba664a7d28f4dab84e5f8b464add20c3acaa69c5ab221a23a57eb5f345c96f4d1322d0a2ff7a9cd43401cd536639a615a5c9429b55ca3c1b55354559669a154aca46cd761c41ab8ace385363b95675f068e18db5a673c11291bd4187892a9a3a33514f3712b26c13026103298ed76bc9a"_hex }, 
        // TC5: Every even bit set in key and IV.
        { "5555555555555555555555555555555555555555555555555555555555555555"_hex, "5555555555555555"_hex, "a600f07727ff93f3da00dd74cc3e8bfb5ca7302f6a0a2944953de00450eecd40b860f66049f2eaed63b2ef39cc310d2c488f5d9a241b615dc0ab70f921b91b95140eff4aa495ac61289b6bc57de072419d09daa7a7243990daf348a8f2831e597cf379b3b284f00bda27a4c68085374a8a5c38ded62d1141cae0bb838ddc2232"_hex }, 
        // TC6: Every odd bit set in key and IV.
        { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"_hex, "aaaaaaaaaaaaaaaa"_hex, "856505b01d3b47aae03d6a97aa0f033a9adcc94377babd8608864fb3f625b6e314f086158f9f725d811eeb953b7f747076e4c3f639fa841fad6c9a709e6213976dd6ee9b5e1e2e676b1c9e2b82c2e96c1648437bff2f0126b74e8ce0a9b06d1720ac0b6f09086f28bc201587f0535ed9385270d08b4a9382f18f82dbde18210e"_hex }, 
        // TC7: Sequence patterns in key and IV.
        { "00112233445566778899aabbccddeeffffeeddccbbaa99887766554433221100"_hex, "0f1e2d3c4b596877"_hex, "6e93f25816ed8151dbab6c9a500d562ef3ac3cfd1899708c1574b912f71b13121149852170bd0f4543f0b73f9f27c363773632e9e2aa6324f6bed87ab0d0305ecd9a2aa9ea93c2675e82881408de852c62fa746a30e52b45a26962cf4351e304d31320bbd6aa6cc8f32637f95934e4c145efd56231ef3161032836f49671833e"_hex }, 
        // TC8: Random key and IV.
        { "c46ec1b18ce8a878725a37e780dfb7351f68ed2e194c79fbc6aebee1a667975d"_hex, "1ada31d5cf688221"_hex, "1482072784bc6d06b4e73bdc118bc0103c7976786ca918e06986aa251f7e9cc1b2749a0a16ee83b4242d2e99b08d7c20092b80bc466c87283b61b1b39d0ffbabd94b116bc1ebdb329b9e4f620db695544a8e3d9b68473d0c975a46ad966ed631e42aff530ad5eac7d8047adfa1e5113c91f3e3b883f1d189ac1c8fe07ba5a42b"_hex }
    }));

    Bytes expected_keystream = std::get<2>(params);
    Bytes keystream = get_keystream<Chacha12>(inplace, std::get<0>(params), std::get<1>(params), expected_keystream.size());
    
    REQUIRE_THAT(keystream, Equals(expected_keystream));
}

TEST_CASE("Chacha8: keystream matches test vectors", "[chacha8][keystream]") {
    bool inplace = GENERATE(false, true);
    CAPTURE(inplace);

    auto params = GENERATE(table<Bytes, Bytes, Bytes>({
        // TC1: All zero key and IV.  
        { "0000000000000000000000000000000000000000000000000000000000000000"_hex, "0000000000000000"_hex, "3e00ef2f895f40d67f5bb8e81f09a5a12c840ec3ce9a7f3b181be188ef711a1e984ce172b9216f419f445367456d5619314a42a3da86b001387bfdb80e0cfe42d2aefa0deaa5c151bf0adb6c01f2a5adc0fd581259f9a2aadcf20f8fd566a26b5032ec38bbc5da98ee0c6f568b872a65a08abf251deb21bb4b56e5d8821e68aa"_hex },
        // TC2: Single bit in key set. All zero IV.
        { "0100000000000000000000000000000000000000000000000000000000000000"_hex, "0000000000000000"_hex, "cf5ee9a0494aa9613e05d5ed725b804b12f4a465ee635acc3a311de8740489ea289d04f43c7518db56eb4433e498a1238cd8464d3763ddbb9222ee3bd8fae3c8b4355a7d93dd8867089ee643558b95754efa2bd1a8a1e2d75bcdb32015542638291941feb49965587c4fdfe219cf0ec132a6cd4dc067392e67982fe53278c0b4"_hex },
        // TC3: Single bit in IV set. All zero key.
        { "0000000000000000000000000000000000000000000000000000000000000000"_hex, "0100000000000000"_hex, "2b8f4bb3798306ca5130d47c4f8d4ed13aa0edccc1be6942090faeeca0d7599b7ff0fe616bb25aa0153ad6fdc88b954903c22426d478b97b22b8f9b1db00cf06470bdffbc488a8b7c701ebf4061d75c5969186497c95367809afa80bd843b040a79abc6e73a91757f1db73c8eacfa543b38f289d065ab2f3032d377b8c37fe46"_hex },
        // TC4: All bits in key and IV are set.
        { "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"_hex, "ffffffffffffffff"_hex, "e163bbf8c9a739d18925ee8362dad2cdc973df05225afb2aa26396f2a9849a4a445e0547d31c1623c537df4ba85c70a9884a35bcbf3dfab077e98b0f68135f5481d4933f8b322ac0cd762c27235ce2b31534e0244a9a2f1fd5e94498d47ff108790c009cf9e1a348032a7694cb28024cd96d3498361edb1785af752d187ab54b"_hex }, 
        // TC5: Every even bit set in key and IV.
        { "5555555555555555555555555555555555555555555555555555555555555555"_hex, "5555555555555555"_hex, "7cb78214e4d3465b6dc62cf7a1538c88996952b4fb72cb6105f1243ce3442e2975a59ebcd2b2a598290d7538491fe65bdbfefd060d88798120a70d049dc2677dd48ff5a2513e497a5d54802d7484c4f1083944d8d0d14d6482ce09f7e5ebf20b29807d62c31874d02f5d3cc85381a745ecbc60525205e300a76961bfe51ac07c"_hex }, 
        // TC6: Every odd bit set in key and IV.
        { "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"_hex, "aaaaaaaaaaaaaaaa"_hex, "40f9ab86c8f9a1a0cdc05a75e5531b612d71ef7f0cf9e387df6ed6972f0aae21311aa581f816c90e8a99de990b6b95aac92450f4e112712667b804c99e9c6edaf8d144f560c8c0ea36880d3b77874c9a9103d147f6ded386284801a4ee158e5ea4f9c093fc55fd344c33349dc5b699e21dc83b4296f92ee3ecabf3d51f95fe3f"_hex }, 
        // TC7: Sequence patterns in key and IV.
        { "00112233445566778899aabbccddeeffffeeddccbbaa99887766554433221100"_hex, "0f1e2d3c4b596877"_hex, "60fdedbd1a280cb741d0593b6ea0309010acf18e1471f68968f4c9e311dca149b8e027b47c81e0353db013891aa5f68ea3b13dd2f3b8dd0873bf3746e7d6c567fe882395601ce8aded444867fe62ed8741420002e5d28bb573113a418c1f4008e954c188f38ec4f26bb8555e2b7c92bf4380e2ea9e553187fdd42821794416de"_hex }, 
        // TC8: Random key and IV.
        { "c46ec1b18ce8a878725a37e780dfb7351f68ed2e194c79fbc6aebee1a667975d"_hex, "1ada31d5cf688221"_hex, "838751b42d8ddd8a3d77f48825a2ba752cf4047cb308a5978ef274973be374c96ad848065871417b08f034e681fe46a93f7d5c61d1306614d4aaf257a7cff08b16f2fda170cc18a4b58a2667ed962774af792a6e7f3c77992540711a7a136d7e8a2f8d3f93816709d45a3fa5f8ce72fde15be7b841acba3a2abd557228d9fe4f"_hex }
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

TEMPLATE_TEST_CASE("Encrypting, then decrypting again yields the original plaintext", "[keystream]", Chacha20, Chacha12, Chacha8) {
    bool inplace = GENERATE(false, true);
    CAPTURE(inplace);

    // Encrypt and decrypt a megabyte of [0, 1, 2, ..., 255, 0, 1, ...].
    Bytes plain(1024 * 1024);
    for (size_t i = 0; i < plain.size(); i++) {
        plain[i] = i & 255;
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