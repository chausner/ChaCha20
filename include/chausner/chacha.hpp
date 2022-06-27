#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>

namespace chausner {

class ChachaBlock {
    // This is basically a random number generator seeded with key and nonce.
    // Generates 64 random bytes every time count is incremented.

    uint32_t state[16];

    static uint32_t rotl32(uint32_t x, int n) {
        return (x << n) | (x >> (32 - n));
    }

    static uint32_t pack4(const uint8_t *a) {
        return
            static_cast<uint32_t>(a[0] << 0*8) |
            static_cast<uint32_t>(a[1] << 1*8) |
            static_cast<uint32_t>(a[2] << 2*8) |
            static_cast<uint32_t>(a[3] << 3*8);
    }

    static void unpack4(uint32_t src, uint8_t *dst) {
        dst[0] = (src >> 0*8) & 0xff;
        dst[1] = (src >> 1*8) & 0xff;
        dst[2] = (src >> 2*8) & 0xff;
        dst[3] = (src >> 3*8) & 0xff;
    }

    template<int a, int b, int c, int d>
    static void quarter_round(uint32_t x[16]) {
        x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 16);
        x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 12);
        x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 8);
        x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 7);
    }

public:
    ChachaBlock(const uint8_t key[32], const uint8_t nonce[8], uint64_t counter = 0) {
        const uint8_t *magic_constant = reinterpret_cast<const uint8_t *>("expand 32-byte k");
        state[ 0] = pack4(magic_constant + 0*4);
        state[ 1] = pack4(magic_constant + 1*4);
        state[ 2] = pack4(magic_constant + 2*4);
        state[ 3] = pack4(magic_constant + 3*4);
        state[ 4] = pack4(key + 0*4);
        state[ 5] = pack4(key + 1*4);
        state[ 6] = pack4(key + 2*4);
        state[ 7] = pack4(key + 3*4);
        state[ 8] = pack4(key + 4*4);
        state[ 9] = pack4(key + 5*4);
        state[10] = pack4(key + 6*4);
        state[11] = pack4(key + 7*4);
        set_counter(counter);
        state[14] = pack4(nonce + 0*4);
        state[15] = pack4(nonce + 1*4);
    }

    void set_counter(uint64_t counter) {
        state[12] = static_cast<uint32_t>(counter);
        state[13] = counter >> 32;
    }

    template<int rounds>
    void next(uint32_t result[16]) {
        static_assert(rounds >= 2 && rounds % 2 == 0, "\"rounds\" must be an even number and greater or equal to 2");
        
        for (int i = 0; i < 16; i++) {            
            result[i] = state[i];
        }
        
        for (int i = 0; i < rounds / 2; i++) {
            quarter_round<0, 4, 8, 12>(result);
            quarter_round<1, 5, 9, 13>(result);
            quarter_round<2, 6, 10, 14>(result);
            quarter_round<3, 7, 11, 15>(result);
            quarter_round<0, 5, 10, 15>(result);
            quarter_round<1, 6, 11, 12>(result);
            quarter_round<2, 7, 8, 13>(result);
            quarter_round<3, 4, 9, 14>(result);
        }

        for (int i = 0; i < 16; i++) {
            result[i] += state[i];
        }

        uint32_t *counter = state + 12;
        // Increment counter
        counter[0]++;
        if (counter[0] == 0) {
            // Wrap around occured, increment higher 32 bits of counter.
            counter[1]++;
            // Limited to 2^64 blocks of 64 bytes each.
            assert(counter[1] != 0);
        }
    }
    
    template<int rounds>
    void next(uint8_t result8[64]) {
        uint32_t temp32[16];
        
        next<rounds>(temp32);
        
        for (size_t i = 0; i < 16; i++) {
            unpack4(temp32[i], result8 + i*4);
        }
    }
};

template<int rounds>
class Chacha {
    // XORs plaintext/encrypted bytes with whatever ChachaBlock generates.
    // Encryption and decryption are the same operation.
    // ChachaBlocks can be skipped, so this can be done in parallel.
    // If keys are reused, messages can be decrypted.
    // Known encrypted text with known position can be tampered with.
    // See https://en.wikipedia.org/wiki/Stream_cipher_attack.

    ChachaBlock block;
    uint8_t keystream[64];
    uint8_t position;

public:
    Chacha(const uint8_t key[32], const uint8_t nonce[8], uint64_t counter = 0)
        : block(key, nonce, counter), position(64) {
    }

    void encrypt(const uint8_t *bytes, size_t n_bytes, uint8_t *dest) {
        size_t i = 0;
        for (; i < n_bytes && position < 64; i++, position++) {
            dest[i] = bytes[i] ^ keystream[position];
        }
        for (; i + 63 < n_bytes; i += 64) {
            block.next<rounds>(keystream);
            for (int j = 0; j < 64; j++) {
                dest[i + j] = bytes[i + j] ^ keystream[j];
            }
        }
        if (i < n_bytes) {
            block.next<rounds>(keystream);
            position = 0;
            for (; i < n_bytes; i++, position++) {
                dest[i] = bytes[i] ^ keystream[position];
            }
        }
    }

    void encrypt_inplace(uint8_t *bytes, size_t n_bytes) {
        size_t i = 0;
        for (; i < n_bytes && position < 64; i++, position++) {
            bytes[i] ^= keystream[position];
        }
        for (; i + 63 < n_bytes; i += 64) {
            block.next<rounds>(keystream);
            for (int j = 0; j < 64; j++) {
                bytes[i + j] ^= keystream[j];
            }
        }
        if (i < n_bytes) {
            block.next<rounds>(keystream);
            position = 0;
            for (; i < n_bytes; i++, position++) {
                bytes[i] ^= keystream[position];
            }
        }
    }

    void decrypt(const uint8_t *bytes, size_t n_bytes, uint8_t *dest) {
        return encrypt(bytes, n_bytes, dest);
    }

    void decrypt_inplace(uint8_t *bytes, size_t n_bytes) {
        return encrypt_inplace(bytes, n_bytes);
    }

    void set_counter(uint64_t counter) {
        block.set_counter(counter);
        position = 64;
    }
};

using Chacha20 = Chacha<20>;
using Chacha12 = Chacha<12>;
using Chacha8 = Chacha<8>;

}
