# ChaCha
Single-header C++ implementation of the ChaCha20/12/8 stream ciphers, currently unstable/work-in-progress.

Compatible with any C++11-compliant compiler.

## Usage

### Installation

Copy header `chausner/chacha.hpp` into your project and include it:

```c++
#include "chausner/chacha.hpp"
```

If you are using CMake, any alternative way to integrate the library is as a CMake package:

```cmake
find_package(ChaCha REQUIRED)
target_link_libraries(<target> PRIVATE ChaCha::chacha)
```

### API

The library defines the classes `Chacha20`, `Chacha12` and `Chacha8` for the 20-, 12- and 8-round cipher variants, respectively.
The following examples demonstrate the 20-round variant but usage of the other variants is identical.

#### Initialization

Create a new cipher object by passing the 256-bit key and a 64-bit nonce to the constructor:

```c++
uint8_t key[32] = { /* ... */ };
uint8_t nonce[8] = { /* ... */ };
Chacha20 chacha(key, nonce);
```

#### Encryption

Encrypt blocks of data using the `encrypt` member function:

```c++
std::vector<uint8_t> plaintext { /* ... */ };
std::vector<uint8_t> ciphertext(plaintext.size());
chacha.encrypt(plaintext.data(), plaintext.size(), ciphertext.data());
```

There is also a function for performing the encryption in-place:

```c++
std::vector<uint8_t> buffer { /* ... */ };
chacha.encrypt_inplace(buffer.data(), buffer.size());
```

It does not matter whether you encrypt all data at once using a single call of these functions,
or using multiple calls on smaller buffers.

#### Decryption

Since ChaCha is a stream cipher, the decryption operation is identical to the encryption operation.
Nevertheless, the library provides separate `decrypt` and `decrypt_inplace` functions
to allow the calling code to be more explicit:

```c++
std::vector<uint8_t> ciphertext { /* ... */ };
std::vector<uint8_t> plaintext(ciphertext.size());
chacha.decrypt(ciphertext.data(), ciphertext.size(), plaintext.data());
```

or the in-place variant:

```c++
std::vector<uint8_t> buffer { /* ... */ };
chacha.decrypt_inplace(buffer.data(), buffer.size());
```

#### Random-access to keystream

ChaCha allows to seek forward or backwards to arbitrary positions in the keystream (at a 64 byte interval),
without needing to encrypt or decrypt any of the preceding data.

To seek to byte position `offset`, with `offset` being a multiple of 64,
call the `set_counter` member function as follows:

```c++
chacha.set_counter(offset / 64);
```

For example, to decrypt a block of 1024 bytes at offset 512 in the ciphertext, you may use:

```c++
chacha.set_counter(8); // 512 / 64 
chacha.decrypt(ciphertext.data() + 512, 1024, plaintext.data());
```

## Building the tests and benchmark

### Using Conan

[Conan](https://conan.io/) can be used to resolve dependencies required for the unit tests.

If using a single-configuration generator (e.g. Make, Ninja), run from the repository root:

```shell
mkdir build
cd build
conan install .. -s build_type=Release
cmake .. -DCMAKE_TOOLCHAIN_FILE=generators/conan_toolchain.cmake -DCMAKE_POLICY_DEFAULT_CMP0091=NEW -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

If using a multi-configuration generator (e.g. Visual Studio), run from the repository root:

```shell
mkdir build
cd build
conan install .. -s build_type=Release
cmake .. -DCMAKE_TOOLCHAIN_FILE=generators/conan_toolchain.cmake -DCMAKE_POLICY_DEFAULT_CMP0091=NEW
cmake --build . --config Release
```

In either case, to perform a debug build instead of a release build,
specify "Debug" instead of "Release" in the calls to `conan` and `cmake`.

### Without Conan

It is also possible to build the tests without Conan.
In this case, you need to manually install [Catch2](https://github.com/catchorg/Catch2/blob/v2.13.9/docs/cmake-integration.md) 2.13.9 as a CMake package first.
Then, configure and build using a single-configuration generator:

```shell
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

or using a multi-configuration generator:

```shell
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

## Running the tests

After building the tests, run from the build folder:

```shell
ctest
```

## Credit

This project started out as a fork of https://github.com/983/ChaCha20.
Thanks [983](https://github.com/983) for providing the base implementation!