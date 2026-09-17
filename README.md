# DynamicCrypter

A lightweight, single-header, **compile-time polymorphic string encryption** library for modern C++ (C++17 or newer).

Inspired by the structural architecture of `skCrypter`. Rather than eight hand-written algorithms, every string gets its own algorithm **assembled from four independent dimensions** - keystream generator, per-character combiner, chaining mode and processing order - chosen per call site from a hash of the source position, the compiler's counter and an optional per-build salt. That is **1200 distinct algorithm shapes** from a few hundred lines of code, and every one of them is proven correct by the test suite at compile time.

## Key Features
* 🎛️ **Four orthogonal dimensions:** 8 keystream generators × 10 combiners × 3 modes × 5 processing orders = 1200 shapes, all reachable.
* 🎭 **Polymorphic per call site:** no two call sites share a key, an algorithm or a binary layout.
* 🧂 **Optional per-build salt:** with `-DDYNAMICCRYPTER_BUILD_SALT=ON`, no two builds of the same source share keys, ciphertext bytes or signatures.
* 🧹 **RAII plaintext lifetime:** the decrypted text is re-encrypted automatically when its handle goes out of scope.
* 📦 **Header-Only:** simply drop `DynamicCrypter.hpp` into your project.
* 🌍 **Portable:** no compiler-specific extension, no `<immintrin.h>`, no architecture requirement. MSVC, GCC, Clang, ICC and any other conforming C++17 compiler on x86, x64, ARM, RISC-V, ...
* ✅ **Self-Verifying:** the whole header is a constant expression, so the test suite proves a full encrypt/decrypt round trip for every dimension, every seed and every character type *at compile time*.

## Compiler support

| Requirement | Detail |
| --- | --- |
| Language | C++17 (`/std:c++17`, `-std=c++17`) |
| Toolchains | MSVC 2017+, GCC 7+, Clang 5+, ICC and other conforming C++17 compilers |
| Architectures | Any |
| Character types | `char`, `wchar_t`, `char16_t`, `char32_t` (1, 2 and 4 byte widths) |

The header checks its own configuration, so including it without C++17 produces

```
error: DynamicCrypter requires C++17 or newer: use /std:c++17 (MSVC) or -std=c++17 (GCC/Clang).
```

On MSVC `/Zc:__cplusplus` is recommended. The header reads `_MSVC_LANG`, so it works without it, but other code in your project may depend on a correct `__cplusplus`.

## Continuous integration

[![CI](https://github.com/TankNQX/DynamicCryptor/actions/workflows/ci.yml/badge.svg)](https://github.com/TankNQX/DynamicCryptor/actions/workflows/ci.yml)

`.github/workflows/ci.yml` builds and tests the library on every push to `main` and every pull request:

| Job | Covers |
| --- | --- |
| `linux` | GCC 12/13/14 and Clang 16/17/18 on x86-64, Debug and Release |
| `linux-older` | GCC 10/11 and Clang 12/14, the older end of the range |
| `linux-arm64` | GCC and Clang on arm64 Linux |
| `linux-i386` | 32-bit x86 (`-m32`) with GCC and Clang |
| `standards` | C++17, C++20 and C++23 |
| `sanitizers` | AddressSanitizer + UndefinedBehaviorSanitizer |
| `warnings`, `warnings-msvc` | `-Wall -Wextra -Wpedantic -Wshadow -Werror`, and `/W4 /WX` |
| `rejects-cxx14` | compiling without C++17 must fail with the intended message, not a wall of template errors |
| `salt` | the salt is off and reproducible by default, applied on request, and changes both the site hash and the binary |
| `macos` | AppleClang on arm64 macOS 14 and 15 |
| `msvc` | MSVC x64 and Win32, Debug and Release, plus one C++20 build |
| `mingw` | MinGW-w64 GCC on Windows, where the platform is Windows but `_MSC_VER` is not defined |

`ci-status` aggregates them into one check, so branch protection only ever needs to require that single job.

Two caveats worth stating plainly. The oldest compilers the table above claims support (MSVC 2017, GCC 7, Clang 5) are not installed on any GitHub runner image, so they are supported *by construction* - the header uses no extension those compilers lack - rather than exercised by CI. And the version lists track whatever the runner images happen to ship; if a version disappears the affected leg fails with an obvious `Unable to locate package` and only the `matrix` list needs editing.

## Quick Start

### 1. Include and protect

```cpp
#include <iostream>
#include "DynamicCrypter.hpp"

int main() {
    // Each of these strings compiles into a completely distinct algorithm
    std::cout << CRYPT_STR("Hello World! This uses one flavour.") << std::endl;
    std::cout << CRYPT_STR("Critical System Component Initiated.") << std::endl;
    std::cout << CRYPT_STR("https://secure-endpoint.local") << std::endl;

    return 0;
}
```

`CRYPT_STR(...)` yields a small RAII object that converts implicitly to `const CharType*`, so it streams, prints and compares like the pointer it wraps:

```cpp
std::cout << CRYPT_STR("streamed directly");   // fine: lives for the whole statement
std::wcout << CRYPT_STR(L"wide as well");      // wchar_t works the same way
printf("%s\n", CRYPT_STR("needs .get()").get());

auto message = CRYPT_STR("valid while message exists");
std::string copy(message);        // implicit conversion
std::cout << message.get();       // .get() / .c_str() / .data() / .size()
// the plaintext buffer is re-encrypted here, when `message` goes out of scope
```

Note that **variadic argument lists never apply user-defined conversions**, so `printf("%s", CRYPT_STR(...))` would pass the wrapper object rather than the pointer. Use `.get()`, or use `CRYPT_STR_RAW`, which hands out a raw pointer in the first place.

Several handles can be alive at once: two `CRYPT_STR(...)` calls at *different* call sites are independent (e.g. `CRYPT_STR("x") == CRYPT_STR("y")`), and nested handles of the *same* call site also work, because the buffer is decrypted once for the outermost handle and re-encrypted only when the last one is gone.

### 2. Pointer lifetime

The pointer handed out by `CRYPT_STR()` is valid **for as long as the object returned by the macro is alive**, because that object owns a lease on the buffer:

```cpp
// OK - the temporary lives until the end of the full expression
std::cout << CRYPT_STR("hello") << std::endl;

// OK - the handle is alive
auto handle = CRYPT_STR("hello");
std::cout << handle << std::endl;

// WRONG - the handle dies at the end of this statement and the buffer is
// re-encrypted with it
const char* dangling = CRYPT_STR("hello");
```

If a `const char*` has to live in a variable, go into a container, be returned from a function or be handed to a C API, use **`CRYPT_STR_RAW`**: it decrypts on first use and leaves the plaintext in place (never re-encrypting).

```cpp
const char* raw = CRYPT_STR_RAW("outlives the statement");
std::vector<const char*> items = {
    CRYPT_STR_RAW("Array Element A"),
    CRYPT_STR_RAW("Array Element B"),
};
```

### 3. Required compiler flags

Because this library uses `if constexpr` and guaranteed copy elision, **C++17 is required**:

* **MSVC / Visual Studio:** `/std:c++17` under Language Properties.
* **GCC / Clang:** `-std=c++17`.

For maximum stealth, ensure Release optimizations are active (`/O2`, `/Ob2` on MSVC) so the decryption inlines into the calling code. See *What this does and does not buy you* below before trusting the optimizer.

## Configuration macros

| Macro | Default | Effect |
| --- | --- | --- |
| `CRYPTER_BUILD_SALT` | `0u` | 32-bit value mixed into every site hash, and therefore into the seed and all four dimension selections. `0` keeps builds reproducible. The CMake option `DYNAMICCRYPTER_BUILD_SALT` generates a random value per build. |
| `CRYPTER_FORCEINLINE` | `__forceinline` (MSVC) / `inline __attribute__((always_inline))` (GCC, Clang) / `inline` | Override the always-inline hint. Define it before including the header. |
| `CRYPTER_NO_STANDARD_CHECK` | undefined | Suppress the C++17 check. Not recommended. |

The `CRYPTER_USE_HW_CRC32` option of earlier revisions is gone; defining it now produces a `#pragma message` explaining why. See *Notes on this revision*.

## The four dimensions

Every flavour is one value from each row.

### Keystream generator — how the per-character key is produced

| Value | Construction |
| --- | --- |
| `seed_xor` | `seed ^ index`, truncated to the character width |
| `lcg` | linear congruential stream (1664525 / 1013904223) |
| `xorshift` | xorshift32 stream |
| `splitmix` | splitmix-style add-multiply-mix stream |
| `crc32c` | CRC-32C over the index bytes |
| `mul_high` | multiply-and-take-the-high-bits stream |
| `murmur` | murmur3-style finaliser over seed and index |
| `rev_counter` | byte-reversed counter |

The keystream is materialised into a temporary array before the mode runs, which is what makes the four dimensions composable: the generators are pure functions of the seed and the index, so the inverse always sees exactly the same sequence.

### Combiner — how one character is combined with one key

| Value | Construction | Algebraically |
| --- | --- | --- |
| `bit_xor` | `value ^ key` | linear |
| `not_xor` | complement, then XOR key | affine |
| `bitrev` | reverse the bits, then XOR key | linear |
| `nibble_swap` | swap the nibbles of every byte, then XOR key | linear |
| `feistel` | one Feistel-lite round over the two halves | affine |
| `rotl_add` | rotate left by `key % 8`, then add key | non-linear (carries) |
| `add` / `sub` | add / subtract the key | non-linear (carries) |
| `mul_odd` | multiply by the odd part of the key, invertible mod 2ⁿ | non-linear |
| `sbox` | GF(2⁸) inverse composed with an invertible affine map (AES-style S-box) | non-linear |

The first five rows are included for **code-shape diversity**, not algebraic strength: a solver that handles linear maps handles all of them. If your threat model includes algebraic key recovery rather than pattern matching, `sbox`, `mul_odd`, `add`, `sub` and `rotl_add` are the ones that matter.

The S-box and its inverse are *derived*, never written out by hand: the inverses come from a walk of the multiplicative group of GF(2⁸), and the inverse S-box is built by inverting the permutation, so the pair agrees by construction. `static_assert` proves it is a bijection on all 256 inputs at compile time.

### Mode — how characters influence each other

| Value | Construction |
| --- | --- |
| `stream` | each character is independent (`c[i] = C(p[i], k[i])`) |
| `cbc` | `c[i] = C(p[i] ^ c[i-1], k[i])` |
| `cfb` | `c[i] = C(p[i], k[i] ^ c[i-1])` — the keystream depends on the data |

`cbc` and `cfb` make the key stream a function of the *ciphertext* rather than of the index alone, so there is no separable key schedule to lift out of the binary. Both are inverted by walking the processing order backwards, which is what makes in-place decryption possible: the ciphertext of the preceding step has not been overwritten yet.

(PCBC is deliberately absent. Its inverse needs the previous *plaintext*, which a backwards in-place walk cannot provide without a second buffer; `cfb` delivers the same data-dependent keystream without that cost.)

### Order — the sequence the characters are processed in

| Value | Sequence of indices |
| --- | --- |
| `forward` | `0, 1, 2, ...` |
| `backward` | `..., 2, 1, 0` |
| `rotate` | wrapped by a seed-derived offset |
| `evens_first` | `0, 2, 4, ..., 1, 3, ...` |
| `odds_first` | `1, 3, ..., 0, 2, ...` |

Chaining modes follow the processing order, so an unusual order changes the dependency graph as well as the loop shape.

## Classic presets

The eight flavours of earlier revisions, expressed in the dimension scheme, are available as `DynamicCrypter::Presets::classic_N`:

| Preset | Dimensions |
| --- | --- |
| `classic_0` | `seed_xor` / `bit_xor` / `stream` / `forward` |
| `classic_1` | `seed_xor` / `rotl_add` / `stream` / `forward` |
| `classic_2` | `seed_xor` / `mul_odd` / `stream` / `forward` |
| `classic_3` | `seed_xor` / `bit_xor` / `cbc` / `forward` |
| `classic_4` | `seed_xor` / `not_xor` / `stream` / `forward` |
| `classic_5` | `crc32c` / `bit_xor` / `stream` / `forward` |
| `classic_6` | `seed_xor` / `feistel` / `stream` / `forward` |
| `classic_7` | `lcg` / `bit_xor` / `stream` / `forward` |

You can also pick a flavour explicitly:

```cpp
using MyFlavour = DynamicCrypter::Flavour<DynamicCrypter::Keygen::splitmix,
                                         DynamicCrypter::Combiner::sbox,
                                         DynamicCrypter::Mode::cfb,
                                         DynamicCrypter::Order::odds_first>;

DynamicCrypter::EncryptedString<char, 11, MyFlavour, 0x12345678u> secret("Top Secret");
std::cout << secret.decrypt();   // decrypts in place, .encrypt() restores
```

## Per-build salt

Without a salt, keys are a pure function of the source, so an analyst can recompute them from the preprocessed file, and two builds of the same source produce identical blobs - one signature covers every binary you ship.

```sh
cmake -S . -B build -DDYNAMICCRYPTER_BUILD_SALT=ON
```

The option generates a random 32-bit value, stores it in the CMake cache (so reconfiguring does not roll a new one and incremental builds stay stable), and defines `CRYPTER_BUILD_SALT`. Set `DYNAMICCRYPTER_SALT_VALUE` yourself if you want to control or reproduce it, or clear the cache to roll a new one.

## What this does and does not buy you

**It raises:** the cost of bulk static extraction and signature matching. Every site has a different algorithm and key; with the salt, every *binary* does. A YARA rule or a byte-pattern scanner written against one sample matches nothing else, and static key recovery needs the salt.

**It does not stop:** a human with a debugger. The plaintext must exist in memory at every use, so a breakpoint on whatever consumes the string (`WriteFile`, `send`, `MessageBox`) reads it directly, and an emulator (Unicorn, Triton) can execute the decryption function and dump the result. No amount of per-site algorithm diversity changes that.

**Known limitation worth checking on your own build:** with optimizations on, nothing in the current design *prevents* the compiler from constant-folding the decryption (the ciphertext is a constant, the transform is a pure constant expression) and emitting the plaintext. That would defeat the library in Release builds specifically. Verify with a disassembler by searching a Release binary for a known string literal. The usual mitigations - a `noinline` boundary plus loading the ciphertext through a `volatile` view - cost a stack copy and cannot be combined with a fully `constexpr` header, so they are not enabled here; ask if you want them.

## Tests and example

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

Two targets are built:

| Target | Source | Purpose |
| --- | --- | --- |
| `DynamicCrypterTest` | `test/test.cpp` | Self-verifying test driver; exits non-zero if anything fails. |
| `DynamicCrypterExample` | `test/main.cpp` | Short consumer-facing usage example; built with the tests so it cannot rot, and smoke-run by `ctest`. |

Build options:

| Option | Default | Effect |
| --- | --- | --- |
| `DYNAMICCRYPTER_BUILD_SALT` | `OFF` | Generate a random per-build salt and define `CRYPTER_BUILD_SALT`. |
| `DYNAMICCRYPTER_SALT_VALUE` | empty | Use a specific hex salt (without the `0x` prefix) instead of generating one; stored in the cache so incremental builds stay stable. |
| `DYNAMICCRYPTER_CXX_STANDARD` | `17` | Language standard used for the tests and the example. The library itself needs at least 17; the CI matrix uses this to check that newer standards keep working. |

The test target contains compile-time proofs plus run-time checks:

* one `static_assert` per flavour being checked, so a failure names the exact dimensions that broke, and each is a separate constant evaluation (MSVC budgets those per expression);
* a full cycle - encrypt, decrypt, re-encrypt and compare against the original ciphertext - for every value of every dimension, for the eight presets on a long string, for four seeds including both edge values, and for all four character types;
* a spread of 12 sampled points across the whole 1200-combination product space, because the dimensions must still compose when combined;
* a check that over 256 sites the automatic selection reaches every value of every dimension, so a degenerate slice cannot silently shrink the flavour space;
* run-time checks of both macros, pointer lifetimes, repeated and overlapping use of one call site, and that different seeds really do produce different ciphertexts.

## Notes on this revision

* `CRYPT_STR` yields the RAII handle described above. `CRYPT_STR_RAW` is the pointer form with the old semantics (minus the bug that made every second call return garbage).
* `CRYPTER_USE_HW_CRC32` and the SSE4.2 CRC32 intrinsic path were removed: the keystream generator is shared with the compile-time encryption path, which must remain a constant expression, and an intrinsic cannot be one. CRC-32C survives as the portable `crc32c` keystream generator.
* `DynamicCrypter::EncryptedString` now takes the flavour as a *type* (`Flavour<...>`) instead of an integer, and the helper functions moved into `DynamicCrypter::detail`.

## License & Attribution
This project is licensed under the **MIT License**—see the [LICENSE](LICENSE) file for details.

### Acknowledgements & Development
* **Architectural Concept:** Inspired by the pioneering compile-time string encryption layout of [skCrypter](https://github.com/skadro-official/skCrypter) (MIT License).
* **Implementation:** The multi-flavour polymorphic expansion and the architecture for this header-only library were collaboratively co-developed with **Google's Gemini LLM** (September 2026).
* **Portability, correctness and tooling:** Contributed by **Reasonix**, an AI coding agent. That work covered the compiler-portability pass (no extensions, explicit C++17 diagnostics, the `Include` path fix that broke non-Windows builds), the fixes for the chaining, modular-inverse and CRC keystream flavours that were silently incorrect or unreachable, the four-dimensional flavour redesign with its per-build salt, the compile-time `static_assert` verification harness, and the CI matrix.

## Disclaimer
This project is developed strictly for educational analysis, authorized security research, software reverse-engineering mitigation, and digital asset protection. The authors assume no liability for unintended or unauthorized deployment.
