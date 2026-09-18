# DynamicCrypter

A lightweight, single-header, **compile-time polymorphic string encryption** library for modern C++ (C++17 or newer).

Inspired by the structural architecture of `skCrypter`. Rather than eight hand-written algorithms, every string gets its own algorithm **assembled from four independent dimensions** - keystream generator, per-character combiner, chaining mode and processing order - chosen per call site from a hash of the source position, the compiler's counter and an optional per-build salt. That is **1200 distinct algorithm shapes** from a few hundred lines of code, and every one of them is proven correct by the test suite at compile time.

## Key Features
* 🎛️ **Four orthogonal dimensions:** 8 keystream generators × 10 combiners × 3 modes × 5 processing orders = 1200 shapes, all reachable.
* 🎭 **Polymorphic per call site:** no two call sites share a key, an algorithm or a binary layout.
* 🧂 **Optional per-build salt:** with `-DDYNAMICCRYPTER_BUILD_SALT=ON`, no two builds of the same source share keys, ciphertext bytes or signatures.
* 🗃️ **One object, one string:** `CRYPT_STR()` hands back a small object that owns its buffer and flips it between plain and cipher - `get()` / `decrypt()` / `encrypt()` / `isEncrypted()` / `clear()`, the skCrypter model, with C++ looking after the lifetime.
* 🔒 **Read-only ciphertext:** the encrypted bytes are a `static const` compile-time constant that nothing writes to, so the site is never decoded in place and never carries a writable copy of the plaintext.
* 🧹 **Every path ends in a wipe:** the buffer is cleared by `clear()`, or automatically by the destructor when the object goes out of scope.
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

`CRYPT_STR(...)` yields a small object that owns the string and converts implicitly to `const CharType*`, so it streams, prints and compares like the pointer it wraps:

```cpp
std::cout << CRYPT_STR("streamed directly");      // fine: lives for the whole statement
std::wcout << CRYPT_STR(L"wide as well").get();   // .get() for a wide stream - see below
printf("%s\n", CRYPT_STR("needs .get()").get());

auto message = CRYPT_STR("valid while message exists");
std::string copy(message);        // implicit conversion
std::cout << message.get();       // .get() / .c_str() / .data() / .size()
// the object's buffer is cleared here, when `message` goes out of scope
```

Note that **variadic argument lists never apply user-defined conversions**, so `printf("%s", CRYPT_STR(...))` would pass the wrapper object rather than the pointer. Use `.get()`. The same goes for a wide stream: `std::wcout << CRYPT_STR(L"...")` prints the *pointer*, because the wide-string inserter is a function template and template argument deduction cannot see through a user-defined conversion, which leaves the `const void*` overload as the match. `std::wcout << CRYPT_STR(L"...").get()` prints the text - and the `char` case needs no `.get()`, because a narrow stream has a plain `const char*` member overload.

Several objects can be alive at once, and each owns its own buffer: two `CRYPT_STR(...)` calls at *different* call sites are independent (e.g. `CRYPT_STR("x") == CRYPT_STR("y")`), and re-entering the *same* call site is independent as well, because there is no shared per-site state to keep in step.

### 2. Pointer lifetime

The pointer handed out by `CRYPT_STR()` is valid **for as long as the object returned by the macro is alive**, because that object owns the buffer the pointer points into:

```cpp
// OK - the temporary lives until the end of the full expression
std::cout << CRYPT_STR("hello") << std::endl;

// OK - the object is alive
auto text = CRYPT_STR("hello");
std::cout << text << std::endl;

// WRONG - the object dies at the end of this statement and takes its buffer with
// it; `dangling` points at storage whose lifetime has ended
const char* dangling = CRYPT_STR("hello");
```

If the characters have to live in a variable, go into a container, be returned from a function or be handed to a C API, **copy them into storage you own**:

```cpp
std::string owned(CRYPT_STR("outlives the statement"));

std::vector<std::string> items = {
    CRYPT_STR("Array Element A").get(),
    CRYPT_STR("Array Element B").get(),
};
```

### 3. The object's state machine

The object holds one buffer and knows which of the three states it is in. Every read decodes first if it has to, so there is never a "is it plaintext right now?" question at the point of use:

```cpp
auto credential = CRYPT_STR("correct horse battery staple");

use(credential);           // decodes on use
credential.encrypt();      // ciphertext is back in the object's own buffer
credential.isEncrypted();  // true

use(credential);           // decodes again, with no extra call
credential.clear();        // zeroed: the string is gone for good
```

| Method | Effect |
| --- | --- |
| `get()` / `c_str()` / `data()` / `operator const CharType*()` | decode if needed, hand out the text |
| `decrypt()` | the explicit form of the same thing; a no-op when already plain |
| `encrypt()` | recompute the ciphertext into the object's own buffer |
| `isEncrypted()` | is the buffer holding ciphertext right now? |
| `clear()` | zero the buffer; a cleared object stays empty and reads as `""` |
| `size()` | character count, terminator included |
| `~Crypter()` | runs `clear()`, so the end of the scope is always enough |

The site's blob in `EncryptedString` is never written to: the object seeds itself from it once, and `encrypt()` recomputes ciphertext from what the object's own buffer holds. Reads and state changes are `const`-callable (the buffer and the state flag inside are `mutable`), so an object passed on as `const&` still reads - at the cost of one object not being thread safe, since two threads reading it race on the decode.

#### How this differs from skCrypter

The same model, with three deliberate differences:

* **The lifetime is C++'s.** skCrypter has no destructor, so its plaintext sits in the object until someone calls `encrypt()` or `clear()`; here the destructor clears the buffer, and `clear()` is for dropping the text early rather than for tidying up at the end of every scope.
* **`get()` decodes.** skCrypter's `get()` hands out the raw buffer, which still holds ciphertext until the accessor that decrypts has run; here every read accessor means "the text". Only `const` pointers come out, and there is no accessor that hands out ciphertext.
* **The state is a flag, not a sentinel.** skCrypter infers "encrypted" from the NUL terminator; the transforms here leave no recognisable sentinel to test, so the state is tracked explicitly. `clear()` is therefore final: a cleared object is not re-encrypted into keystream bytes, which is what `skCrypter::encrypt()` would do to its zeroed buffer.

### 4. Required compiler flags

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

`cbc` and `cfb` make the key stream a function of the *ciphertext* rather than of the index alone, so there is no separable key schedule to lift out of the binary. Both are inverted by reading the ciphertext of the *preceding* step, which is why the inverse walks the processing order backwards. That walk is also what lets the inverse work in place, as the object's own `decrypt()` does: a descending walk reads the slot it needs before the step that overwrites it runs. Decoding out of place, as a `Crypter` does when it seeds itself from its site, is the same read of an untouched buffer.

(PCBC is deliberately absent. Its inverse needs the previous *plaintext*, and the backward walk over the ciphertext does not have it; `cfb` delivers the same data-dependent keystream without that cost.)

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

const DynamicCrypter::EncryptedString<char, 11, MyFlavour, 0x12345678u> site("Top Secret");
const DynamicCrypter::Crypter<char, 11, MyFlavour, 0x12345678u> secret(site);

std::cout << secret.get();   // reads decode; the site stays ciphertext
secret.encrypt();            // hide it again, then secret.clear() to drop it
```

## Per-build salt

Without a salt, keys are a pure function of the source, so an analyst can recompute them from the preprocessed file, and two builds of the same source produce identical blobs - one signature covers every binary you ship.

```sh
cmake -S . -B build -DDYNAMICCRYPTER_BUILD_SALT=ON
```

The option generates a random 32-bit value, stores it in the CMake cache (so reconfiguring does not roll a new one and incremental builds stay stable), and defines `CRYPTER_BUILD_SALT`. Set `DYNAMICCRYPTER_SALT_VALUE` yourself if you want to control or reproduce it, or clear the cache to roll a new one.

## What this does and does not buy you

**It raises:** the cost of bulk static extraction and signature matching. Every site has a different algorithm and key; with the salt, every *binary* does. A YARA rule or a byte-pattern scanner written against one sample matches nothing else, and static key recovery needs the salt. The site's encrypted bytes are also a compile-time constant in read-only memory - a decode cannot rewrite them - so the writable buffer holding the plaintext is always the object's own, never the site.

**It does not stop:** a human with a debugger. The plaintext must exist in memory at every use, so a breakpoint on whatever consumes the string (`WriteFile`, `send`, `MessageBox`) reads it directly, and an emulator (Unicorn, Triton) can execute the decryption function and dump the result. No amount of per-site algorithm diversity changes that.

**The wipe is best effort.** `clear()` - and so the destructor - zeroes the object's buffer through a `volatile` view, which stops an optimizer from deleting the stores as dead code, but by then the characters may also sit in a register, in a `std::string` the caller built or in a buffer the C library owns. It narrows the window; it does not close it.

**Known limitation worth checking on your own build:** with optimizations on, nothing in the current design *prevents* the compiler from constant-folding the decryption (the ciphertext is a constant, the transform is a pure constant expression) and emitting the plaintext. That would defeat the library in Release builds specifically. Decoding into the object's own buffer does not change that: a folded decode is still just a store of the constant plaintext, now into that buffer. Verify with a disassembler by searching a Release binary for a known string literal. The usual mitigations - a `noinline` boundary plus loading the ciphertext through a `volatile` view - cannot be combined with a fully `constexpr` header, so they are not enabled here; ask if you want them.

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
| `DYNAMICCRYPTER_WERROR` | `OFF` | Add `/WX` (MSVC) or `-Werror` (GCC/Clang) to the test and example targets. CI turns it on for two jobs. |

The test target contains compile-time proofs plus run-time checks:

* one `static_assert` per flavour being checked, so a failure names the exact dimensions that broke, and each is a separate constant evaluation (MSVC budgets those per expression);
* a full cycle - encrypt, decode into a buffer of its own, confirm the ciphertext survived the decode, then re-encrypt and compare against the original ciphertext - for every value of every dimension, for the eight presets on a long string, for four seeds including both edge values, and for all four character types;
* a spread of 12 sampled points across the whole 1200-combination product space, because the dimensions must still compose when combined;
* a check that over 256 sites the automatic selection reaches every value of every dimension, so a degenerate slice cannot silently shrink the flavour space;
* run-time checks of the macro and its state machine - reads decode, `encrypt()` reports ciphertext and hides it, a read brings the text back, `clear()` ends it, and none of it touches the site - pointer lifetimes, repeated and overlapping use of one call site, and that different seeds really do produce different ciphertexts.

## Notes on this revision

* `CRYPT_STR` yields a `DynamicCrypter::Crypter<...>`: one object that owns its buffer and flips it between plain and cipher through `get()` / `decrypt()` / `encrypt()` / `isEncrypted()` / `clear()`, the skCrypter model with the lifetime left to C++ - the destructor clears the buffer. The site it seeds from is a `static const` compile-time constant that nothing writes to, and the core API matches: `EncryptedString::decrypt(CharType* out)` decodes out of place, `transform_inverse` takes `(out, in)`, and the old in-place `encrypt()` is gone because the object recomputes its own ciphertext.
* `CRYPT_STR_RAW` was removed. It promised a `const char*` that outlives the statement, which an object owning its buffer cannot provide; copy the characters into storage you own instead (see *Pointer lifetime*).
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
