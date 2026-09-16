# DynamicCrypter

A lightweight, single-header, **compile-time polymorphic string encryption** library for modern C++ (C++17 or newer). 

Inspired by the structural architecture of `skCrypter`, this library expands string obfuscation by automatically alternating between **8 distinct encryption flavours** at compile time using the `__COUNTER__` macro. Every string instantiated creates a unique binary layout, significantly increasing the complexity of static analysis and reverse engineering.

## Key Features
* 🛡️ **8 Encryption Flavours:** Features classic XOR, bitwise rotations, modular mathematics, cipher block chaining (cascading), hardware-assisted CRC32 PRNG streams, and Feistel-lite structures.
* 🎭 **Polymorphic Obfuscation:** The compiler automatically assigns different algorithms and unique seeds to different strings, ensuring no two strings share the same decryption signature.
* 📦 **Header-Only:** Simply drop `DynamicCrypter.hpp` into your project.
* ⚙️ **MSVC Bug-Resistant:** Tailored to bypass aggressive macro-expansion bugs common in the Microsoft Visual Studio compiler.

## Quick Start

### 1. Include and Protect
Wrap your string literals with the `CRYPT_STR` macro:

```cpp
#include <iostream>
#include "DynamicCrypter.hpp"

int main() {
    // Each of these strings compiles into a completely distinct assembly pattern
    std::cout << CRYPT_STR("Hello World! This uses one flavour.") << std::endl;
    std::cout << CRYPT_STR("Critical System Component Initiated.") << std::endl;
    std::cout << CRYPT_STR("https://secure-endpoint.local") << std::endl;

    return 0;
}
```

### 2. Required Compiler Flags

Because this library utilizes compile-time `if constexpr` branch optimization, you must enable **C++17** or newer:

* **MSVC / Visual Studio:** Enable `/std:c++17` under your Language Properties.
* **GCC / Clang:** Append `-std=std=c++17`.

For maximum stealth, ensure Release optimizations are active (`/O2`, `/Ob2`, and `/Oi` on MSVC) so the decryption algorithms inline perfectly and strip out dead variations.

## License & Attribution
This project is licensed under the **MIT License**—see the [LICENSE](LICENSE) file for details.

### Acknowledgements & Development
* **Architectural Concept:** Inspired by the pioneering compile-time string encryption layout of [skCrypter]([https://github.com](https://github.com/skadro-official/skCrypter)) (MIT License).
* **Implementation:** The multi-flavour polymorphic expansion, MSVC macro bug mitigation, and architecture for this header-only library were collaboratively co-developed with **Google's Gemini LLM** (September 2026).

## Disclaimer
This project is developed strictly for educational analysis, authorized security research, software reverse-engineering mitigation, and digital asset protection. The authors assume no liability for unintended or unauthorized deployment.
