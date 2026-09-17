// ============================================================================
//  DynamicCrypter - usage example
// ----------------------------------------------------------------------------
//  A short, copy-pasteable introduction to the library. Every string below is
//  encrypted at compile time with its own algorithm and key, and the plaintext
//  only exists while the handle returned by CRYPT_STR() is alive.
//
//  The full self-verifying test suite lives in test/test.cpp.
//
//  Build:  cmake --build build --target DynamicCrypterExample
//  Run:    build/<config>/DynamicCrypterExample
// ============================================================================

#include <cstdio>
#include <iostream>
#include <string>
#include <vector>

#include "DynamicCrypter.hpp"

int main() {
    // ------------------------------------------------------------------
    // 1. The common case: hand the string straight to whatever consumes it.
    //    The handle lives until the end of the statement, so the plaintext is
    //    re-encrypted as soon as the call returns.
    // ------------------------------------------------------------------
    std::cout << CRYPT_STR("Hello World! This uses one polymorphic flavour.") << std::endl;
    std::cout << CRYPT_STR("Critical System Component Initiated.") << std::endl;
    std::cout << CRYPT_STR("https://secure-endpoint.local") << std::endl;

    // ------------------------------------------------------------------
    // 2. When the plaintext has to outlive the statement, keep the handle.
    //    It converts to const CharType* implicitly and also offers .get(),
    //    .c_str(), .data() and .size().
    // ------------------------------------------------------------------
    auto message = CRYPT_STR("Protected for as long as `message` is alive.");
    std::cout << message.get() << std::endl;

    std::string copy(message);  // implicit conversion
    std::cout << "copied " << copy.size() << " characters" << std::endl;
    // ...and the buffer is re-encrypted here, when `message` goes out of scope.

    // ------------------------------------------------------------------
    // 3. Wide strings behave exactly the same way.
    // ------------------------------------------------------------------
    std::wcout << CRYPT_STR(L"Wide-String Hello Protection") << std::endl;

    // ------------------------------------------------------------------
    // 4. printf-style APIs need .get(): variadic argument lists do not apply
    //    user defined conversions, so the wrapper object cannot convert there.
    // ------------------------------------------------------------------
    std::printf("printf says: %s\n", CRYPT_STR("streamed into printf").get());

    // ------------------------------------------------------------------
    // 5. When the pointer itself has to outlive the statement - a container,
    //    a return value, a C API - use CRYPT_STR_RAW. It decrypts on first use
    //    and leaves the plaintext in place.
    // ------------------------------------------------------------------
    const char* raw = CRYPT_STR_RAW("Outlives the statement.");
    const std::vector<const char*> endpoints = {
        CRYPT_STR_RAW("https://one.example"),
        CRYPT_STR_RAW("https://two.example"),
    };

    std::cout << raw << std::endl;
    for (const char* endpoint : endpoints) {
        std::cout << " -> " << endpoint << std::endl;
    }

    // ------------------------------------------------------------------
    // 6. Optional: pick the dimensions yourself instead of letting the call
    //    site hash decide. See the README for the full table.
    // ------------------------------------------------------------------
    using Chosen = DynamicCrypter::Flavour<DynamicCrypter::Keygen::splitmix,
                                           DynamicCrypter::Combiner::sbox,
                                           DynamicCrypter::Mode::cfb,
                                           DynamicCrypter::Order::odds_first>;

    constexpr char kExplicit[] = "Explicitly chosen flavour";
    DynamicCrypter::EncryptedString<char, sizeof(kExplicit), Chosen, 0x12345678u> chosen(kExplicit);
    std::cout << chosen.decrypt() << std::endl;

    return 0;
}
