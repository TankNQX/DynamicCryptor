// ============================================================================
//  DynamicCrypter - usage example
// ----------------------------------------------------------------------------
//  A short, copy-pasteable introduction to the library. Every string below is
//  encrypted at compile time with its own algorithm and key, the encrypted bytes
//  stay a read-only compile-time constant for the whole run of the program, and
//  CRYPT_STR() hands back one small object that owns the string and can flip it
//  between its plain and cipher forms.
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
    //    The object lives until the end of the statement, and its buffer is
    //    cleared as soon as the call returns.
    // ------------------------------------------------------------------
    std::cout << CRYPT_STR("Hello World! This uses one polymorphic flavour.") << std::endl;
    std::cout << CRYPT_STR("Critical System Component Initiated.") << std::endl;
    std::cout << CRYPT_STR("https://secure-endpoint.local") << std::endl;

    // ------------------------------------------------------------------
    // 2. When the text has to outlive the statement, keep the object. It is
    //    readable for as long as it is alive, converts to const CharType*
    //    implicitly and also offers .get(), .c_str(), .data() and .size().
    // ------------------------------------------------------------------
    auto message = CRYPT_STR("Protected for as long as `message` is alive.");
    std::cout << message.get() << std::endl;

    std::string copy(message);  // implicit conversion
    std::cout << "copied " << copy.size() << " characters" << std::endl;

    // ------------------------------------------------------------------
    // 3. Its state machine is yours to drive, exactly like skCrypter's:
    //    encrypt() puts the ciphertext back into the object's own buffer, any
    //    read decodes it again, and clear() ends the string for good. The
    //    destructor clears the buffer too, so the scope is always enough.
    // ------------------------------------------------------------------
    auto credential = CRYPT_STR("correct horse battery staple");
    std::printf("plain:      %s\n", credential.get());
    std::printf("encrypted:  %d\n", static_cast<int>(credential.isEncrypted()));

    credential.encrypt();  // no plaintext left in the buffer while it waits
    std::printf("encrypted:  %d\n", static_cast<int>(credential.isEncrypted()));
    std::printf("decoded:    %s\n", credential.get());  // reads decode on demand

    credential.clear();  // traceless: zeroed, and there is no way back
    std::printf("cleared:    [%s]\n", credential.get());

    // ------------------------------------------------------------------
    // 4. Wide strings behave the same way - but a wide stream needs .get():
    //    the wide-string inserter is a function template, and deduction cannot
    //    see through the object's conversion operator.
    // ------------------------------------------------------------------
    std::wcout << CRYPT_STR(L"Wide-String Hello Protection").get() << std::endl;

    // ------------------------------------------------------------------
    // 5. printf-style APIs need .get() for the same reason: variadic argument
    //    lists do not apply user defined conversions.
    // ------------------------------------------------------------------
    std::printf("printf says: %s\n", CRYPT_STR("streamed into printf").get());

    // ------------------------------------------------------------------
    // 6. The pointer is only valid while its object is, so characters that have
    //    to outlive it get copied into storage you own. Two objects are two
    //    independent buffers, never two views on one.
    // ------------------------------------------------------------------
    std::vector<std::string> endpoints = {
        CRYPT_STR("https://one.example").get(),
        CRYPT_STR("https://two.example").get(),
    };
    for (const std::string& endpoint : endpoints) {
        std::cout << " -> " << endpoint << std::endl;
    }

    // ------------------------------------------------------------------
    // 7. Optional: pick the dimensions yourself instead of letting the call
    //    site hash decide. See the README for the full table.
    // ------------------------------------------------------------------
    using Chosen = DynamicCrypter::Flavour<DynamicCrypter::Keygen::splitmix,
                                           DynamicCrypter::Combiner::sbox,
                                           DynamicCrypter::Mode::cfb,
                                           DynamicCrypter::Order::odds_first>;

    constexpr char kExplicit[] = "Explicitly chosen flavour";
    const DynamicCrypter::EncryptedString<char, sizeof(kExplicit), Chosen, 0x12345678u>
        site(kExplicit);

    // The site is the read-only compile-time blob; the object seeds itself from
    // it and owns the plaintext from then on.
    const DynamicCrypter::Crypter<char, sizeof(kExplicit), Chosen, 0x12345678u> chosen(site);
    std::cout << chosen.get() << std::endl;

    return 0;
}
