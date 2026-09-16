#include <iostream>
#include <vector>
#include "DynamicCrypter.hpp"

int main() {
    std::cout << "[+] DynamicCrypter Test Initialised." << std::endl;

    // Each string literal called here will be encrypted using a completely distinct algorithm path at compile time
    const char* secure_string_1 = CRYPT_STR("Hello World! This uses one polymorphic flavour.");
    const char* secure_string_2 = CRYPT_STR("Critical System Component Initiated.");
    const char* secure_string_3 = CRYPT_STR("https://secure-endpoint.local");

    std::cout << "String 1: " << secure_string_1 << std::endl;
    std::cout << "String 2: " << secure_string_2 << std::endl;
    std::cout << "String 3: " << secure_string_3 << std::endl;

    // Example demonstrating usage inside a container or loop
    std::vector<const char*> protected_array = {
        CRYPT_STR("Array Element A"),
        CRYPT_STR("Array Element B"),
        CRYPT_STR("Array Element C")
    };

    std::cout << "\n[+] Iterating protected array element indicators:" << std::endl;
    for (const auto& str : protected_array) {
        std::cout << " -> " << str << std::endl;
    }

    // 1. Standard Narrow String (char)
    const char* narrow_str = CRYPT_STR("Standard Hello");
    std::cout << narrow_str << std::endl;

    // 2. Wide String (wchar_t) - Works seamlessly via Windows API patterns
    const wchar_t* wide_str = CRYPT_STR(L"Wide-String Hello Protection");
    std::wcout << wide_str << std::endl;

    return 0;
}
