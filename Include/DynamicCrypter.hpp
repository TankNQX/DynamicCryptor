#pragma once
#include <cstddef>
#include <cstdint>
#include <type_traits> // Required for std::remove_cv_t and std::remove_pointer_t

#if defined(_M_IX86) || defined(_M_X64) || defined(__i386__) || defined(__x86_64__)
#include <immintrin.h>
#define CRYPTER_X86_64
#endif

namespace DynamicCrypter {

    // --- Compile-Time Pure C++ Math Helpers ---
    template <typename T>
    constexpr T ct_rotate_left(T val, int count) {
        constexpr size_t bits = sizeof(T) * 8;
        return (val << (count % bits)) | (val >> (bits - (count % bits)));
    }

    template <typename T>
    constexpr T ct_rotate_right(T val, int count) {
        constexpr size_t bits = sizeof(T) * 8;
        return (val >> (count % bits)) | (val << (bits - (count % bits)));
    }

    constexpr uint32_t ct_crc32_step(uint32_t crc, uint8_t data) {
        crc ^= data;
        for (int j = 0; j < 8; ++j) {
            crc = (crc >> 1) ^ (crc & 1 ? 0xEDB88320 : 0);
        }
        return crc;
    }

    // --- Core Universal Engine ---
    template <typename CharType, size_t Size, int SelectedFlavour, uint32_t Seed>
    class EncryptedString {
    public:
        // Compile-time Encryption Constructor (Accepts const input string pointer)
        constexpr EncryptedString(const CharType* plaintext) : _storage{} {
            CharType last_cipher = static_cast<CharType>(Seed & 0xFF); 
            uint32_t lcg_state = Seed;

            for (size_t i = 0; i < Size; ++i) {
                CharType step_key = static_cast<CharType>(Seed ^ i);
                CharType raw_character = plaintext[i];

                constexpr int flavour_id = SelectedFlavour % 8;

                if constexpr (flavour_id == 0) {
                    _storage[i] = raw_character ^ step_key;
                }
                else if constexpr (flavour_id == 1) {
                    _storage[i] = ct_rotate_left(raw_character, step_key % 8) + step_key;
                }
                else if constexpr (flavour_id == 2) {
                    _storage[i] = (raw_character * 7) ^ step_key;
                }
                else if constexpr (flavour_id == 3) {
                    _storage[i] = raw_character ^ last_cipher ^ static_cast<CharType>(Seed + i);
                    last_cipher = _storage[i];
                }
                else if constexpr (flavour_id == 4) {
                    CharType working = raw_character ^ static_cast<CharType>(Seed + i);
                    _storage[i] = ~working;
                }
                else if constexpr (flavour_id == 5) {
                    uint32_t ct_crc = Seed;
                    for (size_t b = 0; b < sizeof(CharType); ++b) {
                        ct_crc = ct_crc32_step(ct_crc, static_cast<uint8_t>((i + b) & 0xFF));
                    }
                    _storage[i] = raw_character ^ static_cast<CharType>(ct_crc);
                }
                else if constexpr (flavour_id == 6) {
                    constexpr size_t total_bits = sizeof(CharType) * 8;
                    constexpr size_t half_bits = total_bits / 2;
                    constexpr CharType mask = (static_cast<CharType>(1) << half_bits) - 1;

                    CharType L = (raw_character >> half_bits) & mask;
                    CharType R = raw_character & mask;
                    CharType new_R = L ^ ((R ^ step_key) & mask);
                    CharType new_L = R;
                    _storage[i] = (new_L << half_bits) | new_R;
                }
                else if constexpr (flavour_id == 7) {
                    lcg_state = lcg_state * 1664525 + 1013904223;
                    _storage[i] = raw_character ^ static_cast<CharType>(lcg_state);
                }
            }
        }

        // Inline Runtime Decryption
        __forceinline const CharType* decrypt() {
            uint32_t lcg_state = Seed;
            constexpr int flavour_id = SelectedFlavour % 8;

            for (size_t i = 0; i < Size; ++i) {
                CharType step_key = static_cast<CharType>(Seed ^ i);
                CharType cipher_char = _storage[i];

                if constexpr (flavour_id == 0) {
                    _storage[i] = cipher_char ^ step_key;
                }
                else if constexpr (flavour_id == 1) {
                    _storage[i] = ct_rotate_right(static_cast<CharType>(cipher_char - step_key), step_key % 8);
                }
                else if constexpr (flavour_id == 2) {
                    if constexpr (sizeof(CharType) == 1) {
                        _storage[i] = static_cast<CharType>((cipher_char ^ step_key) * 183);
                    } else if constexpr (sizeof(CharType) == 2) {
                        _storage[i] = static_cast<CharType>((cipher_char ^ step_key) * 56167);
                    } else {
                        _storage[i] = static_cast<CharType>((cipher_char ^ step_key) * 3681400535U);
                    }
                }
                else if constexpr (flavour_id == 4) {
                    _storage[i] = (~cipher_char) ^ static_cast<CharType>(Seed + i);
                }
                else if constexpr (flavour_id == 5) {
                    uint32_t hw_crc = Seed;
#if defined(CRYPTER_X86_64) && defined(_MSC_VER)
                    for (size_t b = 0; b < sizeof(CharType); ++b) {
                        hw_crc = _mm_crc32_u8(hw_crc, static_cast<uint8_t>((i + b) & 0xFF));
                    }
#else
                    for (size_t b = 0; b < sizeof(CharType); ++b) {
                        hw_crc = ct_crc32_step(hw_crc, static_cast<uint8_t>((i + b) & 0xFF));
                    }
#endif
                    _storage[i] = cipher_char ^ static_cast<CharType>(hw_crc);
                }
                else if constexpr (flavour_id == 6) {
                    constexpr size_t total_bits = sizeof(CharType) * 8;
                    constexpr size_t half_bits = total_bits / 2;
                    constexpr CharType mask = (static_cast<CharType>(1) << half_bits) - 1;

                    CharType new_L = (cipher_char >> half_bits) & mask;
                    CharType new_R = cipher_char & mask;
                    CharType R = new_L;
                    CharType L = new_R ^ ((R ^ step_key) & mask);
                    _storage[i] = (L << half_bits) | R;
                }
                else if constexpr (flavour_id == 7) {
                    lcg_state = lcg_state * 1664525 + 1013904223;
                    _storage[i] = cipher_char ^ static_cast<CharType>(lcg_state);
                }
            }

            if constexpr (flavour_id == 3) {
                if (Size > 0) {
                    for (size_t i = Size - 1; i > 0; --i) {
                        _storage[i] = _storage[i] ^ _storage[i - 1] ^ static_cast<CharType>(Seed + i);
                    }
                    _storage = _storage ^ static_cast<CharType>(Seed & 0xFF);
                }
            }

            return reinterpret_cast<const CharType*>(_storage);
        }

    private:
        CharType _storage[Size]; // Properly mutable character buffer now
    };
}

// Generates a dynamic seed per macro call
#define CRYPTER_SEED (static_cast<uint32_t>((__LINE__ * 0x1E35A) ^ (__COUNTER__ * 0x7B13)))

// Fixes C3892: Added std::remove_cv_t to completely strip out "const" from deduced array items
#define CRYPT_STR(str) []() { \
    using TypeRaw = std::remove_pointer_t<std::decay_t<decltype(str)>>; \
    using TypeDeduction = std::remove_cv_t<TypeRaw>; \
    constexpr int current_flavour_id = __COUNTER__; \
    static auto instance = DynamicCrypter::EncryptedString<TypeDeduction, sizeof(str)/sizeof(TypeDeduction), current_flavour_id, CRYPTER_SEED>(str); \
    return instance.decrypt(); \
}()
