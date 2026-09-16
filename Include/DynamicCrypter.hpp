#pragma once
#include <cstddef>
#include <cstdint>

namespace DynamicCrypter {

    // --- Compile-Time Pure C++ Math Helpers ---
    constexpr uint8_t ct_rotate_left(uint8_t val, int count) {
        return (val << (count % 8)) | (val >> (8 - (count % 8)));
    }

    constexpr uint8_t ct_rotate_right(uint8_t val, int count) {
        return (val >> (count % 8)) | (val << (8 - (count % 8)));
    }

    constexpr uint32_t ct_crc32_step(uint32_t crc, uint8_t data) {
        crc ^= data;
        for (int j = 0; j < 8; ++j) {
            crc = (crc >> 1) ^ (crc & 1 ? 0xEDB88320 : 0);
        }
        return crc;
    }

    // --- Core Compile-Time & Runtime Engine ---
    // Note: SelectedFlavour changed to a primitive int to fix the MSVC C2440 macro bug
    template <size_t Size, int SelectedFlavour, uint32_t Seed>
    class EncryptedString {
    public:
        // Compile-time Encryption Constructor
        constexpr EncryptedString(const char* plaintext) : _storage{} {
            uint8_t last_cipher = Seed & 0xFF; 
            uint32_t lcg_state = Seed;

            for (size_t i = 0; i < Size; ++i) {
                uint8_t step_key = static_cast<uint8_t>(Seed ^ i);
                uint8_t raw_byte = static_cast<uint8_t>(plaintext[i]);

                // Modulo ensures the flavour identifier wraps neatly within 0-7 bounds
                constexpr int flavour_id = SelectedFlavour % 8;

                if constexpr (flavour_id == 0) {
                    _storage[i] = raw_byte ^ step_key;
                }
                else if constexpr (flavour_id == 1) {
                    _storage[i] = ct_rotate_left(raw_byte, step_key % 8) + step_key;
                }
                else if constexpr (flavour_id == 2) {
                    _storage[i] = (raw_byte * 7) ^ step_key;
                }
                else if constexpr (flavour_id == 3) {
                    _storage[i] = raw_byte ^ last_cipher ^ static_cast<uint8_t>(Seed + i);
                    last_cipher = _storage[i];
                }
                else if constexpr (flavour_id == 4) {
                    uint8_t working = raw_byte ^ static_cast<uint8_t>(Seed + i);
                    _storage[i] = (i % 2 == 0) ? ~working : working;
                }
                else if constexpr (flavour_id == 5) {
                    uint32_t ct_crc = ct_crc32_step(Seed, static_cast<uint8_t>(i));
                    _storage[i] = raw_byte ^ static_cast<uint8_t>(ct_crc & 0xFF);
                }
                else if constexpr (flavour_id == 6) {
                    uint8_t L = (raw_byte >> 4) & 0x0F;
                    uint8_t R = raw_byte & 0x0F;
                    uint8_t new_R = L ^ ((R ^ step_key) & 0x0F);
                    uint8_t new_L = R;
                    _storage[i] = (new_L << 4) | new_R;
                }
                else if constexpr (flavour_id == 7) {
                    lcg_state = lcg_state * 1664525 + 1013904223;
                    _storage[i] = raw_byte ^ static_cast<uint8_t>((lcg_state >> 16) & 0xFF);
                }
            }
        }

        // Inline Runtime Decryption
        __forceinline const char* decrypt() {
            uint32_t lcg_state = Seed;
            constexpr int flavour_id = SelectedFlavour % 8;

            for (size_t i = 0; i < Size; ++i) {
                uint8_t step_key = static_cast<uint8_t>(Seed ^ i);
                uint8_t cipher_byte = static_cast<uint8_t>(_storage[i]);

                if constexpr (flavour_id == 0) {
                    _storage[i] = cipher_byte ^ step_key;
                }
                else if constexpr (flavour_id == 1) {
                    _storage[i] = ct_rotate_right(static_cast<uint8_t>(cipher_byte - step_key), step_key % 8);
                }
                else if constexpr (flavour_id == 2) {
                    _storage[i] = static_cast<uint8_t>((cipher_byte ^ step_key) * 183);
                }
                else if constexpr (flavour_id == 4) {
                    uint8_t working = (i % 2 == 0) ? ~cipher_byte : cipher_byte;
                    _storage[i] = working ^ static_cast<uint8_t>(Seed + i);
                }
                else if constexpr (flavour_id == 5) {
#if defined(CRYPTER_X86_64) && defined(_MSC_VER)
                    uint32_t hw_crc = _mm_crc32_u8(Seed, static_cast<uint8_t>(i));
#else
                    uint32_t hw_crc = ct_crc32_step(Seed, static_cast<uint8_t>(i));
#endif
                    _storage[i] = cipher_byte ^ static_cast<uint8_t>(hw_crc & 0xFF);
                }
                else if constexpr (flavour_id == 6) {
                    uint8_t new_L = (cipher_byte >> 4) & 0x0F;
                    uint8_t new_R = cipher_byte & 0x0F;
                    uint8_t R = new_L;
                    uint8_t L = new_R ^ ((R ^ step_key) & 0x0F);
                    _storage[i] = (L << 4) | R;
                }
                else if constexpr (flavour_id == 7) {
                    lcg_state = lcg_state * 1664525 + 1013904223;
                    _storage[i] = cipher_byte ^ static_cast<uint8_t>((lcg_state >> 16) & 0xFF);
                }
            }

            if constexpr (flavour_id == 3) {
                if (Size > 0) {
                    for (size_t i = Size - 1; i > 0; --i) {
                        _storage[i] = _storage[i] ^ _storage[i - 1] ^ static_cast<uint8_t>(Seed + i);
                    }
                    _storage = _storage ^ static_cast<uint8_t>(Seed) ^ static_cast<uint8_t>(Seed & 0xFF);
                }
            }

            return reinterpret_cast<const char*>(_storage);
        }

    private:
        uint8_t _storage[Size];
    };
}

// Generates a dynamic seed per expansion based on environmental parameters
#define CRYPTER_SEED (static_cast<uint32_t>((__LINE__ * 0x1E35A) ^ (__COUNTER__ * 0x7B13)))

// Bypasses MSVC macro bugs by using primitive integers inside the lambda wrapper scope
#define CRYPT_STR(str) []() { \
    constexpr int current_flavour_id = __COUNTER__; \
    static auto instance = DynamicCrypter::EncryptedString<sizeof(str), current_flavour_id, CRYPTER_SEED>(str); \
    return instance.decrypt(); \
}()
