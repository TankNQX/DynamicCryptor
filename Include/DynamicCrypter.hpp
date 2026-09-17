// ============================================================================
//  DynamicCrypter - compile-time polymorphic string encryption (header only)
// ----------------------------------------------------------------------------
//  Requires C++17 or newer and depends on no compiler-specific extension and no
//  architecture: it builds with MSVC, GCC, Clang, ICC and any other conforming
//  C++17 compiler on any target, and the whole header is usable in constant
//  expressions.
//
//  Every string gets its own algorithm, assembled from four independent
//  dimensions (keystream / combiner / mode / order) that are chosen per call
//  site from a hash of the site, the source position and an optional per-build
//  salt. See the README for the dimension tables and the classic presets.
//
//  Quick start:
//      std::cout << CRYPT_STR("Hello World!") << std::endl;   // RAII variant
//      const char* p = CRYPT_STR_RAW("kept alive");           // legacy variant
// ============================================================================
#ifndef DYNAMICCRYPTER_HPP
#define DYNAMICCRYPTER_HPP

#pragma once

#include <cstddef>
#include <cstdint>
#include <type_traits>

// ---------------------------------------------------------------------------
//  Preprocessor compatibility layer
// ---------------------------------------------------------------------------

// MSVC reports 199711L for __cplusplus unless /Zc:__cplusplus is given, so the
// language level has to be read from _MSVC_LANG there.
#if defined(_MSVC_LANG)
#  define CRYPTER_CPLUSPLUS _MSVC_LANG
#else
#  define CRYPTER_CPLUSPLUS __cplusplus
#endif

#if !defined(CRYPTER_NO_STANDARD_CHECK) && (CRYPTER_CPLUSPLUS < 201703L)
#  error "DynamicCrypter requires C++17 or newer: use /std:c++17 (MSVC) or -std=c++17 (GCC/Clang)."
#endif

// __COUNTER__ is an extension (MSVC, GCC, Clang, ICC, ...) but a very common
// one. Without it we degrade to __LINE__, which still yields working - though
// less varied - per-string flavours.
#if defined(__COUNTER__)
#  define CRYPTER_COUNTER __COUNTER__
#else
#  define CRYPTER_COUNTER __LINE__
#endif

// Always-inline hint. Override by defining CRYPTER_FORCEINLINE before including
// this header, e.g. to plain "inline" on a compiler whose always_inline
// attribute misbehaves in some build configuration.
#ifndef CRYPTER_FORCEINLINE
#  if defined(_MSC_VER)
#    define CRYPTER_FORCEINLINE __forceinline
#  elif defined(__GNUC__) || defined(__clang__) || defined(__INTEL_COMPILER) || \
        defined(__ibmxl__) || defined(__NVCOMPILER)
#    define CRYPTER_FORCEINLINE inline __attribute__((always_inline))
#  else
#    define CRYPTER_FORCEINLINE inline
#  endif
#endif

// Per-build salt. Define it (e.g. CMake option DYNAMICCRYPTER_BUILD_SALT) to
// make every key, every flavour selection and therefore every emitted byte
// unique to one build, so signatures and keys do not transfer between builds.
// The default of 0 keeps builds reproducible.
#ifndef CRYPTER_BUILD_SALT
#  define CRYPTER_BUILD_SALT 0u
#endif

// The SSE4.2 CRC32 intrinsic path of earlier revisions is gone. The keystream
// generator is shared between the compile-time encryption and the run-time
// decryption, so it has to be a constant expression, and an intrinsic cannot
// be one. CRC-32C is still available as a portable keystream generator
// (Keygen::crc32c), and it agrees in both directions by construction.
#if defined(CRYPTER_USE_HW_CRC32)
#  pragma message("DynamicCrypter: CRYPTER_USE_HW_CRC32 is obsolete and ignored; the CRC-32C keystream generator is portable C++.")
#endif

namespace DynamicCrypter {

    // =======================================================================
    //  The four dimensions every string flavour is assembled from
    // =======================================================================

    // How the per-character key material is produced.
    enum class Keygen : int {
        seed_xor,       // seed ^ index, truncated to the character width
        lcg,            // linear congruential stream (1664525 / 1013904223)
        xorshift,       // xorshift32 stream
        splitmix,       // splitmix-style add-multiply-mix stream
        crc32c,         // CRC-32C over the index bytes
        mul_high,       // multiply-and-take-the-high-bits stream
        murmur,         // murmur3-style finaliser over seed and index
        rev_counter,    // byte-reversed counter
        count
    };

    // How one character is combined with one key value.
    enum class Combiner : int {
        bit_xor,        // value ^ key
        add,            // value + key
        sub,            // value - key
        rotl_add,       // rotate left by key % 8, then add key
        mul_odd,        // multiply by the odd part of key (invertible mod 2^n)
        feistel,        // one Feistel-lite round over the two halves
        bitrev,         // reverse the bits, then XOR key
        nibble_swap,    // swap the nibbles of every byte, then XOR key
        not_xor,        // complement, then XOR key
        sbox,           // GF(2^8) inverse plus affine map (AES-style S-box)
        count
    };

    // How characters influence each other.
    enum class Mode : int {
        stream,         // each character is independent
        cbc,            // c[i] = C(p[i] ^ c[i-1], k[i])
        cfb,            // c[i] = C(p[i], k[i] ^ c[i-1])  (data dependent key)
        count
    };

    // The order in which the characters are processed.
    enum class Order : int {
        forward,        // 0, 1, 2, ...
        backward,       // ..., 2, 1, 0
        rotate,         // a seed derived rotation
        evens_first,    // 0, 2, 4, ..., 1, 3, ...
        odds_first,     // 1, 3, ..., 0, 2, ...
        count
    };

    // A flavour is just the four dimension values bundled into one type.
    template <Keygen K, Combiner C, Mode M, Order O>
    struct Flavour {
        static constexpr Keygen keygen = K;
        static constexpr Combiner combiner = C;
        static constexpr Mode mode = M;
        static constexpr Order order = O;
    };

    namespace detail {

        // -------------------------------------------------------------------
        //  Type helpers and bit tricks
        // -------------------------------------------------------------------

        // All arithmetic is performed on the unsigned counterpart of the
        // character type. That keeps the operations well defined (no signed
        // overflow, no implementation-defined shift of a negative value) and
        // makes the resulting byte pattern identical on every compiler - which
        // is what matters, since encryption and decryption must agree.
        template <typename CharType>
        using uint_type = std::make_unsigned_t<CharType>;

        // Portable rotates. Only ever instantiated with unsigned types: shifting
        // a signed value is implementation-defined, and shifting by the full
        // width is undefined behaviour.
        template <typename U>
        constexpr U rotl(U value, unsigned count) noexcept {
            constexpr unsigned bits = static_cast<unsigned>(sizeof(U)) * 8u;
            const unsigned r = count % bits;
            const U left = static_cast<U>(value << r);
            const U right = static_cast<U>(value >> ((bits - r) % bits));
            return static_cast<U>(left | right);
        }

        template <typename U>
        constexpr U rotr(U value, unsigned count) noexcept {
            constexpr unsigned bits = static_cast<unsigned>(sizeof(U)) * 8u;
            const unsigned r = count % bits;
            const U left = static_cast<U>(value >> r);
            const U right = static_cast<U>(value << ((bits - r) % bits));
            return static_cast<U>(left | right);
        }

        template <typename U>
        constexpr U reverse_bits(U value) noexcept {
            constexpr unsigned bits = static_cast<unsigned>(sizeof(U)) * 8u;
            U result = 0;
            for (unsigned bit = 0; bit < bits; ++bit) {
                result = static_cast<U>(static_cast<U>(result << 1u) |
                                        static_cast<U>((value >> bit) & static_cast<U>(1u)));
            }
            return result;
        }

        template <typename U>
        constexpr U swap_nibbles(U value) noexcept {
            U result = 0;
            for (unsigned byte = 0; byte < sizeof(U); ++byte) {
                const unsigned shift = byte * 8u;
                const uint8_t b = static_cast<uint8_t>((value >> shift) & static_cast<U>(0xFFu));
                const uint8_t swapped =
                    static_cast<uint8_t>(static_cast<uint8_t>(b << 4u) | static_cast<uint8_t>(b >> 4u));
                result = static_cast<U>(result |
                                        static_cast<U>(static_cast<uint32_t>(swapped) << shift));
            }
            return result;
        }

        constexpr uint32_t reverse_bytes32(uint32_t value) noexcept {
            return ((value & 0x000000FFu) << 24) | ((value & 0x0000FF00u) << 8) |
                   ((value & 0x00FF0000u) >> 8) | ((value & 0xFF000000u) >> 24);
        }

        // 32 bit finaliser (the well known "lowbias32" bijection). Used both for
        // site hashing and inside the keystream generators.
        constexpr uint32_t mix32(uint32_t x) noexcept {
            x ^= x >> 16;
            x *= 0x7FEB352Du;
            x ^= x >> 15;
            x *= 0x846CA68Bu;
            x ^= x >> 16;
            return x;
        }

        // -------------------------------------------------------------------
        //  AES-style S-box, built and inverted at compile time
        // -------------------------------------------------------------------
        //  The S-box is the composition of the multiplicative inverse in
        //  GF(2^8) (modulo 0x11B) with an invertible affine map, i.e. the
        //  classic construction. Everything is derived, nothing is written out
        //  by hand:
        //
        //    * the inverses come from a walk of the multiplicative group,
        //      because 3 generates it: (3^k)^-1 == 3^(255-k)
        //    * the inverse S-box is then built by inverting the permutation,
        //      so forward and inverse agree by construction
        //    * sbox_is_bijection() below proves the result on all 256 inputs at
        //      compile time, on every compiler
        //
        //  The walk matters for another reason: computing 256 inverses by
        //  exponentiation would need roughly 180k constexpr evaluation steps,
        //  well past MSVC's default /constexpr:steps budget of 100k.

        constexpr uint8_t gf_mul(uint8_t a, uint8_t b) noexcept {
            uint8_t result = 0;
            for (int i = 0; i < 8; ++i) {
                if ((b & 1u) != 0u) {
                    result = static_cast<uint8_t>(result ^ a);
                }
                const uint8_t carry = static_cast<uint8_t>(a & 0x80u);
                a = static_cast<uint8_t>(a << 1u);
                if (carry != 0u) {
                    a = static_cast<uint8_t>(a ^ 0x1Bu);
                }
                b = static_cast<uint8_t>(b >> 1u);
            }
            return result;
        }

        constexpr uint8_t sbox_affine(uint8_t inverse) noexcept {
            return static_cast<uint8_t>(inverse ^ rotl<uint8_t>(inverse, 1u) ^
                                        rotl<uint8_t>(inverse, 2u) ^ rotl<uint8_t>(inverse, 3u) ^
                                        rotl<uint8_t>(inverse, 4u) ^ 0x63u);
        }

        struct SboxTables {
            uint8_t forward[256];
            uint8_t inverse[256];

            constexpr SboxTables() noexcept : forward{}, inverse{} {
                // power[k] == 3^k in GF(2^8); 3 generates the multiplicative group.
                uint8_t power[256] = {};
                power[0] = 1u;
                for (unsigned k = 1; k < 256u; ++k) {
                    power[k] = gf_mul(power[k - 1u], static_cast<uint8_t>(3u));
                }

                uint8_t multiplicative_inverse[256] = {};
                for (unsigned k = 0; k < 255u; ++k) {
                    // (3^k)^-1 == 3^(255-k), and 0 keeps its inverse of 0.
                    multiplicative_inverse[power[k]] = power[255u - k];
                }

                for (unsigned i = 0; i < 256u; ++i) {
                    forward[i] = sbox_affine(multiplicative_inverse[static_cast<uint8_t>(i)]);
                }
                for (unsigned i = 0; i < 256u; ++i) {
                    inverse[forward[i]] = static_cast<uint8_t>(i);
                }
            }
        };

        // C++17 inline variable: one shared pair of tables per translation unit,
        // and no storage at all if the S-box combiner is never instantiated.
        inline constexpr SboxTables g_sbox{};

        constexpr bool sbox_is_bijection() noexcept {
            bool seen[256] = {};
            for (unsigned i = 0; i < 256u; ++i) {
                const uint8_t mapped = g_sbox.forward[i];
                if (seen[mapped]) {
                    return false;
                }
                seen[mapped] = true;
                if (g_sbox.inverse[mapped] != static_cast<uint8_t>(i)) {
                    return false;
                }
            }
            return true;
        }

        template <typename U>
        constexpr U sbox_word(U value) noexcept {
            // Evaluated only where the S-box is actually used, so translation
            // units that never select that combiner do not pay for it. It
            // validates both tables, and therefore also sbox_word_inverse.
            static_assert(sbox_is_bijection(),
                          "DynamicCrypter: the S-box construction is not a bijection, "
                          "so it could not be inverted");
            U result = 0;
            for (unsigned byte = 0; byte < sizeof(U); ++byte) {
                const unsigned shift = byte * 8u;
                const uint8_t b = static_cast<uint8_t>((value >> shift) & static_cast<U>(0xFFu));
                result = static_cast<U>(result |
                                        static_cast<U>(static_cast<uint32_t>(g_sbox.forward[b]) << shift));
            }
            return result;
        }

        template <typename U>
        constexpr U sbox_word_inverse(U value) noexcept {
            U result = 0;
            for (unsigned byte = 0; byte < sizeof(U); ++byte) {
                const unsigned shift = byte * 8u;
                const uint8_t b = static_cast<uint8_t>((value >> shift) & static_cast<U>(0xFFu));
                result = static_cast<U>(result |
                                        static_cast<U>(static_cast<uint32_t>(g_sbox.inverse[b]) << shift));
            }
            return result;
        }

        // -------------------------------------------------------------------
        //  Modular inverse of an odd multiplier
        // -------------------------------------------------------------------
        //  x_{n+1} = x_n * (2 - a * x_n) doubles the number of correct low bits
        //  each round, so five rounds take it to the full 32 bits. The low bits
        //  of that inverse are also the inverse modulo 2^8 and 2^16.
        constexpr uint32_t mul_inverse32(uint32_t odd) noexcept {
            uint32_t x = 1u;
            for (int i = 0; i < 5; ++i) {
                x = x * (2u - odd * x);
            }
            return x;
        }

        template <typename U>
        constexpr U mul_inverse(U odd) noexcept {
            return static_cast<U>(mul_inverse32(static_cast<uint32_t>(odd)));
        }

        // -------------------------------------------------------------------
        //  Reflected CRC-32C (Castagnoli) single byte step
        // -------------------------------------------------------------------
        constexpr uint32_t crc32c_step(uint32_t crc, uint8_t data) noexcept {
            crc ^= data;
            for (int bit = 0; bit < 8; ++bit) {
                crc = (crc >> 1) ^ (0x82F63B78u & (0u - (crc & 1u)));
            }
            return crc;
        }

        // -------------------------------------------------------------------
        //  Dimension 1: keystream generators
        // -------------------------------------------------------------------
        //  Filled into a temporary array in index order. Materialising the
        //  keystream keeps the generators independent of the processing order
        //  and of the mode, which is what makes the four dimensions composable,
        //  and it guarantees the inverse sees exactly the same sequence.
        template <Keygen K, uint32_t Seed, typename U, size_t Size>
        constexpr void make_keystream(U (&keys)[Size]) noexcept {
            // Unused by the generators that are pure functions of the index.
            [[maybe_unused]] uint32_t state = Seed;

            if constexpr (K == Keygen::xorshift) {
                if (state == 0u) {
                    state = 0x9E3779B9u;  // xorshift would otherwise stay at zero
                }
            }

            for (size_t i = 0; i < Size; ++i) {
                U value = 0;

                if constexpr (K == Keygen::seed_xor) {
                    value = static_cast<U>(Seed ^ static_cast<uint32_t>(i));
                } else if constexpr (K == Keygen::lcg) {
                    state = state * 1664525u + 1013904223u;
                    value = static_cast<U>(state);
                } else if constexpr (K == Keygen::xorshift) {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    value = static_cast<U>(state);
                } else if constexpr (K == Keygen::splitmix) {
                    state += 0x9E3779B9u;
                    value = static_cast<U>(mix32(state));
                } else if constexpr (K == Keygen::crc32c) {
                    uint32_t crc = Seed;
                    for (size_t b = 0; b < sizeof(U); ++b) {
                        crc = crc32c_step(crc, static_cast<uint8_t>((i + b) & 0xFFu));
                    }
                    value = static_cast<U>(crc);
                } else if constexpr (K == Keygen::mul_high) {
                    state = state * 0x9E3779B1u + 0x85EBCA6Bu;
                    constexpr unsigned shift = 32u - static_cast<unsigned>(sizeof(U)) * 8u;
                    value = static_cast<U>(state >> shift);
                } else if constexpr (K == Keygen::murmur) {
                    value = static_cast<U>(mix32(Seed ^ (static_cast<uint32_t>(i) * 0x9E3779B9u)));
                } else {  // Keygen::rev_counter
                    value = static_cast<U>(reverse_bytes32(Seed + static_cast<uint32_t>(i)));
                }

                // A zero key would leave the character untouched for the XOR
                // style combiners, so the low bit is forced on. Both directions
                // derive the same value, and it costs one bit nothing.
                keys[i] = static_cast<U>(value | static_cast<U>(1u));
            }
        }

        // -------------------------------------------------------------------
        //  Dimension 2: per character combiners
        // -------------------------------------------------------------------
        template <Combiner C, typename U>
        constexpr U combine(U value, U key) noexcept {
            if constexpr (C == Combiner::bit_xor) {
                return static_cast<U>(value ^ key);
            } else if constexpr (C == Combiner::add) {
                return static_cast<U>(value + key);
            } else if constexpr (C == Combiner::sub) {
                return static_cast<U>(value - key);
            } else if constexpr (C == Combiner::rotl_add) {
                const unsigned shift = static_cast<unsigned>(key % 8u);
                return static_cast<U>(rotl<U>(value, shift) + key);
            } else if constexpr (C == Combiner::mul_odd) {
                // Explicitly widened: for 16 bit characters the promoted product
                // would otherwise overflow a signed int.
                return static_cast<U>(static_cast<uint32_t>(value) *
                                      static_cast<uint32_t>(static_cast<U>(key | static_cast<U>(1u))));
            } else if constexpr (C == Combiner::feistel) {
                constexpr size_t half = sizeof(U) * 8u / 2u;
                constexpr U mask = static_cast<U>((static_cast<uint64_t>(1) << half) - 1u);
                const U left = static_cast<U>(value >> half);
                const U right = static_cast<U>(value & mask);
                const U new_right = static_cast<U>(left ^ ((right ^ key) & mask));
                return static_cast<U>((static_cast<U>(right) << half) | new_right);
            } else if constexpr (C == Combiner::bitrev) {
                return static_cast<U>(reverse_bits<U>(value) ^ key);
            } else if constexpr (C == Combiner::nibble_swap) {
                return static_cast<U>(swap_nibbles<U>(value) ^ key);
            } else if constexpr (C == Combiner::not_xor) {
                return static_cast<U>(static_cast<U>(~value) ^ key);
            } else {  // Combiner::sbox
                return sbox_word<U>(static_cast<U>(value ^ key));
            }
        }

        template <Combiner C, typename U>
        constexpr U uncombine(U value, U key) noexcept {
            if constexpr (C == Combiner::bit_xor) {
                return static_cast<U>(value ^ key);
            } else if constexpr (C == Combiner::add) {
                return static_cast<U>(value - key);
            } else if constexpr (C == Combiner::sub) {
                return static_cast<U>(value + key);
            } else if constexpr (C == Combiner::rotl_add) {
                const unsigned shift = static_cast<unsigned>(key % 8u);
                return rotr<U>(static_cast<U>(value - key), shift);
            } else if constexpr (C == Combiner::mul_odd) {
                return static_cast<U>(static_cast<uint32_t>(value) *
                                      static_cast<uint32_t>(mul_inverse<U>(
                                          static_cast<U>(key | static_cast<U>(1u)))));
            } else if constexpr (C == Combiner::feistel) {
                constexpr size_t half = sizeof(U) * 8u / 2u;
                constexpr U mask = static_cast<U>((static_cast<uint64_t>(1) << half) - 1u);
                const U stored_left = static_cast<U>(value >> half);   // == original right
                const U stored_right = static_cast<U>(value & mask);   // == left ^ ((right ^ key) & mask)
                const U right = stored_left;
                const U left = static_cast<U>(stored_right ^ ((right ^ key) & mask));
                return static_cast<U>((left << half) | right);
            } else if constexpr (C == Combiner::bitrev) {
                return reverse_bits<U>(static_cast<U>(value ^ key));
            } else if constexpr (C == Combiner::nibble_swap) {
                return swap_nibbles<U>(static_cast<U>(value ^ key));
            } else if constexpr (C == Combiner::not_xor) {
                return static_cast<U>(static_cast<U>(~value) ^ key);
            } else {  // Combiner::sbox
                return static_cast<U>(sbox_word_inverse<U>(value) ^ key);
            }
        }

        // -------------------------------------------------------------------
        //  Dimension 3: processing order
        // -------------------------------------------------------------------
        template <Order O, uint32_t Seed, size_t Size>
        constexpr size_t step_index(size_t step) noexcept {
            if constexpr (O == Order::forward) {
                return step;
            } else if constexpr (O == Order::backward) {
                return Size - 1u - step;
            } else if constexpr (O == Order::rotate) {
                constexpr size_t offset =
                    static_cast<size_t>(mix32(Seed ^ 0x51ED270Bu) % static_cast<uint32_t>(Size));
                return (step + offset) % Size;
            } else if constexpr (O == Order::evens_first) {
                constexpr size_t evens = (Size + 1u) / 2u;
                return (step < evens) ? (step * 2u) : ((step - evens) * 2u + 1u);
            } else {  // Order::odds_first
                constexpr size_t odds = Size / 2u;
                return (step < odds) ? (step * 2u + 1u) : ((step - odds) * 2u);
            }
        }

        // -------------------------------------------------------------------
        //  Automatic dimension selection
        // -------------------------------------------------------------------
        //  Four decorrelated slices of one site hash pick one value per
        //  dimension. Exposed as functions rather than only as an alias so that
        //  they can be exercised at run time (see the tests).
        constexpr Keygen select_keygen(uint32_t hash) noexcept {
            return static_cast<Keygen>(mix32(hash ^ 0x9E3779B9u) %
                                       static_cast<uint32_t>(Keygen::count));
        }

        constexpr Combiner select_combiner(uint32_t hash) noexcept {
            return static_cast<Combiner>(mix32(hash ^ 0x85EBCA6Bu) %
                                         static_cast<uint32_t>(Combiner::count));
        }

        constexpr Mode select_mode(uint32_t hash) noexcept {
            return static_cast<Mode>(mix32(hash ^ 0xC2B2AE35u) %
                                     static_cast<uint32_t>(Mode::count));
        }

        constexpr Order select_order(uint32_t hash) noexcept {
            return static_cast<Order>(mix32(hash ^ 0x27D4EB2Fu) %
                                      static_cast<uint32_t>(Order::count));
        }

        // Chain state that precedes the first processed character. Non-zero so
        // that a chained mode never leaves the first character untouched.
        template <typename U, uint32_t Seed>
        constexpr U chaining_iv() noexcept {
            return static_cast<U>(static_cast<U>(mix32(Seed ^ 0xA5A5A5A5u)) | static_cast<U>(1u));
        }

        // -------------------------------------------------------------------
        //  Dimension 4: the mode, i.e. how characters influence each other
        // -------------------------------------------------------------------
        template <typename FlavourT, uint32_t Seed, typename CharType, size_t Size>
        constexpr void transform_forward(CharType* out, const CharType* in) noexcept {
            using U = uint_type<CharType>;
            constexpr Keygen KG = FlavourT::keygen;
            constexpr Combiner CB = FlavourT::combiner;
            constexpr Mode MD = FlavourT::mode;
            constexpr Order OD = FlavourT::order;

            U keys[Size] = {};
            make_keystream<KG, Seed>(keys);

            [[maybe_unused]] U previous = chaining_iv<U, Seed>();

            for (size_t step = 0; step < Size; ++step) {
                const size_t i = step_index<OD, Seed, Size>(step);
                const U plain = static_cast<U>(in[i]);

                U effective = keys[i];
                U feed = plain;
                if constexpr (MD == Mode::cbc) {
                    feed = static_cast<U>(plain ^ previous);
                } else if constexpr (MD == Mode::cfb) {
                    effective = static_cast<U>(effective ^ previous);
                }

                const U cipher = combine<CB>(feed, effective);
                out[i] = static_cast<CharType>(cipher);

                if constexpr (MD != Mode::stream) {
                    previous = cipher;
                }
            }
        }

        template <typename FlavourT, uint32_t Seed, typename CharType, size_t Size>
        constexpr void transform_inverse(CharType* buf) noexcept {
            using U = uint_type<CharType>;
            constexpr Combiner CB = FlavourT::combiner;
            constexpr Mode MD = FlavourT::mode;
            constexpr Order OD = FlavourT::order;

            U keys[Size] = {};
            make_keystream<FlavourT::keygen, Seed>(keys);

            // Walking the processing order backwards is what makes in-place
            // decryption possible: the ciphertext of the preceding step - the
            // value the chain needs - has not been overwritten yet, because only
            // later steps have been processed at this point.
            [[maybe_unused]] const U iv = chaining_iv<U, Seed>();

            for (size_t step = Size; step-- > 0;) {
                const size_t i = step_index<OD, Seed, Size>(step);
                const U cipher = static_cast<U>(buf[i]);

                [[maybe_unused]] U previous = 0;
                if constexpr (MD != Mode::stream) {
                    previous = (step == 0)
                                   ? iv
                                   : static_cast<U>(buf[step_index<OD, Seed, Size>(step - 1)]);
                }

                U plain = cipher;
                if constexpr (MD == Mode::cbc) {
                    plain = static_cast<U>(uncombine<CB>(cipher, keys[i]) ^ previous);
                } else if constexpr (MD == Mode::cfb) {
                    plain = uncombine<CB>(cipher, static_cast<U>(keys[i] ^ previous));
                } else {
                    plain = uncombine<CB>(cipher, keys[i]);
                }

                buf[i] = static_cast<CharType>(plain);
            }
        }

    } // namespace detail

    // -----------------------------------------------------------------------
    //  Automatic flavour selection
    // -----------------------------------------------------------------------
    //  One hash per call site, four decorrelated slices of it picking one value
    //  per dimension.
    template <uint32_t Hash>
    using FlavourOf = Flavour<detail::select_keygen(Hash), detail::select_combiner(Hash),
                              detail::select_mode(Hash), detail::select_order(Hash)>;

    // The eight flavours of the original library, expressed in the dimension
    // scheme. Useful for documentation, explicit selection and testing.
    namespace Presets {

        using classic_0 = Flavour<Keygen::seed_xor, Combiner::bit_xor, Mode::stream, Order::forward>;
        using classic_1 = Flavour<Keygen::seed_xor, Combiner::rotl_add, Mode::stream, Order::forward>;
        using classic_2 = Flavour<Keygen::seed_xor, Combiner::mul_odd, Mode::stream, Order::forward>;
        using classic_3 = Flavour<Keygen::seed_xor, Combiner::bit_xor, Mode::cbc, Order::forward>;
        using classic_4 = Flavour<Keygen::seed_xor, Combiner::not_xor, Mode::stream, Order::forward>;
        using classic_5 = Flavour<Keygen::crc32c, Combiner::bit_xor, Mode::stream, Order::forward>;
        using classic_6 = Flavour<Keygen::seed_xor, Combiner::feistel, Mode::stream, Order::forward>;
        using classic_7 = Flavour<Keygen::lcg, Combiner::bit_xor, Mode::stream, Order::forward>;

    } // namespace Presets

    // -----------------------------------------------------------------------
    //  Core engine: holds the encrypted characters and can convert the buffer
    //  between its cipher and plain forms in place.
    // -----------------------------------------------------------------------
    template <typename CharType, size_t Size, typename FlavourT, uint32_t Seed>
    class EncryptedString {
        static_assert(std::is_integral<CharType>::value,
                      "DynamicCrypter: the character type must be an integral type");
        static_assert(Size > 0,
                      "DynamicCrypter: an encrypted string must contain at least one character");

    public:
        // Compile-time encryption. Accepts a string literal or any character
        // array; if the input is not a constant expression the very same
        // constructor simply runs at run time.
        constexpr EncryptedString(const CharType* plaintext) noexcept : _storage{} {
            detail::transform_forward<FlavourT, Seed, CharType, Size>(_storage, plaintext);
        }

        EncryptedString(const EncryptedString&) = delete;
        EncryptedString& operator=(const EncryptedString&) = delete;

        // In place decryption; returns the decrypted buffer.
        CRYPTER_FORCEINLINE constexpr const CharType* decrypt() noexcept {
            detail::transform_inverse<FlavourT, Seed, CharType, Size>(_storage);
            return _storage;
        }

        // Re-applies the forward transform, restoring the ciphertext. This is
        // what makes it possible to take the plaintext back out of memory.
        CRYPTER_FORCEINLINE constexpr const CharType* encrypt() noexcept {
            detail::transform_forward<FlavourT, Seed, CharType, Size>(_storage, _storage);
            return _storage;
        }

        CRYPTER_FORCEINLINE constexpr const CharType* data() const noexcept { return _storage; }
        static constexpr size_t size() noexcept { return Size; }

    private:
        CharType _storage[Size];
    };

    namespace detail {

        // One of these exists per CRYPT_STR() call site and owns the encrypted
        // buffer plus the bookkeeping needed to know whether that buffer
        // currently holds plaintext.
        template <typename CharType, size_t Size, typename FlavourT, uint32_t Seed>
        struct StringSite {
            EncryptedString<CharType, Size, FlavourT, Seed> cipher;
            unsigned depth;

            constexpr StringSite(const CharType* plaintext) noexcept
                : cipher(plaintext), depth(0u) {}
        };

    } // namespace detail

    // -----------------------------------------------------------------------
    //  RAII view on a decrypted string.
    //  The buffer is decrypted when the first view is created and re-encrypted
    //  once the last view goes out of scope, so no plaintext is left behind.
    //  The pointer handed out is only valid while this object lives.
    // -----------------------------------------------------------------------
    template <typename CharType, size_t Size, typename FlavourT, uint32_t Seed>
    class DecryptedString {
    public:
        CRYPTER_FORCEINLINE explicit DecryptedString(
            detail::StringSite<CharType, Size, FlavourT, Seed>& site) noexcept
            : _site(&site), _ptr(site.cipher.data()) {
            if (_site->depth++ == 0u) {
                _ptr = _site->cipher.decrypt();
            }
        }

        CRYPTER_FORCEINLINE ~DecryptedString() noexcept {
            if (--_site->depth == 0u) {
                _site->cipher.encrypt();
            }
        }

        CRYPTER_FORCEINLINE const CharType* get() const noexcept { return _ptr; }
        CRYPTER_FORCEINLINE const CharType* c_str() const noexcept { return _ptr; }
        CRYPTER_FORCEINLINE const CharType* data() const noexcept { return _ptr; }
        static constexpr size_t size() noexcept { return Size; }

        // Implicit so that the object can be streamed and compared exactly like
        // the underlying raw pointer.
        CRYPTER_FORCEINLINE operator const CharType*() const noexcept { return _ptr; }

        DecryptedString(const DecryptedString&) = delete;
        DecryptedString& operator=(const DecryptedString&) = delete;

    private:
        detail::StringSite<CharType, Size, FlavourT, Seed>* _site;
        const CharType* _ptr;
    };

} // namespace DynamicCrypter

// ---------------------------------------------------------------------------
//  Site hashing
// ---------------------------------------------------------------------------
//  One hash per call site, mixing the source position, the compiler's counter
//  and the optional per-build salt. Everything else - the seed and all four
//  dimensions - is derived from it, so CRYPT_STR() reads the counter exactly
//  once (reading it twice, as an earlier revision did, advanced it by two per
//  call and made half of the flavours unreachable).
//
//  The hashing core takes the salt explicitly, so tests can vary it and prove
//  that it really reaches the key material.
#define CRYPTER_SITE_HASH_EX(line, counter, salt)                                  \
    (DynamicCrypter::detail::mix32(static_cast<uint32_t>(line) * 0x1E35Au ^        \
                                   static_cast<uint32_t>(counter) * 0x7B13u ^      \
                                   static_cast<uint32_t>(salt)))

#define CRYPTER_SITE_HASH(line, counter) \
    CRYPTER_SITE_HASH_EX(line, counter, CRYPTER_BUILD_SALT)

// Legacy alias, kept for source compatibility.
#define CRYPTER_SEED CRYPTER_SITE_HASH(__LINE__, CRYPTER_COUNTER)

// ---------------------------------------------------------------------------
//  CRYPT_STR - preferred form.
//  Yields a small RAII object that converts to const CharType* and restores the
//  ciphertext at the end of the enclosing scope.
//
//      std::cout << CRYPT_STR("streamed, dies with the statement") << '\n';
//      auto message = CRYPT_STR("alive as long as `message` is");
//      use(message);        // implicit conversion, .get(), .c_str(), .data()
// ---------------------------------------------------------------------------
#define CRYPT_STR(str)                                                                         \
    ([]() {                                                                                    \
        using CRYPTER_CHAR_T =                                                                 \
            std::remove_cv_t<std::remove_pointer_t<std::decay_t<decltype(str)>>>;              \
        static_assert(std::is_array<std::remove_reference_t<decltype(str)>>::value,            \
                      "CRYPT_STR() needs a string literal or a character array, "              \
                      "not a pointer: sizeof() would not know the length");                    \
        constexpr size_t CRYPTER_SIZE_T = sizeof(str) / sizeof(CRYPTER_CHAR_T);                \
        constexpr uint32_t CRYPTER_HASH_T = CRYPTER_SITE_HASH(__LINE__, CRYPTER_COUNTER);      \
        using CRYPTER_FLAVOUR_T = DynamicCrypter::FlavourOf<CRYPTER_HASH_T>;                    \
        using CRYPTER_SITE_T =                                                                 \
            DynamicCrypter::detail::StringSite<CRYPTER_CHAR_T, CRYPTER_SIZE_T,                 \
                                               CRYPTER_FLAVOUR_T, CRYPTER_HASH_T>;             \
        static CRYPTER_SITE_T CRYPTER_SITE_VAR((str));                                         \
        return DynamicCrypter::DecryptedString<CRYPTER_CHAR_T, CRYPTER_SIZE_T,                 \
                                               CRYPTER_FLAVOUR_T, CRYPTER_HASH_T>(             \
            CRYPTER_SITE_VAR);                                                                 \
    }())

// ---------------------------------------------------------------------------
//  CRYPT_STR_RAW - legacy pointer form.
//  Decrypts once on first use and leaves the plaintext in place. Use it when
//  the const char* has to outlive the statement; prefer CRYPT_STR() otherwise,
//  since this variant never re-encrypts.
// ---------------------------------------------------------------------------
#define CRYPT_STR_RAW(str)                                                                     \
    ([]() {                                                                                    \
        using CRYPTER_CHAR_T =                                                                 \
            std::remove_cv_t<std::remove_pointer_t<std::decay_t<decltype(str)>>>;              \
        static_assert(std::is_array<std::remove_reference_t<decltype(str)>>::value,            \
                      "CRYPT_STR_RAW() needs a string literal or a character array, "          \
                      "not a pointer: sizeof() would not know the length");                    \
        constexpr size_t CRYPTER_SIZE_T = sizeof(str) / sizeof(CRYPTER_CHAR_T);                \
        constexpr uint32_t CRYPTER_HASH_T = CRYPTER_SITE_HASH(__LINE__, CRYPTER_COUNTER);      \
        using CRYPTER_FLAVOUR_T = DynamicCrypter::FlavourOf<CRYPTER_HASH_T>;                    \
        using CRYPTER_SITE_T =                                                                 \
            DynamicCrypter::detail::StringSite<CRYPTER_CHAR_T, CRYPTER_SIZE_T,                 \
                                               CRYPTER_FLAVOUR_T, CRYPTER_HASH_T>;             \
        static CRYPTER_SITE_T CRYPTER_SITE_VAR((str));                                         \
        if (CRYPTER_SITE_VAR.depth == 0u) {                                                    \
            CRYPTER_SITE_VAR.depth = 1u;                                                       \
            CRYPTER_SITE_VAR.cipher.decrypt();                                                 \
        }                                                                                      \
        return CRYPTER_SITE_VAR.cipher.data();                                                 \
    }())

// Only resolved while this header is being parsed, so it can be cleaned up.
// CRYPTER_COUNTER and CRYPTER_SITE_HASH must stay defined: CRYPT_STR() and
// CRYPT_STR_RAW() expand in the caller's translation unit and use them.
#undef CRYPTER_CPLUSPLUS

#endif // DYNAMICCRYPTER_HPP
