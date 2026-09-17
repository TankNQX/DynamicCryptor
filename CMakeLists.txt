cmake_minimum_required(VERSION 3.14)
project(DynamicCrypter VERSION 1.2.0 LANGUAGES CXX)

# The library itself requires C++17. That is also the default here, and the CI
# matrix overrides it to prove that newer standards keep working.
set(DYNAMICCRYPTER_CXX_STANDARD 17 CACHE STRING
    "C++ standard used to build the tests and the example (the library needs at least 17)")
set(CMAKE_CXX_STANDARD ${DYNAMICCRYPTER_CXX_STANDARD})
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Define our single-header library target
add_library(DynamicCrypter INTERFACE)

# NOTE: the directory is "Include" with a capital I. The previous value said
# "include", which only worked because Windows filesystems are case
# insensitive - it broke on Linux and macOS.
target_include_directories(DynamicCrypter INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/Include>
    $<INSTALL_INTERFACE:Include>
)

# Consumers of the header need C++17 as well.
target_compile_features(DynamicCrypter INTERFACE cxx_std_17)

# ---------------------------------------------------------------------------
#  Optional per-build salt
# ---------------------------------------------------------------------------
#  Mixes a random value into every key and every flavour selection, so that no
#  two builds of the same source share keys, ciphertext bytes or signatures.
#  Off by default: the default configuration stays byte reproducible.
#
#  The generated value is stored in the cache, so reconfiguring does not roll a
#  new one and incremental builds stay stable. Clear the cache (or set
#  DYNAMICCRYPTER_SALT_VALUE yourself) to roll a new salt.
set(_salt_help
    "Hex salt without the 0x prefix. Empty means: generate one and remember it in the cache.")

option(DYNAMICCRYPTER_BUILD_SALT "Mix a random per-build salt into every key and flavour" OFF)

# Treat compiler warnings as errors. Off by default, so a stricter compiler
# cannot break a consumer's release build; CI turns it on for the warnings jobs.
#
# The flag is added per target rather than by replacing CMAKE_CXX_FLAGS. On MSVC
# the toolchain defaults (/DWIN32 /D_WINDOWS /W3 /GR /EHsc) live *in*
# CMAKE_CXX_FLAGS, so replacing it silently drops /EHsc - <iostream> then warns
# C4530 ("exception handler used, but unwind semantics are not enabled") and,
# with warnings as errors, fails the build.
option(DYNAMICCRYPTER_WERROR "Treat compiler warnings as errors" OFF)

if(DYNAMICCRYPTER_BUILD_SALT)
    set(DYNAMICCRYPTER_SALT_VALUE "" CACHE STRING "${_salt_help}")
    if(NOT DYNAMICCRYPTER_SALT_VALUE)
        string(RANDOM LENGTH 8 ALPHABET 0123456789abcdef _generated_salt)
        set(DYNAMICCRYPTER_SALT_VALUE "${_generated_salt}" CACHE STRING "${_salt_help}" FORCE)
    endif()
    target_compile_definitions(DynamicCrypter INTERFACE
        "CRYPTER_BUILD_SALT=0x${DYNAMICCRYPTER_SALT_VALUE}u")
    message(STATUS "DynamicCrypter: per-build salt 0x${DYNAMICCRYPTER_SALT_VALUE}")
endif()

# Self-verifying test driver. Exits non-zero if any check fails.
add_executable(DynamicCrypterTest test/test.cpp)
target_link_libraries(DynamicCrypterTest PRIVATE DynamicCrypter)

# Consumer facing usage example. It is built alongside the tests so that the
# documentation cannot drift away from the code.
add_executable(DynamicCrypterExample test/main.cpp)
target_link_libraries(DynamicCrypterExample PRIVATE DynamicCrypter)

enable_testing()
add_test(NAME DynamicCrypterTest COMMAND DynamicCrypterTest)
add_test(NAME DynamicCrypterExample COMMAND DynamicCrypterExample)

# Apply target-specific compilation switches for security and optimization, and
# turn the warning level up so that the header and the example are checked
# strictly. Warnings are deliberately not errors, so a strict compiler cannot
# break a release build.
foreach(_dc_target DynamicCrypterTest DynamicCrypterExample)
    if(MSVC)
        target_compile_options(${_dc_target} PRIVATE
            /W4                          # High warning level
            /permissive-                 # Conformance mode
            /Zc:__cplusplus              # Report the real __cplusplus value
            $<$<CONFIG:Release>:/O2>     # Maximize speed
            $<$<CONFIG:Release>:/Ob2>    # Force aggressive inlining for CRYPTER_FORCEINLINE
            $<$<CONFIG:Release>:/GF>     # String pooling
            $<$<CONFIG:Release>:/MT>     # Statically link C runtime (no dependency on external MSVC DLLs)
        )
        if(DYNAMICCRYPTER_WERROR)
            target_compile_options(${_dc_target} PRIVATE /WX)
        endif()
        # Remove runtime checks in release to prevent signature artifacts
        target_compile_definitions(${_dc_target} PRIVATE $<$<CONFIG:Release>:NDEBUG>)
    else()
        # GCC, Clang and anything else that speaks the same dialect
        target_compile_options(${_dc_target} PRIVATE
            -Wall
            -Wextra
            -Wpedantic
            -Wshadow
            $<$<CONFIG:Release>:-O3>
            $<$<CONFIG:Release>:-fomit-frame-pointer>
        )
        if(DYNAMICCRYPTER_WERROR)
            target_compile_options(${_dc_target} PRIVATE -Werror)
        endif()
    endif()
endforeach()
