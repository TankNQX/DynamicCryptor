cmake_minimum_required(VERSION 3.14)
project(DynamicCrypter VERSION 1.0.0 LANGUAGES CXX)

# Force C++17 Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Define our single-header library target
add_library(DynamicCrypter INTERFACE)
target_include_directories(DynamicCrypter INTERFACE 
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# Define an executable to test the library
add_executable(DynamicCrypterTest test/main.cpp)
target_link_libraries(DynamicCrypterTest PRIVATE DynamicCrypter)

# Apply target-specific compilation switches for security and optimization
if(MSVC)
    target_compile_options(DynamicCrypterTest PRIVATE
        $<$<CONFIG:Release>:/O2>     # Maximize speed
        $<$<CONFIG:Release>:/Ob2>    # Force aggressive inlining for __forceinline
        $<$<CONFIG:Release>:/Oi>     # Enable intrinsics (Required for Hardware CRC32)
        $<$<CONFIG:Release>:/GF>     # String pooling execution
        $<$<CONFIG:Release>:/MT>     # Statically link C runtime (no dependency on external MSVC DLLs)
    )
    # Remove runtime checks in release to prevent signature artifacts
    target_compile_definitions(DynamicCrypterTest PRIVATE $<$<CONFIG:Release>:NDEBUG>)
else()
    # Optimization flags for GCC and Clang
    target_compile_options(DynamicCrypterTest PRIVATE
        $<$<CONFIG:Release>:-O3>
        $<$<CONFIG:Release>:-fomit-frame-pointer>
    )
endif()
