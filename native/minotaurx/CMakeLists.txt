cmake_minimum_required(VERSION 3.16)

project(lcc_minotaurx LANGUAGES C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(LCC_CORE_SOURCE
    "/opt/lcc-testnet-rialto/source/src"
    CACHE PATH "Litecoin Cash Core source directory"
)

set(MX "${LCC_CORE_SOURCE}/crypto/minotaurx")

set(MX_SOURCES
    "${MX}/blake.c"
    "${MX}/bmw.c"
    "${MX}/cubehash.c"
    "${MX}/echo.c"
    "${MX}/fugue.c"
    "${MX}/groestl.c"
    "${MX}/hamsi.c"
    "${MX}/jh.c"
    "${MX}/keccak.c"
    "${MX}/luffa.c"
    "${MX}/shabal.c"
    "${MX}/shavite.c"
    "${MX}/simd.c"
    "${MX}/skein.c"
    "${MX}/whirlpool.c"
    "${MX}/sph_sha2big.c"
    "${MX}/yespower/yespower.c"
    "${MX}/yespower/crypto/sha256.c"
)

add_library(lcc_minotaurx SHARED
    wrapper.cpp
    ${MX_SOURCES}
)

# LCC_MINOTAURX_ENDIAN_FIX
# Linux glibc already provides these endian conversion functions.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_compile_definitions(lcc_minotaurx PRIVATE
        HAVE_ENDIAN_H=1
        HAVE_DECL_HTOBE16=1
        HAVE_DECL_HTOLE16=1
        HAVE_DECL_BE16TOH=1
        HAVE_DECL_LE16TOH=1
        HAVE_DECL_HTOBE32=1
        HAVE_DECL_HTOLE32=1
        HAVE_DECL_BE32TOH=1
        HAVE_DECL_LE32TOH=1
        HAVE_DECL_HTOBE64=1
        HAVE_DECL_HTOLE64=1
        HAVE_DECL_BE64TOH=1
        HAVE_DECL_LE64TOH=1
    )
endif()

target_include_directories(lcc_minotaurx PRIVATE
    "${LCC_CORE_SOURCE}"
    "${MX}"
    "${MX}/yespower"
)

if(MSVC)
    target_compile_options(lcc_minotaurx PRIVATE /O2)
else()
    target_compile_options(lcc_minotaurx PRIVATE -O2)
    target_link_libraries(lcc_minotaurx PRIVATE m)
endif()

set_target_properties(lcc_minotaurx PROPERTIES
    OUTPUT_NAME "lcc_minotaurx"
)
