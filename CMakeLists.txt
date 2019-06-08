cmake_minimum_required(VERSION 3.0)
project(Round5 LANGUAGES C)
include(GNUInstallDirs)
include(CheckLibraryExists)
include(CheckFunctionExists)

find_package(OpenSSL 1.1.0 REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

add_compile_options(-g -lcrypto -lssl -lm -Xlinker -zmuldefs)
add_definitions(-DR5ND_5PKE_5d)
set(BIN_DIRECTORY bin)

set(DILITHIUM_SOURCE_FILES
    dilithium/ref/PQCgenKAT_sign.c 
    dilithium/ref/aes256ctr.c 
    dilithium/ref/fips202.c 
    dilithium/ref/ntt.c 
    dilithium/ref/packing.c 
    dilithium/ref/poly.c 
    dilithium/ref/polyvec.c 
    dilithium/ref/reduce.c 
    dilithium/ref/rounding.c 
    dilithium/ref/sign.c
    dilithium/ref/aes256ctr.h 
    dilithium/ref/api.h 
    dilithium/ref/config.h 
    dilithium/ref/ntt.h 
    dilithium/ref/packing.h 
    dilithium/ref/params.h 
    dilithium/ref/poly.h 
    dilithium/ref/polyvec.h 
    dilithium/ref/randombytes.h 
    dilithium/ref/reduce.h 
    dilithium/ref/rounding.h 
    dilithium/ref/sign.h 
    dilithium/ref/symmetric.h
)

file(GLOB XKCP_CORE1 
    XKCP/lib/high/KangarooTwelve/*.c
    XKCP/lib/high/Keccak/*.c 
    XKCP/lib/high/Keccak/*.h
    XKCP/lib/high/Ketje/*.c
    XKCP/lib/high/Keyak/*.c
)
file(GLOB_RECURSE XKCP_CORE2 
    XKCP/lib/high/Keccak/*.c
    XKCP/lib/high/Keccak/*.h
    XKCP/lib/low/Ketje/SnP-compliant/*.c
    XKCP/lib/low/KeccakP-1600/Optimized64/*.c
    XKCP/lib/low/KeccakP-1600/Optimized64/*.h
    XKCP/lib/low/KeccakP-800/Optimized32/*.c
    XKCP/lib/low/KeccakP-800/Optimized32/*.h
    XKCP/lib/low/Ketje/SnP-compliant/*.h
)
file(GLOB XKCP_CORE3 
    XKCP/lib/low/common/*.h
    XKCP/lib/low/KeccakP-200/Compact/*
    XKCP/lib/low/KeccakP-400/Reference/*
    XKCP/lib/low/KeccakP-1600-times2/FallbackOn1/*
    XKCP/lib/low/KeccakP-1600-times4/FallbackOn1/*
    XKCP/lib/low/KeccakP-1600-times8/FallbackOn1/*
)

set(XKCP_SOURCE_FILES
    ${XKCP_CORE1}
    ${XKCP_CORE2}
    ${XKCP_CORE3}
)

file(GLOB ROUND5_CORE Round5/reference/src/*.c Round5/reference/src/*.h)

set(ROUND5
    Round5/reference/src/a_fixed.c 
    Round5/reference/src/a_random.c 
    Round5/reference/src/cca_encrypt.c 
    Round5/reference/src/cpa_kem.c 
    Round5/reference/src/drbg.c 
    Round5/reference/src/little_endian.c 
    Round5/reference/src/misc.c 
    Round5/reference/src/nist_rng.c 
    # Round5/reference/src/pack.c 
    Round5/reference/src/parameters.c 
    Round5/reference/src/r5_cca_kem.c 
    Round5/reference/src/r5_cca_pke.c 
    Round5/reference/src/r5_core.c 
    Round5/reference/src/r5_cpa_kem.c 
    Round5/reference/src/r5_cpa_pke.c 
    Round5/reference/src/r5_dem.c Round5/reference/src/r5_hash.c Round5/reference/src/r5_memory.c Round5/reference/src/r5_parameter_sets.c Round5/reference/src/shake.c Round5/reference/src/xef_ref.c
)

set(ROUND5_SOURCE_FILES
    ${ROUND5_CORE}
)

set(METHODS_SOURCE_FILES
    meths/round5_meth.c
    meths/round5_meth.h
    meths/asn1_meth.c
    meths/asn1_meth.h
    meths/dilithium_meth.c
    meths/dilithium_meth.h
)

set(OSSL_SOURCE_FILES
    ossl/objects.c
    ossl/objects.h
    ossl/objects_internal.h
    ossl/ossl_compat.c
    ossl/ossl_compat.h
)

set(UTIL_SOURCE_FILES
    keypair.c
    keypair.h
)

file(GLOB ENGINE_SOURCE round5_engine.c)

# file(GLOB_RECURSE XKCP_SOURCES RELATIVE ${CMAKE_SOURCE_DIR} "XKCP/K*.c" "XKCP/K*.h" "XKCP/S*.c" "XKCP/S*.h" "XKCP/L*.c")

set(ROUND5_ENGINE_SOURCE_FILES
    ${ENGINE_SOURCE}
    ${METHODS_SOURCE_FILES}
    ${OSSL_SOURCE_FILES}
    ${UTIL_SOURCE_FILES}
    ${XKCP_SOURCE_FILES}
    # ${DILITHIUM_SOURCE_FILES}
)

set(TEST
    test/
)

# Include header files
include_directories(${CMAKE_SOURCE_DIR})
include_directories(meths)
include_directories(ossl)
include_directories(dilithium/ref)
include_directories(Round5/reference/src)
include_directories(XKCP/bin/generic64/libkeccak.a.headers)

add_library(xkcp STATIC ${XKCP_SOURCE_FILES})
set_target_properties(xkcp PROPERTIES POSITION_INDEPENDENT_CODE ON)
set_target_properties(xkcp PROPERTIES COMPILE_FLAGS "-fPIC")

add_library(round5 STATIC ${ROUND5_SOURCE_FILES})
set_target_properties(round5 PROPERTIES POSITION_INDEPENDENT_CODE ON)
set_target_properties(round5 PROPERTIES COMPILE_FLAGS "-fPIC")

add_library(dilithium STATIC ${DILITHIUM_SOURCE_FILES})
set_target_properties(dilithium PROPERTIES POSITION_INDEPENDENT_CODE ON)
set_target_properties(dilithium PROPERTIES COMPILE_FLAGS "-fPIC")

# Create shared library
add_library(round5_engine SHARED ${ROUND5_ENGINE_SOURCE_FILES})
target_link_libraries(dilithium)
set_target_properties(round5_engine PROPERTIES COMPILE_FLAGS "-fPIC -lkeccak -lcrypto -lssl -Xlinker -zmuldefs")
target_link_libraries(round5_engine dilithium ${OPENSSL_CRYPTO_LIBRARY} round5)

# 
add_executable(test ${TEST}/engine_check.c)
target_link_libraries(dilithium ${OPENSSL_CRYPTO_LIBRARY} round5 round5_engine)

# Install library
install(TARGETS xkcp DESTINATION ${BINARY_DIR})
install(TARGETS round5 DESTINATION ${BINARY_DIR})
install(TARGETS dilithium DESTINATION ${BINARY_DIR})
install(TARGETS round5_engine DESTINATION ${BINARY_DIR})
install(TARGETS test DESTINATION ${TEST})
