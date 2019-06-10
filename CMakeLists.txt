cmake_minimum_required(VERSION 3.0)
project(Round5 LANGUAGES C)
include(GNUInstallDirs)
include(CheckLibraryExists)
include(CheckFunctionExists)

find_package(OpenSSL 1.1.0 REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

add_compile_options(-g -lcrypto -lssl -lm -Xlinker -zmuldefs)
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

# set(ROUND5

# )

set(ROUND5_SOURCE_FILES
    ${ROUND5_CORE}
)

set(METHODS_SOURCE_FILES
    meths/round5_meth.c
    meths/round5_meth.h
    meths/asn1_meth.c
    meths/asn1_meth.h
    # meths/dilithium_meth.c
    # meths/dilithium_meth.h
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

set(ROUND5_LIB_SOURCE
    ${XKCP_SOURCE_FILES}
    #${DILITHIUM_SOURCE_FILES}
    ${ROUND5_SOURCE_FILES}
)

set(ROUND5_ENGINE_SOURCE_FILES
    ${ENGINE_SOURCE}
    ${METHODS_SOURCE_FILES}
    ${OSSL_SOURCE_FILES}
    ${UTIL_SOURCE_FILES}
    # ${XKCP_SOURCE_FILES}
    # ${ROUND5_SOURCE_FILES}
    # ${DILITHIUM_SOURCE_FILES}
)

set(TEST
    test/engine_check.c
)

# Include header files
include_directories(${CMAKE_SOURCE_DIR})
include_directories(meths)
include_directories(ossl)
# include_directories(dilithium/ref)
include_directories(Round5/reference/src)
include_directories(XKCP/bin/generic64/libkeccak.a.headers)

add_library(dilithium STATIC ${DILITHIUM_SOURCE_FILES})
set_target_properties(dilithium PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_library(round5 STATIC ${ROUND5_LIB_SOURCE})
set_target_properties(round5 PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_compile_definitions(round5 PUBLIC R5ND_5PKE_5d)
set_target_properties(round5 PROPERTIES COMPILE_FLAGS "-lkeccak -lcrypto -lssl -Xlinker -zmuldefs")

# add_library(dilithium STATIC ${DILITHIUM_SOURCE_FILES})
# set_target_properties(dilithium PROPERTIES POSITION_INDEPENDENT_CODE ON)

# Create shared library
add_library(round5_engine SHARED ${ROUND5_ENGINE_SOURCE_FILES})
# set_target_properties(round5_engine PROPERTIES COMPILE_FLAGS "-fPIC -lkeccak -lcrypto -lssl -Xlinker -zmuldefs")
# <<<<<<< Updated upstream
# target_link_libraries(round5_engine dilithium ${OPENSSL_CRYPTO_LIBRARY})
target_link_libraries(round5_engine round5 ${OPENSSL_CRYPTO_LIBRARY} -Xlinker -zmuldefs)
# >>>>>>> Stashed changes
# target_include_directories(round5_engine PUBLIC Round5/reference/src)
target_compile_definitions(round5_engine PUBLIC R5ND_5PKE_5d)
set_target_properties(round5_engine PROPERTIES COMPILE_FLAGS "-lkeccak -lcrypto -lssl -DR5ND_5PKE_5d -Xlinker -zmuldefs")

# run test
add_executable(engine_check ${TEST})
# set_target_properties(engine_check PROPERTIES COMPILE_FLAGS "-lcrypto -lssl -lkeccak")
target_link_libraries(engine_check ${OPENSSL_CRYPTO_LIBRARY} round5_engine) #round5 round5_engine dilithium)
target_compile_definitions(engine_check PUBLIC R5ND_5PKE_5d)
set_target_properties(engine_check PROPERTIES COMPILE_FLAGS "-lcrypto -lssl")

# file(MAKE_DIRECTORY )
# Install library
install(DIRECTORY DESTINATION bin)
install(TARGETS round5_engine #dilithium round5 xkcp
        ARCHIVE  DESTINATION bin
        LIBRARY  DESTINATION bin
        RUNTIME  DESTINATION bin
        COMPONENT library
)
# install(FILES gostsum.1 gost12sum.1 DESTINATION ${OPENSSL_MAN_INSTALL_DIR})