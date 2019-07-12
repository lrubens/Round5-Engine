cmake_minimum_required(VERSION 3.0)
project(Round5 LANGUAGES C)
include(GNUInstallDirs)
include(CheckLibraryExists)
include(CheckFunctionExists)

find_package(OpenSSL 1.1.0 REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

add_compile_options(-g -lcrypto -lssl -lm -Xlinker -zmuldefs -finstrument-functions)

file(GLOB dilithium_core dilithium/ref/*.c dilithium/ref/*.h)
set(DILITHIUM_SOURCE_FILES
    ${dilithium_core}
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

set(ROUND5_SOURCE_FILES
    ${ROUND5_CORE}
)

file(GLOB METHS meths/*.c)

set(METHODS_SOURCE_FILES
    ${METHS}
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
    cert_util.h
    cert_util.c
)

file(GLOB NETWORK_CORE network/linux/*.c network/linux/*.h)

set(NETWORK_FILES
    ${NETWORK_CORE}
)

file(GLOB ENGINE_SOURCE round5_engine.c)

set(ROUND5_LIB_SOURCE
    ${XKCP_SOURCE_FILES}
    ${ROUND5_SOURCE_FILES}
)

set(ROUND5_ENGINE_SOURCE_FILES
    ${ENGINE_SOURCE}
    ${METHODS_SOURCE_FILES}
    ${OSSL_SOURCE_FILES}
    ${UTIL_SOURCE_FILES}
)

set(ENGINE_CORE
    ${METHODS_SOURCE_FILES}
    ${OSSL_SOURCE_FILES}
    ${UTIL_SOURCE_FILES}
    ${NETWORK_FILES}
)

set(TEST
    test/engine_check.c
)

# set (PARAMS "R5ND_5PKE_5d" CACHE STRING "Round5 parameter to be used")
# set_property(CACHE PARAMS
#     PROPERTY STRINGS
# )

#set(PARAM R5N1_3PKE_0smallCT CACHE STRING "Round5 algorithm parameter")
set(PARAM R5ND_5PKE_5d)
message("Param set: ${PARAM}")
# Include header files
include_directories(${CMAKE_SOURCE_DIR})
include_directories(meths)
include_directories(ossl)
include_directories(dilithium/ref)
include_directories(Round5/reference/src)
include_directories(XKCP/bin/generic64/libkeccak.a.headers)

# Create dilithium library
add_library(dilithium STATIC ${DILITHIUM_SOURCE_FILES})
set_target_properties(dilithium PROPERTIES POSITION_INDEPENDENT_CODE ON)

# Create round5 library
add_library(round5 STATIC ${ROUND5_LIB_SOURCE})
set_target_properties(round5 PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_compile_definitions(round5 PUBLIC ${PARAM})
set_target_properties(round5 PROPERTIES COMPILE_FLAGS "-lkeccak -lcrypto -lssl -Xlinker -zmuldefs")

# Create engine util library
add_library(engine_lib STATIC ${ENGINE_CORE})
set_target_properties(engine_lib PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(engine_lib PUBLIC Round5/reference/src)
target_compile_definitions(engine_lib PUBLIC ${PARAM})

# Create shared library
add_library(round5_engine SHARED ${ROUND5_ENGINE_SOURCE_FILES})
target_link_libraries(round5_engine dilithium round5 engine_lib ${OPENSSL_CRYPTO_LIBRARY} -Xlinker -zmuldefs)
target_include_directories(round5_engine PUBLIC Round5/reference/src)
target_compile_definitions(round5_engine PUBLIC ${PARAM})
set_target_properties(round5_engine PROPERTIES PREFIX "" OUTPUT_NAME "round5")
set_target_properties(round5_engine PROPERTIES COMPILE_FLAGS "-lkeccak -lcrypto -lssl -Xlinker -zmuldefs")

# run test
add_executable(engine_check ${TEST} ${DILITHIUM_SOURCE_FILES})
target_link_libraries(engine_check dilithium round5 engine_lib ${OPENSSL_CRYPTO_LIBRARY}  -Xlinker -zmuldefs)
target_compile_definitions(engine_check PUBLIC ${PARAM})
set_target_properties(engine_check PROPERTIES COMPILE_FLAGS "-lcrypto -lssl -ggdb3 -O0")

# add_executable(test_network test/test_network.c)
# target_link_libraries(test_network engine_lib dilithium round5 ${OPENSSL_CRYPTO_LIBRARY} -Xlinker -zmuldefs)
# target_compile_definitions(test_network PUBLIC ${PARAM})
# set_target_properties(test_network PROPERTIES COMPILE_FLAGS "-lcrypto -lssl -ggdb3 -O0")

add_executable(test_tls test/test_tls.c)
target_link_libraries(test_tls engine_lib dilithium round5 ${OPENSSL_CRYPTO_LIBRARY} -Xlinker -zmuldefs)
target_compile_definitions(test_tls PUBLIC ${PARAM})
set_target_properties(test_tls PROPERTIES COMPILE_FLAGS "-lcrypto -lssl -ggdb3 -O0")

# Install library
set(ENGINE_DIR /usr/local/ssl/lib/engines-1.1/)
install(TARGETS round5_engine #engine_lib round5 dilithium #dilithium round5 xkcp
        # EXPORT round5_engine #engine_lib round5 dilithium
        ARCHIVE  DESTINATION ${ENGINE_DIR}
        LIBRARY  DESTINATION ${ENGINE_DIR}
        RUNTIME  DESTINATION ${ENGINE_DIR}
        # COMPONENT library
)

