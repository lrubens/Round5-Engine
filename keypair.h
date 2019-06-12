//
// Created by ruben on 5/23/2019.
//

#ifndef ROUND5_KEYPAIR_H
#define ROUND5_KEYPAIR_H
#include <openssl/obj_mac.h>
#include <stdint.h>
#include <stddef.h>
#include "Round5/reference/src/parameters.h"
#define CURVE25519_BITS 253
#define CURVE25519_SECURITY_BITS 128
// #ifdef PKLEN
// #undef PKLEN
// #endif
// #ifdef SKLEN
// #undef SKLEN
// #endif
extern int PKLEN = 0;
extern int SKLEN = 0;

struct ROUND5{
    unsigned char *sk;
    unsigned char *pk;
    int nid;
};

struct DILITHIUM{
    int nid;
    unsigned char *pk;
    unsigned char *sk;
};

typedef enum {
    NO_FLAG=0,
    NO_PRIV_KEY=1,
} round5_keypair_flags_t;

struct ROUND5 *round5_new();

int round5_free(struct ROUND5 *keypair);

int set_key_size();

struct round5_nid_data_st {
    const char *name;
    size_t sk_bytes;
    size_t pk_bytes;
    int (*sk_to_pk)(unsigned char *pk, const unsigned char *sk);
};

const struct round5_nid_data_st *round5_get_nid_data(int nid);

#endif //ROUND5_KEYPAIR_H

