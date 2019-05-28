//
// Created by ruben on 5/23/2019.
//

#ifndef ROUND5_KEYPAIR_H
#define ROUND5_KEYPAIR_H
#include <openssl/obj_mac.h>
#include <stdint.h>
#include <stddef.h>
#define CURVE25519_BITS 253
#define CURVE25519_SECURITY_BITS 128
#define PKLEN 1349
#define SKLEN 1413

typedef struct {
    union {
        unsigned char *sk;
        unsigned char *pk;
    } key;
    int nid;
    char has_private;
} ROUND5_KEYPAIR;



typedef enum {
    NO_FLAG=0,
    NO_PRIV_KEY=1,
} round5_keypair_flags_t;

ROUND5_KEYPAIR *_round5_keypair_new(int nid, round5_keypair_flags_t flags);

int _round5_keypair_free(ROUND5_KEYPAIR *keypair);

struct round5_nid_data_st {
    const char *name;
    size_t sk_bytes;
    size_t pk_bytes;
    int (*sk_to_pk)(unsigned char *pk, const unsigned char *sk);
};

const struct round5_nid_data_st *round5_get_nid_data(int nid);


#endif //ROUND5_KEYPAIR_H

