//
// Created by ruben on 5/23/2019.
//
#include "keypair.h"
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include "ossl/ossl_compat.h"
#include "ossl/objects.h"
#include "Round5/optimized/src/cpa_kem.h"
#include "Round5/optimized/src/cca_encrypt.h"
extern int round5_sk_to_pk(unsigned char *pk, unsigned char *sk);

// parameters *params;

struct round5_nid_data_st _round5_nid_data[] = {
        {
            0, 0, NULL, NID_undef
        }
};

inline const struct round5_nid_data_st *round5_get_nid_data(int nid){
    if (nid == NID_ROUND5) {
        return &_round5_nid_data[0];
    }
    return NULL;
}

int set_key_size(){
    // params = set_parameters_from_api();
    #ifndef PKLEN && SKLEN
    PKLEN = CRYPTO_PUBLICKEYBYTES;
    SKLEN = CRYPTO_SECRETKEYBYTES;
    #endif
    return 1;
}

struct ROUND5 *round5_new(){
    #ifndef PKLEN && SKLEN
    set_key_size();
    #endif
    // params = set_parameters_from_api();
    // size_t pk_len = get_crypto_public_key_bytes(params);
    // size_t sk_len = get_crypto_secret_key_bytes(params, 1);
    // PKLEN = pk_len;
    // SKLEN = sk_len;
    // printf("\nPKLEN: %d\n\nSKLEN: %d\n", PKLEN, SKLEN);
    int nid = NID_ROUND5;
    struct ROUND5 *kpair = NULL;
    // const struct round5_nid_data_st *nid_data = round5_get_nid_data(nid);
    // if (nid_data == NULL)
        // goto err;
    kpair = OPENSSL_secure_malloc(sizeof(*kpair));
    kpair->pk = OPENSSL_secure_malloc(PKLEN);
    kpair->sk = OPENSSL_secure_malloc(SKLEN);
    if (kpair == NULL)
        goto err;
    kpair->nid = nid;
    // printf("\nPKLEN: %d\n\nSKLEN: %d\n", PKLEN, SKLEN);

    //free(nid_data);
    return kpair;
    err:
    if (kpair)
        OPENSSL_secure_free(kpair);
    #undef PKLEN
    #undef SKLEN
    return NULL;
}

int round5_free(struct ROUND5 *kpair){
    if (!kpair)
        return 0;
    OPENSSL_secure_free(kpair->pk);
    OPENSSL_secure_free(kpair->sk);
    OPENSSL_secure_free(kpair);
    return 1;
}

