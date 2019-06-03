//
// Created by ruben on 5/23/2019.
//
#include "keypair.h"
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include "ossl/ossl_compat.h"
#include "ossl/objects.h"
extern int round5_sk_to_pk(unsigned char *pk, const unsigned char *sk);

struct round5_nid_data_st _round5_nid_data[] = {
        {
            SKLEN, PKLEN, round5_sk_to_pk, NID_undef
        }
};

inline const struct round5_nid_data_st *round5_get_nid_data(int nid){
    if (nid == NID_ROUND5) {
        return &_round5_nid_data[0];
    }
    return NULL;
}

struct ROUND5 *round5_new(){
    int nid = NID_ROUND5;
    struct ROUND5 *kpair = NULL;
    const struct round5_nid_data_st *nid_data = round5_get_nid_data(nid);
    if (nid_data == NULL)
        goto err;
    kpair = OPENSSL_secure_malloc(sizeof(*kpair));
    if (kpair == NULL)
        goto err;
    kpair->nid = nid;
    //free(nid_data);
    return kpair;
    err:
    if (kpair)
        OPENSSL_secure_free(kpair);
    return NULL;
}

int round5_free(struct ROUND5 *keypair){
    if (!keypair)
        return 0;
    OPENSSL_secure_free(keypair);
    return 1;
}

