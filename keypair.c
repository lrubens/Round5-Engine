//
// Created by ruben on 5/23/2019.
//
#include "keypair.h"
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include "ossl/suola_err.h"
#include "ossl/ossl_compat.h"

extern int round5_sk_to_pk(unsigned char *pk, const unsigned char *sk);

ROUND5_KEYPAIR *_round5_keypair_new(int nid, round5_keypair_flags_t flags){
    ROUND5_KEYPAIR *kpair = NULL;
    const struct round5_nid_data_st *nid_data = round5_get_nid_data(nid);
    if (nid_data == NULL)
        goto err;
    kpair = OPENSSL_secure_malloc(sizeof(*kpair));
    if (kpair == NULL)
        goto err;
    kpair->nid = nid;
    kpair->has_private = 0;
    if (flags & NO_PRIV_KEY == 0){
        kpair->has_private = 1;
    }
    return kpair;
    err:
    if (kpair)
        OPENSSL_secure_free(kpair);
    return NULL;
}

int _round5_keypair_free(ROUND5_KEYPAIR *keypair){
    if (!keypair)
        return 0;
    OPENSSL_secure_free(keypair);
    return 1;
}
