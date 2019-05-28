//
// Created by ruben on 5/23/2019.
//

#include "round5_meth.h"
#include "../optimized/src/cca_encrypt.h"
i//#include "../optimized/src/parameters.h"
#include "../optimized/src/r5_memory.c"
#include "../optimized/src/rng.h"
#include "../optimized/src/cca_kem.h"
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include "../keypair.h"

#if PARAMS_TAU == 1 && PARAMS_N == 1
#include "../optimized/src/a_fixed.h"
#endif

typedef ROUND5_KEYPAIR Round5
#define keypair_new(flags) _round5_keypair_new(NID_ROUND5, (flags))

int round5_sk_to_pk(unsigned char *pk, const unsigned char *sk){
    // parameters *params;
    // params = set_parameters_from_api();
    // set_parameter_tau(params, 1);
    if (crypto_encrypt_keypair(pk, sk) != 0)
        return 0;
    return 1;
}

static int keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey){
    Round5 *kpair = NULL;
    kpair = keypair_new(NO_FLAG);
    if (!kpair)
        goto err;
    if (!round5_sk_to_pk(kpair->key.pk, kpair->key.sk))
        goto err;
    EVP_PKEY_assign(pkey, NID_ROUND5, kpair);
    return 1;
    err:
    if (kpair)
        _round5_keypair_free(kpair);
    return 0;
}

void pki_register_round5(EVP_PKEY_METHOD *pmeth){
    EVP_PKEY_meth_set_keygen(pmeth, keygen);
}

