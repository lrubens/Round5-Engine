//
// Created by ruben on 5/23/2019.
//

#include "round5_meth.h"
#include "../reference/src/r5_cca_pke.h"
#include "../reference/src/parameters.h"
#include "../reference/src/r5_memory.c"
#include "../reference/src/r5_cpa_kem.h"
#include "../reference/src/misc.h"
#include "../reference/src/r5_memory.h"
#include "../reference/src/rng.h"
#include "../reference/src/a_fixed.h"
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include "../keypair.h"
#include "../ossl/objects.h"
#include "dilithium_meth.h"

int round5_sk_to_pk(unsigned char *pk, const unsigned char *sk, parameters *params){
    if (r5_cca_pke_keygen(pk, sk, params) != 0){
        return 0;
    }
    else{
        return 1;
    }
}

static int keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey){
    printf("\nkeygen\n");
    struct ROUND5 *kpair = NULL;
    kpair = EVP_PKEY_get0(pkey);
    parameters *params;
    params = set_parameters_from_api();
    if (!kpair){
        kpair = OPENSSL_malloc(sizeof(*kpair));
        EVP_PKEY_assign(pkey, NID_ROUND5, kpair);
    }
    
    
    if (!round5_sk_to_pk(kpair->pk, kpair->sk, params))
        goto err;
    printf("\n\nFinished printing: %d\n\n", sizeof(kpair->pk));
    //EVP_PKEY_assign(pkey, NID_ROUND5, kpair);
    //printf("\n\n\n\n%d\n\n\n\n", sizeof(kpair->sk));
    // free(kpair);
    // free(kpair->sk);
    return 1;
    err:
    return 0;
}

void pki_register_round5(EVP_PKEY_METHOD *pmeth){
    // EVP_PKEY_meth_set_sign(pmeth, NULL, dilithium_sign);
    EVP_PKEY_meth_set_keygen(pmeth, NULL, keygen);
}
