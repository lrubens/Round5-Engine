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
#define NID_ROUND5 (0)
#define keypair_new(flags) \
  _round5_keypair_new(NID_ROUND5, (flags))


// struct Round5 {

// }

int round5_sk_to_pk(unsigned char *pk, const unsigned char *sk){
    //set_parameter_tau(params, 1);
    parameters *params;
    params = set_parameters_from_api();
    if (r5_cca_pke_keygen(pk, sk, params) != 0){
        return 0;
    }
    else
        return 1;
    
}

static int keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey){
    struct ROUND5 *kpair = EVP_PKEY_get0(pkey);
    //kpair = OPENSSL_secure_malloc(sizeof(*kpair));
    //kpair = EVP_PKEY_get0(pkey);
    if (!kpair){
        kpair = OPENSSL_malloc(sizeof(*kpair));
        EVP_PKEY_assign(pkey, 1061, kpair);
    }

    parameters *params;
    params = set_parameters_from_api();
    // kpair->key.pk = malloc(params->pk_size);
    // kpair->key.sk = malloc((uint32_t) params->kappa_bytes + (uint32_t) params->kappa_bytes + params->pk_size);
    if (!round5_sk_to_pk(kpair->pk, kpair->sk))
        goto err;
    printf("%d", kpair->pk);
    //kpair = OPENSSL_secure_malloc(sizeof(*kpair));
    // EVP_PKEY_assign(pkey, EVP_PKEY_base_id(pkey), kpair);
     //this is bad
    return 1;
    err:
    return 0;
}

void pki_register_round5(EVP_PKEY_METHOD *pmeth){
    EVP_PKEY_meth_set_keygen(pmeth, NULL, keygen);
}
