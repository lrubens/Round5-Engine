//
// Created by ruben on 5/23/2019.
//

#include "round5_meth.h"
#include "../../configurable/src/r5_cca_pke.h"
#include "../../configurable/src/parameters.h"
#include "../../configurable/src/r5_memory.c"
#include "../../configurable/src/r5_cpa_kem.h"
#include "../../configurable/src/misc.h"
#include "../../configurable/src/r5_memory.h"
#include "../../configurable/src/rng.h"
#include "../../configurable/src/a_fixed.h"
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include "../keypair.h"
#include "../ossl/objects.h"


parameters *params;


int round5_sk_to_pk(unsigned char *pk, const unsigned char *sk, parameters *params){
    // printf("\nupdate\n");
    if (r5_cca_pke_keygen(pk, sk, params) != 0){
        return 0;
    }
    else{
        return 1;
    }
}


static int keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey){
    set_key_size();
    struct ROUND5 *kpair = NULL;
    kpair = EVP_PKEY_get0(pkey);
    params = set_parameters_from_api();
    // pd(get_crypto_public_key_bytes(params));
    if (!kpair){
        kpair = round5_new();
        EVP_PKEY_assign(pkey, NID_ROUND5, kpair);
    }
    kpair->pk = malloc(get_crypto_public_key_bytes(params) + 1);
    kpair->sk = malloc(get_crypto_secret_key_bytes(params, 1) + 1);
    if (!round5_sk_to_pk(kpair->pk, kpair->sk, params))
        goto err;
    print_hex("PK", kpair->pk, params->pk_size, 1);
    print_hex("SK", kpair->sk, params->kappa_bytes, 1);
//  unsigned char *msg = "hello world";
//  unsigned long long msg_len = strlen(msg);
//  unsigned char *m = malloc(msg_len + 1);
//  unsigned long long m_len;
//  unsigned char *ct = malloc((get_crypto_bytes(params, 1) + msg_len));
//  unsigned long long ct_len;
//  r5_cca_pke_encrypt(ct, &ct_len, msg, msg_len, kpair->pk, params);
//  r5_cca_pke_decrypt(m, &m_len, ct, ct_len, kpair->sk, params);
//  fflush(stdout);
//  ps(m);
//  pd(m_len);
    return 1;
    err:
    return 0;
}

static int round5_encrypt(EVP_PKEY_CTX *pctx, unsigned char *out, size_t *out_len, const unsigned char *data, size_t data_len){
    params = set_parameters_from_api();
    // out = (unsigned char *)malloc((get_crypto_bytes(params, 1) + data_len));
    // pd((get_crypto_bytes(params, 1) + data_len));
    // out_len = get_crypto_cipher_text_bytes(params, 0, 0);
    // data = malloc(get_crypto_bytes(params, 1));
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(pctx); 
    struct ROUND5 *kpair = NULL;
    kpair = EVP_PKEY_get0(pkey);
    // if(!data)

    // return (!r5_cca_kem_encapsulate(out, data, kpair->pk, params));
    return !(r5_cca_pke_encrypt(out, out_len, data, data_len, kpair->pk, params));
} 

static int round5_decrypt(EVP_PKEY_CTX *pctx, unsigned char *data, size_t *data_len, const unsigned char *in, size_t in_len){
    params = set_parameters_from_api();
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(pctx);
    data = malloc(get_crypto_bytes(params, 0));
    struct ROUND5 *kpair = NULL;
    kpair = EVP_PKEY_get0(pkey);
    // return (!r5_cpa_kem_decapsulate(data, in, kpair->sk, params));
    return !(r5_cca_pke_decrypt(data, data_len, in, in_len, kpair->sk, params));
}

static int round5_encrypt_init(EVP_PKEY_CTX *pctx){
    return 1;
}

static int round5_decrypt_init(EVP_PKEY_CTX *pctx){
    return 1;
}

void pki_register_round5(EVP_PKEY_METHOD *pmeth){
    EVP_PKEY_meth_set_keygen(pmeth, NULL, keygen);
    EVP_PKEY_meth_set_encrypt(pmeth, round5_encrypt_init, round5_encrypt);
    EVP_PKEY_meth_set_decrypt(pmeth, round5_decrypt_init, round5_decrypt);
}
