//
// Created by ruben on 5/23/2019.
//

#include "round5_meth.h"
#include "../keypair.h"
#include "cpa_kem.h"
#include "cca_encrypt.h"
#include "rng.h"
#include "r5_memory.h"
// #include "../../configurable/src/r5_cca_pke.h"
// #include "../../configurable/src/parameters.h"
// #include "../../configurable/src/r5_memory.c"
// #include "../../configurable/src/r5_cpa_kem.h"
// #include "../../configurable/src/misc.h"
// #include "../../configurable/src/r5_memory.h"
// #include "../../configurable/src/rng.h"
// #include "../../configurable/src/a_fixed.h"
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include "../ossl/objects.h"


// parameters *params;


int round5_sk_to_pk(unsigned char *pk, unsigned char *sk){//, parameters *params){
    // printf("\nupdate\n");
    if(crypto_encrypt_keypair(pk, sk) != 0){
        return 0;
    }
    else{
        return 1;
    }
}


static int keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey){
    // set_key_size();
    struct ROUND5 *kpair = NULL;
    kpair = EVP_PKEY_get0(pkey);
    // params = set_parameters_from_api();
    // pd(get_crypto_public_key_bytes(params));
    if (!kpair){
        kpair = round5_new();
        EVP_PKEY_assign(pkey, NID_ROUND5, kpair);
    }
    kpair->pk = malloc(CRYPTO_SECRETKEYBYTES);
    kpair->sk = malloc(CRYPTO_PUBLICKEYBYTES);
    if (!round5_sk_to_pk(kpair->pk, kpair->sk))
        goto err;
    print_hex("PK", kpair->pk, CRYPTO_PUBLICKEYBYTES, 1);
    print_hex("SK", kpair->sk, CRYPTO_SECRETKEYBYTES, 1);
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

size_t get_params(size_t message_len){
    // ct_size = get_crypto_cipher_text_bytes(params, 1, 1);
    // params = set_parameters_from_api();
    return (CRYPTO_BYTES + message_len);
}

static int round5_encrypt(EVP_PKEY_CTX *pctx, unsigned char *out, size_t *out_len, const unsigned char *data, size_t data_len){
    // params = set_parameters_from_api();
    // out = (unsigned char *)malloc((get_crypto_bytes(params, 1) + data_len));
    // pd((get_crypto_bytes(params, 1) + data_len));
    // out_len = get_crypto_cipher_text_bytes(params, 0, 0);
    // data = malloc(get_crypto_bytes(params, 1));
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(pctx); 
    struct ROUND5 *kpair = NULL;
    kpair = EVP_PKEY_get0(pkey);
    // print_hex("PK", kpair->pk, params->pk_size, 1);
    // if(!data)
    // pd(out_len);
    // pd(data_len);
    // return (!r5_cca_kem_encapsulate(out, data, kpair->pk, params));
    print_hex("key in encrypt", data, data_len, 1);
    crypto_encrypt(out, (unsigned long long *)out_len, data, (const unsigned long long)data_len, kpair->pk);
    pd(out_len);
    // exit(0);
    print_hex("Encrypted_key", out, out_len, 1);
    return 1;
} 

static int round5_decrypt(EVP_PKEY_CTX *pctx, unsigned char *data, size_t *data_len, const unsigned char *in, size_t in_len){
    // params = set_parameters_from_api();
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(pctx);
    // data = malloc(get_crypto_bytes(params, 0));
    struct ROUND5 *kpair = NULL;
    kpair = EVP_PKEY_get0(pkey);
    // return (!r5_cpa_kem_decapsulate(data, in, kpair->sk, params));
    // pd(in_len);
    print_hex("SK", kpair->sk, CRYPTO_SECRETKEYBYTES, 1);
    crypto_encrypt_open((unsigned char *)data, (unsigned long long *)&data_len, in, in_len, kpair->sk);
    // ps(data);
    pd(data_len);
    print_hex("key", data, data_len, 1);
    return 1;
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
