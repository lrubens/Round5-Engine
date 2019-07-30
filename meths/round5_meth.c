//
// Created by ruben on 5/23/2019.
//

#include "round5_meth.h"
#include "../keypair.h"
#include "cca_encrypt.h"
#include "cpa_kem.h"
#include "rng.h"
// #include "r5_memory.h"
// #include "r5_parameter_sets.h"
// #include "r5_cca_pke.h"
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include "../ossl/objects.h"


// parameters *params;


int round5_sk_to_pk(unsigned char *pk, unsigned char *sk){
    #if CRYPTO_CIPHERTEXTBYTES == 0    
    // ps("Executing PKE keygen");
    return (!crypto_encrypt_keypair(pk, sk));
    #else
    return (!crypto_kem_keypair(pk, sk));
    #endif
}


static int keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey){
    struct ROUND5 *kpair = NULL;
    kpair = EVP_PKEY_get0(pkey);
    if (!kpair){
        kpair = round5_new();
        EVP_PKEY_assign(pkey, NID_ROUND5, kpair);
    }
    // kpair->pk = malloc(CRYPTO_PUBLICKEYBYTES);
    // kpair->sk = malloc(CRYPTO_SECRETKEYBYTES);
    if (!round5_sk_to_pk(kpair->pk, kpair->sk))
        goto err;
    // print_hex("PK", kpair->pk, CRYPTO_PUBLICKEYBYTES, 1);
    // print_hex("SK in keygen", kpair->sk, CRYPTO_SECRETKEYBYTES, 1);
    // exit(0);
    return 1;
    err:
    return 0;
}

size_t get_params(size_t message_len){
    return (CRYPTO_BYTES + message_len);
}

static int round5_encrypt(EVP_PKEY_CTX *pctx, unsigned char *out, size_t *out_len, const unsigned char *data, size_t data_len){
    int out_null = 0;
    if(!out){
        #if CRYPTO_CIPHERTEXTBYTES == 0
        out = (unsigned char *)malloc((CRYPTO_BYTES + data_len));
        out_null = 1;
        #else
        *out_len = CRYPTO_CIPHERTEXTBYTES;
        return 1;
        #endif
    }                 
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(pctx); 
    struct ROUND5 *kpair = NULL;
    kpair = (struct ROUND5 *)EVP_PKEY_get0(pkey);
    // print_hex("PK in encrypt", kpair->pk, CRYPTO_PUBLICKEYBYTES, 1);
    unsigned long long output_len = 0;
    #if CRYPTO_CIPHERTEXTBYTES == 0
    crypto_encrypt(out, &output_len, data, (const unsigned long long)data_len, kpair->pk);
    *out_len = output_len;
    #else
    // ps("kem encrypt");
    crypto_kem_enc(out, data, kpair->pk);
    // #ifdef DEBUG
    // print_hex("key", data, CRYPTO_BYTES, 1);
    // #endif
    // crypto_kem_dec(encrypted, data, kpair->sk);
    // printf("\n");
    // ps(encrypted);
    // print_hex("key in encrypt", encrypted, 16, 1);
    *out_len = CRYPTO_CIPHERTEXTBYTES;
    #endif
    if(out_null)
        free(out);
    // if(out)
    //     print_hex("decoded key", out, *out_len, 1);
    return 1;
} 

static int round5_decrypt(EVP_PKEY_CTX *pctx, unsigned char *message, size_t *message_len, const unsigned char *ct, size_t ct_len){
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(pctx);
    // if(!message){
    //     #if CRYPTO_CIPHERTEXTBYTES != 0
    //     *message_len = 16;
    //     return 1;
    //     #endif
    // }
    // pd(CRYPTO_BYTES);
    // pd(ct_len);
    // print_hex("Encrypted_key in decrypt", ct, ct_len, 1);
    // pd(CRYPTO_CIPHERTEXTBYTES);
    struct ROUND5 *kpair = NULL;
    kpair = (struct ROUND5 *)EVP_PKEY_get0(pkey);
    unsigned long long data_len = 0;
    #if CRYPTO_CIPHERTEXTBYTES == 0
    crypto_encrypt_open((unsigned char *)message, &data_len, ct, ct_len, kpair->sk);
    *message_len = data_len;
    #else
    if(message){
        crypto_kem_dec(message, ct, kpair->sk);
        // print_hex("Key", message, CRYPTO_BYTES, 1);
    }
    // #ifdef DEBUG
    // #endif
    *message_len = CRYPTO_BYTES;
    // print_hex("Shared secret", message, CRYPTO_BYTES, 1);
    #endif
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
