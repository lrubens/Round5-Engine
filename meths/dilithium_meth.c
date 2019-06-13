#undef CRYPTO_PUBLICKEYBYTES
#undef CRYPTO_SECRETKEYBYTES
#include "../keypair.h"
#include "dilithium_meth.h"
#include <openssl/crypto.h>
#include "../ossl/objects.h"
#include "../../dilithium/ref/test/cpucycles.h"
#include "../../dilithium/ref/test/speed.h"
#include "../../dilithium/ref/randombytes.h"
#include "../../dilithium/ref/params.h"
#include "../../dilithium/ref/sign.h"
#include "../../dilithium/ref/packing.h"
#include <inttypes.h>
// #include "../../reference/src/r5_cca_pke.h"
//#include "KeccakHash.h"

static EVP_MD *keccak = NULL;

static int dilithium_init(EVP_PKEY_CTX *ctx)
{
    struct MD_DATA *data = OPENSSL_malloc(sizeof(*data));
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);

    if (!data)
        return 0;
    memset(data, 0, sizeof(*data));
    data->mac_size = 4;
    data->mac_param_nid = NID_undef;

    if (pkey) {
        struct DILITHIUM *key = EVP_PKEY_get0(pkey);
        // if (key) {
        //     data->mac_param_nid = key->mac_param_nid;
        //     data->mac_size = key->mac_size;
        // }
    }

    EVP_PKEY_CTX_set_data(ctx, data);
    return 1;
}

struct DILITHIUM *dilithium_new(){
    int nid = NID_DILITHIUM;
    struct DILITHIUM *kpair = NULL;
    // const struct round5_nid_data_st *nid_data = round5_get_nid_data(nid);
    // if (nid_data == NULL)
        // goto err;
    kpair = OPENSSL_secure_malloc(sizeof(*kpair));
    int secret = 0;
    int public = 0;
    // #ifdef CRYPTO_PUBLICKEYBYTES
    // secret = crypto_get_bytes("secret");
    // public = crypto_get_bytes("public");
    // #endif
    // printf("\npublic: %d\n", public);
    kpair->pk = OPENSSL_secure_malloc(CRYPTO_PUBLICKEYBYTES);
    kpair->sk = OPENSSL_secure_malloc(CRYPTO_SECRETKEYBYTES);
    if (kpair == NULL)
        goto err;
    kpair->nid = nid;
    // printf("\nPKLEN: %d\n\nSKLEN: %d\n", PKLEN, SKLEN);

    //free(nid_data);
    return kpair;
    err:
    if (kpair)
        OPENSSL_secure_free(kpair);
    return NULL;
}

static int dilithium_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    struct DILITHIUM *kpair = EVP_PKEY_get0(pkey);
    if (!kpair){
        kpair = dilithium_new();
        EVP_PKEY_assign(pkey, NID_DILITHIUM, kpair);
    }
    if (crypto_sign_keypair(kpair->pk, kpair->sk))
        goto err;
    return 1;
    err:
    printf("\nerr in dilithium\n");
    return 0;
}

static int dilithium_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)
{
    struct MD_DATA *data = EVP_PKEY_CTX_get_data(ctx);

    if (data == NULL) {
        dilithium_init(ctx);
    }

    data = EVP_PKEY_CTX_get_data(ctx);
    if (!data) {
        printf("error\n");
        return 0;
    }

    return 1;
}

static int dilithium_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig,
                                 size_t *siglen, EVP_MD_CTX *mctx)
{
    unsigned int tmpsiglen;
    int ret;
    struct MD_DATA *data = EVP_PKEY_CTX_get_data(ctx);

    if (!siglen)
        return 0;
    tmpsiglen = *siglen;        /* for platforms where sizeof(int) !=
                                 * sizeof(size_t) */

    if (!sig) {
        *siglen = data->mac_size;
        return 1;
    }

    EVP_MD_meth_get_ctrl(EVP_MD_CTX_md(mctx))
        (mctx, 256, data->mac_size, NULL);
    ret = EVP_DigestFinal_ex(mctx, sig, &tmpsiglen);
    *siglen = data->mac_size;
    return ret;
}


void pki_register_dilithium(EVP_PKEY_METHOD *pmeth){
    EVP_PKEY_meth_set_sign(pmeth, NULL, dilithium_sign);
    EVP_PKEY_meth_set_keygen(pmeth, NULL, dilithium_keygen);
    EVP_PKEY_meth_set_verify(pmeth, NULL, dilithium_verify);
    EVP_PKEY_meth_set_signctx(pmeth, NULL, dilithium_sign_ctx);
}



static int dilithium_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbs_len)
{
    //unsigned char *unpacked_sig = NULL;
    //unpacked_sig = OPENSSL_malloc(2713);
    //*siglen =  tbs_len + CRYPTO_BYTES;
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    //int order = 0;

    if (!siglen)
        return 0;
    if (!pkey)
        return 0;

    if (!sig) {
        //*siglen = order;
        return 1;
    }
    struct DILITHIUM *kpair = EVP_PKEY_get0(pkey);
    return crypto_sign(sig, siglen, tbs, tbs_len, kpair->sk);
    //int res = crypto_sign_open(tbs, &tbs_len, sig, siglen, r5s->pk);
    //printf("\n%d\n", res);
}

int dilithium_verify(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbs_len)
{
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    struct DILITHIUM *kpair = EVP_PKEY_get0(pkey);
    return crypto_sign_open(tbs, &tbs_len, sig, *siglen, kpair->pk);
}

// int dilithium_sign_ctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *md){
//     struct gost_mac_pmeth_data *data = EVP_PKEY_CTX_get_data(ctx);

//     if (data == NULL) {
//         pkey_gost_mac_init(ctx);
//     }

//     data = EVP_PKEY_CTX_get_data(ctx);
//     if (!data) {
//         GOSTerr(GOST_F_PKEY_GOST_MAC_SIGNCTX_INIT, GOST_R_MAC_KEY_NOT_SET);
//         return 0;
//     }

//     return 1;
// }


int dilithium_sign_ctx(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, EVP_MD_CTX *md){
    int nid = EVP_MD_CTX_type(md);
    printf("\nnid: %d\n", nid);
    return 1;
}



