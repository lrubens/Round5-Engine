#include "dilithium_meth.h"
#include <openssl/crypto.h>
#include "../ossl/objects.h"
#include "../../dilithium/ref/test/cpucycles.h"
#include "../../dilithium/ref/test/speed.h"
#include "../../dilithium/ref/randombytes.h"
#include "../../dilithium/ref/params.h"
#include "../../dilithium/ref/sign.h"
#include "../keypair.h"
#include "../../dilithium/ref/packing.h"
#include <inttypes.h>
#include "../../reference/src/r5_cca_pke.h"
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
    if (!crypto_sign_keypair(kpair->pk, kpair->sk))
        goto err;
    return 1;
    err:
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

// int keccak_digest_init(EVP_MD_CTX *ctx){
//     Keccak_HashInstance *inst;
//     struct digest_init_ctx *c = EVP_MD_CTX_md_data(ctx);
//     Keccak_HashInitialize_SHA3_256(c->instance); 
//     return 1;
// }
// int keccak_digest_init(EVP_MD_CTX *ctx){
    
//     struct hash_ctx *c = EVP_MD_CTX_md_data(ctx);
//     memset(&(c->dgst), 0, sizeof(struct digest_init_ctx));
//     Keccak_HashInstance h;
//     // Keccak_HashInitialize_SHAKE256(&(c->inst));
//     Keccak_HashInitialize_SHAKE256(&h);
//     // gost_init(&(c->cctx), &GostR3411_94_CryptoProParamSet);
//     c->dgst.instance = &(h);
//     return 1;
    
    
    
    
    
    
    
    
    
    // printf("\nstarted digest_init\n");
    // struct digest_init_ctx *c = EVP_MD_CTX_md_data(ctx);;
    // // c = malloc(sizeof(*c));
    // // c = EVP_MD_CTX_md_data(ctx);
    // Keccak_HashInstance h; 
    // // memset(&(c->instance), 0, sizeof(Keccak_HashInstance));
    // // c->instance = h;

    // // Keccak_HashInitialize_SHAKE256((Keccak_HashInstance *)EVP_MD_CTX_md_data(ctx));
    // Keccak_HashInitialize_SHAKE256((EVP_MD_CTX_md_data(ctx)));

    // return 1;
// }

// int keccak_digest_update(EVP_MD_CTX *ctx, void *data, size_t count){
//     // Keccak_HashInstance *inst = EVP_MD_CTX_md_data(ctx);
//     // Keccak_HashInstance anything;
//     printf("started digest_update");
//     struct hash_ctx *c = EVP_MD_CTX_md_data(ctx);
//     // struct digest_init_ctx *c = EVP_MD_CTX_md_data(ctx);
//     // c->instance = malloc(sizeof(*(c->instance)));
//     // memset((c->instance), 0, sizeof(*(c->instance)));
//     Keccak_HashUpdate(c->dgst.instance, data, count);
//     printf("\nafter hashupdate\n");
//     // Keccak_HashUpdate(&anything, data, count);

//     //exit(0);
//     return 1;
// }
// int keccak_digest_final(EVP_MD_CTX *ctx, unsigned char *digest){
//     // struct digest_init_ctx *c = malloc(sizeof(struct digest_init_ctx));
//     // c = EVP_MD_CTX_md_data(ctx);
//     printf("\nstarted digest_final\n");
//     struct hash_ctx *c = NULL;
//     // c = malloc(sizeof(*c));
//     // c->instance = malloc(sizeof(*(c->instance)));
//     c = EVP_MD_CTX_md_data(ctx);
//     // digest = malloc(64);
//     // memset((c->instance), 0, sizeof(*(c->instance)));
//     // Keccak_HashFinal(&(c->instance), digest);
//     Keccak_HashFinal(c->dgst.instance, digest);
//     //Keccak_HashSqueeze(&(c->instance), digest, 64);
//     printf("\ndigest:  %s\n", digest);
//     return 1;
// }

// int keccak_digest_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from){
//     struct digest_init_ctx *md_ctx = EVP_MD_CTX_md_data(to);
//     if (EVP_MD_CTX_md_data(to) && EVP_MD_CTX_md_data(from)) {
//         memcpy(EVP_MD_CTX_md_data(to), EVP_MD_CTX_md_data(from),
//                sizeof(struct digest_init_ctx));
//         //md_ctx->dctx.cipher_ctx = &(md_ctx->cctx);
//     }
//     return 1;
// }

// int keccak_digest_cleanup(EVP_MD_CTX *ctx)
// {
//     if (EVP_MD_CTX_md_data(ctx))
//         memset(EVP_MD_CTX_md_data(ctx), 0,
//                sizeof(struct digest_init_ctx));
//     return 1;
// }

// EVP_MD *keccak_digest(void){
//     if(keccak == NULL){
//         EVP_MD *md;
//         if ((md = EVP_MD_meth_new(NID_KECCAK, NID_undef)) == NULL
//             // || !EVP_MD_meth_set_result_size(md, sizeof(struct digest_init_ctx))
//             || !EVP_MD_meth_set_result_size(md, 64)
//             || !EVP_MD_meth_set_input_blocksize(md, 24)
//             // || !EVP_MD_meth_set_app_datasize(md, sizeof(struct digest_init_ctx))
//             || !EVP_MD_meth_set_app_datasize(md, 64)
//             || !EVP_MD_meth_set_init(md, keccak_digest_init)
//             || !EVP_MD_meth_set_update(md, keccak_digest_update)
//             || !EVP_MD_meth_set_final(md, keccak_digest_final)
//             || !EVP_MD_meth_set_copy(md, keccak_digest_copy)
//             || !EVP_MD_meth_set_cleanup(md, keccak_digest_cleanup)) {
//             EVP_MD_meth_free(md);
//             md = NULL;
//         }
//         keccak = md;
//         EVP_MD_meth_free(md);
//     }
//     return keccak;
// }

void pki_register_dilithium(EVP_PKEY_METHOD *pmeth){
    EVP_PKEY_meth_set_sign(pmeth, NULL, dilithium_sign);
    EVP_PKEY_meth_set_keygen(pmeth, NULL, dilithium_keygen);
    EVP_PKEY_meth_set_verify(pmeth, NULL, dilithium_verify);
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

