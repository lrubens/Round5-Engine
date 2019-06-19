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
#include <openssl/evp.h>
// #include <openssl/cms.h>
#include <openssl/asn1.h>

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
    struct ROUND5 *kpair = NULL;
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
    struct ROUND5 *kpair = EVP_PKEY_get0(pkey);
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
    printf("\n3\n");
    EVP_MD_meth_get_ctrl(EVP_MD_CTX_md(mctx))
        (mctx, 256, data->mac_size, NULL);
    ret = EVP_DigestFinal_ex(mctx, sig, &tmpsiglen);
    *siglen = data->mac_size;
    return ret;
}






static int dilithium_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbs_len)
{
    //unsigned char *unpacked_sig = NULL;
    //unpacked_sig = OPENSSL_malloc(2713);
    //*siglen =  tbs_len + CRYPTO_BYTES;
    printf("\n1\n");
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
    printf("\n2\n");
    struct ROUND5 *kpair = EVP_PKEY_get0(pkey);
    return crypto_sign(sig, siglen, tbs, tbs_len, kpair->sk);
    //int res = crypto_sign_open(tbs, &tbs_len, sig, siglen, r5s->pk);
    //printf("\n%d\n", res);
}

int dilithium_verify(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbs_len)
{
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    struct ROUND5 *kpair = EVP_PKEY_get0(pkey);
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

static int dilithium_ctx_init(EVP_PKEY_CTX *ctx)
{
    struct MD_DATA *data;
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);

    data = OPENSSL_malloc(sizeof(*data));
    if (!data)
        return 0;
    memset(data, 0, sizeof(*data));
    // if (pkey && EVP_PKEY_get0(pkey)) {
    //     switch (EVP_PKEY_base_id(pkey)) {
    //     case NID_id_GostR3410_2001:
    //     case NID_id_GostR3410_2012_256:
    //     case NID_id_GostR3410_2012_512:
    //         {
    //             const EC_GROUP *group =
    //                 EC_KEY_get0_group(EVP_PKEY_get0((EVP_PKEY *)pkey));
    //             if (group != NULL) {
    //                 data->sign_param_nid = EC_GROUP_get_curve_name(group);
    //                 break;
    //             }
    //             /* else */
    //         }
    //     default:
    //         OPENSSL_free(data);
    //         return 0;
    //     }
    // }
    EVP_PKEY_CTX_set_data(ctx, data);
    return 1;
}

int dilithium_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2){
    int md_nid = NID_undef;
    struct MD_DATA *md = NULL;
    md = (struct MD_DATA *)EVP_PKEY_CTX_get_data(ctx);
    // pd(type);
    // pd(p1);
    switch(type){
        case EVP_PKEY_CTRL_MD:
            ps("EVP_PKEY_CTRL_MD");
            md->md = (EVP_MD *)p2;
            return 1;
        case EVP_PKEY_CTRL_GET_MD:
            ps("EVP_PKEY_CTRL_GET_MD");
            *(const EVP_MD **)p2 = md->md;
            return 1;
        case EVP_PKEY_CTRL_DIGESTINIT:
            ps("EVP_PKEY_CTRL_DIGESTINIT");
            return 1;
        case EVP_PKEY_CTRL_PKCS7_SIGN:
            ps("hello");
            return 1;
        case EVP_PKEY_CTRL_CMS_SIGN:
            ps("EVP_PKEY_CTRL_CMS_SIGN");
            return 1;
        default:
            printf("\ndefault\n");
            return 0;
    }
}

// int dilithium_ctrl(EVP_PKEY *pkey, int op, long arg1, void *arg2)
// {
//     int nid = EVP_PKEY_base_id(pkey), md_nid = NID_undef;
//     X509_ALGOR *alg1 = NULL, *alg2 = NULL;

//     if(nid == NID_DILITHIUM){
//         md_nid = EVP_MD_type((const EVP_MD *)arg2);
//         printf("\nevp md type: %d\n", md_nid);
//     }
//     else{
//         return -1;
//     }

//     switch (op) {
//     case ASN1_PKEY_CTRL_PKCS7_SIGN:
//         if (arg1 == 0) {
//             // PKCS7_SIGNER_INFO_get0_algs((PKCS7_SIGNER_INFO *)arg2, NULL,
//                                         // &alg1, &alg2);
//             X509_ALGOR_set0(alg1, OBJ_nid2obj(md_nid), V_ASN1_NULL, 0);
//             X509_ALGOR_set0(alg2, OBJ_nid2obj(nid), V_ASN1_NULL, 0);
//         }
//         return 1;
// #ifndef OPENSSL_NO_CMS
//     case ASN1_PKEY_CTRL_CMS_SIGN:
//         if (arg1 == 0) {
//             // CMS_SignerInfo_get0_algs((CMS_SignerInfo *)arg2, NULL, NULL,
//                                     //  &alg1, &alg2);
//             X509_ALGOR_set0(alg1, OBJ_nid2obj(md_nid), V_ASN1_NULL, 0);
//             X509_ALGOR_set0(alg2, OBJ_nid2obj(nid), V_ASN1_NULL, 0);
//         }
//         return 1;
// #endif
//     case ASN1_PKEY_CTRL_PKCS7_ENCRYPT:
//         if (arg1 == 0) {
//             // ASN1_STRING *params = encode_gost_algor_params(pkey);
//             // if (!params) {
//             //     return -1;
//             // }
//             // PKCS7_RECIP_INFO_get0_alg((PKCS7_RECIP_INFO *)arg2, &alg1);
//             X509_ALGOR_set0(alg1, OBJ_nid2obj(EVP_PKEY_id(pkey)),
//                             V_ASN1_SEQUENCE, "params");
//         }
//         return 1;
// #ifndef OPENSSL_NO_CMS
//     case ASN1_PKEY_CTRL_CMS_ENVELOPE:
//         if (arg1 == 0) {
//             // ASN1_STRING *params = encode_gost_algor_params(pkey);
//             // if (!params) {
//             //     return -1;
//             // }
//             // CMS_RecipientInfo_ktri_get0_algs((CMS_RecipientInfo *)arg2, NULL,
//             //                                  NULL, &alg1);
//             X509_ALGOR_set0(alg1, OBJ_nid2obj(EVP_PKEY_id(pkey)),
//                             V_ASN1_SEQUENCE, "params");
//         }
//         return 1;
// #endif
//     case ASN1_PKEY_CTRL_DEFAULT_MD_NID:
//         *(int *)arg2 = md_nid;
//         return 2;
//     }

//     return -2;
// }

int dilithium_sign_ctx(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, EVP_MD_CTX *md){
    ps("dilithium_sign_ctxefwefwefwefewefwef");
    struct MD_DATA *data = (struct MD_DATA *)EVP_PKEY_CTX_get_data(ctx);
    EVP_MD_meth_get_ctrl(EVP_MD_CTX_md(ctx))
        (md, 32, 32, NULL);
    int ret = EVP_DigestFinal_ex(md, sig, siglen);
    return ret;
}

int dilithium_sign_ctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *md){
    ps("dilithium_sign_ctx_init");
    struct MD_DATA *data = (struct MD_DATA *)EVP_PKEY_CTX_get_data(ctx);
    if(!data){
        ps("!data");
    }
    return 1;
}

int dilithium_ctrl_str(EVP_PKEY_CTX *ctx, const char *type, const char *value){
    ps(type);
    ps(value);
    return 1;
}

void pki_register_dilithium(EVP_PKEY_METHOD *pmeth){
    EVP_PKEY_meth_set_init(pmeth, dilithium_ctx_init);
    EVP_PKEY_meth_set_sign(pmeth, NULL, dilithium_sign);
    EVP_PKEY_meth_set_keygen(pmeth, NULL, dilithium_keygen);
    EVP_PKEY_meth_set_verify(pmeth, NULL, dilithium_verify);
    EVP_PKEY_meth_set_signctx(pmeth, dilithium_sign_ctx_init, NULL);
    EVP_PKEY_meth_set_ctrl(pmeth, dilithium_ctrl, dilithium_ctrl_str);


}