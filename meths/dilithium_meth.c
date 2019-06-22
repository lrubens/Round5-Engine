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
    // data->mac_size = 4;
    // data->mac_param_nid = NID_undef;

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

struct ROUND5 *dilithium_new(){
    int nid = NID_DILITHIUM;
    struct ROUND5 *kpair = NULL;
    // const struct round5_nid_data_st *nid_data = round5_get_nid_data(nid);
    // if (nid_data == NULL)
        // goto err;
    kpair = (struct ROUND5 *)OPENSSL_secure_malloc(sizeof(*kpair));
    // #ifdef CRYPTO_PUBLICKEYBYTES
    // secret = crypto_get_bytes("secret");
    // public = crypto_get_bytes("public");
    // #endif
    // printf("\npublic: %d\n", public);

    kpair->pk = (unsigned char *)OPENSSL_secure_malloc(CRYPTO_PUBLICKEYBYTES);
    kpair->sk = (unsigned char *)OPENSSL_secure_malloc(CRYPTO_SECRETKEYBYTES);
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

int get_crypto_bytes_(int op){
    // 0 for public
    // 1 for private
    return (op == 0 ? CRYPTO_PUBLICKEYBYTES : CRYPTO_SECRETKEYBYTES);
}

static int dilithium_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    struct ROUND5 *kpair = (struct ROUND5 *)EVP_PKEY_get0(pkey);
    if (!kpair){
        kpair = dilithium_new();
        EVP_PKEY_assign(pkey, NID_DILITHIUM, kpair);
    }
    if (crypto_sign_keypair(kpair->pk, kpair->sk))
        goto err;
    // ps(kpair->pk);
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

static int dilithium_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbs_len)
{
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    if (!siglen)
        return 0;
    if (!pkey)
        return 0;

    if (!sig) {
        //*siglen = order;
        return 1;
    }
    printf("\n2\n");
    struct ROUND5 *kpair = (struct ROUND5 *)EVP_PKEY_get0(pkey);
    return crypto_sign(sig, (unsigned long long *)siglen, tbs, tbs_len, kpair->sk);
}

int dilithium_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t *siglen, unsigned char *tbs, size_t tbs_len){
    ps("in verify");
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    struct ROUND5 *kpair = (struct ROUND5 *)EVP_PKEY_get0(pkey);
    return crypto_sign_open(tbs, (unsigned long long *)tbs_len, sig, *siglen, kpair->pk);
}

static int dilithium_ctx_init(EVP_PKEY_CTX *ctx){
    struct MD_DATA *data;
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);

    data = (struct MD_DATA *)OPENSSL_malloc(sizeof(*data));
    if (!data)
        return 0;
    memset(data, 0, sizeof(*data));

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
            // ps("EVP_PKEY_CTRL_MD");
            md->md = (EVP_MD *)p2;
            return 1;
        case EVP_PKEY_CTRL_GET_MD:
            // ps("EVP_PKEY_CTRL_GET_MD");
            *(const EVP_MD **)p2 = md->md;
            return 1;
        case EVP_PKEY_CTRL_DIGESTINIT:
            // EVP_DigestInit_ex()
            // ps("EVP_PKEY_CTRL_DIGESTINIT");
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

int dilithium_sign_ctx(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, EVP_MD_CTX *mctx){
    if(!sig){
        ps("Signature should not be null");
        exit(0);
    }
    // unsigned char *data = EVP_MD_CTX_md_data(mctx);
    unsigned int tmp_len = EVP_MD_CTX_size(mctx) + CRYPTO_BYTES;
    // pd(*siglen);
    struct ROUND5 *kpair = (struct ROUND5 *)EVP_PKEY_get0(EVP_PKEY_CTX_get0_pkey(ctx));
    unsigned char *tbs = NULL;
    tbs = malloc(EVP_MD_CTX_size(mctx));
    unsigned int tbs_len = 64;
    int r = EVP_DigestFinal_ex(mctx, tbs, &tbs_len);
    int ret = crypto_sign(sig, &tmp_len, tbs, EVP_MD_CTX_size(mctx), kpair->sk);
    // pd(tmp_len);
    // pd(ret);
    // ps(sig);
    return 1;
}

int dilithium_sign_ctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx){
    // ps("dilithium_sign_ctx_init");
    // struct MD_DATA *data = (struct MD_DATA *)EVP_PKEY_CTX_get_data(ctx);
    // if(!data){
    //     ps("!data");
    // }
    return 1;
}

int dilithium_ctrl_str(EVP_PKEY_CTX *ctx, const char *type, const char *value){
    ps(type);
    ps(value);
    return 1;
}

int dilithium_sign_init(EVP_PKEY_CTX *ctx){
    // ps("sign_init");
    return 1;
}

int dilithium_keygen_init(EVP_PKEY_CTX *ctx){
    return 1;
}

int dilithium_verify_init(EVP_PKEY_CTX *ctx){
    return 1;
}

int dilithium_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src){
    // ps(__func__);
    return 1;
}

void pki_register_dilithium(EVP_PKEY_METHOD *pmeth){
    EVP_PKEY_meth_set_init(pmeth, dilithium_ctx_init);
    EVP_PKEY_meth_set_sign(pmeth, dilithium_sign_init, dilithium_sign);
    EVP_PKEY_meth_set_keygen(pmeth, dilithium_keygen_init, dilithium_keygen);
    EVP_PKEY_meth_set_verify(pmeth, dilithium_verify_init, dilithium_verify);
    EVP_PKEY_meth_set_signctx(pmeth, dilithium_sign_ctx_init, dilithium_sign_ctx);
    EVP_PKEY_meth_set_ctrl(pmeth, dilithium_ctrl, dilithium_ctrl_str);
    EVP_PKEY_meth_set_copy(pmeth, dilithium_copy);

}