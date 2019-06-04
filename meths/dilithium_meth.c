#include "dilithium_meth.h"
#include <openssl/crypto.h>
#include "../ossl/objects.h"
#include "../../dilithium/ref/test/cpucycles.h"
#include "../../dilithium/ref/test/speed.h"
#include "../../dilithium/ref/randombytes.h"
#include "../../dilithium/ref/params.h"
#include "../../dilithium/ref/sign.h"
#include "../keypair.h"
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
        if (key) {
            data->mac_param_nid = key->mac_param_nid;
            data->mac_size = key->mac_size;
        }
    }

    EVP_PKEY_CTX_set_data(ctx, data);
    return 1;
}

static int dilithium_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey, int mac_nid)
{
    struct MD_DATA *data = EVP_PKEY_CTX_get_data(ctx);
    struct DILITHIUM *keydata;
    if (!data || !data->key_set) {
        printf("error\n");
        return 0;
    }
    keydata = OPENSSL_malloc(sizeof(struct DILITHIUM));
    if (keydata == NULL)
        return 0;
    memcpy(keydata->key, data->key, 1413);
    keydata->mac_param_nid = data->mac_param_nid;
    keydata->mac_size = data->mac_size;
    EVP_PKEY_assign(pkey, mac_nid, keydata);
    return 1;
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
int keccak_digest_init(EVP_MD_CTX *ctx){
    printf("\nstarted digest_init\n");
    //return 1;
    struct digest_init_ctx *c = EVP_MD_CTX_md_data(ctx);
    c->data = malloc(2048);
    c->len = 2048;
    c->offset = 0;
    Keccak_HashInitialize_SHA3_256(c->instance); 
    // printf("\nfinished digest_init\n");
    return 1;
}

int keccak_digest_update(EVP_MD_CTX *ctx, void *data, size_t count){
    struct digest_init_ctx *c = EVP_MD_CTX_md_data(ctx);
    Keccak_HashUpdate(c->instance, data, count);
    return 1;
}
int keccak_digest_final(EVP_MD_CTX *ctx, unsigned char *digest){
    struct digest_init_ctx *c = EVP_MD_CTX_md_data(ctx);
    Keccak_HashFinal(c->instance, digest);
    return 1;
}

int keccak_digest_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from){
    struct digest_init_ctx *md_ctx = EVP_MD_CTX_md_data(to);
    if (EVP_MD_CTX_md_data(to) && EVP_MD_CTX_md_data(from)) {
        memcpy(EVP_MD_CTX_md_data(to), EVP_MD_CTX_md_data(from),
               sizeof(struct digest_init_ctx));
        //md_ctx->dctx.cipher_ctx = &(md_ctx->cctx);
    }
    return 1;
}

int keccak_digest_cleanup(EVP_MD_CTX *ctx)
{
    if (EVP_MD_CTX_md_data(ctx))
        memset(EVP_MD_CTX_md_data(ctx), 0,
               sizeof(struct digest_init_ctx));
    return 1;
}

EVP_MD *keccak_digest(void){
    if(keccak == NULL){
        EVP_MD *md;
        if ((md = EVP_MD_meth_new(NID_KECCAK, NID_undef)) == NULL
            || !EVP_MD_meth_set_result_size(md, sizeof(struct digest_init_ctx))
            //|| !EVP_MD_meth_set_input_blocksize(md, sizeof(struct digest_init_ctx))
            || !EVP_MD_meth_set_app_datasize(md, sizeof(struct digest_init_ctx))
            || !EVP_MD_meth_set_init(md, keccak_digest_init)
            || !EVP_MD_meth_set_update(md, keccak_digest_update)
            || !EVP_MD_meth_set_final(md, keccak_digest_final)
            || !EVP_MD_meth_set_copy(md, keccak_digest_copy)
            || !EVP_MD_meth_set_cleanup(md, keccak_digest_cleanup)) {
            EVP_MD_meth_free(md);
            md = NULL;
        }
        keccak = md;
    }
    return keccak;
}

void pki_register_dilithium(EVP_PKEY_METHOD *pmeth){
    //printf("\ncrypto bytes: %d", CRYPTO_BYTES);
    EVP_PKEY_meth_set_sign(pmeth, NULL, dilithium_sign);
}

static unsigned char *sign_digest(const unsigned char *dgst, int dlen, struct ROUND5 *key){
    unsigned char *sm = NULL;
    size_t smlen = dlen + CRYPTO_BYTES;
    sm = OPENSSL_malloc(smlen);
    printf("\nbefore crypto sign\n");
    printf("\nsiglen: %d\n", smlen);
    crypto_sign(sm, &smlen, dgst, dlen, key->sk);
    printf("\n\nsignature: %s\n\n", sm);
    return sm;
}

static int verify_digest(const unsigned char *dgst, int dgst_len, unsigned char *sig, struct ROUND5 *pkey){
    // BN_CTX *ctx;
    // const EC_GROUP *group = (ec) ? EC_KEY_get0_group(ec) : NULL;
    // BIGNUM *order;
    // BIGNUM *md = NULL, *e = NULL, *R = NULL, *v = NULL,
    //     *z1 = NULL, *z2 = NULL;
    // const BIGNUM *sig_s = NULL, *sig_r = NULL;
    // BIGNUM *X = NULL, *tmp = NULL;
    // EC_POINT *C = NULL;
    // const EC_POINT *pub_key = NULL;
    int ok = 0;

    // OPENSSL_assert(dgst != NULL && sig != NULL && group != NULL);

    // if (!(ctx = BN_CTX_new())) {
    //     //GOSTerr(GOST_F_GOST_EC_VERIFY, ERR_R_MALLOC_FAILURE);
    //     return 0;
    // }

    // BN_CTX_start(ctx);
    // order = BN_CTX_get(ctx);
    // e = BN_CTX_get(ctx);
    // z1 = BN_CTX_get(ctx);
    // z2 = BN_CTX_get(ctx);
    // tmp = BN_CTX_get(ctx);
    // X = BN_CTX_get(ctx);
    // R = BN_CTX_get(ctx);
    // v = BN_CTX_get(ctx);
    // if (!order || !e || !z1 || !z2 || !tmp || !X || !R || !v) {
    //     //GOSTerr(GOST_F_GOST_EC_VERIFY, ERR_R_MALLOC_FAILURE);
    //     goto err;
    // }

    pkey = EVP_PKEY_get0(pkey);
    if (!pkey->pk) {
        //GOSTerr(GOST_F_GOST_EC_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    //DSA_SIG_get0(sig, &sig_r, &sig_s);

    // if (BN_is_zero(sig_s) || BN_is_zero(sig_r) ||
    //     (BN_cmp(sig_s, order) >= 1) || (BN_cmp(sig_r, order) >= 1)) {
    //     //GOSTerr(GOST_F_GOST_EC_VERIFY, GOST_R_SIGNATURE_PARTS_GREATER_THAN_Q);
    //     goto err;

    // }

    // OPENSSL_assert(dgst_len == 32 || dgst_len == 64);
    // md = hashsum2bn(dgst, dgst_len);
    // if (!md || !BN_mod(e, md, order, ctx)) {
    //     // GOSTerr(GOST_F_GOST_EC_VERIFY, ERR_R_INTERNAL_ERROR);
    //     goto err;
    // }
    // if (BN_is_zero(e) && !BN_one(e)) {
    //     // GOSTerr(GOST_F_GOST_EC_VERIFY, ERR_R_INTERNAL_ERROR);
    //     goto err;
    // }
    // v = BN_mod_inverse(v, e, order, ctx);
    // if (!v || !BN_mod_mul(z1, sig_s, v, order, ctx)
    //     || !BN_sub(tmp, order, sig_r)
    //     || !BN_mod_mul(z2, tmp, v, order, ctx)) {
    //     // GOSTerr(GOST_F_GOST_EC_VERIFY, ERR_R_INTERNAL_ERROR);
    //     goto err;
    // }

    C = EC_POINT_new(group);
    if (!C) {
        // GOSTerr(GOST_F_GOST_EC_VERIFY, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (!EC_POINT_mul(group, C, z1, pub_key, z2, ctx)) {
        // GOSTerr(GOST_F_GOST_EC_VERIFY, ERR_R_EC_LIB);
        goto err;
    }
    if (!EC_POINT_get_affine_coordinates_GFp(group, C, X, NULL, ctx)) {
        // GOSTerr(GOST_F_GOST_EC_VERIFY, ERR_R_EC_LIB);
        goto err;
    }
    if (!BN_mod(R, X, order, ctx)) {
        // GOSTerr(GOST_F_GOST_EC_VERIFY, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (BN_cmp(R, sig_r) != 0) {
        // GOSTerr(GOST_F_GOST_EC_VERIFY, GOST_R_SIGNATURE_MISMATCH);
    } else {
        ok = 1;
    }
 err:
    if (C)
        EC_POINT_free(C);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    if (md)
        BN_free(md);
    return ok;
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
    struct ROUND5 *r5s = EVP_PKEY_get0(pkey);
    printf("\n\n\n\n\n\n\nr5s->sk: %s\n\n\n\n\n\n\n", r5s->sk);
    sig = sign_digest(tbs, tbs_len, r5s);
    printf("\nsig: %s\n", sig);
    if (!sig) {
        return 0;
    }
    return 1;
}

