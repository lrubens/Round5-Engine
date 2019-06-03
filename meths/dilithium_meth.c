#include "dilithium_meth.h"
#include <openssl/crypto.h>
#include "../ossl/objects.h"
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
    return 1;
    struct digest_init_ctx *c = EVP_MD_CTX_md_data(ctx);
    c->data = malloc(2048);
    c->len = 2048;
    c->offset = 0;
    Keccak_HashInitialize_SHA3_256(c->instance); 
    printf("\nfinished digest_init\n");
    return 1;
}

int keccak_digest_update(EVP_MD_CTX *ctx, void *data, size_t count){
    struct digest_init_ctx *c = EVP_MD_CTX_md_data(ctx);
    Keccak_HashUpdate(c->instance, data, count);
    printf("\nfinished digest_update\n");
    return 1;
}
int keccak_digest_final(EVP_MD_CTX *ctx, unsigned char *digest){
    struct digest_init_ctx *c = EVP_MD_CTX_md_data(ctx);
    Keccak_HashFinal(c->instance, digest);
    printf("\ndigest: %s\n", digest);
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