#include <openssl/crypto.h>
#include "../keypair.h"
#include "../ossl/objects.h"
#include "round5_md.h"
#include <inttypes.h>
#include <openssl/sha.h>
#include <openssl/asn1.h>

static EVP_MD *digest_md = NULL;

int digest_init(EVP_MD_CTX *ctx){
    SHA256_CTX *context = EVP_MD_CTX_md_data(ctx);
    return 1;
}

int digest_update(EVP_MD_CTX *ctx, const void *data, size_t count){
    ps("worked");
    SHA256_CTX *context = EVP_MD_CTX_md_data(ctx);
    return SHA256_Update(context, data, count);
}

int digest_final(EVP_MD_CTX *ctx, unsigned char *md){
    ps("worked");
    SHA256_CTX *context = EVP_MD_CTX_md_data(ctx);
    return SHA256_Final(md, context);
}

int digest_copy(EVP_MD_CTX *to, EVP_MD_CTX *from){
    return 1;
}

int digest_cleanup(EVP_MD_CTX *ctx){
    EVP_MD_CTX_free(ctx);
}

EVP_MD *digest(void)
{
    ps("worked");
    if (digest_md == NULL) {
        EVP_MD *md;

        if ((md = EVP_MD_meth_new(NID_KECCAK, NID_undef)) == NULL
            || !EVP_MD_meth_set_result_size(md, 32)
            || !EVP_MD_meth_set_input_blocksize(md, 32)
            || !EVP_MD_meth_set_app_datasize(md, sizeof(SHA256_CTX))
            || !EVP_MD_meth_set_init(md, digest_init)
            || !EVP_MD_meth_set_update(md, digest_update)
            || !EVP_MD_meth_set_final(md, digest_final)
            || !EVP_MD_meth_set_copy(md, digest_copy)
            || !EVP_MD_meth_set_cleanup(md, digest_cleanup)) {
            EVP_MD_meth_free(md);
            md = NULL;
        }
        digest_md = md;
    }
    return digest_md;
}