#ifndef ROUND5_DILITHIUM_METH_H
#define ROUND5_DILITHIUM_METH_H
#include <openssl/evp.h>
#include "KeccakHash.h"

struct MD_DATA{
    short int key_set;
    short int mac_size;
    int mac_param_nid;
    EVP_MD *md;
    unsigned char key[1413];
    unsigned char *data;
};

// struct digest_init_ctx{
//     Keccak_HashInstance *instance;
//     unsigned char * data;
// };






static int dilithium_init(EVP_PKEY_CTX *ctx);
static int dilithium_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);

void pki_register_dilithium(EVP_PKEY_METHOD *pmeth);
static int dilithium_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbs_len);
int dilithium_verify(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbs_len);

//unsigned char *h(const unsigned char *dgst, int dlen, struct ROUND5 *key);

#endif //DILITHIUM_METH_H