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

struct DILITHIUM{
    int mac_param_nid;
    unsigned char key[1413];
    short int mac_size;
};

// struct digest_init_ctx{
//     Keccak_HashInstance *instance;
//     unsigned char * data;
// };

struct digest_init_ctx{
    unsigned long long offset;
    unsigned long long len;
    unsigned char *data;
    Keccak_HashInstance *instance;
};

static int dilithium_init(EVP_PKEY_CTX *ctx);
static int dilithium_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey, int mac_nid);
int keccak_digest_init(EVP_MD_CTX *ctx);
int keccak_digest_update(EVP_MD_CTX *ctx, void *data, size_t count);
int keccak_digest_final(EVP_MD_CTX *ctx, unsigned char *digest);
int keccak_digest_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from);
int keccak_digest_cleanup(EVP_MD_CTX *ctx);
EVP_MD * keccak_digest(void);

#endif //DILITHIUM_METH_H