#include <openssl/evp.h>

EVP_MD *digest(void);
int digest_init(EVP_MD_CTX *ctx);
int digest_update(EVP_MD_CTX *ctx, const void *data, size_t count);
int digest_final(EVP_MD_CTX *ctx, unsigned char *md);
int digest_copy(EVP_MD_CTX *to, EVP_MD_CTX *from);
int digest_cleanup(EVP_MD_CTX *ctx);