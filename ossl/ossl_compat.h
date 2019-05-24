//
// Created by ruben on 5/24/2019.
//

#ifdef OPENSSL_V102_COMPAT

#ifndef ROUND5_OSSL_COMPAT_H
#define ROUND5_OSSL_COMPAT_H

#define OPENSSL_secure_malloc(a) OPENSSL_malloc(a)
#define OPENSSL_secure_free(a) OPENSSL_free(a)
void *OPENSSL_memdup(const void *src, size_t size);
#define OPENSSL_clear_free(ptr, oldsize) CRYPTO_clear_free(ptr, oldsize, __FILE__, __LINE__)
void CRYPTO_clear_free(void *src, size_t oldlen, const char *file, int line);
#define OPENSSL_clear_realloc(src, oldlen, newlen) CRYPTO_clear_realloc(src, oldlen, newlen, __FILE__, __LINE__)
void *CRYPTO_clear_realloc(void *s, size_t oldlen, size_t newlen, const char *file, int line);
void *OPENSSL_zalloc(size_t size);
#define OPENSSL_zalloc(size) CRYPTO_zalloc(size, __FILE__, __LINE__)
void *CRYPTO_zalloc(size_t num, const char *file, int line);

int ASN1_buf_print(BIO *bp, const unsigned char *buf, size_t buflen, int indent);
#define ASN1_STRING_get0_data(x) ((x)->data)

#endif //ROUND5_OSSL_COMPAT_H
#endif