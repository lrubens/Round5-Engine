#include <stdio.h>
#include <string.h>
#include <err.h>
#include <openssl/x509v3.h>

struct CSR{
    // char *name;
    char *country;
    char *province;
    char *city;
    char *organization;
    char *fqdn;
};

X509_REQ *gen_csr(unsigned char *country, unsigned char *province, unsigned char *city, unsigned char *organization, unsigned char * fqdn);
X509 * sign_csr(X509_REQ *req, EVP_PKEY *server_key);
EVP_PKEY *genkey_dilithium();
int validate_peer_cert(X509 *cert, EVP_PKEY *pkey);
char *X509_to_PEM(X509 *cert);
X509 * PEM_to_X509(const char *cert);
X509_REQ *PEM_toX509Req(const char *csr_str);
char *X509Req_to_PEM(X509_REQ *csr);
int char_to_EVP_PKEY(char *key_str, EVP_PKEY *pkey);
char *EVP_PKEY_to_char(EVP_PKEY *pkey);
char *get_IP();
int EVP_gen_round5(EVP_PKEY *pkey);
int generate_cert(char *data);
