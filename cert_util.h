#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/ssl.h>
#include "keypair.h"
#include <openssl/bio.h>
#include <openssl/x509v3.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>


inline X509_REQ *gen_csr(unsigned char *country, unsigned char *province, unsigned char *city, unsigned char *organization, unsigned char * fqdn){
  char *algname = "Round5";
  EVP_PKEY *tkey;
  tkey = EVP_PKEY_new();
  EVP_PKEY_set_type_str(tkey, algname, strlen(algname));
  EVP_PKEY_CTX *ctx = NULL;
  ctx = EVP_PKEY_CTX_new(tkey, NULL);
  EVP_PKEY_keygen_init(ctx);

  EVP_PKEY *pkey = NULL;
  pkey = EVP_PKEY_new();
  EVP_PKEY_keygen(ctx, &pkey);
  EVP_PKEY_free(tkey);

  X509_REQ *req = NULL;
  req = X509_REQ_new();
  X509_REQ_set_version(req, 0L);
  X509_NAME *name;
  name = X509_NAME_new();
  X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, country, -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "ST",  MBSTRING_ASC, province, -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "L",  MBSTRING_ASC, city, -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, organization, -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, fqdn, -1, -1, 0);
  X509_REQ_set_subject_name(req, name);
  X509_REQ_set_pubkey(req, pkey);
  X509_NAME_free(name);
  return req;
}

inline X509 * sign_csr(X509_REQ *req, EVP_PKEY *server_key){
  X509_NAME *name = X509_NAME_new();
  X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, "US", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "ST",  MBSTRING_ASC, "MA", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "L",  MBSTRING_ASC, "Cambridge", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, "Draper", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, "Server", -1, -1, 0);
  X509 *signed_cert = NULL;
  signed_cert = X509_new();
  X509_set_version(signed_cert, 2);
  BIGNUM *brnd = BN_new();
  BN_rand(brnd, 20 * 8 - 1, -1, 0);
  BN_to_ASN1_INTEGER(brnd, X509_get_serialNumber(signed_cert));
  X509_set_issuer_name(signed_cert, name);
  X509_gmtime_adj(X509_getm_notBefore(signed_cert), 0);
  X509_time_adj_ex(X509_getm_notAfter(signed_cert), 1, 0, NULL);
  X509_set_subject_name(signed_cert, X509_REQ_get_subject_name(req));
  X509_set_pubkey(signed_cert, X509_REQ_get0_pubkey(req));
  X509_REQ_free(req);
  BN_free(brnd);

  X509V3_CTX v3ctx;
  X509V3_set_ctx_nodb(&v3ctx);
  X509V3_set_ctx(&v3ctx, signed_cert, signed_cert, NULL, NULL, 0);
  X509_EXTENSION *ext;
  ext = X509V3_EXT_conf_nid(NULL, &v3ctx, NID_basic_constraints, "critical,CA:TRUE");
  X509_add_ext(signed_cert, ext, 0);
  X509_EXTENSION_free(ext);
  ext = X509V3_EXT_conf_nid(NULL, &v3ctx, NID_subject_key_identifier, "hash");
  X509_add_ext(signed_cert, ext, 1);
  X509_EXTENSION_free(ext);
  ext = X509V3_EXT_conf_nid(NULL, &v3ctx, NID_authority_key_identifier, "keyid:always,issuer");
  X509_add_ext(signed_cert, ext, 2);
  X509_EXTENSION_free(ext);
  if (!X509_sign(signed_cert, server_key, EVP_sha512())){
    printf("\n****Error in sign****\n");
    return NULL;
  }
  return signed_cert;
}

inline EVP_PKEY *genkey_dilithium(){
  const char *algoname = "Dilithium";
  EVP_PKEY *ckey;
  ckey = EVP_PKEY_new();
  EVP_PKEY_set_type_str(ckey, algoname, strlen(algoname));
  EVP_PKEY_CTX *tx;
  tx = EVP_PKEY_CTX_new(ckey, NULL);
  EVP_PKEY_keygen_init(tx);
  EVP_PKEY *qkey = NULL;
  qkey = EVP_PKEY_new();
  EVP_PKEY_keygen(tx, &qkey);
  if(!qkey){
    printf("\n!qkey\n");
  }
  EVP_PKEY_free(ckey);
  return qkey;
}

inline int validate_peer_cert(X509 *cert, EVP_PKEY *pkey){
  unsigned char *result;
  int r = X509_verify(cert, pkey);
  return r;
}

inline char *X509_to_PEM(X509 *cert){
    BIO *bio = NULL;
    char *pem = NULL;

    if (NULL == cert) {
        return NULL;
    }

    bio = BIO_new(BIO_s_mem());
    if (NULL == bio) {
        return NULL;
    }

    if (0 == PEM_write_bio_X509(bio, cert)) {
        BIO_free(bio);
        return NULL;
    }

    pem = (char *) malloc(bio->num_write + 1);
    if (NULL == pem) {
        BIO_free(bio);
        return NULL;    
    }

    memset(pem, 0, bio->num_write + 1);
    BIO_read(bio, pem, bio->num_write);
    BIO_free(bio);
    return pem;
}

inline X509 * PEM_to_X509(const char *cert){
  BIO *b = BIO_new(BIO_s_mem());
  BIO_puts(b, cert);
  X509 *cert_obj = PEM_read_bio_X509(b, NULL, NULL, NULL);
  BIO_free(b);
  return cert_obj;
}

inline X509_REQ *PEM_toX509Req(const char *csr_str){
  BIO *b = BIO_new(bIO_s_mem());
  BIO_puts(b, csr_str);
  X509_REQ *req = PEM_read_bio_X509_REQ(b, NULL, NULL, NULL);
  return req;
}

inline char *X509Req_to_PEM(X509_REQ *csr){
  BIO *bio = NULL;
  char *pem = NULL;
  bio = BIO_new(BIO_s_mem());
  PEM_write_bio_X509(bio, csr);
  pem = (char *) malloc(bio->num_write + 1);
  memset(pem, 0, bio->num_write + 1);
  BIO_read(bio, pem, bio->num_write);
  BIO_free(bio);
  return pem;
}

inline int char_to_EVP_PKEY(char *key_str, EVP_PKEY *pkey){
  i2d_PublicKey(pkey, &key_str);
}

inline char *get_IP(){
  char *IP_buf;
  char host_buffer[256];
  struct hostent *host_entry;
  int hostname;
  hostname = gethostname(host_buffer, sizeof(host_buffer));
  IP_buf = inet_ntoa(*((struct in_addr*)host_entry->h_addr_list[0]));
  printf("\n%s\n", IP_buf);
  return IP_buf;
}