#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
//#include <openssl/ssl.h>
#include <openssl/rand.h>
#include "keypair.h"
#include <openssl/bio.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <netdb.h>
#include <ifaddrs.h>

static int add_ext(STACK_OF(X509_EXTENSION) *sk, int nid, char *value){
  X509_EXTENSION *ex;
  ex = X509V3_EXT_conf_nid(NULL, NULL, nid, value);
  if (!ex)
    return 0;
  sk_X509_EXTENSION_push(sk, ex);
  return 1;
 }

int EVP_gen_round5(EVP_PKEY *data){
  char *algname = "Round5";
  EVP_PKEY *tkey;
  tkey = EVP_PKEY_new();
  EVP_PKEY_set_type_str(tkey, algname, strlen(algname));
  EVP_PKEY_CTX *ctx = NULL;
  ctx = EVP_PKEY_CTX_new(tkey, NULL);
  EVP_PKEY_keygen_init(ctx);
  data = EVP_PKEY_new();
  EVP_PKEY_keygen(ctx, &data);
  EVP_PKEY_free(tkey);
}

X509_REQ *gen_csr(unsigned char *country, unsigned char *province, unsigned char *city, unsigned char *organization, unsigned char * fqdn){
  char *algname = "Round5";
  EVP_PKEY *tkey;
  tkey = EVP_PKEY_new();
  EVP_PKEY_set_type_str(tkey, algname, strlen(algname));
  EVP_PKEY_CTX *ctx = NULL;
  ctx = EVP_PKEY_CTX_new(tkey, NULL);
  EVP_PKEY_keygen_init(ctx);
  EVP_PKEY *data = NULL;
  data = EVP_PKEY_new();
  EVP_PKEY_keygen(ctx, &data);
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
  X509_REQ_set_pubkey(req, data);
  X509_NAME_free(name);
  if(!req){
    printf("\nNULL req\n");
    exit(0);
  }
  STACK_OF(X509_EXTENSION) *exts = NULL;
  sk_X509_EXTENSION_new_null();
  add_ext(exts, NID_key_usage, "critical, false, digitalSignature, keyEncipherment");
  X509_REQ_add_extensions(req, exts);
  sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
  return req;
}

EVP_PKEY *genkey_rsa(){
  EVP_PKEY * pkey;
  pkey = EVP_PKEY_new();
  RSA *rsa = NULL;
  BIGNUM *bne = NULL;
  //BIO *bp_public = NULL, *bp_private = NULL;

  int bits = 2048;
  unsigned long e = RSA_F4;

  bne = BN_new();
  BN_set_word(bne,e);
  rsa = RSA_new();
  RSA_generate_key_ex(rsa, bits, bne, NULL);
  EVP_PKEY_assign_RSA(pkey, rsa);
  return pkey;
}

X509 * sign_csr(EVP_PKEY *client_key, EVP_PKEY *server_key){
  // set request info
  X509_REQ *req = NULL;
  req = X509_REQ_new();
  X509_REQ_set_version(req, 0L);
  X509_NAME *name_;
  name_ = X509_NAME_new();
  X509_NAME_add_entry_by_txt(name_, "C",  MBSTRING_ASC, "US", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name_, "ST",  MBSTRING_ASC, "CA", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name_, "L",  MBSTRING_ASC, "Los Angeles", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name_, "O",  MBSTRING_ASC, "Apple", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name_, "CN", MBSTRING_ASC, "Client", -1, -1, 0);
  X509_REQ_set_subject_name(req, name_);
  // Set issuer info
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
  X509_set_pubkey(signed_cert, client_key);
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

EVP_PKEY *genkey_dilithium(){
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

int validate_peer_cert(X509 *cert, EVP_PKEY *data){
  unsigned char *result;
  int r = X509_verify(cert, data);
  return r;
}

char *X509_to_PEM(X509 *cert){
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
  int len = i2d_X509(cert, NULL);
  pem = (char *) malloc(len);
  if (NULL == pem) {
      BIO_free(bio);
      return NULL;
  }    
  memset(pem, 0, len);
  BIO_read(bio, pem, len);
  BIO_free(bio);
  return pem;
}

int generate_cert(EVP_PKEY *pkey){

  // printf("Size: %d", EVP_PKEY_size(data));
  // BIO *b = NULL;
  // b = BIO_new(BIO_s_mem());
  // ASN1_PCTX *pctx = NULL;
  // pctx = ASN1_PCTX_new();
  // char * key_str = NULL;
  // if(!data){
  //   printf("\n!data\n");
  // }
  // EVP_PKEY_print_public(b, data, 4, pctx);
  // BIO_get_mem_data(b, &key_str);
  // printf("\n%s\n", key_str);
        /* Error occurred */
  // if (EVP_PKEY_encrypt_init(ctx) <= 0){
  //   printf("\nEncrypt init: %d\n", EVP_PKEY_encrypt_init(ctx));
  //   printf("CTX init failed");
  //   exit(0);
  // }
  // /* Determine buffer length */
  // if (EVP_PKEY_encrypt(ctx, NULL, &outlen, key, 16) <= 0){
  //   printf("Encrypt initial failed");
  //   exit(0);
  // }
  // out = OPENSSL_malloc(outlen);
  // if (EVP_PKEY_encrypt(ctx, out, &outlen, key, 16) <= 0){
  //   printf("Encrypt failed");
  //   exit(0);
  // }
  // printf("\n%s\n", out);
  return 1;
}

X509 * PEM_to_X509(const char *cert){
  BIO *b = BIO_new(BIO_s_mem());
  BIO_puts(b, cert);
  X509 *cert_obj = PEM_read_bio_X509(b, NULL, NULL, NULL);
  BIO_free(b);
  return cert_obj;
}

X509_REQ *PEM_toX509Req(const char *csr_str){
  printf("\n%s\n", csr_str);
  BIO *b = BIO_new(BIO_s_mem());
  BIO_puts(b, csr_str);
  X509_REQ *req = PEM_read_bio_X509_REQ(b, NULL, NULL, NULL);
  BIO_free(b);
  return req;
}

char *X509Req_to_PEM(X509_REQ *csr){
  BIO *bio = NULL;
  char *pem = NULL;
  bio = BIO_new(BIO_s_mem());
  PEM_write_bio_X509(bio, csr);
  int len = i2d_X509_REQ(csr, NULL);
  pem = (char *) malloc(len);
  memset(pem, 0, len);
  BIO_read(bio, pem, len);
  BIO_free(bio);
  return pem;
}

int char_to_EVP_PKEY(const char *key_str, EVP_PKEY *data){
  // BIO *b = BIO_new(BIO_s_mem());
  // BIO_puts(b, key_str);
  // data = PEM_read_bio_PUBKEY(b, &data, NULL, NULL);
  if(!data){
    printf("\nPKEY NULL\n");
    exit(0);
  }
  i2d_PublicKey(data, &key_str);
  // printf
}

char *EVP_PKEY_to_char(EVP_PKEY *data){
  BIO *b = NULL;
  b = BIO_new(BIO_s_mem());
  ASN1_PCTX *pctx = NULL;
  pctx = ASN1_PCTX_new();
  char * key_str = NULL;
  if(!data){
    printf("\n!data\n");
  }
  EVP_PKEY_print_public(b, data, 4, pctx);
  BIO_get_mem_data(b, &key_str);
  return key_str;
  ASN1_PCTX_free(pctx);
  BIO_free(b);
}

char *get_IP(){
  char *IP_buf;
  //char host_buffer[256];
  //struct hostent *host_entry;
  //int hostname;
  //hostname = gethostname(host_buffer, sizeof(host_buffer));
  //IP_buf = inet_ntoa(*((struct in_addr*)host_entry->h_addr_list[0]));
  //printf("\n%s\n", IP_buf);
  struct ifaddrs *id;
  int val;
  val = getifaddrs(&id);
  IP_buf = id->ifa_addr;
  printf("\n%s\n", IP_buf);
  return IP_buf;
}
