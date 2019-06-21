#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/ssl.h>
#include "meths/round5_meth.h"
#include "meths/asn1_meth.h"
#include "keypair.h"
#include <openssl/bio.h>
#include <openssl/x509v3.h>
#include <openssl/sha.h>
#include "ossl/objects.h"
#include "network/linux/client.h"
#include "network/linux/server.h"
// #include "../dilithium/ref/params.h"
#define T(e) ({ if (!(e)) { \
		ERR_print_errors_fp(stderr); \
		OpenSSLDie(__FILE__, __LINE__, #e); \
	    } \
        })

#define TE(e) ({ if (!(e)) { \
		ERR_print_errors_fp(stderr); \
		fprintf(stderr, "Error at %s:%d %s\n", __FILE__, __LINE__, #e); \
		return -1; \
	    } \
        })


struct certKey{
  X509 *cert;
  EVP_PKEY *key;
};

static void print_pkey(EVP_PKEY *pkey){

  BIO *b = NULL;
  b = BIO_new(BIO_s_mem());
  ASN1_PCTX *pctx = NULL;
  pctx = ASN1_PCTX_new();

  unsigned char *private_key_text = NULL;
  if(!pkey){
    printf("\n!pkey\n");
  }

  EVP_PKEY_print_public(b, pkey, 4, pctx);

  BIO_get_mem_data(b, &private_key_text);

  printf("%s\n", private_key_text);
  BIO_free(b);
  ASN1_PCTX_free(pctx);
}

EVP_PKEY *test_dilithium(){
  const char *algoname = OBJ_nid2sn(NID_DILITHIUM);
  EVP_PKEY *ckey;
  T(ckey = EVP_PKEY_new());

  T(EVP_PKEY_set_type_str(ckey, algoname, strlen(algoname)));
  EVP_PKEY_set_type(ckey, NID_DILITHIUM);

  EVP_PKEY_CTX *tx;
  (tx = EVP_PKEY_CTX_new(ckey, NULL));
  T(EVP_PKEY_keygen_init(tx));

  EVP_PKEY *qkey = NULL;
  qkey = EVP_PKEY_new();
  ((EVP_PKEY_keygen(tx, &qkey)));
  if(!qkey){
    printf("\n!qkey\n");
  }
  // print_pkey(qkey);
  EVP_PKEY_free(ckey);

  return qkey;
}

struct certKey *gen_cert(){
  // Testing Engine functions
  char *algname = "Round5";
  EVP_PKEY *tkey;
  T(tkey = EVP_PKEY_new());
  T(EVP_PKEY_set_type_str(tkey, algname, strlen(algname)));
  EVP_PKEY_CTX *ctx = NULL;
  T(ctx = EVP_PKEY_CTX_new(tkey, NULL));
  T(EVP_PKEY_keygen_init(ctx));

  EVP_PKEY *pkey = NULL;
  pkey = EVP_PKEY_new();
  T((EVP_PKEY_keygen(ctx, &pkey)) == 1);
  EVP_PKEY_free(tkey);

  X509_REQ *req = NULL;
  T(req = X509_REQ_new());
  T(X509_REQ_set_version(req, 0L));
  X509_NAME *name;
  T(name = X509_NAME_new());
  X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char *)"US", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "ST",  MBSTRING_ASC, (unsigned char *)"MA", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "L",  MBSTRING_ASC, (unsigned char *)"Cambridge", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char *)"Draper", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"localhost", -1, -1, 0);
  T(X509_REQ_set_subject_name(req, name));
  T(X509_REQ_set_pubkey(req, pkey));
  X509_NAME_free(name);
  /* Cert. */
  X509 *x509ss = NULL;
  T(x509ss = X509_new());
  T(X509_set_version(x509ss, 2));
  BIGNUM *brnd = BN_new();
  T(BN_rand(brnd, 20 * 8 - 1, -1, 0));
  T(BN_to_ASN1_INTEGER(brnd, X509_get_serialNumber(x509ss)));
  T(X509_set_issuer_name(x509ss, X509_REQ_get_subject_name(req)));
  T(X509_gmtime_adj(X509_getm_notBefore(x509ss), 0));
  T(X509_time_adj_ex(X509_getm_notAfter(x509ss), 1, 0, NULL));
  T(X509_set_subject_name(x509ss, X509_REQ_get_subject_name(req)));
  T(X509_set_pubkey(x509ss, X509_REQ_get0_pubkey(req)));
  X509_REQ_free(req);
  BN_free(brnd);

  X509V3_CTX v3ctx;
  X509V3_set_ctx_nodb(&v3ctx);
  X509V3_set_ctx(&v3ctx, x509ss, x509ss, NULL, NULL, 0);
  X509_EXTENSION *ext;
  T(ext = X509V3_EXT_conf_nid(NULL, &v3ctx, NID_basic_constraints, "critical,CA:TRUE"));
  T(X509_add_ext(x509ss, ext, 0));
  X509_EXTENSION_free(ext);
  T(ext = X509V3_EXT_conf_nid(NULL, &v3ctx, NID_subject_key_identifier, "hash"));
  T(X509_add_ext(x509ss, ext, 1));
  X509_EXTENSION_free(ext);
  T(ext = X509V3_EXT_conf_nid(NULL, &v3ctx, NID_authority_key_identifier, "keyid:always,issuer"));
  T(X509_add_ext(x509ss, ext, 2));
  X509_EXTENSION_free(ext);

  struct certKey *c = (struct certKey *)malloc(sizeof(struct certKey));
  c->cert = (X509 *)malloc(sizeof(x509ss));
  c->key = (EVP_PKEY *)malloc(sizeof(pkey));

  // c->cert = memset(c->cert, 0, sizeof(c->cert));
  c->cert = x509ss;
  // memcpy(c->key, pkey, sizeof(pkey));
  c->key = pkey;
  EVP_MD_CTX *mctx = NULL;
  T(mctx = EVP_MD_CTX_new());
  if(!ctx){
    printf("\n!ctx\n");
  }
  // (EVP_DigestSignInit(mctx, &ctx, NULL, NULL, c->key));

  // // printf("\nbefore x509 sign\n");
  // EVP_PKEY_CTX_set_rsa_padding()
  // (X509_sign_ctx(c->cert, mctx));
  EVP_MD_CTX_free(mctx);

  // print_pkey(c->key);
  // unsigned char *msg = "hellohellohellohello";
  // int len = strlen(msg);
  // EVP_PKEY_CTX *tx = NULL;
  // T(tx = EVP_PKEY_CTX_new(pkey, NULL));
  // EVP_PKEY_encrypt_init(tx);
  // size_t buflen = 1525 + len;
  // unsigned char *buf = NULL;
  // buf = malloc(1525 + len);
  // EVP_PKEY_encrypt(tx, buf, &buflen, msg, len); 
  // EVP_PKEY_decrypt_init(tx);
  // unsigned char *buf2 = NULL;
  // buf2 = malloc(len);
  // EVP_PKEY_decrypt(tx, buf2, &len, buf, buflen);

  // struct certKey *c = NULL;
  // c = OPENSSL_malloc(sizeof(*c));

  // char *algoname = OBJ_nid2sn(NID_DILITHIUM);
  // EVP_PKEY *ckey;
  // T(ckey = EVP_PKEY_new());

  // T(EVP_PKEY_set_type_str(ckey, algoname, strlen(algoname)));
  // // EVP_PKEY_set_type(ckey, NID_DILITHIUM);

  // EVP_PKEY_CTX *tx;
  // (tx = EVP_PKEY_CTX_new(ckey, NULL));
  // T(EVP_PKEY_keygen_init(tx));

  // EVP_PKEY *qkey = NULL;
  // qkey = EVP_PKEY_new();
  // ((EVP_PKEY_keygen(tx, &qkey)));
  // if(!qkey){
  //   printf("\n!qkey\n");
  // }
  // // print_pkey(qkey);
  // EVP_PKEY_free(ckey);

  // unsigned char *msg = "message";
  // int msglen = strlen(msg);
  // int siglen = msglen + CRYPTO_BYTES;
  // unsigned char *sig = malloc(siglen);
  // EVP_PKEY_CTX *cont = EVP_PKEY_CTX_new(qkey, NULL);
  // unsigned char *hash = malloc(SHA_DIGEST_LENGTH);
  // SHA1(msg, strlen(msg), hash);
  // printf("\nhash: %s\n", hash);
  // EVP_PKEY_sign_init(cont);
  // EVP_PKEY_sign(cont, sig, &siglen, hash, strlen(hash));
  // printf("\nsig: %s\n", sig);

  /*
  EVP_MD *md = EVP_get_digestbyname("Keccak");
  // printf("\nnid keccak: %s\n", OBJ_nid2ln(NID_KECCAK));
  // EVP_MD *md = EVP_get_digestbynid(NID_KECCAK);
  EVP_MD_CTX *cx = EVP_MD_CTX_create();
  EVP_MD_CTX_init(cx);
  EVP_DigestInit_ex(cx, md, NULL);
  printf("\ndigest init\n");
  unsigned char *msg = "hello wo";
  EVP_DigestUpdate(cx, msg, strlen(msg));
  printf("\ndigest update\n");
  unsigned char *buf = NULL;
  buf = malloc(64);
  unsigned int *buflen = 64;
  EVP_DigestFinal_ex(cx, buf, NULL);
  printf("\ndigest final\n");
  */



  //printf("\nbuf: %s\n", buf);
  // size_t siglen = 2713;
  // unsigned char *sig;
  // T(sig = OPENSSL_malloc(siglen));
  // unsigned char *hash = NULL;
  // hash = malloc(SHA_DIGEST_LENGTH);
  // unsigned char *msg = "hello world";
  // EVP_PKEY_CTX *cont = EVP_PKEY_CTX_new(pkey, NULL);
  // SHA1(msg, strlen(msg), hash);
  // printf("\n%s\n", hash);
  // T(EVP_PKEY_sign_init(cont));
  // int err = EVP_PKEY_sign(cont, sig, &siglen, hash, SHA_DIGEST_LENGTH);
  // printf("\nsig: %s\n", sig);
  //X509_sign(x509ss, pkey, EVP_sha1());
  //EVP_DigestSignUpdate(cx, "hello", 5);
  //client();
  
  cleanup:
  EVP_PKEY_CTX_free(ctx);
  // EVP_PKEY_CTX_free(tx);
  // free(buf);
  // free(buf2);

  // EVP_PKEY_free(pkey);

  //EVP_PKEY_CTX_free(ctx);
  // EVP_MD_CTX_free(cx);
  // printf("\nfinished\n");
  return c;
}


int main(int argc, const char* argv[]){
  // signature();
  //return 0;
  OPENSSL_add_all_algorithms_conf();
  ERR_load_crypto_strings();
  ENGINE_load_dynamic();
  ENGINE *round5_engine;
	T(round5_engine = ENGINE_by_id("round5"));
	T(ENGINE_init(round5_engine));
  T(ENGINE_set_default(round5_engine, ENGINE_METHOD_ALL));
  // ENGINE_set_default_pkey_asn1_meths(round5_engine);
  // ENGINE_set_default_pkey_meths(round5_engine);

  
  struct certKey *c = gen_cert();
  EVP_PKEY *pkey = test_dilithium();

  // EVP_MD_CTX *cx = EVP_MD_CTX_create();
  // const EVP_MD *keccak = EVP_get_digestbynid(NID_KECCAK);
  // if (!keccak){
  //   ps(keccak);
  //   exit(0);
  // }
  // EVP_DigestInit(cx, keccak);
  // const char *msg = "hello world";
  // ps(msg);
  // unsigned char md[256];
  // unsigned int md_len = 256;
  // size_t msg_len = strlen(msg);
  // EVP_DigestUpdate(cx, msg, msg_len);
  // EVP_DigestFinal(cx, md, &md_len);
  // ps(md);

  const EVP_PKEY_ASN1_METHOD *pk_ameth = EVP_PKEY_get0_asn1(pkey);
  int *ppkey_id = NULL;
  ppkey_id = (int *)malloc(sizeof(*ppkey_id));
  int *ppkey_base_id = NULL;
  int *ppkey_flags = NULL;
  const char **pinfo = NULL;
  const char **ppem_str = NULL;
  ppem_str = (const char **)malloc(sizeof(*ppem_str));
  if(!EVP_PKEY_asn1_get0_info(ppkey_id, ppkey_base_id, ppkey_flags, pinfo, ppem_str, pk_ameth)){
    ps("function bad");
  }
  
  // EVP_PKEY * pkey;
  // pkey = EVP_PKEY_new();
  // RSA *rsa = NULL;
  // BIGNUM *bne = NULL;

  // //BIO *bp_public = NULL, *bp_private = NULL;

  // int bits = 1024;
  // unsigned long e = RSA_F4;

  // bne = BN_new();
  // int ret = BN_set_word(bne,e);
  // if(ret != 1){
  //     //do something
  // }

  // rsa = RSA_new();
  // ret = RSA_generate_key_ex(rsa, bits, bne, NULL);
  // if(ret != 1){
  //     //do something
  // }
  // EVP_PKEY_assign_RSA(pkey, rsa);
  
  EVP_MD_CTX *mctx;
  T(mctx = EVP_MD_CTX_new());
  EVP_PKEY_CTX *pkctx = NULL;
  EVP_MD_CTX_init(mctx);
  T(EVP_DigestSignInit(mctx, &pkctx, EVP_sha512(), NULL, pkey));
  T(X509_sign_ctx(c->cert, mctx));
  EVP_MD_CTX_free(mctx);

  // if(X509_sign(c->cert, pkey, EVP_sha256()) == 0){
  //   printf("X509_sign  failed, error 0x%lx\n", ERR_get_error());
  //   const char* error_string = ERR_error_string(ERR_get_error(), NULL);
  //   printf("X509_sign returns %s\n", error_string);
  //   exit(0);
  // } 
  // T(X509_sign(c->cert, pkey, EVP_sha256()));
  // printf("\nreturn: %d\n", ret);
  X509_print_fp(stdout, c->cert);

  // print_pkey(pkey);
  // printf("\ndone\n");
  // return 0;
  if(!c->key){
    printf("\n!c->key\n");
    return 1;
  }
  FILE * f = fopen("key.pem", "wb");
  PEM_write_PrivateKey(
    f,                  /* write the key to the file we've opened */
    c->key,               /* our key from earlier */
    EVP_des_ede3_cbc(), /* default cipher for encrypting the key on disk */
    (unsigned char *)"hello",       /* passphrase required for decrypting the key on disk */
    5,                 /* length of the passphrase string */
    NULL,               /* callback for requesting a password */
    NULL                /* data to pass to the callback */
  );
  fclose(f);
  FILE * f2 = fopen("cert.pem", "wb");
  if (!f2)
    printf("\n\nf2 not working\n\n");
  PEM_write_X509(
      f2,   /* write the certificate to the file we've opened */
      c->cert /* our certificate */
  );
  fclose(f2);
  X509_free(c->cert);
  EVP_PKEY_free(c->key);
  free(c);
  ENGINE_finish(round5_engine);
  ENGINE_free(round5_engine);
  ENGINE_cleanup();
  return 0;
}