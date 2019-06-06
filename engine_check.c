#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/ssl.h>
#include "r5_cca_pke.h"
#include "parameters.h"
#include "r5_memory.h"
#include "meths/round5_meth.h"
#include "meths/asn1_meth.h"
#include "keypair.h"
#include <openssl/bio.h>
#include <openssl/x509v3.h>
#include <openssl/sha.h>
#include "ossl/objects.h"
#define T(e) ({ if (!(e)) { \
		ERR_print_errors_fp(stderr); \
		OpenSSLDie(__FILE__, __LINE__, #e); \
	    } \
        })

typedef struct{
  unsigned char *sk;
  unsigned char *pk;
} Round5;
struct certKey{
  X509 *cert;
  EVP_PKEY *key;
};

static void generateSimpleRawMaterial(unsigned char *data, unsigned int length, unsigned char seed1, unsigned int seed2){
  unsigned int i;
  for(i = 0; i < length; i++){
    unsigned char iRolled;
    unsigned char byte;
    seed2 = seed2 % 8;
    iRolled = ((unsigned char)i << seed2) | ((unsigned char)i >> (8 - seed2));
    byte = seed1 + 161*length - iRolled + i;
    data[i] = byte;
  }
}

/*struct certKey **/int gen_cert(struct certKey *c){
  // parameters *params;
  // params = set_parameters_from_api();
  // Round5 *kpair = NULL;
  // kpair = OPENSSL_secure_malloc(sizeof(*kpair));
  // kpair->sk = checked_malloc(get_crypto_secret_key_bytes(params, 1));
  // kpair->pk = checked_malloc(get_crypto_public_key_bytes(params));
  // r5_cca_pke_keygen(kpair->pk, kpair->sk, params);
  //Round5 *kpair = NULL;
  
  //round5_sk_to_pk(kpair->key.pk, kpair->key.sk);
  //kpair->key.pk = pk;
  //kpair->key.sk = sk;
  //OPENSSL_config(NULL);
  // SSL_library_init();
  // SSL_load_error_strings();
  OPENSSL_add_all_algorithms_conf();
  ERR_load_crypto_strings();
  ENGINE_load_dynamic();
  ENGINE *round5_engine;
	T(round5_engine = ENGINE_by_id("round5"));
	T(ENGINE_init(round5_engine));
  T(ENGINE_set_default(round5_engine, ENGINE_METHOD_ALL));
	// T(ENGINE_set_default(round5_engine, ENGINE_METHOD_PKEY_METHS));
  // T(ENGINE_set_default(round5_engine, ENGINE_METHOD_PKEY_ASN1_METHS));

  // Testing Engine functions
  char *algname = "Round5";
  EVP_PKEY *tkey;
  T(tkey = EVP_PKEY_new());
  T(EVP_PKEY_set_type_str(tkey, algname, strlen(algname)));
  EVP_PKEY_CTX *ctx;
  T(ctx = EVP_PKEY_CTX_new(tkey, NULL));
  T(EVP_PKEY_keygen_init(ctx));
  //if (paramset)
	//T(EVP_PKEY_CTX_ctrl_str(ctx, "paramset", paramset));
  EVP_PKEY *pkey = NULL;
  pkey = EVP_PKEY_new();
  T((EVP_PKEY_keygen(ctx, &pkey)) == 1);
  
  // BIO *b = NULL;
  // b = BIO_new(BIO_s_mem());
  // ASN1_PCTX *pctx = NULL;
  // pctx = ASN1_PCTX_new();
  // unsigned char *private_key_text = NULL;
  // EVP_PKEY_print_public(b, pkey, 4, pctx);
  // BIO_get_mem_data(b, &private_key_text);
  // printf("%s\n", private_key_text);
  // BIO_free(b);
  // ASN1_PCTX_free(pctx);
  // EVP_PKEY_set1_engine(pkey, round5_engine);
  EVP_PKEY_free(tkey);
  //EVP_PKEY_CTX_free(ctx);

  X509_REQ *req = NULL;
  T(req = X509_REQ_new());
  T(X509_REQ_set_version(req, 0L));
  X509_NAME *name;
  T(name = X509_NAME_new());
  X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char *)"USA", -1, -1, 0);
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

  unsigned char msg[] = "hello";
  printf("\nmsg len: %d\n", strlen(msg));
  int len = strlen(msg);
  EVP_PKEY_CTX *tx = NULL;
  T(tx = EVP_PKEY_CTX_new(pkey, NULL));
  EVP_PKEY_encrypt_init(tx);
  size_t buflen = 1525 + len;
  unsigned char buf[1525 + len];
  EVP_PKEY_encrypt(tx, buf, &buflen, msg, len); 
  printf("\nencrypted message: %s\n", buf);
  EVP_PKEY_decrypt_init(tx);
  unsigned char buf2[len];
  EVP_PKEY_decrypt(tx, buf2, &len, buf, buflen);
  printf("\ndecrypted message: %s\n", buf2);
  printf("\nmsg len: %d\n", strlen(buf2));
  // struct certKey *c = NULL;
  // c = OPENSSL_malloc(sizeof(*c));
  // c->cert = malloc(sizeof(c->cert));
  // c->key = malloc(sizeof(c->key));


   
  c->cert = x509ss;
  c->key = pkey;
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
  
  cleanup:
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_CTX_free(tx);
  ENGINE_finish(round5_engine);
  ENGINE_free(round5_engine);
  //EVP_PKEY_CTX_free(ctx);
  // EVP_MD_CTX_free(cx);
  // printf("\nfinished\n");
  ENGINE_cleanup();
  return 1;
}

int signature(){
  OPENSSL_add_all_algorithms_conf();
  ERR_load_crypto_strings();
  ENGINE_load_dynamic();
  ENGINE *round5_engine;
	T(round5_engine = ENGINE_by_id("round5"));
	T(ENGINE_init(round5_engine));
  T(ENGINE_set_default(round5_engine, ENGINE_METHOD_ALL));
	// T(ENGINE_set_default(round5_engine, ENGINE_METHOD_PKEY_METHS));
  // T(ENGINE_set_default(round5_engine, ENGINE_METHOD_PKEY_ASN1_METHS));
  int hash_nid = NID_KECCAK;
  //const EVP_MD *mdtype;
	// EVP_MD *mdtype = EVP_get_digestbyname("Keccak");
	// EVP_MD_CTX *mctx;
	// T(mctx = EVP_MD_CTX_new());
	// T(EVP_DigestInit_ex(mctx, mdtype, round5_engine));
  // printf("\ninit done\n");
	// T(EVP_DigestUpdate(mctx, "hello", 6));
	// unsigned int len;
	// unsigned char md[512 / 8];
	// T(EVP_DigestFinal(mctx, md, &len));
  // printf("\n%d\n", len);
	// EVP_MD_CTX_free(mctx);
  // printf("\n%s\n", md);

  EVP_PKEY *pkey;
  T(pkey = EVP_PKEY_new());
  char * algname = "Round5";
  T(EVP_PKEY_set_type_str(pkey, algname, strlen(algname)));
  EVP_PKEY_CTX *ctx;
  (ctx = EVP_PKEY_CTX_new(pkey, NULL));
  T(EVP_PKEY_keygen_init(ctx));
  // T(EVP_PKEY_CTX_ctrl(ctx, NID_KECCAK, -1, NULL, NULL, NULL));
  EVP_PKEY *priv_key = NULL;
  //priv_key = EVP_PKEY_new();
  int err = EVP_PKEY_keygen(ctx, &priv_key);
  // printf("\tEVP_PKEY_keygen:\n");
  //print_test_result(err);
  // BIO *b = NULL;
  // b = BIO_new(BIO_s_mem());
  // ASN1_PCTX *pctx = NULL;
  // pctx = ASN1_PCTX_new();
  // unsigned char *private_key_text = NULL;
  // private_key_text = malloc(2048);
  // EVP_PKEY_print_public(b, priv_key, 4, pctx);
  // BIO_get_mem_data(b, &private_key_text);
  // printf("%s\n", private_key_text);
  // BIO_free(b);
  // ASN1_PCTX_free(pctx);
  //EVP_PKEY_set1_engine(pkey, round5_engine);
  // EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  if (err != 1){
    printf("\nerror in keygen\n");
    ENGINE_finish(round5_engine);
    ENGINE_free(round5_engine);
    ENGINE_cleanup();
	  return -1;
  }

  /* Create another key using string interface. */
  EVP_PKEY *key1;
  T(key1 = EVP_PKEY_new());
  T(EVP_PKEY_set_type_str(key1, algname, strlen(algname)));
  EVP_PKEY_CTX *ctx1;
  T(ctx1 = EVP_PKEY_CTX_new(key1, NULL));
  T(EVP_PKEY_keygen_init(ctx1));
  T(EVP_PKEY_CTX_ctrl_str(ctx1, "paramset", NULL));
  EVP_PKEY *key2 = NULL;
  err = EVP_PKEY_keygen(ctx1, &key2);
  // printf("\tEVP_PKEY_*_str:\t\t");
  //print_test_result(err);

  BIO *b = NULL;
  b = BIO_new(BIO_s_mem());
  ASN1_PCTX *pctx = NULL;
  pctx = ASN1_PCTX_new();
  unsigned char *private_key_text = NULL;
  private_key_text = malloc(2048);
  EVP_PKEY_print_public(b, priv_key, 4, pctx);
  BIO_get_mem_data(b, &private_key_text);
  printf("%s\n", private_key_text);
  //BIO_free(b);
  ASN1_PCTX_free(pctx);

  unsigned char msg[] = "hello world";
  unsigned char *hash = NULL;
  hash = malloc(SHA256_DIGEST_LENGTH);
  size_t siglen = 1525 + strlen(msg);//2701 + strlen(hash);
  printf("\nsiglen: %d\n", siglen);
  unsigned char *sig;
  T(sig = OPENSSL_malloc(siglen));
  EVP_PKEY_CTX *cont = EVP_PKEY_CTX_new(priv_key, NULL);
  SHA256(msg, strlen(msg), hash);
  printf("\nhash: %d\n", strlen(hash));
  T(EVP_PKEY_sign_init(cont));
  err = EVP_PKEY_sign(cont, sig, &siglen, hash, 32);
  printf("\nsig2: %s\n", sig);
  ENGINE_finish(round5_engine);
  ENGINE_free(round5_engine);
  ENGINE_cleanup();
  return 1;
}



int main(int argc, const char* argv[]){
  // signature();
  // return 0;
  struct certKey *c = NULL;
  c = OPENSSL_malloc(sizeof(*c));
  // c->cert = NULL;
  // c->cert = malloc(sizeof(c->cert));
  // c->key = NULL;
  // c->key = malloc(sizeof(c->key));
  // printf("\n%d\n", sizeof(struct certKey));
  gen_cert(c);
  // printf("\npast gen_cert\n");
  // BIO *b = NULL;
  // b = BIO_new(BIO_s_mem());
  // ASN1_PCTX *pctx = NULL;
  // pctx = ASN1_PCTX_new();
  // unsigned char *private_key_text = NULL;
  // private_key_text = malloc(2048);
  // EVP_PKEY_print_public(b, c->key, 4, pctx);
  // BIO_get_mem_data(b, &private_key_text);
  // printf("\nhello1\n");
  // printf("%s\n", private_key_text);
  // printf("\nhello\n");
  // //BIO_free(b);
  // ASN1_PCTX_free(pctx);
  // /c = gen_cert();
  // int ret = X509_sign(c->cert, c->key, (EVP_MD *)EVP_sha256());
  //T(EVP_PKEY_set_type_str(c->key, "RSA", 3));
  EVP_PKEY * pkey;
  pkey = EVP_PKEY_new();
  RSA *rsa = NULL;
  BIGNUM *bne = NULL;
  //BIO *bp_public = NULL, *bp_private = NULL;

  int bits = 1024;
  unsigned long e = RSA_F4;

  bne = BN_new();
  int ret = BN_set_word(bne,e);
  if(ret != 1){
      //do something
  }

  rsa = RSA_new();
  ret = RSA_generate_key_ex(rsa, bits, bne, NULL);
  if(ret != 1){
      //do something
  }
  EVP_PKEY_assign_RSA(pkey, rsa);
  EVP_MD_CTX *mctx = NULL;
  T(mctx = EVP_MD_CTX_new());
  T(EVP_DigestSignInit(mctx, NULL, EVP_sha512(), NULL, pkey));
  // printf("\nbefore x509 sign\n");
  T(X509_sign_ctx(c->cert, mctx));
  EVP_MD_CTX_free(mctx);
  // printf("\nreturn: %d\n", ret);
  // X509_print_fp(stdout, c->cert);
  // FILE * f = fopen("key.pem", "wb");
  // PEM_write_PrivateKey(
  //   f,                  /* write the key to the file we've opened */
  //   c->key,               /* our key from earlier */
  //   EVP_des_ede3_cbc(), /* default cipher for encrypting the key on disk */
  //   (unsigned char *)"hello",       /* passphrase required for decrypting the key on disk */
  //   5,                 /* length of the passphrase string */
  //   NULL,               /* callback for requesting a password */
  //   NULL                /* data to pass to the callback */
  // );
  // fclose(f);
  // FILE * f2 = fopen("cert.pem", "wb");
  // PEM_write_X509(
  //     f2,   /* write the certificate to the file we've opened */
  //     c->cert /* our certificate */
  // );
  // fclose(f2);
  BN_free(bne);
  EVP_PKEY_free(pkey);
  X509_free(c->cert);
  //EVP_PKEY_free(c->key);
  free(c);
}


