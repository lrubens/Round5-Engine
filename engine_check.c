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
#include "keypair.h"
#include <openssl/bio.h>
#include <openssl/x509v3.h>
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

struct certKey * gen_cert(){
  // parameters *params;
  // params = set_parameters_from_api();
  // Round5 *kpair = NULL;
  // kpair = OPENSSL_secure_malloc(sizeof(*kpair));
  // kpair->sk = checked_malloc(get_crypto_secret_key_bytes(params, 1));
  // kpair->pk = checked_malloc(get_crypto_public_key_bytes(params));
  // r5_cca_pke_keygen(kpair->pk, kpair->sk, params);
  //Round5 *kpair = NULL;
  //kpair = _round5_keypair_new(1195, 0);
  
  //round5_sk_to_pk(kpair->key.pk, kpair->key.sk);
  //kpair->key.pk = pk;
  //kpair->key.sk = sk;
  const char *o = "test o";
  const char *cn = "test cn";
  //OPENSSL_config(NULL);
  //SSL_library_init();
  //SSL_load_error_strings();
  OPENSSL_add_all_algorithms_conf();
  ERR_load_crypto_strings();
  ENGINE_load_dynamic();
  ENGINE *round5_engine;
	T(round5_engine = ENGINE_by_id("round5"));
	T(ENGINE_init(round5_engine));
	T(ENGINE_set_default(round5_engine, ENGINE_METHOD_PKEY_METHS));
  T(ENGINE_set_default(round5_engine, ENGINE_METHOD_PKEY_ASN1_METHS));

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
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(tkey);
  // EVP_PKEY *pkey = NULL;
  // T(pkey = EVP_PKEY_new());
  // EVP_PKEY *tkey = NULL;
  // tkey = EVP_PKEY_new();
  // T(EVP_PKEY_set_type_str(pkey, algname, strlen(algname)));
  // EVP_PKEY_CTX *ctx;
  // T(ctx = EVP_PKEY_CTX_new(pkey, NULL));
  //EVP_PKEY_set1_engine(pkey, round5_engine);
  // EVP_PKEY_assign(pkey, 1195, kpair);
  // free(kpair->sk);free(kpair->pk); 
  //T(EVP_PKEY_keygen_init(ctx));
  // T(EVP_PKEY_CTX_ctrl_str(ctx, "paramset", "Round5"));
  // EVP_PKEY *tkey = NULL;
  //(EVP_PKEY_keygen(ctx, &pkey));
  
  // X509 * x509;
  // x509 = X509_new();

  // X509_gmtime_adj(X509_get_notBefore(x509), 0);
  // X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

  // BIO *b = NULL;
  // b = BIO_new(BIO_s_mem());
  // ASN1_PCTX *pctx = NULL;
  // pctx = ASN1_PCTX_new();
  // unsigned char *private_key_text = NULL;
  // EVP_PKEY_print_public(b, pkey, 4, pctx);
  // BIO_get_mem_data(b, &private_key_text);
  // printf("Private key: %s\n", private_key_text);
  // BIO_free(b);

  X509_REQ *req = NULL;
  T(req = X509_REQ_new());
  T(X509_REQ_set_version(req, 0L));
  X509_NAME *name;
  T(name = X509_NAME_new());
  X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char *)"CA", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char *)"MyCompany Inc.", -1, -1, 0);
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

  // EVP_MD_CTX *mctx;
  // T(mctx = EVP_MD_CTX_new());
  // T(EVP_DigestSignInit(mctx, NULL, NULL, NULL, pkey));
  // T(X509_sign_ctx(x509ss, mctx));
  // EVP_MD_CTX_free(mctx);

  // X509_NAME * name;
  // name = X509_get_subject_name(x509ss);

  
  //EVP_PKEY_free(pkey);

  // BIO *bio_private = NULL;
  // BIO *bio_public = NULL;
  // bio_private = BIO_new(BIO_s_mem());
  // int ret = PEM_write_bio_PrivateKey(bio_private, tkey, NULL, NULL, 0, NULL, NULL);
  // if (ret != 1)
  // {
  // goto cleanup;
  // }
  // BIO_flush(bio_private);
  // char *public_key_text, private_key_text;
  // BIO_get_mem_data(bio_private, &private_key_text);
  // printf("Private key: %s\n", private_key_text);
  // // write public key to memory
  // bio_public = BIO_new(BIO_s_mem());    
  // ret = PEM_write_bio_PUBKEY(bio_public, tkey);
  // if (ret != 1)
  // {
  // goto cleanup;
  // }
  // BIO_flush(bio_public);

  // BIO_get_mem_data(bio_public, &public_key_text);
  // printf("Public key: %s\n", public_key_text);


  // FILE * f = fopen("key.pem", "wb");
  // PEM_write_PrivateKey(
  //    f,                  /* write the key to the file we've opened */
  //    tkey,               /* our key from earlier */
  //    EVP_des_ede3_cbc(), /* default cipher for encrypting the key on disk */
  //    (unsigned char *)"hello",       /* passphrase required for decrypting the key on disk */
  //    5,                 /* length of the passphrase string */
  //    NULL,               /* callback for requesting a password */
  //    NULL                /* data to pass to the callback */
  // );
  // fclose(f);
  
  //free(o);
  //free(cn);
  cleanup:
  //X509_free(x509ss);
  //EVP_PKEY_CTX_free(ctx);
  // BIO_free(bio_public);
  // BIO_free(bio_private);
  // EVP_PKEY_CTX_free(ctx);
  //EVP_PKEY_free(tkey);
  //OPENSSL_secure_free(kpair);
  ENGINE_finish(round5_engine);
  ENGINE_free(round5_engine);
  //ENGINE_cleanup();
  struct certKey *c = NULL;
  c = OPENSSL_malloc(sizeof(*c));
  c->cert = x509ss;
  c->key = pkey;
  return c;
}

int main(int argc, const char* argv[]){
  
  struct certKey *c = gen_cert();
  int ret = X509_sign(c->cert, c->key, (EVP_MD *)EVP_sha256());
  printf("\nreturn: %d\n", ret);
  X509_print_fp(stdout, c->cert);

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
  PEM_write_X509(
      f2,   /* write the certificate to the file we've opened */
      c->cert /* our certificate */
  );
  fclose(f2);
  free(c);
}


