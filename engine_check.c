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
#define T(e) ({ if (!(e)) { \
		ERR_print_errors_fp(stderr); \
		OpenSSLDie(__FILE__, __LINE__, #e); \
	    } \
        })

typedef struct{
  unsigned char *sk;
  unsigned char *pk;
} Round5;

int main(int argc, const char* argv[]){
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
	T(ENGINE_set_default(round5_engine, ENGINE_METHOD_ALL));
  // Testing Engine functions
  char *algname = "Round5";
  EVP_PKEY *pkey = NULL;
  T(pkey = EVP_PKEY_new());
  EVP_PKEY *tkey = NULL;
  tkey = EVP_PKEY_new();
  T(EVP_PKEY_set_type_str(pkey, algname, strlen(algname)));
  EVP_PKEY_CTX *ctx;
  T(ctx = EVP_PKEY_CTX_new(pkey, NULL));
  //EVP_PKEY_set1_engine(pkey, round5_engine);
  // EVP_PKEY_assign(pkey, 1195, kpair);
  // free(kpair->sk);free(kpair->pk); 
  T(EVP_PKEY_keygen_init(ctx));
  // T(EVP_PKEY_CTX_ctrl_str(ctx, "paramset", "Round5"));
  // EVP_PKEY *tkey = NULL;
  (EVP_PKEY_keygen(ctx, &tkey));
  
  X509 * x509;
  x509 = X509_new();

  X509_gmtime_adj(X509_get_notBefore(x509), 0);
  X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

  X509_set_pubkey(x509, tkey);

  X509_NAME * name;
  name = X509_get_subject_name(x509);

  X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char *)"CA", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char *)"MyCompany Inc.", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"localhost", -1, -1, 0);

  X509_sign(x509, tkey, EVP_sha1());

  // FILE * f = fopen("key.pem", "wb");
  // PEM_write_PrivateKey(
  //   f,                  /* write the key to the file we've opened */
  //   tkey,               /* our key from earlier */
  //   EVP_des_ede3_cbc(), /* default cipher for encrypting the key on disk */
  //   (unsigned char *)"hello",       /* passphrase required for decrypting the key on disk */
  //   5,                 /* length of the passphrase string */
  //   NULL,               /* callback for requesting a password */
  //   NULL                /* data to pass to the callback */
  // );
  // fprintf(f, "hello world");
  // fclose(f);


  FILE * f2 = fopen("cert.pem", "wb");
  PEM_write_X509(
      f2,   /* write the certificate to the file we've opened */
      x509 /* our certificate */
  );
  fprintf(f2, "hello world");
  fclose(f2);
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
  X509_free(x509);
  EVP_PKEY_CTX_free(ctx);
  // BIO_free(bio_public);
  // BIO_free(bio_private);
  // EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  EVP_PKEY_free(tkey);
  //OPENSSL_secure_free(kpair);
  ENGINE_finish(round5_engine);
  ENGINE_free(round5_engine);
  ENGINE_cleanup();
  return 0;
}
