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
#define T(e) ({ if (!(e)) { \
		ERR_print_errors_fp(stderr); \
		OpenSSLDie(__FILE__, __LINE__, #e); \
	    } \
        })

int main(int argc, const char* argv[]){
  parameters *params;
  params = set_parameters_from_api();
  unsigned char *sk = checked_malloc(get_crypto_secret_key_bytes(params, 1));
  unsigned char *pk = checked_malloc(get_crypto_public_key_bytes(params));
  r5_cca_pke_keygen(pk, sk, params);
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
  EVP_PKEY *pkey;
  T(pkey = EVP_PKEY_new());
  T(EVP_PKEY_set_type_str(pkey, algname, strlen(algname)));
  EVP_PKEY_CTX *ctx;
  T(ctx = EVP_PKEY_CTX_new(pkey, NULL));
  //T(EVP_PKEY_keygen_init(ctx));
  // T(EVP_PKEY_CTX_ctrl_str(ctx, "paramset", "Round5"));
  // EVP_PKEY *tkey = NULL;
  // T(EVP_PKEY_keygen(ctx, &tkey) == 1);

  FILE * f = fopen("key.pem", "wb");
  PEM_write_PrivateKey(
      f,                  /* write the key to the file we've opened */
      pkey,               /* our key from earlier */
      EVP_des_ede3_cbc(), /* default cipher for encrypting the key on disk */
      (unsigned char *)"hello",       /* passphrase required for decrypting the key on disk */
      5,                 /* length of the passphrase string */
      NULL,               /* callback for requesting a password */
      NULL                /* data to pass to the callback */
  );
  fclose(f);
  
  //free(o);
  //free(cn);
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  //EVP_PKEY_free(tkey);
  ENGINE_finish(round5_engine);
  ENGINE_free(round5_engine);
  ENGINE_cleanup();
  return 0;
}
