#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/ssl.h>
#define T(e) ({ if (!(e)) { \
		ERR_print_errors_fp(stderr); \
		OpenSSLDie(__FILE__, __LINE__, #e); \
	    } \
        })

int main(int argc, const char* argv[]){
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
  T(EVP_PKEY_keygen_init(ctx));
  T(EVP_PKEY_CTX_ctrl_str(ctx, "paramset", "Round5"));
  EVP_PKEY *tkey = NULL;
  T(EVP_PKEY_keygen(ctx, &tkey) == 1);
 	X509_REQ *req = NULL;
  T(req = X509_REQ_new());
  T(X509_REQ_set_version(req, 0L));
  X509_NAME *name;
  T(name = X509_NAME_new());
  T(X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)o, -1, -1, 0));
  T(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)cn, -1, -1, 0));
  T(X509_REQ_set_subject_name(req, name));
  T(X509_REQ_set_pubkey(req, tkey));
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
	X509_print_fp(stdout, x509ss); 
  //free(o);
  //free(cn);
  X509_free(x509ss);
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  EVP_PKEY_free(tkey);
  ENGINE_finish(round5_engine);
  ENGINE_free(round5_engine);
  ENGINE_cleanup();
  return 0;
}
