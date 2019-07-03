#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
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
#include <time.h>
#include <sys/time.h>
#include "../cert_util.h"

#define cDBLUE	"\033[0;34m"
#define cNORM	"\033[m"
#define cBLUE	"\033[1;34m"
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
  c->cert = x509ss;
  c->key = pkey;
  EVP_MD_CTX *mctx = NULL;
  T(mctx = EVP_MD_CTX_new());
  EVP_MD_CTX_free(mctx);
  cleanup:
  EVP_PKEY_CTX_free(ctx);
  return c;
}

void get_field(char * field){

}

int main(int argc, const char* argv[]){
	unsigned char *nodes[2] = {"192.168.1.10", "192.168.1.11"};
	printf(cBLUE "Testing Certificate Generation\n" cNORM);
	OPENSSL_add_all_algorithms_conf();
	ERR_load_crypto_strings();
	ENGINE_load_dynamic();
  ENGINE *round5_engine;
	T(round5_engine = ENGINE_by_id("round5"));
	T(ENGINE_init(round5_engine));
  T(ENGINE_set_default(round5_engine, ENGINE_METHOD_ALL));
  double time_elapsed;
	int user_input;
	printf("\nEnter 1 for server and 2 for client: ");
	scanf("%d", &user_input);
	while (user_input != 1 && user_input != 2){
		printf("\nPlease enter correct value!\n");
		printf("\nEnter 1 for server and 2 for client: ");
		scanf("%d", &user_input);
	}
  char * sign_key_location = "dilithium.pem";
  EVP_PKEY *pkey;
	if (user_input == 1){
		// if(access(sign_key_location, F_OK) != -1){
    pkey = genkey_dilithium();
    BIO *b = NULL;
    b = BIO_new(BIO_s_mem());
    ASN1_PCTX *pctx = NULL;
    pctx = ASN1_PCTX_new();
    unsigned char *public_key_text = NULL;
    if(!pkey){
      printf("\n!pkey\n");
    }
    EVP_PKEY_print_public(b, pkey, 4, pctx);
    BIO_get_mem_data(b, &public_key_text);
    for (int i = 0; i < sizeof(nodes); i++){
      send_data(nodes[i], public_key_text);
	  }
  }
	else{
    EVP_PKEY *pub_key = NULL;
    char *server_public_key = NULL;
    ps("Receiving public key");
    receive(server_public_key);
    char_to_EVP_PKEY(pub_key, server_public_key);
    FILE *f = fopen("server.pem", "wb");
    PEM_write_PublicKey(
		  f,                  /* write the key to the file we've opened */
	  	pub_key,               /* our key from earlier */
		  EVP_des_ede3_cbc(), /* default cipher for encrypting the key on disk */
		  (unsigned char *)"hello",       /* passphrase required for decrypting the key on disk */
		  5,                 /* length of the passphrase string */
		  NULL,               /* callback for requesting a password */
		  NULL                /* data to pass to the callback */
	  );
	  fclose(f);
	}
	
	// X509_print_fp(stdout, c->cert);
	// int with_dilithium = validate_peer_cert(c->cert, pkey);
	// pd(with_dilithium);
	// unsigned char *params[10] = {"R5ND_1PKE_5d", "R5ND_3PKE_5d", "R5ND_5PKE_5d", "R5ND_1PKE_0d", "R5ND_3PKE_0d", "R5ND_5PKE_0d", "R5ND_1KEM_5d", "R5ND_3KEM_5d", "R5ND_5KEM_5d", "R5N1_3PKE_0smallCT"};
	// ps(params[0]);
	// printf("\n********************************************************\n");
	// // printf("\nComputation time: %lu\n", diff);
	// printf("\n********************************************************\n");
	// FILE *f3 = fopen("data.txt", "a");
	// fprintf(f3, "%f\n", time_elapsed);
	// fclose(f3);
	// fclose(f2);
	// EVP_MD_CTX_free(mctx);
  // BIO_free(b);
  // ASN1_PCTX_free(pctx);
	// X509_free(c->cert);
	// EVP_PKEY_free(c->key);
	free(c);
	ENGINE_finish(round5_engine);
	ENGINE_free(round5_engine);
	ENGINE_cleanup();
	return 0;
}
