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
#include <openssl/bio.h>
#include <openssl/x509v3.h>
#include <openssl/sha.h>
#include "../keypair.h"
#include "network/linux/client.h"
#include "network/linux/server.h"
#include <time.h>
#include <sys/time.h>
#include "../cert_util.h"
//#include <sys/socket.h>

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

int main(int argc, const char* argv[]){
  printf(cBLUE "Testing client-server cert distribution\n" cNORM);
  if(argc < 2){
    printf("Please enter server or client!");
    return 0;
  }
  char *role = argv[1];
  OPENSSL_add_all_algorithms_conf();
  ERR_load_crypto_strings();
  ENGINE_load_dynamic();
  ENGINE *round5_engine;
  T(round5_engine = ENGINE_by_id("round5"));
  T(ENGINE_init(round5_engine));
  T(ENGINE_set_default(round5_engine, ENGINE_METHOD_ALL));
  if(!strcmp(role, "server")){
    char public_key[8192];
    char client_addr[256];
    receive(public_key, client_addr, NULL);
    printf("\nPublic key:\n%s\n", public_key);
    EVP_PKEY *server_key = EVP_PKEY_new();
    char_to_EVP_PKEY(public_key, server_key);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(server_key,NULL);
    BIO *b = NULL;
    b = BIO_new(BIO_s_mem());
    ASN1_PCTX *pctx = NULL;
    pctx = ASN1_PCTX_new();
    char * key_str = NULL;
    if(!server_key){
      printf("\n!data\n");
    }
    EVP_PKEY_print_public(b, server_key, 4, pctx);
    BIO_get_mem_data(b, &key_str);
    printf("\nkey str print: \n%s\n", key_str);
  }
  else if(!strcmp(role, "client")){
    char server_addr[256];
    char *public_key;
    EVP_PKEY *client_key = NULL;
    char *algname = "Round5";
    EVP_PKEY *tkey = NULL;
    tkey = EVP_PKEY_new();
    EVP_PKEY_set_type_str(tkey, algname, strlen(algname));
    EVP_PKEY_CTX *ctx = NULL;
    ctx = EVP_PKEY_CTX_new(tkey, NULL);
    EVP_PKEY_keygen_init(ctx);
    client_key = EVP_PKEY_new();
    EVP_PKEY_keygen(ctx, &client_key);
    EVP_PKEY_free(tkey);
    FILE *f = fopen("certs/client_pub.pem", "wb");
    PEM_write_PUBKEY(f, client_key);
    printf("\nPlease enter address of server:\n");
    scanf("%s", server_addr);
    struct ROUND5 *kpair = EVP_PKEY_get0(client_key);
    char *key_buf = EVP_PKEY_to_char(client_key);
    // printf("\nPublic key: \n%s\n", key_buf);
    send_data(server_addr, key_buf, 1);
    // receive(public_key, server_addr, NULL);
    // send_data(server_addr, key_buf);
  }
  err:
  ENGINE_finish(round5_engine);
  ENGINE_free(round5_engine);
  ENGINE_cleanup();
  return 0;
}
