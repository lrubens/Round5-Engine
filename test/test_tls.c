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
#include "meths/round5_meth.h"
#include "meths/asn1_meth.h"
#include <openssl/sha.h>
#include "../keypair.h"
#include "network/linux/client.h"
#include "network/linux/server.h"
#include <time.h>
#include <sys/time.h>
#include "../cert_util.h"
#include <openssl/rand.h>
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
    char key[17];
    char iv[16], *out;
    // pd(sizeof(key));
    size_t *outlen = NULL;
    if (!RAND_bytes(key, sizeof(key))) {
      printf("Rand_bytes key failed");
      exit(0);
    }
    if (!RAND_bytes(iv, sizeof(iv))) {
      printf("Rand_bytes iv failed");
      exit(0);
    }
    fflush(stdout);
    printf("\n%s\n", key);
    // ps(key[14]);
    // ps(key[15]);
    // pd(sizeof key);
    BIO * b = BIO_new(BIO_s_mem());
    BIO_write(b, public_key, strlen(public_key));
    EVP_PKEY *client_key = NULL;
    PEM_read_bio_PUBKEY(b, &client_key, NULL, NULL);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(client_key,NULL);
    if (EVP_PKEY_encrypt_init(ctx) <= 0){
      printf("\nEncrypt init: %d\n", EVP_PKEY_encrypt_init(ctx));
      printf("CTX init failed");
      exit(0);
    }
    /* Determine buffer length */
    // char dum[5000];
    // if (EVP_PKEY_encrypt(ctx, dum, outlen, key, 16) <= 0){
    //   printf("Encrypt initial failed");
    //   exit(0);
    // }
    out = OPENSSL_malloc(1525);
    if(!out){
      printf("Out is null");
      exit(0);
    }
    size_t out_len;
    int ret = EVP_PKEY_encrypt(ctx, out, &outlen, key, 16);
    pd(outlen);
    if (ret <= 0){
      pd(ret);
      printf("Encrypt failed");
      exit(0);
    }
    ps(out);
    EVP_PKEY_CTX *decrypt_ctx = NULL;
    EVP_PKEY_decrypt_init(decrypt_ctx);
    char *decrypted = malloc(16);
    EVP_PKEY_decrypt(decrypt_ctx, decrypted, 16, out, &outlen);
    ps(decrypted);
    BIO_free(b);
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
    // FILE *f = fopen("certs/client_pub.pem", "wb");
    BIO *b = NULL;
    b = BIO_new(BIO_s_mem());
    unsigned char *key_str = NULL;
    PEM_write_bio_PUBKEY(b, client_key);
    BIO_get_mem_data(b, &key_str);
    // ps(key_str);
    // PEM_write_PUBKEY(f, client_key);
    printf("\nPlease enter address of server:\n");
    scanf("%s", server_addr);
    // struct ROUND5 *kpair = EVP_PKEY_get0(client_key);
    // char *key_buf = EVP_PKEY_to_char(client_key);
    // printf("\nPublic key: \n%s\n", key_buf);
    send_data(server_addr, key_str, 0);
    BIO_free(b);
    // receive(public_key, server_addr, NULL);
    // send_data(server_addr, key_buf);
  }
  err:
  ENGINE_finish(round5_engine);
  ENGINE_free(round5_engine);
  ENGINE_cleanup();
  return 0;
}
