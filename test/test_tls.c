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
    char public_key[2048] = {NULL};
    char client_addr[24];
    char msg_len_buf[4];
    // receive(msg_len_buf, client_addr, NULL);
    // ps(msg_len_buf);
    // size_t msg_len = (size_t)atoi(msg_len_buf);
    // pd(msg_len);
    receive(public_key, client_addr, NULL);
    ps(public_key);
    // char *key = malloc(17);
    // char *key = NULL;
    char *key = "helloworld123456";
    char *iv = malloc(17), *out;
    // if (!RAND_bytes(key, 16)) {
    //   printf("Rand_bytes key failed");
    //   exit(0);
    // }
    if (!RAND_bytes(iv, 16)) {
      printf("Rand_bytes iv failed");
      exit(0);
    }
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
    out = malloc(4096);
    size_t out_len, in_len = 16;
    int ret = EVP_PKEY_encrypt(ctx, out, &out_len, key, strlen(key));
    if (ret <= 0){
      pd(ret);
      printf("Encrypt failed");
      exit(0);
    }
    char data_to_send[1024];
    sprintf(data_to_send, "%s-END-%d", out, out_len);
    fflush(stdout);
    ps(out);
    ps(data_to_send);
    send_data(client_addr, data_to_send, 0);
    BIO_free(b);
  }
  else if(!strcmp(role, "client")){
    char server_addr[24];
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
    BIO *b = NULL;
    b = BIO_new(BIO_s_mem());
    unsigned char *key_str = NULL;
    // memset(key_str, 0, 2048*sizeof(char)); 
    // FILE *f = fopen("client_key.pem", "wb");
    // PEM_write_PUBKEY(f, client_key);
    PEM_write_bio_PUBKEY(b, client_key);
    BIO_get_mem_data(b, &key_str);
    ps(key_str);
    printf("\nPlease enter address of server:\n");
    scanf("%s", server_addr);
    // char *data = malloc(sizeof(int));
    // sprintf(data, "%d", strlen(key_str));
    // char *data_to_send = malloc(strlen(key_str) + 9);
    // sprintf(data_to_send, "%s-END-%d", key_str, strlen(key_str));

    // char strlen_buf[50];
    // sprintf(strlen_buf, "%d", strlen(key_str));
    // ps(strlen_buf);
    // pd(strlen(strlen_buf));
    // sprintf(key_str, "%s\0", key_str);
    // send_data(server_addr, strlen_buf, 0);
    // ps(server_addr);

    send_data(server_addr, key_str, 0);
    char encapsulated_key[8192], *key = malloc(17);
    char *buf = malloc(8192);
    char *server_addr2 = malloc(24);
    receive(encapsulated_key, server_addr2, NULL);
    ps(encapsulated_key);
    size_t out_len = 16, in_len;
    strcpy(buf, encapsulated_key);
    char *data = strtok(buf, "-END-");
    int i = 0;
    char *buf_arr[2] = {NULL};
    while(buf != NULL){
      buf_arr[i++] = buf;
      buf = strtok(NULL, "-END-");
    }
    ps(buf_arr[0]);
    in_len = atoi(buf_arr[0]);
    strcpy(encapsulated_key, buf_arr[1]);
    EVP_PKEY_CTX *decrypt_ctx = EVP_PKEY_CTX_new(client_key, NULL);
    EVP_PKEY_decrypt_init(decrypt_ctx);
    EVP_PKEY_decrypt(decrypt_ctx, key, &out_len, encapsulated_key, in_len);
    ps(key);
    BIO_free(b);
    EVP_PKEY_free(tkey);
  }
  err:
  ENGINE_finish(round5_engine);
  ENGINE_free(round5_engine);
  ENGINE_cleanup();
  return 0;
}
