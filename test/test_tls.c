#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <stdio.h>
// #include <string.h>
#include <unistd.h>
#include <err.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/x509v3.h>
#ifdef __cplusplus
extern "C"{
#endif
#include "cpa_kem.h"
#include "cca_encrypt.h"
#include "rng.h"
#include "r5_memory.h"
// #include "meths/round5_meth.h"
// #include "meths/asn1_meth.h"
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

int validate_peer_cert(X509 *cert, EVP_PKEY *pkey){
  unsigned char *result;
  int r = X509_verify(cert, pkey);
  return r;
}

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
    char public_key[2048];
    char client_addr[24];
    receive(public_key, client_addr, NULL);
    // char *key = malloc(17);
    char *key = "helloworld123456";
    char *out;
    
    /* server receives client Round5 public key */
    BIO * b = BIO_new(BIO_s_mem());
    BIO_write(b, public_key, strlen(public_key));
    EVP_PKEY *client_key = NULL;
    PEM_read_bio_PUBKEY(b, &client_key, NULL, NULL);

    /* server generates rsa public key and sends to client */
    unsigned char *server_key_str = NULL;
    EVP_PKEY *server_key = genkey_rsa();
    BIO *b1 = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(b1, server_key);
    BIO_get_mem_data(b1, &server_key_str);
    send_data(client_addr, server_key_str, 0);
    unsigned char ACK[4];
    receive(ACK, client_addr, NULL);

    /* server generates certificate for client and signs it with rsa key then sends it*/
    X509 *client_cert = sign_csr(client_key, server_key);
    BIO *b2 = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(b2, client_cert);
    unsigned char *client_cert_str = NULL;
    BIO_get_mem_data(b2, &client_cert_str);
    send_data(client_addr, client_cert_str, 0);

    size_t in_len = strlen(key) + 1;
    size_t out_len = get_params(in_len);
    out = malloc(out_len);

    /* server encrypts session key and sends it to client */
    struct ROUND5 *kpair = EVP_PKEY_get0(client_key);
    crypto_encrypt(out, &out_len, key, in_len, kpair->pk);
    print_hex("Encrypted Key", out, out_len, 1);
    send_data(client_addr, out, 0);
    BIO_free(b);
    BIO_free(b1);
    BIO_free(b2);
  }
  else if(!strcmp(role, "client")){
    /* client generates public key and sends to server*/
    char server_addr[24];
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
    PEM_write_bio_PUBKEY(b, client_key);
    BIO_get_mem_data(b, &key_str);
    printf("\nPlease enter address of server:\n");
    scanf("%s", server_addr);
    send_data(server_addr, key_str, 0);

    /* client receives server public key */
    unsigned char client_cert_str[8192];
    unsigned char server_key_str[8192];
    receive(server_key_str, server_addr, NULL);
    BIO *b1 = BIO_new(BIO_s_mem());
    BIO_write(b1, server_key_str, strlen(server_key_str));
    X509 *server_key = NULL;
    PEM_read_bio_PUBKEY(b1, &server_key, NULL, NULL);

    send_data(server_addr, "ACK", 0);

    /* client receives cert from server */
    receive(client_cert_str, server_addr, NULL);
    BIO *b2 = BIO_new(BIO_s_mem());
    BIO_write(b2, client_cert_str, strlen(client_cert_str));
    X509 *client_cert = NULL;
    PEM_read_bio_X509(b2, &client_cert, NULL, NULL);
    int ret = validate_peer_cert(client_cert, server_key);
    if(ret == 1){
      printf("\nCertificate verification success\n");
    }
    else{
      printf("\nCertificate verification failed\n");
      goto client_free;
    }
    FILE *cert_file = fopen("certs/client_cert.pem", "wb");
    PEM_write_X509(cert_file, client_cert);
    fclose(cert_file);

    /* client receives encapsulated key and decrypts*/
    char encapsulated_key[8192];
    char *server_addr2 = malloc(24);
    receive(encapsulated_key, server_addr2, NULL);
    size_t out_len;
    size_t in_len;
    in_len = get_params(16);
    char *key = malloc(16);
    struct ROUND5 *kpair = EVP_PKEY_get0(client_key);
    crypto_encrypt_open(key, &out_len, encapsulated_key, in_len, kpair->sk);
    print_hex("Decrypted Key", key, out_len, 1);

    client_free:
    BIO_free(b);
    EVP_PKEY_free(tkey);
    free(key);
    free(server_addr2);
  }
  err:
  ENGINE_finish(round5_engine);
  ENGINE_free(round5_engine);
  ENGINE_cleanup();
  return 0;
}

#ifdef __cplusplus
}
#endif
