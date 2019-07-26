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
#include "cpa_kem.h"
#include "cca_encrypt.h"
#include "rng.h"
#include "r5_memory.h"
#include <fcntl.h>
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

char *base64(const unsigned char *input, int length)
{
    BIO *bmem, *b64;
    BUF_MEM *bptr;
    
    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
        
    char *buff = (char *)malloc(bptr->length + 1);
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = 0;
    printf("\n%d\n", bptr->length);
    
    BIO_free_all(b64);
    
    return buff;
}

char *unbase64(unsigned char *input, int length){
	BIO *b64, *bmem;
	char *buffer = (char *)malloc(length);
	memset(buffer, 0, length);
	
	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new_mem_buf(input, length);
	bmem = BIO_push(b64, bmem);
	
	BIO_read(bmem, buffer, length);
	
	BIO_free_all(bmem);
	
	return buffer;
}

char* ReadFile(char *filename)
{
   char *buffer = NULL;
   int string_size, read_size;
   FILE *handler = fopen(filename, "r");

   if (handler)
   {
       // Seek the last byte of the file
       fseek(handler, 0, SEEK_END);
       // Offset from the first to the last byte, or in other words, filesize
       string_size = ftell(handler);
       // go back to the start of the file
       rewind(handler);

       // Allocate a string that can hold it all
       buffer = (char*) malloc(sizeof(char) * (string_size + 1) );

       // Read it all in one operation
       read_size = fread(buffer, sizeof(char), string_size, handler);

       // fread doesn't set it so put a \0 in the last position
       // and buffer is now officially a string
       buffer[string_size] = '\0';

       if (string_size != read_size)
       {
           // Something went wrong, throw away the memory and set
           // the buffer to NULL
           free(buffer);
           buffer = NULL;
       }

       // Always remember to close the file.
       fclose(handler);
    }

    return buffer;
}

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

X509 * sign_csr(EVP_PKEY *client_key, EVP_PKEY *server_key){
  // set request info
  X509_REQ *req = NULL;
  req = X509_REQ_new();
  X509_REQ_set_version(req, 0L);
  X509_NAME *name_;
  name_ = X509_NAME_new();
  X509_NAME_add_entry_by_txt(name_, "C",  MBSTRING_ASC, "US", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name_, "ST",  MBSTRING_ASC, "CA", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name_, "L",  MBSTRING_ASC, "Los Angeles", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name_, "O",  MBSTRING_ASC, "Apple", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name_, "CN", MBSTRING_ASC, "Client", -1, -1, 0);
  X509_REQ_set_subject_name(req, name_);
  // Set issuer info
  X509_NAME *name = X509_NAME_new();
  X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, "US", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "ST",  MBSTRING_ASC, "MA", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "L",  MBSTRING_ASC, "Cambridge", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, "Draper", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, "Server", -1, -1, 0);
  X509 *signed_cert = NULL;
  signed_cert = X509_new();
  X509_set_version(signed_cert, 2);
  BIGNUM *brnd = BN_new();
  BN_rand(brnd, 20 * 8 - 1, -1, 0);
  BN_to_ASN1_INTEGER(brnd, X509_get_serialNumber(signed_cert));
  X509_set_issuer_name(signed_cert, name);
  X509_gmtime_adj(X509_getm_notBefore(signed_cert), 0);
  X509_time_adj_ex(X509_getm_notAfter(signed_cert), 1, 0, NULL);
  X509_set_subject_name(signed_cert, X509_REQ_get_subject_name(req));
  if(!client_key){
    ps("client_key broken");
  }
  if(!signed_cert){
    ps("signed_cert broken");
  }
  X509_set_pubkey(signed_cert, client_key);
  X509_REQ_free(req);
  BN_free(brnd);

  X509V3_CTX v3ctx;
  X509V3_set_ctx_nodb(&v3ctx);
  X509V3_set_ctx(&v3ctx, signed_cert, signed_cert, NULL, NULL, 0);
  X509_EXTENSION *ext;
  ext = X509V3_EXT_conf_nid(NULL, &v3ctx, NID_basic_constraints, "critical,CA:TRUE");
  X509_add_ext(signed_cert, ext, 0);
  X509_EXTENSION_free(ext);
  ext = X509V3_EXT_conf_nid(NULL, &v3ctx, NID_subject_key_identifier, "hash");
  X509_add_ext(signed_cert, ext, 1);
  X509_EXTENSION_free(ext);
  ext = X509V3_EXT_conf_nid(NULL, &v3ctx, NID_authority_key_identifier, "keyid:always,issuer");
  X509_add_ext(signed_cert, ext, 2);
  X509_EXTENSION_free(ext);
  if (!X509_sign(signed_cert, server_key, EVP_sha512())){
    printf("\n****Error in sign****\n");
    return NULL;
  }
  return signed_cert;
}

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
    int size = 0;
    char public_key[8192];
    char client_addr[16];
    receive(public_key, client_addr, &size);
    ps(public_key);
    // char *key = malloc(17);
    unsigned char *key = "helloworld12345";
    unsigned char *out;

    /* server receives client Round5 public key */
    // BIO * b = BIO_new(BIO_s_mem());
    BIO *b = NULL;
    b = BIO_new_mem_buf(public_key, (int)sizeof(public_key));
    // pd(CRYPTO_PUBLICKEYBYTES);
    // pd(strlen(public_key));
    // BIO_write(b, (char *)public_key, strlen(public_key));
    EVP_PKEY *client_key = NULL;
    client_key = PEM_read_bio_PUBKEY(b, &client_key, NULL, NULL);
    if(!client_key){
      ps("client key is null");
      // exit(0);
    }
    // struct ROUND5 *kpair = EVP_PKEY_get0(client_key);
    // fflush(stdout);
    // ps(kpair->pk);
    // ps("after");
    // print_hex("PK", kpair->pk, CRYPTO_PUBLICKEYBYTES, 1);

    /* server generates rsa public key and sends to client */
    // unsigned char *server_key_str = malloc(2048);
    // EVP_PKEY *server_key1 = genkey_rsa();
    // FILE *f2 = fopen("certs/server/pubkey.pem", "wb");
    // FILE *f1 = fopen("certs/server/privkey.pem", "wb");
    // PEM_write_PUBKEY(f2, server_key1);
    // PEM_write_PrivateKey(f1, server_key1, EVP_des_ede3_cbc(), (unsigned char *)"hello", 5, NULL, NULL);
    // fclose(f2);
    // fclose(f1);
    FILE *f = fopen("certs/server/pubkey.pem", "rt");
    EVP_PKEY *server_pub_key = EVP_PKEY_new();
    PEM_read_PUBKEY(f, &server_pub_key, NULL, NULL);
    fclose(f);
    // send_file("certs/server/pubkey.pem", client_addr);
    char *server_key_str = ReadFile("certs/server/pubkey.pem");
    // ps(server_key_str);
    // ps(server_key_str);
    send_data(client_addr, server_key_str, strlen(server_key_str));
    // unsigned char ACK[4];
    // receive(ACK, client_addr, NULL);

    /* server generates certificate for client and signs it with rsa key then sends it*/
    FILE *f1 = fopen("certs/server/privkey.pem", "r");
    EVP_PKEY *server_priv_key = PEM_read_PrivateKey(f1, &server_priv_key, NULL, "hello");
    fclose(f1);
    if(!server_priv_key)
      ps("failed to open priv key");
    X509 *client_cert = sign_csr(client_key, server_priv_key);
    BIO *b2 = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(b2, client_cert);
    unsigned char *client_cert_str = NULL;
    BIO_get_mem_data(b2, &client_cert_str);
    // ps(client_cert_str);
    send_data(client_addr, client_cert_str, strlen(client_cert_str));

    unsigned long long in_len = strlen(key);
    unsigned long long out_len = 0;
    unsigned long long outlen = get_params(in_len);
    // pd(out_len);
    out = malloc(outlen);

    /* server encrypts session key and sends it to client */
    // EVP_PKEY_CTX *encrypt_ctx = EVP_PKEY_CTX_new(client_key, NULL);
    // EVP_PKEY_encrypt_init(encrypt_ctx);
    // // EVP_PKEY_encrypt(encrypt_ctx, NULL, &out_len, key, in_len);
    // pd(out_len);
    // EVP_PKEY_encrypt(encrypt_ctx, out, &out_len, key, in_len);
    struct ROUND5 *kpair = malloc(sizeof(struct ROUND5));
    kpair = EVP_PKEY_get0(client_key);
    // print_hex("PK", kpair->pk, CRYPTO_PUBLICKEYBYTES, 1);
    crypto_encrypt(out, &out_len, key, in_len, kpair->pk);
    
    pd(out_len);
    print_hex("key in server", key, in_len, 1);
    print_hex("Encrypted Key in server encrypt", out, out_len, 1);
    char *encoded_key = base64(out, out_len);
    ps(encoded_key);
    send_data(client_addr, encoded_key, strlen(encoded_key));
    BIO_free(b);
    // BIO_free(b1);
    BIO_free(b2);
  }
  else if(!strcmp(role, "client")){
    /* client generates public key and sends to server*/
    char server_addr[16];
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
    // print_pkey(client_key);
    int size = 0;
    BIO *b = NULL;
    b = BIO_new(BIO_s_mem());
    char *key_str = NULL;
    PEM_write_bio_PUBKEY(b, client_key);
    BIO_get_mem_data(b, &key_str);
    // ps(key_str);
    printf("\nPlease enter address of server:\n");
    scanf("%s", server_addr);
    send_data(server_addr, key_str, strlen(key_str));
    // ps(key_str);
    /* client receives server public key */
    unsigned char client_cert_str[4096];
    unsigned char server_key_str[4096];
    char *server_key_file = "certs/client/server_key.pem";
    // receive_file("certs/client/server_key.pem");
    receive(server_key_str, server_addr, &size);
    ps(server_key_str);
    BIO *b1 = BIO_new(BIO_s_mem());
    BIO_write(b1, server_key_str, strlen(server_key_str));
    EVP_PKEY *server_key = NULL;
    PEM_read_bio_PUBKEY(b1, &server_key, NULL, NULL);
    // send_data(server_addr, "ACK", 0);

    /* client receives cert from server */
    receive(client_cert_str, server_addr, &size);
    ps(client_cert_str);
    BIO *b2 = BIO_new(BIO_s_mem());
    BIO_write(b2, client_cert_str, strlen(client_cert_str));
    X509 *client_cert = NULL;
    client_cert = PEM_read_bio_X509(b2, &client_cert, NULL, NULL);
    if(!client_cert){
      ps("client cert is null");
    }
    // FILE *key_file = open(server_key_file, O_RDONLY);
    // server_key = PEM_read_PUBKEY(key_file, NULL, NULL, NULL);
    int ret = validate_peer_cert(client_cert, server_key);
    if(ret == 1){
      printf("\nCertificate verification success\n");
    }
    else{
      printf("\nCertificate verification failed\n");
      // goto client_free;
    }
    FILE *cert_file = fopen("certs/client_cert.pem", "wb");
    PEM_write_X509(cert_file, client_cert);
    fclose(cert_file);

    /* client receives encapsulated key and decrypts*/
    char encapsulated_key[8192];
    char *server_addr2 = malloc(24);
    
    receive(encapsulated_key, server_addr2, &size);
    pd(size);
    char *decoded_key = unbase64(encapsulated_key, size);
    
    print_hex("Encrypted_key in client decrypt", decoded_key, 1541, 1);
    size_t out_len;
    size_t in_len;
    in_len = get_params(16);
    char key[16];
    struct ROUND5 *kpair = EVP_PKEY_get0(client_key);
    print_hex("SK", kpair->sk, 1042, 1);
    crypto_encrypt_open(key, &out_len, decoded_key, in_len, kpair->sk);
    ps(key);
    // EVP_PKEY_CTX *decrypt_ctx = EVP_PKEY_CTX_new(client_key, NULL);
    // EVP_PKEY_decrypt_init(decrypt_ctx);
    // EVP_PKEY_decrypt(decrypt_ctx, key, &out_len, encapsulated_key, in_len);
    print_hex("Decrypted Key", key, out_len, 1);

    client_free:
    BIO_free(b);
    EVP_PKEY_free(tkey);
    // free(key);
    free(server_addr2);
  }
  err:
  ENGINE_finish(round5_engine);
  ENGINE_free(round5_engine);
  ENGINE_cleanup();
  return 0;
}
