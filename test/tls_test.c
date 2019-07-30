#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/obj_mac.h>
#include <openssl/x509v3.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <err.h>
#include <semaphore.h>
#include <openssl/buffer.h>
#include <sys/sem.h>
#include <sys/ipc.h>
#include "../keypair.h"
#include "cpucycles.h"
#include "speed.h"
#include "cpa_kem.h"

#define NTESTS 1

/* For X509_NAME_add_entry_by_txt */
#pragma GCC diagnostic ignored "-Wpointer-sign"

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

#define cRED	"\033[1;31m"
#define cDRED	"\033[0;31m"
#define cGREEN	"\033[1;32m"
#define cDGREEN	"\033[0;32m"
#define cBLUE	"\033[1;34m"
#define cDBLUE	"\033[0;34m"
#define cNORM	"\033[m"
#define TEST_ASSERT(e) {if ((test = (e))) \
		 printf(cRED "  Test FAILED\n" cNORM); \
	     else \
		 printf(cGREEN "  Test passed\n" cNORM);}

struct certkey {
    EVP_PKEY *pkey;
    X509 *cert;
};

unsigned long BUFFER_SIZE;
unsigned long long timing_overhead, encrypt_timing_overhead, decrypt_timing_overhead;

unsigned long get_buffer_size(unsigned long num){
    num--;
    num |= num >> 1;
    num |= num >> 2;
    num |= num >> 4;
    num |= num >> 8;
    num |= num >> 16;
    num++;
    return num;
}

#define ps(s) printf("\n%s: %s:%d\n     %s: %s\n", __FILE__, __func__, __LINE__, #s, s)
#define pd(s) printf("\n%s: %s:%d\n     %s: %d\n", __FILE__, __func__, __LINE__, #s, s)

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
    // printf("\n%d\n", bptr->length);
    
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

int create_server_socket(int port)
{
    int s;
    struct sockaddr_in addr;
    int opt = 1;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
	perror("Unable to create socket");
	exit(EXIT_FAILURE);
    }
    if(setsockopt(s, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)) == -1){
		perror("setsockopt");
		exit(1);
	}
    printf("[+]Server Socket is created.\n");
    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
	perror("[-]Unable to bind");
	exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
	perror("Unable to listen");
	exit(EXIT_FAILURE);
    }

    return s;
}

/*
 * Simple TLS Server code is based on
 * https://wiki.openssl.org/index.php/Simple_TLS_Server
 */
static int s_server(EVP_PKEY *pkey, X509 *cert, int client, unsigned long long *timer){
    SSL_CTX *ctx;
    T(ctx = SSL_CTX_new(TLS_server_method()));
    T(SSL_CTX_use_certificate(ctx, cert));
    T(SSL_CTX_use_PrivateKey(ctx, pkey));
    T(SSL_CTX_check_private_key(ctx));

    SSL *ssl;
    T(ssl = SSL_new(ctx));
    T(SSL_set_fd(ssl, client));
    T(SSL_accept(ssl) == 1);

    /* Receive data from client */
    char buf[BUFFER_SIZE * 2];
    int i;
	int bytes = SSL_read(ssl, buf, BUFFER_SIZE * 2);
    buf[bytes] = NULL;
    // ps(buf);
    BIO *b = NULL;
    b = BIO_new_mem_buf(buf, bytes);
    EVP_PKEY *client_key = NULL;
    client_key = PEM_read_bio_PUBKEY(b, &client_key, NULL, NULL);

    /* Send data to client. */
    unsigned char key[32];
    int key_size = sizeof(key);
    #if CRYPTO_CIPHERTEXTBYTES == 0
    if (!RAND_bytes(key, sizeof(key))){
        perror("RAND_bytes");
    }
    #endif
    unsigned char *encrypted_key = NULL;
    unsigned long long encrypted_key_len = 0;
    encrypt_timing_overhead = cpucycles_overhead();
    // timer = (unsigned long long *)malloc(sizeof(unsigned long long));
    *timer = cpucycles_start();
    EVP_PKEY_CTX *encrypt_ctx = EVP_PKEY_CTX_new(client_key, NULL);
    if(EVP_PKEY_encrypt_init(encrypt_ctx) != 1){
        perror("EVP_PKEY_encrypt_init");
    }
    EVP_PKEY_encrypt(encrypt_ctx, NULL, (size_t *)&encrypted_key_len, key, key_size);
    encrypted_key = (unsigned char *)malloc(encrypted_key_len);
    if(EVP_PKEY_encrypt(encrypt_ctx, (unsigned char *)encrypted_key, (size_t *)&encrypted_key_len, key, key_size) != 1){
        perror("EVP_PKEY_encrypt");
    }
    *timer = cpucycles_stop() - *timer - encrypt_timing_overhead;
    #ifdef DEBUG
    // print_hex("Encrypted key in server", encrypted_key, (const size_t)encrypted_key_len, 1);
    #endif
    // #endif
    char *encoded_key = base64(encrypted_key, encrypted_key_len);
    SSL_write(ssl, &encrypted_key_len, sizeof(encrypted_key_len));
	int bytes_sent = SSL_write(ssl, encoded_key, strlen(encoded_key));
    char *client_done = malloc(5);
    SSL_read(ssl, client_done, 5);
    char *server_done = "DONE";
    SSL_write(ssl, server_done, strlen(server_done));
    // ps(encoded_key);
    // pd(bytes_sent);
    // ps(encoded_key);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client);
    free(encrypted_key);
    free(encoded_key);
    EVP_PKEY_CTX_free(encrypt_ctx);
    EVP_PKEY_free(client_key);
    SSL_CTX_free(ctx);
    BIO_free(b);
    return 1;
}

static EVP_PKEY *round5_keygen(const char *kem_algname){
    EVP_PKEY *tkey;
    T(tkey = EVP_PKEY_new());
    T(EVP_PKEY_set_type_str(tkey, kem_algname, strlen(kem_algname)));
    EVP_PKEY_CTX *ctx;
    T(ctx = EVP_PKEY_CTX_new(tkey, NULL));
    T(EVP_PKEY_keygen_init(ctx));
    EVP_PKEY *pkey = NULL;
    T((EVP_PKEY_keygen(ctx, &pkey)) == 1);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(tkey);
    return pkey;
}

/*
 * Simple TLC Client code is based on man BIO_f_ssl and
 * https://wiki.openssl.org/index.php/SSL/TLS_Client
 */
static int s_client(int server, EVP_PKEY *client_key, unsigned long long *timer)
{
    SSL_CTX *ctx;
    T(ctx = SSL_CTX_new(TLS_client_method()));

    BIO *sbio;
    T(sbio = BIO_new_ssl_connect(ctx));
    SSL *ssl;
    T(BIO_get_ssl(sbio, &ssl));
    T(SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY));
#if 0
    /* Does not work with reneg. */
    BIO_set_ssl_renegotiate_bytes(sbio, 100 * 1024);
#endif
    T(SSL_set_fd(ssl, server));
    X509_STORE_CTX *store_ctx;
    store_ctx = X509_STORE_CTX_new();
    X509_STORE *store = X509_STORE_new();
    FILE *cacert_file = fopen("certs/cacert.pem", "r");
    X509 *cacert = PEM_read_X509(cacert_file, NULL, NULL, NULL);
    X509_STORE_add_cert(store, cacert);
    X509_STORE_CTX_init(store_ctx, store, cacert, NULL);
    SSL_set0_verify_cert_store(ssl, store);
    T(BIO_do_handshake(sbio) == 1);
    #ifdef DEBUG
    printf("Protocol: %s\n", SSL_get_version(ssl));
    printf("Cipher:   %s\n", SSL_get_cipher_name(ssl));
    #endif
#if 0
    SSL_SESSION *sess = SSL_get0_session(ssl);
    SSL_SESSION_print_fp(stdout, sess);
#endif

    X509 *cert;
    T(cert = SSL_get_peer_certificate(ssl));
    X509_free(cert);
    int verify = SSL_get_verify_result(ssl);
    #ifdef DEBUG
    printf("Verify:   %s\n", X509_verify_cert_error_string(verify));
    #endif
    // if (verify != X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
	//     err(1, "invalid SSL_get_verify_result");

    /* Send data to server. */
    char buf[BUFFER_SIZE * 2];
    int i;
    BIO *b = NULL;
    b = BIO_new(BIO_s_mem());
    char *client_key_str = NULL;
    PEM_write_bio_PUBKEY(b, client_key);
    BIO_get_mem_data(b, &client_key_str);
	int num = BIO_write(sbio, client_key_str, strlen(client_key_str));
    (void)BIO_shutdown_wr(sbio);
    unsigned long long encrypted_key_len;
    BIO_read(sbio, &encrypted_key_len, sizeof(encrypted_key_len));
    int bytes_received = BIO_read(sbio, buf, BUFFER_SIZE * 2);
    buf[bytes_received] = NULL;
    // ps(buf);
    unsigned char *key;
    // ps(buf);
    char *decoded_key = unbase64((unsigned char *)buf, strlen(buf));
    #ifdef DEBUG
    // print_hex("decoded key", (const unsigned char *)decoded_key, encrypted_key_len, 1);
    #endif
    unsigned long long decoded_key_len = encrypted_key_len, key_len;
    decrypt_timing_overhead = cpucycles_overhead();
    // timer = malloc(sizeof(unsigned long long));
    *timer = cpucycles_start();
    EVP_PKEY_CTX *decrypt_ctx = EVP_PKEY_CTX_new(client_key, NULL);
    EVP_PKEY_decrypt_init(decrypt_ctx);
    EVP_PKEY_decrypt(decrypt_ctx, NULL, (size_t *)&key_len, (const unsigned char *)decoded_key, encrypted_key_len);
    key = (unsigned char *)malloc(key_len);
    EVP_PKEY_decrypt(decrypt_ctx, (unsigned char *)key, (size_t *)&key_len, (const unsigned char *)decoded_key, encrypted_key_len);
    *timer = cpucycles_stop() - *timer - decrypt_timing_overhead;
    char *server_done = "DONE";
    BIO_write(sbio, server_done, strlen(server_done));
    char *client_done = malloc(5);
    BIO_read(sbio, client_done, 5);
    #if 0
    print_hex("key", key, key_len, 1);
    #endif
    i = BIO_get_num_renegotiates(sbio);
    BIO_free_all(sbio);
    SSL_CTX_free(ctx);
    EVP_PKEY_CTX_free(decrypt_ctx);
    BIO_free(b);
    free(decoded_key);
    free(key);
    return 1;
}

/* Generate simple cert+key pair. Based on req.c */
static struct certkey certgen(const char *kem_algname, EVP_PKEY *privkey)
{
    /* Keygen. */
    EVP_PKEY *tkey;
    T(tkey = EVP_PKEY_new());
    T(EVP_PKEY_set_type_str(tkey, kem_algname, strlen(kem_algname)));
    EVP_PKEY_CTX *ctx;
    T(ctx = EVP_PKEY_CTX_new(tkey, NULL));
    T(EVP_PKEY_keygen_init(ctx));
    EVP_PKEY *pkey = EVP_PKEY_new();
    T((EVP_PKEY_keygen(ctx, &pkey)) == 1);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(tkey);

    /* REQ. */
    X509_REQ *req = NULL;
    T(req = X509_REQ_new());
    T(X509_REQ_set_version(req, 0L));
    X509_NAME *name;
    T(name = X509_NAME_new());
    T(X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, "Test CA", -1, -1, 0));
    T(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, "Test Key", -1, -1, 0));
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

    EVP_MD_CTX *mctx;
    T(mctx = EVP_MD_CTX_new());
    T(EVP_DigestSignInit(mctx, NULL, NULL, NULL, privkey));
    T(X509_sign_ctx(x509ss, mctx));
    EVP_MD_CTX_free(mctx);
#if 0
    /* Print cert in text format. */
    X509_print_fp(stdout, x509ss);
#endif
#if 0
    /* Print cert in PEM format. */
    BIO *out = BIO_new_fp(stdout, BIO_NOCLOSE | BIO_FP_TEXT);
    PEM_write_bio_X509(out, x509ss);
    BIO_free_all(out);
#endif
    if(!pkey){
        perror("pkey");
    }
    return (struct certkey){ .pkey = pkey, .cert = x509ss };
}

/**
 * Create an 256 bit key and IV using the supplied key_data. salt can be added for taste.
 * Fills in the encryption and decryption ctx objects and returns 0 on success
 **/
int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt, int key_len, EVP_CIPHER_CTX *ctx){
  int i, nrounds = 5;
  unsigned char key[32]; 
  unsigned char *iv = NULL;
 
  /*
   * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
   * nrounds is the number of times the we hash the material. More rounds are more secure but
   * slower.
   */
  i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
 
  EVP_CIPHER_CTX_init(ctx);
  EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
 
  return 1;
}
 
/*
 * Encrypt *len bytes of data
 * All data going in & out is considered binary (unsigned char[])
 */
unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len)
{
  /* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
  int c_len = *len + 256, f_len = 0;
  unsigned char *ciphertext = malloc(c_len);
 
  /* allows reusing of 'e' for multiple encryption cycles */
  EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);
 
  /* update ciphertext, c_len is filled with the length of ciphertext generated,
    *len is the size of plaintext in bytes */
  EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);
 
  /* update ciphertext with the final remaining bytes */
  EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len);
 
  *len = c_len + f_len;
  return ciphertext;
}
 
/*
 * Decrypt *len bytes of ciphertext
 */
unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len)
{
  /* plaintext will always be equal to or lesser than length of ciphertext*/
  int p_len = *len, f_len = 0;
  unsigned char *plaintext = malloc(p_len);
 
  EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
  EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
  EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len);
 
  *len = p_len + f_len;
  return plaintext;
}

int main(int argc, char **argv){
    printf(cBLUE "Round5 Parameter: %s", CRYPTO_ALGNAME);
    printf(cNORM "\n");
    int ret = 0;
    int one = 1;
    int port = 5054;
    OPENSSL_add_all_algorithms_conf();
    ERR_load_crypto_strings();
    ENGINE *eng;
    T(eng = ENGINE_by_id("round5"));
    T(ENGINE_init(eng));
    T(ENGINE_set_default(eng, ENGINE_METHOD_ALL));
    EVP_PKEY *dummy_key = round5_keygen("round5");
    BUFFER_SIZE = get_buffer_size(EVP_PKEY_size(dummy_key));
    EVP_PKEY_free(dummy_key);
    #ifdef DEBUG
    // pd(BUFFER_SIZE);
    #endif
    unsigned long long ttls[NTESTS];
    unsigned long long tkeygen[NTESTS];
    unsigned long long tencrypt[NTESTS];
    unsigned long long tdecrypt[NTESTS];
    int i;
    #ifdef LOCALHOST
    struct certkey ck;
    // const char *sig_algname = "rsa";
    const char *kem_algname = "rsa";
    FILE *privkey_file = fopen("certs/privkey.pem", "r");
    EVP_PKEY *privkey = PEM_read_PrivateKey(privkey_file, NULL, NULL, NULL);
    ck = certgen(kem_algname, privkey);
    EVP_PKEY_free(privkey);
    timing_overhead = cpucycles_overhead();
    for(i = 0; i < NTESTS; ++i){
        pd(i);
        ttls[i] = cpucycles_start();
        int sockfd[2];
        if (socketpair(AF_LOCAL, SOCK_STREAM, 0, sockfd) == -1)
            err(1, "socketpair");
        
        pid_t pid = fork();
        if(pid < 0)
            err(1, "fork");
        if(pid > 0){
            int status;
            const char *kem_algname = "round5";
            tkeygen[i] = cpucycles_start();
            EVP_PKEY *client_key = round5_keygen(kem_algname);
            tkeygen[i] = cpucycles_stop() - tkeygen[i] - timing_overhead;
            ret = s_client(sockfd[0], client_key, &tdecrypt[i]);
            wait(&status);
            ret |= WIFEXITED(status) && WEXITSTATUS(status);
            X509_free(ck.cert);
            EVP_PKEY_free(ck.pkey);
        } else if(pid == 0){
            ret = s_server(ck.pkey, ck.cert, sockfd[1], &tencrypt[i]);
            X509_free(ck.cert);
            EVP_PKEY_free(ck.pkey);
            exit(ret);
        }
        ttls[i] = cpucycles_stop() - ttls[i] - timing_overhead;
    }
    print_results("Round5 keygen:", tkeygen, NTESTS);
    print_results("TLS performance:", ttls, NTESTS);
    #else
    if(argc < 2){
        printf("Please enter server or client!");
        return 0;
    }
    timing_overhead = cpucycles_overhead();
    if(!strcmp(argv[1], "client")){
        EVP_PKEY *client_key = NULL;
        int client_socket = socket(AF_INET, SOCK_STREAM, 0);
        #ifdef DEBUG
        char server_addr[] = "172.31.17.212";
        //char *server_addr = "172.27.232.36";
        #else
        char server_addr[16];
        printf("Please enter address of server:\n");
        scanf("%s", server_addr);
        #endif
        struct sockaddr_in addr;
        bzero(&addr, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if(inet_pton(AF_INET, server_addr, &addr.sin_addr) <= 0){
            perror("Invalid address/ Address not supported");
            abort();
        }
        if(connect(client_socket, (struct sockaddr *)&addr, sizeof(addr))){
            perror("Connection failed");
            abort();
        }
        const char *kem_algname = "round5";
        tkeygen[i] = cpucycles_start();
        client_key = round5_keygen(kem_algname);
        tkeygen[i] = cpucycles_stop() - tkeygen[i] - timing_overhead;
        
        int status = 0;
        ttls[i] = cpucycles_start();
        unsigned long long timer;
        ret = s_client(client_socket, client_key, &timer);
        // pd(timer);
        tdecrypt[i] = timer;
        ttls[i] = cpucycles_stop() - ttls[i] - timing_overhead;
        wait(&status);
        ret |= WIFEXITED(status) && WEXITSTATUS(status);
        EVP_PKEY_free(client_key);

        print_results("Round5 keygen:", tkeygen, NTESTS);
        print_results("TLS performance:", ttls, NTESTS);
        print_results("Round5 decrypt:", tdecrypt, NTESTS);
    }
    else if(!strcmp(argv[1], "server")){
        struct sockaddr_in addr;
        uint8_t len = sizeof(addr);
        int server_socket = create_server_socket(port);
        int count = 0;
        // i = 0;
        struct certkey ck;
        // const char *sig_algname = "rsa";
        const char *kem_algname = "rsa";
        FILE *privkey_file = fopen("certs/privkey.pem", "r");
        ck.pkey = PEM_read_PrivateKey(privkey_file, NULL, NULL, NULL);
        // ck = certgen(kem_algname, pkey);
        FILE *cacert_file = fopen("certs/cacert.pem", "r");
        ck.cert = PEM_read_X509(cacert_file, NULL, NULL, NULL);
        fclose(privkey_file);
        fclose(cacert_file);
        int client_socket;
        int status;
        client_socket = accept(server_socket, (struct sockaddr *)&addr, &len);
        ttls[count] = cpucycles_start();
        unsigned long long timer;
        ret = s_server(ck.pkey, ck.cert, client_socket, &timer);
        tencrypt[count] = timer;
        ttls[count] = cpucycles_stop() - ttls[count] - timing_overhead;
        X509_free(ck.cert);
        EVP_PKEY_free(ck.pkey);
        print_results("TLS performance:", ttls, NTESTS);
        print_results("Round5 encrypt:", tencrypt, NTESTS);
    }
    #endif
    free:
    ENGINE_finish(eng);
    ENGINE_free(eng);
    ENGINE_cleanup();
    return 1;
}
