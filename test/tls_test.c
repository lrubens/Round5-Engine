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
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <err.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include "../keypair.h"

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

/* How much K to transfer between client and server. */
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
static int s_server(EVP_PKEY *pkey, X509 *cert, int client)
{
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
    char buf[BUFFER_SIZE];
    int i;
	int bytes = SSL_read(ssl, buf, sizeof(buf));
    BIO *b = NULL;
    b = BIO_new_mem_buf(buf, bytes);
    EVP_PKEY *client_key = NULL;
    client_key = PEM_read_bio_PUBKEY(b, &client_key, NULL, NULL);

    /* Send data to client. */
    char key[16];
    int key_size = sizeof(key);
    if (!RAND_bytes(key, key_size)){
        perror("RAND_bytes");
    }
    #ifdef DEBUG
    print_hex("Key", key, key_size, 1);
    #endif
    char *encrypted_key;
    unsigned long long encrypted_key_len = 0;
    EVP_PKEY_CTX *encrypt_ctx = EVP_PKEY_CTX_new(client_key, NULL);
    EVP_PKEY_encrypt_init(encrypt_ctx);
    EVP_PKEY_encrypt(encrypt_ctx, NULL, &encrypted_key_len, key, key_size);
    encrypted_key = malloc(encrypted_key_len);
    EVP_PKEY_encrypt(encrypt_ctx, encrypted_key, &encrypted_key_len, key, key_size);
    #ifdef DEBUG
    pd(encrypted_key_len);
    ps(encrypted_key);
    print_hex("Encrypted key in server", encrypted_key, (const size_t)encrypted_key_len, 1);
    #endif
    // #endif
    char *encoded_key = base64(encrypted_key, encrypted_key_len);
	int bytes_sent = SSL_write(ssl, encoded_key, strlen(encoded_key));
    #ifdef DEBUG
    pd(bytes_sent);
    #endif
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client);

    SSL_CTX_free(ctx);
    return 1;
}

static EVP_PKEY *round5_keygen(const char *algname){
    EVP_PKEY *tkey;
    T(tkey = EVP_PKEY_new());
    T(EVP_PKEY_set_type_str(tkey, algname, strlen(algname)));
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
static int s_client(int server, EVP_PKEY *client_key)
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
    T(BIO_do_handshake(sbio) == 1);

    printf("Protocol: %s\n", SSL_get_version(ssl));
    printf("Cipher:   %s\n", SSL_get_cipher_name(ssl));
#if 0
    SSL_SESSION *sess = SSL_get0_session(ssl);
    SSL_SESSION_print_fp(stdout, sess);
#endif

    X509 *cert;
    T(cert = SSL_get_peer_certificate(ssl));
    X509_free(cert);
    int verify = SSL_get_verify_result(ssl);
    printf("Verify:   %s\n", X509_verify_cert_error_string(verify));
    if (verify != X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
	    err(1, "invalid SSL_get_verify_result");

    /* Send data to server. */
    char buf[BUFFER_SIZE];
    int i;
    const char *algname = "round5";
    BIO *b = NULL;
    b = BIO_new(BIO_s_mem());
    char *client_key_str = malloc(BUFFER_SIZE);
    memset(client_key_str, 0, BUFFER_SIZE * sizeof(char));
    PEM_write_bio_PUBKEY(b, client_key);
    BIO_get_mem_data(b, &client_key_str);
	BIO_write(sbio, client_key_str, strlen(client_key_str));
    (void)BIO_shutdown_wr(sbio);
    int n = BIO_read(sbio, buf, sizeof(buf));
    buf[n] = NULL;
    char *key;
    char *decoded_key = unbase64(buf, strlen(buf));
    unsigned long long decoded_key_len = EVP_PKEY_size(client_key) + 16, key_len;
    #ifdef DEBUG
    printf("Received: %s", buf);
    #endif
    EVP_PKEY_CTX *decrypt_ctx = EVP_PKEY_CTX_new(client_key, NULL);
    EVP_PKEY_decrypt_init(decrypt_ctx);
    EVP_PKEY_decrypt(decrypt_ctx, NULL, &key_len, decoded_key, decoded_key_len);
    key = malloc(key_len);
    EVP_PKEY_decrypt(decrypt_ctx, key, &key_len, decoded_key, decoded_key_len);
    print_hex("key", key, key_len, 1);
    i = BIO_get_num_renegotiates(sbio);
    BIO_free_all(sbio);
    SSL_CTX_free(ctx);
    BIO_free(b);
    return 1;
}

/* Generate simple cert+key pair. Based on req.c */
static struct certkey certgen(const char *algname, const char *paramset)
{
    /* Keygen. */
    EVP_PKEY *tkey;
    T(tkey = EVP_PKEY_new());
    T(EVP_PKEY_set_type_str(tkey, algname, strlen(algname)));
    EVP_PKEY_CTX *ctx;
    T(ctx = EVP_PKEY_CTX_new(tkey, NULL));
    T(EVP_PKEY_keygen_init(ctx));
    if (paramset)
	    T(EVP_PKEY_CTX_ctrl_str(ctx, "paramset", paramset));
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
    T(EVP_DigestSignInit(mctx, NULL, NULL, NULL, pkey));
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
    return (struct certkey){ .pkey = pkey, .cert = x509ss };
}

int main(int argc, char **argv){
    if(argc < 2){
        printf("Please enter server or client!");
        return 0;
    }
    printf(cBLUE "TestTLS %s", "round5");
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
    set_key_size();
    BUFFER_SIZE = get_buffer_size(PKLEN);
    pd(BUFFER_SIZE);
    if(!strcmp(argv[1], "client")){
        int client_socket = socket(AF_INET, SOCK_STREAM, 0);
        #ifdef DEBUG
        char server_addr[] = "172.31.17.212";
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
        const char *algname = "round5";
        EVP_PKEY *client_key = NULL;
        client_key = EVP_PKEY_new();
        client_key = round5_keygen(algname);
        
        int status = 0;
        ret = s_client(client_socket, client_key);
        wait(&status);
        ret |= WIFEXITED(status) && WEXITSTATUS(status);
        EVP_PKEY_free(client_key);
    }
    else if(!strcmp(argv[1], "server")){
        struct sockaddr_in addr;
        uint8_t len = sizeof(addr);
        int server_socket = create_server_socket(port);
        int client_socket = accept(server_socket, (struct sockaddr *)&addr, &len);
        struct certkey ck;
        const char *algname = "rsa";
        ck = certgen(algname, NULL);
        
        ret = s_server(ck.pkey, ck.cert, client_socket);
        X509_free(ck.cert);
        EVP_PKEY_free(ck.pkey);
    }

    ENGINE_finish(eng);
    ENGINE_free(eng);
    ENGINE_cleanup();

    // if (ret)
	//     printf(cDRED "= Some tests FAILED!\n" cNORM);
    // else
	//     printf(cDGREEN "= All tests passed!\n" cNORM);
    return 1;
}