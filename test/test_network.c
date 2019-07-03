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


struct nodes{
  unsigned char *addresses[2];
  unsigned char *names[2];
};

int main(int argc, const char* argv[]){
  printf(cBLUE "Testing client-server cert distribution\n" cNORM);
  struct nodes *clients= malloc(sizeof(struct nodes));
  char *server_addr = "192.168.2.2";
	clients->addresses[0] = "192.168.2.5";    // Change accordingly
  clients->addresses[1] = "192.168.1.4";    //Change accordingly
  clients->names[0] = "Alice";
  clients->names[1] = "Bob";
  char *hostname = "Alice";
  printf("\n---Hostname: [ %s ]---\n", hostname);
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
    char *host = "server";
    printf("\nhostname: %s\n", host);
    char *client_addr = NULL;
		unsigned char *csr_str = NULL;
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
    printf("\nPress enter to send public key to clients\n");
    while( getchar() != '\n' );
    // for (int i = 0; i < sizeof(clients->addresses); i++){
    //   ps(clients->addresses[i]);
    //   send_data(clients->addresses[i], public_key_text);
	  // }
    send_data("192.168.2.5", public_key_text);
    receive(csr_str, client_addr);
    printf("\nReceived CSR from host (%s):\n %s", client_addr, csr_str);
    X509_REQ *csr = PEM_toX509Req((const char*)csr_str);
    X509 *signed_cert = sign_csr(csr, pkey);
    char *cert_str = X509_to_PEM(signed_cert);
    printf("\nPress enter to send client signed cert\n");
    while(getchar() != '\n');
  }
	else{
    EVP_PKEY *pub_key = NULL;
    char *server_public_key = NULL;
    char *client_addr = NULL;
    ps("Receiving public key");
    receive(server_public_key, client_addr);
    char_to_EVP_PKEY(pub_key, server_public_key);
    FILE *f = fopen("certs/server.pem", "wb");
    PEM_write_PUBKEY(f, pub_key);
	  fclose(f);
    client_addr = NULL;
    unsigned char *country = "US";
    unsigned char *province = "MA";
    unsigned char *city = "Cambridge";
    unsigned char *organization = "Draper"; 
    unsigned char * fqdn = hostname;
    X509_REQ *req = gen_csr(country, province, city, organization, fqdn);
    unsigned char *csr_str = X509Req_to_PEM(req);
    printf("\nPress enter to send server CSR\n");
    unsigned char *user_input = NULL;
    scanf("%s", user_input);
    send_data(server_addr, csr_str);
    unsigned char *signed_cert_str = NULL;
    receive(signed_cert_str, client_addr);
    printf("\nReceived signed cert from host (%s):\n %s", client_addr, signed_cert_str);
    X509 *signed_cert = PEM_to_X509((const char*)signed_cert_str);
    FILE *f2 = fopen("certs/client.pem", "wb");
    PEM_write_X509(f2, signed_cert);
    fclose(f2);
	}
	ENGINE_finish(round5_engine);
	ENGINE_free(round5_engine);
	ENGINE_cleanup();
	return 0;
}
