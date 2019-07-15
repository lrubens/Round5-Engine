#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include "../r5_cca_pke.h"
#include "../parameters.h"
#include "../r5_memory.h"
#include "../rng.h"
#include "../a_fixed.h"


int main(int argc, char *argv[]){
  EVP_PKEY_ASN1_METHOD *EVP_ROUND5_meth = EVP_PKEY_asn1_new(10, ASN1_PKEY_SIGPARAM_NULL, "Round5", "Post Quantum Crypto");
  int ret = 0;
  BIO *out = NULL, *bio_err = NULL;
  EVP_PKEY *pkey = NULL;
  X509 *cert = NULL;
  X509_REQ *x509_req = NULL;
  X509_NAME *x509_name = NULL;
  uint8_t tau = ROUND5_API_TAU;
  const char *szCountry = "US";
  const char *szProvince = "MA";
  const char *szCity = "Cambridge";
  const char *szOrganization = "Draper";
  const char *szCommon = "localhost";
  const char *szPath = "x509Req.pem";
  parameters *params;
  // generate key
 	if ((params = set_parameters_from_api()) == NULL) {
  	fprintf(stderr, "example: Invalid parameters\n");
    exit(EXIT_FAILURE);
  }
  set_parameter_tau(params, tau); // Even when using the API values, we still allow setting tau
  printf("Using API parameters:\n");
  printf("CRYPTO_SECRETKEYBYTES =%u\n", CRYPTO_SECRETKEYBYTES);
  printf("CRYPTO_PUBLICKEYBYTES =%u\n", CRYPTO_PUBLICKEYBYTES);
  printf("CRYPTO_BYTES          =%u\n", CRYPTO_BYTES);
  printf("CRYPTO_CIPHERTEXTBYTES=%u\n", CRYPTO_CIPHERTEXTBYTES);
  printf("CRYPTO_ALGNAME        =%s\n", CRYPTO_ALGNAME);
  //print_parameters(params);
  printf("This set of parameters correspond to NIST security level %c.\n", CRYPTO_ALGNAME[5]); 
  // end
 	if (params->tau == 1) {
		unsigned char *seed = checked_malloc(params->kappa_bytes);
    randombytes(seed, params->kappa_bytes);
    print_hex("Generated A using seed", seed, params->kappa_bytes, 1);
    create_A_fixed(seed, params);
    free(seed);
  }
  unsigned long long ct_len, m_len;
  const char *message = "This is the message to be encrypted.";
  const unsigned long long message_len = strlen(message) + 1;
  unsigned char * sk = checked_malloc(get_crypto_secret_key_bytes(params, 1));
  unsigned char * pk = checked_malloc(get_crypto_secret_key_bytes(params, 1));
  unsigned char *m = checked_malloc(message_len);
  printf("\n\n%d\n%d\n\n", get_crypto_bytes(params, 1), message_len);
  unsigned char *ct = checked_malloc((get_crypto_bytes(params, 1) + message_len));
  printf("Setting up key pair\n");
  r5_cca_pke_keygen(pk, sk, params);
  r5_cca_pke_encrypt(ct, &ct_len, (const unsigned char *) message, message_len, sk, params);
  r5_cca_pke_decrypt(m, &m_len, ct, ct_len, pk, params);
  printf("\n");
  printf("Encrypted Message: %s \n", ct);
  printf("Decrypted Message: %s \n", m);
	
  x509_req = X509_REQ_new();
  ret = X509_REQ_set_version(x509_req, 1);
 	x509_name = X509_REQ_get_subject_name(x509_req);
  ret = X509_NAME_add_entry_by_txt(x509_name,"C", MBSTRING_ASC, (const unsigned char*)szCountry, -1, -1, 0);
 	if (ret != 1){
	  goto free_all;
  }
	ret = X509_NAME_add_entry_by_txt(x509_name,"ST", MBSTRING_ASC, (const unsigned char*)szProvince, -1, -1, 0);
  if (ret != 1){
	  goto free_all;
  }
  ret = X509_NAME_add_entry_by_txt(x509_name,"L", MBSTRING_ASC, (const unsigned char*)szCity, -1, -1, 0);
  if (ret != 1){
	  goto free_all;
  }   
  ret = X509_NAME_add_entry_by_txt(x509_name,"O", MBSTRING_ASC, (const unsigned char*)szOrganization, -1, -1, 0);
  if (ret != 1){
	  goto free_all;
  }
 	ret = X509_NAME_add_entry_by_txt(x509_name,"CN", MBSTRING_ASC, (const unsigned char*)szCommon, -1, -1, 0);
  if (ret != 1){
  	goto free_all;
  }
  pkey = EVP_PKEY_new();
  EVP_PKEY_assign(pkey, 4, pk);
  ret = X509_REQ_set_pubkey(x509_req, pkey);
  printf("Setting public key in cert");
  ret = X509_REQ_sign(x509_req, pkey, EVP_sha1());
  out = BIO_new_file(szPath, "w");
  ret = PEM_write_bio_X509_REQ(out, x509_req);
  free(sk);
  free(pk);
  free(ct);
  free(m);
free_all:
  X509_REQ_free(x509_req);
  EVP_PKEY_free(pkey);
  BIO_free_all(out);  
  return ret;
}
