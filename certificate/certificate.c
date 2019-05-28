#include <openssl/evp.h>
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

void certgen(){
    
    EVP_PKEY * pkey;
    pkey = EVP_PKEY_new();

    int ret = 0;
    RSA *rsa = NULL;
    BIGNUM *bne = NULL;
    //BIO *bp_public = NULL, *bp_private = NULL;
 
    int bits = 2048;
    unsigned long e = RSA_F4;
 
    bne = BN_new();
    ret = BN_set_word(bne,e);
    if(ret != 1){
        //do something
    }
 
    //this should be the round5 algorithm
    rsa = RSA_new();
    ret = RSA_generate_key_ex(rsa, bits, bne, NULL);
    if(ret != 1){
        //do something
    }

    EVP_PKEY_assign_RSA(pkey, rsa);

    X509 * x509;
    x509 = X509_new();

    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

    X509_set_pubkey(x509, pkey);

    X509_NAME * name;
    name = X509_get_subject_name(x509);

    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char *)"CA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char *)"MyCompany Inc.", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"localhost", -1, -1, 0);

    X509_sign(x509, pkey, EVP_sha1());

    FILE * f = fopen("key.pem", "wb");
    PEM_write_PrivateKey(
        f,                  /* write the key to the file we've opened */
        pkey,               /* our key from earlier */
        EVP_des_ede3_cbc(), /* default cipher for encrypting the key on disk */
        (unsigned char *)"hello",       /* passphrase required for decrypting the key on disk */
        5,                 /* length of the passphrase string */
        NULL,               /* callback for requesting a password */
        NULL                /* data to pass to the callback */
    );

    FILE * f2 = fopen("cert.pem", "wb");
    PEM_write_X509(
        f2,   /* write the certificate to the file we've opened */
        x509 /* our certificate */
    );
    fclose(f);
    fclose(f2);
}

int main(int argc, char **argv){
    certgen();
    return 0;
}