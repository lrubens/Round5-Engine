//
// Created by ruben on 5/23/2019.
//

#include "asn1_meth.h"
#include "../keypair.h"
#include "../ossl/objects.h"
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/bn.h>
#include <string.h>
#include "round5_meth.h"

#ifndef OPENSSL_V102_COMPAT
#define RC_CONST const
#else
#define RC_CONST
#endif

typedef enum {
    PUBLIC,
    PRIVATE
} key_op_t;

static void pki_free(EVP_PKEY *pkey){
    //struct ROUND5 *kpair = NULL;
    //kpair = OPENSSL_malloc(sizeof(*kpair));
    struct ROUND5 *kpair = EVP_PKEY_get0(pkey);
    //kpair->pk = NULL;
    //kpair = NULL;
    if(kpair){
        // if (!kpair->pk)
            // OPENSSL_free(kpair->pk);
        // if (!kpair->sk)
            // OPENSSL_free(kpair->sk);  
        kpair = NULL;
        // free(kpair);
    }
    //free(&kpair->pk);
    pkey = NULL;

    
}

static int pki_key_print( BIO *bp, const EVP_PKEY *pkey,
                            int indent, ASN1_PCTX *ctx, key_op_t op)
{
    if (!pkey)
        return 0;
    int nid = EVP_PKEY_base_id(pkey);
    struct ROUND5 *kpair = NULL;
    kpair = EVP_PKEY_get0(pkey);
    //kpair = OPENSSL_malloc(sizeof(*kpair));
    //const struct round5_nid_data_st *nid_data = NULL;
    if (!kpair){
        printf("<Undefined Key>\n");
        return 0;
    }
    if (op == PRIVATE) {
//        if (suola_keypair_is_invalid_private(kpair)) {
//            if (BIO_printf(bp, "%*s<INVALID PRIVATE KEY>\n", indent, "") <= 0)
//                return 0;
//            return 1;
//        }
        //nid_data = round5_get_nid_data(1061); //fix later
        // if (BIO_printf(bp, "%*s%s Private-Key:\n", indent, "", nid_data->name) <= 0)
        if (BIO_printf(bp, "%*s%s Private-Key:\n", indent, "", "") <= 0)
            return 0;
        // if (ASN1_buf_print(bp, kpair->sk, nid_data->sk_bytes, indent + 4) == 0)
        if (ASN1_buf_print(bp, kpair->sk, (nid == NID_ROUND5 ? SKLEN : CRYPTO_SECRETKEYBYTES), indent + 4) == 0)
            return 0;
    } else {
       if (!kpair) {
           if (BIO_printf(bp, "%*s<INVALID PUBLIC KEY>\n", indent, "") <= 0)
               return 0;
           return 1;
       }
        //nid_data = round5_get_nid_data(1061);
        if (BIO_printf(bp, "%*s%sPublic-Key:\n", indent, "", "") <= 0) //change last parameter back to nid_data->name
            return 0;
        if (!ASN1_buf_print(bp, kpair->pk, (nid == NID_ROUND5 ? PKLEN : CRYPTO_PUBLICKEYBYTES), indent + 4))
            return 0;
    }
    // if (BIO_printf(bp, "%*s", indent, "") <= 0)
    //     return 0;
    //printf("nid_data->pk_bytes: %d\n", nid_data->pk_bytes); //nid_data is broken
    return 1;
}

static int pki_gen_priv_print(BIO *bp, const EVP_PKEY *pkey, int indent, ASN1_PCTX *ctx)
{
    return pki_key_print(bp, pkey, indent, ctx, PRIVATE);
}

static int pki_gen_pub_print(BIO *bp, const EVP_PKEY *pkey, int indent, ASN1_PCTX *ctx)
{
    return pki_key_print(bp, pkey, indent, ctx, PUBLIC);
}

//static int round5_gen_ctrl(int nid, EVP_PKEY *pkey, int op, long arg1, void *arg2){
//    ROUND5_KEYPAIR *kpair = NULL;
//    cont unsigned char *p = NULL;
//    const struct round5_nid_data_st *nid_data = round5_get_nid_data(nid);
//    int
//}

static int pki_gen_ctrl(int nid, EVP_PKEY *pkey, int op, long arg1, void *arg2)
{
    struct ROUND5 *kp = NULL;
    const unsigned char *p = NULL;
    const struct round5_nid_data_st *nid_data = round5_get_nid_data(nid);
    int pklen = 0;
    X509_ALGOR *alg1 = NULL;
    X509_ALGOR *alg2 = NULL;


    switch (op) {

#ifndef OPENSSL_V102_COMPAT
        // FIXME: check if/how this control signals should be handled in 1.0.2
        case ASN1_PKEY_CTRL_SET1_TLS_ENCPT:
            p = arg2;
            pklen = arg1;

//            if (p == NULL || pklen != nid_data->pubk_bytes ) {
//                SUOLAerr(SUOLA_F_ASN1_GENERIC_CTRL, SUOLA_R_WRONG_LENGTH);
//                return 0;
//            }

            kp = round5_new();
//            if (suola_keypair_is_invalid(kp)) {
//                return 0;
//            }

            memcpy(kp->pk, p, pklen);

            EVP_PKEY_assign(pkey, nid, kp);
            return 1;


        case ASN1_PKEY_CTRL_GET1_TLS_ENCPT:
            kp = EVP_PKEY_get0(pkey);
            if (kp == NULL && nid == kp->nid) {
                unsigned char **ppt = arg2;
                *ppt = OPENSSL_memdup(kp->sk, PKLEN);
                if (*ppt != NULL)
                    return nid_data->pk_bytes;
            }
            return 0;
        case ASN1_PKEY_CTRL_PKCS7_SIGN:
            if(arg1 == 0){
                PKCS7_SIGNER_INFO_get0_algs((PKCS7_SIGNER_INFO *)arg2, NULL, &alg1, &alg2);
                X509_ALGOR_set0(alg1, OBJ_nid2obj(EVP_PKEY_base_id(pkey)), V_ASN1_NULL, 0);
                X509_ALGOR_set0(alg2, OBJ_nid2obj(EVP_MD_type(EVP_sha256())), V_ASN1_NULL, 0);
            }
            return 1;
        case EVP_PKEY_CTRL_DIGESTINIT:
            printf("\nEVP_PKEY_CTRL_DIGESTINIT\n");
            return 1;
#endif
        default:
            return -2;

    }
}


// static int pki_gen_priv_encode(int nid, PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pkey)
static int pki_gen_priv_encode(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pkey)
{
    int nid = NID_ROUND5;
    // const struct round5_nid_data_st *nid_data = round5_get_nid_data(nid);
    // ASN1_OBJECT *algobj = OBJ_nid2obj(nid);
    ASN1_OBJECT *algobj = OBJ_nid2obj(nid);
    ASN1_STRING *params = ASN1_STRING_new();//encode_gost_algor_params(pk);
    unsigned char /**priv_buf = NULL,*/ *buf = NULL;
    size_t key_len, /*priv_len = 0,*/ i = 0;

    if (!params) {
        return 0;
    }

    // ROUND5_KEYPAIR *key_data = NULL;
    // key_data = _round5_keypair_new(nid, 0);
    // key_data = EVP_PKEY_get0(pkey);
    struct ROUND5 *key_data = NULL;
    key_data = EVP_PKEY_get0(pkey);
    // key_data = OPENSSL_secure_malloc(sizeof(*key_data));
    // key_data = EVP_PKEY_get0(pkey);
    //BN data = BN_new();  
    printf("\nkey_data->sk: %s\n", key_data->sk);
    return PKCS8_pkey_set0(p8, algobj, 0, V_ASN1_SEQUENCE, params,
                           key_data->sk, SKLEN);
}

static int pki_curve25519_bits(const EVP_PKEY *pkey)
{
    return CURVE25519_BITS;
}

static int pki_curve25519_security_bits(const EVP_PKEY *pkey)
{
    return CURVE25519_SECURITY_BITS;
}

static int pki_gen_priv_decode(EVP_PKEY *pk, RC_CONST PKCS8_PRIV_KEY_INFO *p8inf)
{

    const unsigned char *pkey_buf = NULL, *p = NULL;
    int priv_len = 0;
    unsigned char *pk_num = NULL;
    int ret = 0;
    const X509_ALGOR *palg = NULL;
    const ASN1_OBJECT *palg_obj = NULL;
    ASN1_INTEGER *priv_key = NULL;
    int expected_key_len = 32;
    if (!PKCS8_pkey_get0(&palg_obj, &pkey_buf, &priv_len, &palg, p8inf))
        return 0;
    struct ROUND5 *kpair = NULL;
    kpair = round5_new();
    //kpair->sk = OPENSSL_malloc(priv_len);
    memcpy(kpair->sk, pkey_buf, priv_len);
    EVP_PKEY_assign(pk, NID_ROUND5, kpair);

    return 1;
}

static int pki_gen_pub_encode(X509_PUBKEY *pub,  EVP_PKEY *pk)
{
    // int ret = init_round5();
    ASN1_OBJECT *algobj = NULL;
    //ASN1_OCTET_STRING *octet = NULL;
    //void *pval = NULL;
    unsigned char *databuf = NULL;
    int data_len, ret = -1;
    int ptype = V_ASN1_UNDEF ;
    struct ROUND5 *kpair = EVP_PKEY_get0(pk);
    set_key_size();
    algobj = OBJ_nid2obj(EVP_PKEY_base_id(pk));
    // char buffer[1024];
    // OBJ_obj2txt(buffer, 1024, algobj, 1);
    // printf("algobj%s\n", buffer);
	ASN1_STRING *params = ASN1_STRING_new();//encode_gost_algor_params(pk);
	//pval = params;
	ptype = V_ASN1_SEQUENCE;
    // databuf = OPENSSL_memdup(kpair->pk, PKLEN);
    // printf("\npk: %s\n", PKLEN);
    databuf = OPENSSL_malloc(PKLEN);
    // printf("\npk: %s\n", PKLEN);
    if(kpair->pk)
        memcpy(databuf, kpair->pk, PKLEN);
    if (!databuf)
        printf("Invalid key\n\n");
    X509_PUBKEY_set0_param(pub, algobj, ptype, params, databuf, PKLEN);
    // memset(databuf, 0, sizeof(*databuf));
    // round5_free(kpair);
    //ASN1_STRING_free(params);
    // memset(kpair, 0, sizeof(*kpair));
    return 1;
}

static int pki_gen_pub_decode(EVP_PKEY *pkey, X509_PUBKEY *pubkey)
{
    X509_ALGOR *palg = NULL;
    const unsigned char *pubkey_buf = NULL;
    unsigned char *databuf;
    ASN1_OBJECT *palgobj = NULL;
    int pub_len;
    struct ROUND5 *kpair = NULL;
    size_t len;
    if (!X509_PUBKEY_get0_param(&palgobj, &pubkey_buf, &pub_len, &palg, pubkey))
        return 0;
    kpair = round5_new();
    //kpair->pk = OPENSSL_malloc(pub_len);
    memcpy(kpair->pk, pubkey_buf, pub_len);
    printf("\npubkey buf: %s\n", pubkey_buf);
    EVP_PKEY_assign(pkey, NID_ROUND5, kpair);
    // OPENSSL_free(kpair->pk);
    return 1;
}

static int pki_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b){
    return 1;
}

int _register_asn1_meth(int nid, EVP_PKEY_ASN1_METHOD **ameth, const char *pem_str, const char *info){
    *ameth = EVP_PKEY_asn1_new(nid, ASN1_PKEY_SIGPARAM_NULL, pem_str, info);
    if (!*ameth)
        return 0;
    if (nid == NID_ROUND5){
        EVP_PKEY_asn1_set_public(*ameth, pki_gen_pub_decode, pki_gen_pub_encode, pki_pub_cmp, pki_gen_pub_print, NULL, pki_curve25519_bits);
        EVP_PKEY_asn1_set_private(*ameth, pki_gen_priv_decode, pki_gen_priv_encode, pki_gen_priv_print);
        EVP_PKEY_asn1_set_ctrl(*ameth, pki_gen_ctrl);
    }
    else if (nid == NID_DILITHIUM){
        EVP_PKEY_asn1_set_public(*ameth, pki_gen_pub_decode, pki_gen_pub_encode, pki_pub_cmp, pki_gen_pub_print, NULL, pki_curve25519_bits);
        EVP_PKEY_asn1_set_private(*ameth, pki_gen_priv_decode, pki_gen_priv_encode, pki_gen_priv_print);
        EVP_PKEY_asn1_set_ctrl(*ameth, pki_gen_ctrl);
    }
    EVP_PKEY_asn1_set_param(*ameth, 0, 0, 0, 0, pki_pub_cmp, 0);
#ifndef OPENSSL_V102_COMPAT
    EVP_PKEY_asn1_set_security_bits(*ameth, pki_curve25519_security_bits);
#endif
    EVP_PKEY_asn1_set_free(*ameth, pki_free);
    return 1;
}

