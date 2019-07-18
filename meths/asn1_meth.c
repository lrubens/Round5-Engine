//
// Created by ruben on 5/23/2019.
//

#include "asn1_meth.h"
#include "../keypair.h"
#include "../ossl/objects.h"
#include "cpa_kem.h"
#include "cca_encrypt.h"
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/bn.h>
#include <string.h>
#include "round5_meth.h"
#include "dilithium_meth.h"

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
    struct ROUND5 *kpair = (struct ROUND5 *)EVP_PKEY_get0(pkey);
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
    // ps(__func__);
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

static int pki_gen_ctrl(/*int nid,*/ EVP_PKEY *pkey, int op, long arg1, void *arg2)
{
    if(!pkey){
        printf("\n!pkey\n");
    }
    int nid2 = EVP_PKEY_base_id(pkey);
    int md_nid = NID_undef;
    X509_ALGOR *alg1 = NULL, *alg2 = NULL;
    // char *algname = OBJ_nid2sn(nid2);
    // ps(algname);
    // if(nid2 == NID_DILITHIUM){
    //     md_nid = EVP_MD_type((const EVP_MD *)arg2);
    //     printf("\nevp md type: %d\n", md_nid);
    // }
    // else{
    //     printf("\nelse\n");

    //     return -1;
    // }
    // pd(op);
    switch (op) {
    case ASN1_PKEY_CTRL_PKCS7_SIGN:
        ps("case 1");
        if (arg1 == 0) {
            int snid, hnid;
            X509_ALGOR *alg1, *alg2;
            PKCS7_SIGNER_INFO_get0_algs(arg2, NULL, &alg1, &alg2);
            if (alg1 == NULL || alg1->algorithm == NULL)
                return -1;
            hnid = OBJ_obj2nid(alg1->algorithm);
            if (hnid == NID_undef)
                return -1;
            if (!OBJ_find_sigid_by_algs(&snid, hnid, EVP_PKEY_id(pkey)))
                return -1;
            X509_ALGOR_set0(alg2, OBJ_nid2obj(snid), V_ASN1_UNDEF, 0);
        }
        return 1;
#ifndef OPENSSL_NO_CMS
    case ASN1_PKEY_CTRL_CMS_SIGN:
        printf("\ncase 2\n");
        if (arg1 == 0) {
            // CMS_SignerInfo_get0_algs((CMS_SignerInfo *)arg2, NULL, NULL,
            //                          &alg1, &alg2);
            X509_ALGOR_set0(alg1, OBJ_nid2obj(md_nid), V_ASN1_NULL, 0);
            X509_ALGOR_set0(alg2, OBJ_nid2obj(nid2), V_ASN1_NULL, 0);
        }
        return 1;
#endif
    case ASN1_PKEY_CTRL_PKCS7_ENCRYPT:
        printf("\ncase 3\n");
        if (arg1 == 0) {
            // ASN1_STRING *params = encode_gost_algor_params(pkey);
            // if (!params) {
            //     return -1;
            // }
            PKCS7_RECIP_INFO_get0_alg((PKCS7_RECIP_INFO *)arg2, &alg1);
            X509_ALGOR_set0(alg1, OBJ_nid2obj(EVP_PKEY_id(pkey)),
                            V_ASN1_SEQUENCE, "params");
        }
        return 1;
#ifndef OPENSSL_NO_CMS
    case ASN1_PKEY_CTRL_CMS_ENVELOPE:
        printf("\ncase 4\n");
        if (arg1 == 0) {
            // ASN1_STRING *params = encode_gost_algor_params(pkey);
            // if (!params) {
            //     return -1;
            // }
            // CMS_RecipientInfo_ktri_get0_algs((CMS_RecipientInfo *)arg2, NULL,
            //                                  NULL, &alg1);
            X509_ALGOR_set0(alg1, OBJ_nid2obj(EVP_PKEY_id(pkey)),
                            V_ASN1_SEQUENCE, "params");
        }
        return 1;
#endif
    case ASN1_PKEY_CTRL_DEFAULT_MD_NID:
        // printf("\ncase 5\n");
        *(int *)arg2 = NID_sha512;
        return 2;
    }
    printf("\nbase case\n");
    return -2;
}


// static int pki_gen_priv_encode(int nid, PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pkey)
static int pki_gen_priv_encode(PKCS8_PRIV_KEY_INFO *p8, const EVP_PKEY *pkey)
{
    // ps("hello");
    int nid = EVP_PKEY_base_id(pkey);
    // const struct round5_nid_data_st *nid_data = round5_get_nid_data(nid);
    // ASN1_OBJECT *algobj = OBJ_nid2obj(nid);
    ASN1_OBJECT *algobj = OBJ_nid2obj(nid);
    ASN1_STRING *params = ASN1_STRING_new();//encode_gost_algor_params(pk);
    unsigned char /**priv_buf = NULL,*/ *buf = NULL;
    size_t key_len, /*priv_len = 0,*/ i = 0;
    struct ROUND5 *kpair = NULL;
    kpair = (struct ROUND5 *)EVP_PKEY_get0(pkey);
    // ps(kpair->pk);
    return PKCS8_pkey_set0(p8, algobj, 0, V_ASN1_SEQUENCE, params,
                           kpair->sk, EVP_PKEY_base_id(pkey) == NID_ROUND5 ? SKLEN : CRYPTO_BYTES);
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
    // ps(__func__);
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
    if(EVP_PKEY_base_id(pk) == NID_ROUND5)
        kpair = round5_new();
    else
        kpair = dilithium_new();
    //kpair->sk = OPENSSL_malloc(priv_len);
    memcpy(kpair->sk, pkey_buf, priv_len);
    EVP_PKEY_assign(pk, NID_ROUND5, kpair);

    return 1;
}

static int pki_gen_pub_encode(X509_PUBKEY *pub,  EVP_PKEY *pk)
{
    // ps(__func__);
    // int ret = init_round5();
    ASN1_OBJECT *algobj = NULL;
    //ASN1_OCTET_STRING *octet = NULL;
    //void *pval = NULL;
    unsigned char *databuf = NULL;
    int data_len, ret = -1;
    int ptype = V_ASN1_UNDEF ;
    struct ROUND5 *kpair = (struct ROUND5 *)EVP_PKEY_get0(pk);
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
    // pd(PKLEN);
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
    // ps(__func__);
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
    strcpy(kpair->pk, pubkey_buf);
    EVP_PKEY_assign(pkey, NID_ROUND5, kpair);
    return 1;
}

static int pki_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b){
    return 1;
}

static int dilithium_item_sign(EVP_MD_CTX *ctx, const ASN1_ITEM *it, void *asn, X509_ALGOR *alg1, X509_ALGOR *alg2, ASN1_BIT_STRING *str){
    X509_ALGOR_set0(alg1, OBJ_nid2obj(NID_DILITHIUM), V_ASN1_UNDEF, NULL);
    if(alg2){
        X509_ALGOR_set0(alg2, OBJ_nid2obj(NID_DILITHIUM), V_ASN1_UNDEF, NULL);
    }
    return 3;
}

static int get_pkey_size(const EVP_PKEY *pkey){
    // pd(SHA512_DIGEST_LENGTH + CRYPTO_BYTES);
    return SHA512_DIGEST_LENGTH + 2701;
    // int nid = EVP_PKEY_base_id(pkey);
    // return (nid == NID_ROUND5 ? SKLEN : SHA512_DIGEST_LENGTH + CRYPTO_BYTES);
}

static int dilithium_item_verify(EVP_MD_CTX *ctx, const ASN1_ITEM *it, void *asn, X509_ALGOR *sigalg, ASN1_BIT_STRING *str, EVP_PKEY *pkey){
    const ASN1_OBJECT *obj;
    int ptype;
    X509_ALGOR_get0(&obj, &ptype, NULL, sigalg);
    if(OBJ_obj2nid(obj) != NID_DILITHIUM || ptype != V_ASN1_UNDEF){
        ps("Error");
        return 0;
    }
    if(!EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey)){
        return 0;
    }
    return 2;
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
        EVP_PKEY_asn1_set_public(*ameth, pki_gen_pub_decode, pki_gen_pub_encode, pki_pub_cmp, pki_gen_pub_print, get_pkey_size, pki_curve25519_bits);
        EVP_PKEY_asn1_set_private(*ameth, pki_gen_priv_decode, pki_gen_priv_encode, pki_gen_priv_print);
        EVP_PKEY_asn1_set_ctrl(*ameth, pki_gen_ctrl);
        EVP_PKEY_asn1_set_item(*ameth, dilithium_item_verify, dilithium_item_sign);
    }
    EVP_PKEY_asn1_set_param(*ameth, 0, 0, 0, 0, pki_pub_cmp, 0);
#ifndef OPENSSL_V102_COMPAT
    EVP_PKEY_asn1_set_security_bits(*ameth, pki_curve25519_security_bits);
#endif
    EVP_PKEY_asn1_set_free(*ameth, pki_free);
    return 1;
}
