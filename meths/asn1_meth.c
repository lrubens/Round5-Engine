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

    struct ROUND5 *kpair = NULL;
    kpair = OPENSSL_malloc(sizeof(*kpair));
    kpair = EVP_PKEY_get0(pkey);
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
        if (ASN1_buf_print(bp, kpair->sk, SKLEN, indent + 4) == 0)
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
        printf("\nkpair->pk: %d\n", sizeof(kpair->pk));
        if (!ASN1_buf_print(bp, kpair->pk, PKLEN, indent + 4))
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
                *ppt = OPENSSL_memdup(kp->sk, nid_data->pk_bytes);    // TODO: figure out pubk_bytes
                if (*ppt != NULL)
                    return nid_data->pk_bytes;
            }
            return 0;
        case EVP_PKEY_CTRL_PKCS7_SIGN:
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
    const struct round5_nid_data_st *nid_data = round5_get_nid_data(nid);
    // ASN1_OBJECT *algobj = OBJ_nid2obj(nid);
    ASN1_OBJECT *algobj = OBJ_nid2obj(nid);
    ASN1_STRING *params = ASN1_STRING_new();//encode_gost_algor_params(pk);
    unsigned char /**priv_buf = NULL,*/ *buf = NULL;
    size_t key_len, /*priv_len = 0,*/ i = 0;

    if (!params) {
        return 0;
    }

    key_len = nid_data->sk_bytes;
    //key_len = 1413; //TODO: take this out
    if (key_len == 0) {
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

    return PKCS8_pkey_set0(p8, algobj, 0, V_ASN1_SEQUENCE, params,
                           key_data->sk, key_len);
    /*const ROUND5_KEYPAIR *kp = EVP_PKEY_get0(pkey);
    ASN1_OCTET_STRING oct;
    unsigned char *penc = NULL;
    int penclen;
    const struct round5_nid_data_st *nid_data = round5_get_nid_data(nid);
    char *tmp_buf = NULL;
    int ret = 0;

    if (nid_data == NULL) {
//        SUOLAerr(SUOLA_F_ASN1_GENERIC_PRIV_ENCODE, SUOLA_R_MISSING_NID_DATA);
        return 0;
    }

//    if (suola_keypair_is_invalid(kp) || kp->nid != nid) {
//        SUOLAerr(SUOLA_F_ASN1_GENERIC_PRIV_ENCODE, SUOLA_R_INVALID_PRIVATE_KEY);
//        return 0;
//    }

    tmp_buf = OPENSSL_secure_malloc(nid_data->sk_bytes);     // TODO: figure out privk_bytes
    if (NULL == tmp_buf) {
//        SUOLAerr(SUOLA_F_ASN1_GENERIC_PRIV_ENCODE, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    oct.data = memcpy(tmp_buf, kp->key.sk, nid_data->sk_bytes);      //TODO: privk_bytes
    oct.length = nid_data->sk_bytes;     //TODO: privk_bytes
    oct.flags = 0;

    penclen = i2d_ASN1_OCTET_STRING(&oct, &penc);
    if (penclen < 0) {
//        SUOLAerr(ROUDN5_F_ASN1_GENERIC_PRIV_ENCODE, ERR_R_MALLOC_FAILURE);
        ret = 0;
        goto err;
    }

    if (!PKCS8_pkey_set0(p8, OBJ_nid2obj(nid), 0,
                         V_ASN1_UNDEF, NULL, penc, penclen)) {
        OPENSSL_clear_free(penc, penclen);
//        SUOLAerr(SUOLA_F_ASN1_GENERIC_PRIV_ENCODE, ERR_R_MALLOC_FAILURE);
        ret = 0;
        goto err;
    }

    ret = 1;
    err:
    _round5_keypair_free(kp);
    if (tmp_buf)
        OPENSSL_secure_free(tmp_buf);
    free(nid_data->name);
    free(nid_data);
    nid_data = NULL;
    return ret; */
    
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
    // free(kpair->sk);
    // key_data = OPENSSL_malloc(sizeof(*key_data));
    // key_data = EVP_PKEY_get0(pk);
    // printf("\n%s\n", key_data->sk);
//     const unsigned char *p;
//     int plen;
//     ASN1_OCTET_STRING *oct = NULL;
//     RC_CONST X509_ALGOR *palg;
//     ROUND5_KEYPAIR *kp = NULL;

//     const struct round5_nid_data_st *nid_data = round5_get_nid_data(nid);
//     if (nid_data == NULL) {
// //        SUOLAerr(SUOLA_F_ASN1_GENERIC_PRIV_DECODE, SUOLA_R_MISSING_NID_DATA);
//         return 0;
//     }

//     if (!PKCS8_pkey_get0(NULL, &p, &plen, &palg, p8))
//         return 0;

//     oct = d2i_ASN1_OCTET_STRING(NULL, &p, plen);
//     if (oct == NULL) {
//         p = NULL;
//         plen = 0;
//     } else {
//         p = ASN1_STRING_get0_data(oct);
//         plen = ASN1_STRING_length(oct);
//     }

//     if (palg != NULL) {
//         int ptype;

//         /* Algorithm parameters must be absent */
//         X509_ALGOR_get0(NULL, &ptype, NULL, palg);
//         if (ptype != V_ASN1_UNDEF) {
// //            SUOLAerr(SUOLA_F_ASN1_GENERIC_PRIV_DECODE, SUOLA_R_INVALID_ENCODING);
//             return 0;
//         }
//     }

//     if (p == NULL || plen != nid_data->sk_bytes) {
// //        SUOLAerr(SUOLA_F_ASN1_GENERIC_PRIV_DECODE, SUOLA_R_WRONG_LENGTH);
//         return 0;
//     }

//     kp = round5_new(nid);
// //    if (suola_keypair_is_invalid_private(kp)){
// //        SUOLAerr(SUOLA_F_ASN1_GENERIC_PRIV_DECODE, SUOLA_R_INVALID_PRIVATE_KEY);
// //        return 0;
// //    }

//     memcpy(kp->key.sk, p, nid_data->sk_bytes);       //TODO: privk_bytes

//     ASN1_OCTET_STRING_free(oct);
//     oct = NULL;
//     free(p);
//     p = NULL;
//     plen = 0;

//     // Generate corresponding public key
//     if ( 1 != (nid_data->sk_to_pk)(kp->key.pk, kp->key.sk) ) {
//         round5_free(kp);
//         return 0;
//     }

//     EVP_PKEY_assign(pkey, nid, kp);

    return 1;
}

static int pki_gen_pub_encode(X509_PUBKEY *pub,  EVP_PKEY *pk)
{
    ASN1_OBJECT *algobj = NULL;
    //ASN1_OCTET_STRING *octet = NULL;
    //void *pval = NULL;
    unsigned char *databuf = NULL;
    int data_len, ret = -1;
    int ptype = V_ASN1_UNDEF ;
    struct ROUND5 *kpair = EVP_PKEY_get0(pk);
    algobj = OBJ_nid2obj(NID_ROUND5);
    // char buffer[1024];
    // OBJ_obj2txt(buffer, 1024, algobj, 1);
    // printf("algobj%s\n", buffer);
	ASN1_STRING *params = ASN1_STRING_new();//encode_gost_algor_params(pk);
	//pval = params;
	ptype = V_ASN1_SEQUENCE;
    // databuf = OPENSSL_memdup(kpair->pk, PKLEN);
    databuf = OPENSSL_malloc(PKLEN);
    //printf("\npk: %s\n", kpair->pk);
    if(kpair->pk)
        memcpy(databuf, kpair->pk, (size_t)PKLEN);
    if (!databuf)
        printf("Invalid key\n\n");
    X509_PUBKEY_set0_param(pub, algobj, ptype, params, databuf, PKLEN);
    //free(databuf);
    //ASN1_STRING_free(params);
    //memset(kpair, 0, sizeof(*kpair));
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
    EVP_PKEY_assign(pkey, NID_ROUND5, kpair);
    OPENSSL_free(kpair->pk);
    return 1;
}

static int pki_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b){
    return 1;
}

int _register_asn1_meth(int nid, EVP_PKEY_ASN1_METHOD **ameth, const char *pem_str, const char *info){
    *ameth = EVP_PKEY_asn1_new(nid, 0, pem_str, info);
    if (!*ameth)
        return 0;
    if (nid == NID_ROUND5){
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

