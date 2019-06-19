//
// Created by ruben on 5/24/2019.
//

#include <string.h>
#include "keypair.h"
#include <openssl/engine.h>
#include <openssl/obj_mac.h>
#include "ossl/ossl_compat.h"
#include "meths/round5_meth.h"
#include "meths/asn1_meth.h"
#include "ossl/objects.h"
#include "meths/dilithium_meth.h"
#include "meths/round5_md.h"
// #include "meths/dilithium_meth.h"
#ifndef ENGINE_ID
#define ENGINE_ID "round5"
#endif

#ifndef ENGINE_NAME
#define ENGINE_NAME "An engine integrating round5 into OpenSSL"
#endif
#define sizeof_static_array(a) \
    ( (sizeof((a))) / sizeof((a)[0]) )

// static const EVP_MD k = {
//     NID_KECCAK,
//     0,
//     16,
//     0,
//     keccak_digest_init,
//     keccak_digest_update,
//     keccak_digest_final,
//     keccak_digest_copy,
//     keccak_digest_cleanup,
//     EVP_PKEY_NULL_method,
//     64,
//     sizeof(EVP_MD_CTX),
//     NULL
// };

static const char *engine_id = ENGINE_ID;
static const char *engine_name = ENGINE_NAME;

static int setup_digest(ENGINE *e, const EVP_MD **digest, const int **nids, int nid);
static int register_methods();
static int pkey_asn1_meths(ENGINE *e, EVP_PKEY_ASN1_METHOD **ameth, const int **nids, int nid);
static int pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth, const int **nids, int nid);
static int pkey_meth_nids[] = {
        0,   //NID_ROUND5
        0,    //NID_DILITHIUM to be integrated later
        0
};
static int md_meth_nids[] = {
        0,   //NID_ROUND5
        0    //NID_DILITHIUM to be integrated later
};

static int digest_nids_init(){
    md_meth_nids[0] = NID_KECCAK;
}


static void pkey_meth_nids_init(){
    pkey_meth_nids[0] = NID_ROUND5;
    pkey_meth_nids[1] = NID_DILITHIUM;
}

static EVP_PKEY_METHOD *pmeth_round5 = NULL;
static EVP_PKEY_METHOD *pmeth_dilithium = NULL;

static EVP_MD *md_obj = NULL;

static int register_ameth(int id, EVP_PKEY_ASN1_METHOD **ameth, int flags);

static int pkey_asn1_meth_nids[] = {
        0,
        0,
        0
};

static void pkey_asn1_meth_nids_init(){
    pkey_asn1_meth_nids[0] = NID_ROUND5;
    pkey_asn1_meth_nids[1] = NID_DILITHIUM;
}

static EVP_PKEY_ASN1_METHOD *ameth_round5 = NULL;
static EVP_PKEY_ASN1_METHOD *ameth_dilithium = NULL;
static EVP_PKEY_ASN1_METHOD *ameth_keccak = NULL;


static int e_init(ENGINE *e){
    // OBJ_cleanup();
    return 1;
}

static int e_destroy(ENGINE *e){
    // EVP_MD_meth_free(md_obj);
    OBJ_cleanup();
    return 1;
}

static int e_finish(ENGINE *e){
    return 1;
}

static int setup_digest(ENGINE *e, const EVP_MD **d, const int **nids, int nid){
    if(!md_obj){
        // printf("\nerror in digest method, d is null\n");
        *nids = md_meth_nids;
        return sizeof_static_array(md_meth_nids) - 1; 
    }
    if(nid == NID_KECCAK){
        ps("uihiu");
        md_obj = digest();
        // printf("\ndigest method success\n");
        return 1;
    }
    // *d = NULL;
    // printf("\nerror in digest method\n");
    
    return 0;
}

static int bind(ENGINE *e, const char *id){
    int ret = 0;
    if (!ENGINE_set_id(e, engine_id)) {
        printf("ENGINE_set_id failed\n");
        goto end;
    }
    if (!ENGINE_set_name(e, engine_name)) {
        printf("ENGINE_set_name failed\n");
        goto end;
    }

    if(!ENGINE_set_init_function(e, e_init)) {
        printf("ENGINE_set_init_function failed\n");
        goto end;
    }
    if(!ENGINE_set_destroy_function(e, e_destroy)) {
        printf("ENGINE_set_destroy_function failed\n");
        goto end;
    }
    if(!ENGINE_set_finish_function(e, e_finish)) {
        printf("ENGINE_set_finish_function failed\n");
        goto end;
    }

//    if (!ERR_load_SUOLA_strings()) {
//        errorf("ERR_load_SUOLA_strings failed\n");
//        goto end;
//    }

    if (!_register_nids()) {
        printf("Failure registering NIDs\n");
        goto end;
    } else {
        // printf("\nregistered nids\n");
        pkey_meth_nids_init();
        pkey_asn1_meth_nids_init();
        digest_nids_init();
    }

    if (!register_methods()) {
        printf("Failure registering methods\n");
        goto end;
    }

    if (!ENGINE_set_pkey_asn1_meths(e, pkey_asn1_meths)) {
        printf("ENGINE_set_pkey_asn1_meths failed\n");
        goto end;
    }


    if (!ENGINE_set_pkey_meths(e, pkey_meths)) {
        printf("ENGINE_set_pkey_meths failed\n");
        goto end;
    }
    //  || !EVP_add_digest(md_obj)
    // if(!ENGINE_register_digests(e)){
    //     printf("failed\n");
    //     goto end;
    // }
    // if (!ENGINE_set_digests(e, setup_digest)){
    //     if (!md_obj)
    //         ps(md_obj);
    //     printf("ENGINE_set_digests failed\n");
    //     goto end;
    // }
    // else{
    //     if(md_obj){
    //         printf("\nnot null\n");
    //     }
    // }
    
    // ENGINE_register_all_complete();
//    if (suola_implementation_init() != 0) {       // TODO: figure this out
//        errorf("suola_implementation_init failed\n");
//        goto end;
//    }

    ret = 1;
    end:
    return ret;
}


static int pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth, const int **nids, int nid){
    if (!pmeth){
        *nids = pkey_meth_nids;
        return sizeof_static_array(pkey_meth_nids) - 1;
    }
    if (nid == NID_ROUND5){
        *pmeth = pmeth_round5;
        return 1;
    }
    else if(nid == NID_DILITHIUM){
        *pmeth = pmeth_dilithium;
        return 1;
    }
    *pmeth = NULL;
    return 0;
}

static int register_pmeth(int id, EVP_PKEY_METHOD **pmeth, int flags){
    *pmeth = EVP_PKEY_meth_new(id, flags);
    if (*pmeth == NULL)
        return 0;
    if (id == NID_ROUND5){
        pki_register_round5(*pmeth);
        // EVP_PKEY_meth_set_sign(pmeth, NULL, dilithium_sign);
    }
    else if(id == NID_DILITHIUM){
        pki_register_dilithium(*pmeth);
    }
    else{
        EVP_PKEY_meth_free(*pmeth); 
        return 0;
    }
    return 1;
}

static int pkey_asn1_meths(ENGINE *e, EVP_PKEY_ASN1_METHOD **ameth, const int **nids, int nid){
    if (!ameth){
        pkey_asn1_meth_nids_init();
        *nids = pkey_asn1_meth_nids;
        // printf("\nsize: %d\n", sizeof_static_array(pkey_asn1_meth_nids));
        // printf("\nnids[0]: %d\n", *nids[0]);
        // printf("\nnids[1]: %d\n", *nids[1]);
        return sizeof_static_array(pkey_asn1_meth_nids);
    }
    if (nid == NID_ROUND5){
        *ameth = ameth_round5;
        return 1;
    }
    else if(nid == NID_DILITHIUM){
        *ameth = ameth_dilithium;
        return 1;
    }
    *ameth = NULL;
    return 0;
}

static int register_ameth(int id, EVP_PKEY_ASN1_METHOD **ameth, int flags){
    const char *pem_str = NULL;
    const char *info = NULL;
    if (!ameth)
        return 0;
    pem_str = OBJ_nid2sn(id);
    info = OBJ_nid2ln(id);
    // ps(pem_str);
    return _register_asn1_meth(id, ameth, pem_str, info);
}

// int register_md_identity(EVP_MD *md){
//     // printf("\nreached register_md_identify\n");
//     if ((md = EVP_MD_meth_new(NID_KECCAK, NID_undef)) == NULL
//         || !EVP_MD_meth_set_result_size(md, sizeof(struct digest_init_ctx))
//         //|| !EVP_MD_meth_set_input_blocksize(md, sizeof(struct digest_init_ctx))
//         || !EVP_MD_meth_set_app_datasize(md, sizeof(struct digest_init_ctx))
//         || !EVP_MD_meth_set_init(md, keccak_digest_init)
//         || !EVP_MD_meth_set_update(md, keccak_digest_update)
//         || !EVP_MD_meth_set_final(md, keccak_digest_final)
//         || !EVP_MD_meth_set_copy(md, keccak_digest_copy)
//         || !EVP_MD_meth_set_cleanup(md, keccak_digest_cleanup)) {
//         EVP_MD_meth_free(md);
//         md = NULL;
//         // printf("\nregistration failed\n");
//         return 0;
//     }
//     // printf("\nregistration succeeded\n");
//     return 1;
// }

static int register_md(int md_id, int pkey_type, EVP_MD **md, int flags)
{
    int ret = 0;
    // printf("registering md method for '%s' with md_id=%d, pkey_type=%d, flags=%08x\n",
            // OBJ_nid2ln(md_id), md_id, pkey_type, flags);

    *md = EVP_MD_meth_new(md_id, pkey_type);

    if (*md == NULL)
        return 0;
    //printf("\nmd is not null\n");
    if ( md_id == NID_KECCAK ) {
        md_obj = digest();
        // printf("\nmd: %s\n", OBJ_nid2ln(NID_KECCAK));
        ret = 1;
    }

    if (ret == 1) {
        //printf("\n\n\n\n\n\n\n\n\n\n\nworked\n\n\n\n\n\n\n\n\n\n\n\n");
        ret = EVP_add_digest(md_obj);
        //free(*md);
        return ret;
    }
    EVP_MD_meth_free(*md);
    /* Unsupported md type */
    return 0;
}

static int register_methods(){
    if (!register_ameth(NID_ROUND5, &ameth_round5, 0)){
        return 0;
    }
    if (!register_pmeth(NID_ROUND5, &pmeth_round5, 0)){
        return 0;
    }
    // if (!register_md(NID_KECCAK, NID_ROUND5, &md_obj, 0)){
    //     return 0;
    // }
    if (!register_pmeth(NID_DILITHIUM, &pmeth_dilithium, 0)){
        return 0;
    }
    if (!register_ameth(NID_DILITHIUM, &ameth_dilithium, 0)){
        return 0;
    }
    if (!register_ameth(NID_KECCAK, &ameth_keccak, 0)){
        return 0;
    }
    // EVP_MD_meth_free(md_obj);
    return 1;
}



IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind)

