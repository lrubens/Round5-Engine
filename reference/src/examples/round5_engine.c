//
// Created by ruben on 5/24/2019.
//

#include <string.h>
#include <openssl/engine.h>
#include <openssl/obj_mac.h>
#include "../../../ossl/ossl_compat.h"
#include "../../../meths/round5_meth.h"
#include "../../../meths/asn1_meth.h"
#include "../../../ossl/objects.h"
//#include "
#ifndef ENGINE_ID
#define ENGINE_ID "round5"
#endif
#define NID_ROUND5 1
#ifndef ENGINE_NAME
#define ENGINE_NAME "An engine integrating round5 into OpenSSL"
#endif

static const char *engine_id = ENGINE_ID;
static const char *engine_name = ENGINE_NAME;

static int register_methods();
static int pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth, const int **nids, int nid);
static int pkey_meth_nids[] = {
        0,   //NID_ROUND5
        0    //NID_DILITHIUM to be integrated later
};

static void pkey_meth_nids_init(){
    pkey_meth_nids[0] = NID_ROUND5;
//    pkey_meth_nids[1] = NID_DILITHIUM     to be added later
}
static int pkey_asn1_meths(ENGINE *e, EVP_PKEY_ASN1_METHOD **ameth, const int **nids, int nid);
static EVP_PKEY_METHOD *pmeth_round5 = NULL;

static int register_ameth(int id, EVP_PKEY_ASN1_METHOD **ameth, int flags);

static int pkey_asn1_meth_nids[] = {
        0,
        0
};

static void pkey_asn1_meth_nids_init(){
    pkey_asn1_meth_nids[0] = NID_ROUND5;
}

static EVP_PKEY_ASN1_METHOD *ameth_round5 = NULL;

static int e_init(ENGINE *e){
    return 1;
}

static int e_destroy(ENGINE *e){
    OBJ_cleanup();
    return 1;
}

static int e_finish(ENGINE *e){
    return 1;
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
        pkey_meth_nids_init();
        pkey_asn1_meth_nids_init();
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
        return sizeof(pkey_meth_nids) - 1;
    }
    if (nid == NID_ROUND5){
        *pmeth = pmeth_round5;
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
    }
    else
        return 0;
    return 1;
}

static int pkey_asn1_meths(ENGINE *e, EVP_PKEY_ASN1_METHOD **ameth, const int **nids, int nid){
    if (!ameth){
        *nids = pkey_asn1_meth_nids;
        return sizeof(pkey_asn1_meth_nids) - 1;
    }
    if (nid == NID_ROUND5){
        *ameth = ameth_round5;
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
    return _register_asn1_meth(id, ameth, pem_str, info);
}

static int register_methods(){
    if (!register_ameth(NID_ROUND5, &ameth_round5, 0)){
        return 0;
    }
    if (!register_pmeth(NID_ROUND5, &pmeth_round5, 0)){
        return 0;
    }
    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind)
