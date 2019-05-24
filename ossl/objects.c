//
// Created by ruben on 5/24/2019.
//

#include "objects.h"
#include "objects_internal.h"

int NID_ROUND5;


static int _register_nid(const char *oid_str, const char *sn, const char *ln) {
    int new_nid = NID_undef;

    if (NID_undef != (new_nid = OBJ_sn2nid(sn)) ) {
        debug("'%s' is already registered with NID %d\n", sn, new_nid);
        return new_nid;
    }

    new_nid = OBJ_create(oid_str, sn, ln);

    if (new_nid == NID_undef) {
        fatalf("Failed to register NID for '%s'\n", ln);
        return 0;
    }
    debug("Registered '%s' with NID %d\n", sn, new_nid);

    ASN1_OBJECT *obj = OBJ_nid2obj(new_nid);
    if ( !obj ) {
        fatalf("Failed to retrieve ASN1_OBJECT for dynamically registered NID\n");
        return 0;
    }

    return new_nid;
}

#define _REGISTER_NID(___BASENAME) \
    if ( NID_undef == (NID_##___BASENAME = _register_nid(  _OID_##___BASENAME, \
                                                                 _SN_##___BASENAME , \
                                                                 _LN_##___BASENAME ))\
       ) { \
        errorf("Failed to register NID for '%s'\n", suola_SN_##___BASENAME ); \
        return 0; \
    }


int _register_nids()
{
    _REGISTER_NID(ROUND5);

//    SUOLA_REGISTER_NID(ED25519);

    return 1;
}