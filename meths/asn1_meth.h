//
// Created by ruben on 5/23/2019.
//

#ifndef ROUND5_ASN1_METH_H
#define ROUND5_ASN1_METH_H

#include <openssl/evp.h>

int _register_asn1_meth(int nid, EVP_PKEY_ASN1_METHOD **ameth, const char *pem_str, const char *info);

#endif //ROUND5_ASN1_METH_H
