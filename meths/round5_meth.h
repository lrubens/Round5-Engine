//
// Created by ruben on 5/23/2019.
//

#ifndef ROUND5_ROUND5_METH_H
#define ROUND5_ROUND5_METH_H

#include <openssl/evp.h>
void pki_register_round5(EVP_PKEY_METHOD *pmeth);
static int keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
static int init_round5();

#endif //ROUND5_ROUND5_METH_H
