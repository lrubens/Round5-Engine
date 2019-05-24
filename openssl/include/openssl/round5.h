//
// Created by ruben on 5/21/2019.
//

#ifndef POST_QUANTUM_PKI_ROUND5_H
#define POST_QUANTUM_PKI_ROUND5_H
#include <openssl/opensslconf.h>
#include "../../../liboqs/src/kem/round5/upstream/reference/src/parameters.h"

typedef struct ROUND5{
    parameters * params, non_api_params;
    unsigned char *sk;
    unsigned char *pk;
};

int setup(parameters * params);
int keygen(unsigned char *pk, unsigned char *sk, parameters * params);
int encrypt(unsigned char *ct, unsigned long long &ct_len, const unsigned char *message, const unsigned long long m_len, unsigned char *pk, parameters *params);
int decrypt(unsigned char *m, unsigned long long m_len, unsigned char *ct, unsigned long long ct_len, unsigned char *sk, parameters *params);

#endif //POST_QUANTUM_PKI_ROUND5_H
