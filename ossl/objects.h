//
// Created by ruben on 5/23/2019.
//

#ifndef ROUND5_OBJECTS_H
#define ROUND5_OBJECTS_H

#include <openssl/objects.h>

#ifdef NID_ROUND5
#undef NID_ROUND5
#endif
#ifdef NID_KECCAK
#undef NID_KECCAK
#endif
#ifdef NID_DILITHIUM
#undef NID_DILITHIUM
#endif

extern int NID_ROUND5;
extern int NID_KECCAK;
extern int NID_DILITHIUM;

int _register_nids();
int get_nid();

#endif //ROUND5_OBJECTS_H
