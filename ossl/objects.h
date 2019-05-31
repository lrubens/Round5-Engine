//
// Created by ruben on 5/23/2019.
//

#ifndef ROUND5_OBJECTS_H
#define ROUND5_OBJECTS_H

#include <openssl/objects.h>

#ifdef NID_ROUND5
#undef NID_ROUND5
#endif

extern int NID_ROUND5;

int _register_nids();
int get_nid();

#endif //ROUND5_OBJECTS_H
