#include <stdlib.h>
#include <oqs/kem_round5.h>
#include "upstream/reference/src/r5_cpa_kem.h"
#include "upstream/reference/src/r5_cca_pke.h"
#include "upstream/reference/src/misc.h"
#include "upstream/reference/src/r5_memory.h"
#include "upstream/reference/src/parameters.h"
#include "upstream/reference/src/rng.h"
#include "upstream/reference/src/a_fixed.h"

#ifdef OQS_ENABLE_KEM_round5

OQS_KEM *OQS_KEM_round5_new() {

	OQS_KEM *kem = malloc(sizeof(OQS_KEM));
	if (kem == NULL) {
		return NULL;
	}
	kem->method_name = OQS_KEM_alg_round5;
	kem->alg_version = "";

	kem->claimed_nist_level = 1;
	kem->ind_cca = true;

	kem->length_public_key = OQS_KEM_round5_length_public_key;
	kem->length_secret_key = OQS_KEM_round5_length_secret_key;
	kem->length_ciphertext = OQS_KEM_round5_length_ciphertext;
	kem->length_shared_secret = OQS_KEM_round5_length_shared_secret;

	kem->keypair = OQS_KEM_round5_keypair;
	kem->encaps = OQS_KEM_round5_encaps;
	kem->decaps = OQS_KEM_round5_decaps;

	return kem;
}

#endif
