#include "code.h"
#include "gf2x.h"
#include "hqc.h"
#include "parameters.h"
#include "parsing.h"
#include "randombytes.h"
#include "shake_prng.h"
#include <stdint.h>
#include <stdio.h>
#include "api.h"
#include "sha2.h"
#include "fips202.h"
#include "domains.h"
#include "shake_ds.h"
#include "vector.h"
#include <string.h>

int main() {

	unsigned char pk[PUBLIC_KEY_BYTES];
	unsigned char sk[SECRET_KEY_BYTES];
	unsigned char ct[CIPHERTEXT_BYTES];
	unsigned char key1[SHARED_SECRET_BYTES];
	unsigned char key2[SHARED_SECRET_BYTES];
	
	//----------------- KeyGen ----------------------
	PQCLEAN_HQC128_CLEAN_crypto_kem_keypair(pk, sk);
	
	//----------------- Encryption ----------------------
	PQCLEAN_HQC128_CLEAN_crypto_kem_enc(ct, key1, pk);

	//----------------- Decryption ----------------------
	int result = PQCLEAN_HQC128_CLEAN_crypto_kem_dec(key2, ct, sk);
	
	if(result == 0)
		printf("\nTest passed successfully.\n");
	else
		printf("\nTest failed.\n");

	return 0;
}
