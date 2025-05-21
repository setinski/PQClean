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
	//printf("%d\n", PUBLIC_KEY_BYTES);
	//printf("%d\n", SECRET_KEY_BYTES);
	//printf("%d\n", CIPHERTEXT_BYTES);
	//printf("%d\n", SHARED_SECRET_BYTES);
	
	uint8_t sk_seed[SEED_BYTES] = {0};
    uint8_t sigma[VEC_K_SIZE_BYTES] = {0};
    uint8_t pk_seed[SEED_BYTES] = {0};
	
    uint64_t x[VEC_N_SIZE_64] = {0};
    uint64_t y[VEC_N_SIZE_64] = {0};
    uint64_t h[VEC_N_SIZE_64] = {0};
    uint64_t s[VEC_N_SIZE_64] = {0};
	
	uint8_t theta[SHAKE256_512_BYTES] = {0};
    uint64_t u[VEC_N_SIZE_64] = {0};
    uint64_t v[VEC_N1N2_SIZE_64] = {0};
    uint8_t mc[VEC_K_SIZE_BYTES + VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES] = {0};
    uint8_t tmp[VEC_K_SIZE_BYTES + PUBLIC_KEY_BYTES + SALT_SIZE_BYTES] = {0};
    uint8_t *m = tmp;
    uint8_t *salt = tmp + VEC_K_SIZE_BYTES + PUBLIC_KEY_BYTES;
	
	uint64_t r1[VEC_N_SIZE_64] = {0};
	uint64_t r2[VEC_N_SIZE_64] = {0};
	uint64_t e[VEC_N_SIZE_64] = {0};
	uint64_t tmp1[VEC_N_SIZE_64] = {0};
	uint64_t tmp2[VEC_N_SIZE_64] = {0};
	
	uint8_t result;
    uint64_t u2[VEC_N_SIZE_64] = {0};
    uint64_t v2[VEC_N1N2_SIZE_64] = {0};
    uint8_t *mm = tmp;
	
	uint8_t pkk[PUBLIC_KEY_BYTES] = {0};
	
	//----------------- KeyGen ----------------------
	//PQCLEAN_HQC128_CLEAN_crypto_kem_keypair(pk, sk);
	
	seedexpander_state sk_seedexpander;
    seedexpander_state pk_seedexpander;
    

    // Create seed_expanders for public key and secret key
    randombytes(sk_seed, SEED_BYTES);
    randombytes(sigma, VEC_K_SIZE_BYTES);
    PQCLEAN_HQC128_CLEAN_seedexpander_init(&sk_seedexpander, sk_seed, SEED_BYTES);

    randombytes(pk_seed, SEED_BYTES);
    PQCLEAN_HQC128_CLEAN_seedexpander_init(&pk_seedexpander, pk_seed, SEED_BYTES);

    // Compute secret key
    PQCLEAN_HQC128_CLEAN_vect_set_random_fixed_weight(&sk_seedexpander, x, PARAM_OMEGA);
    PQCLEAN_HQC128_CLEAN_vect_set_random_fixed_weight(&sk_seedexpander, y, PARAM_OMEGA);

    // Compute public key
    PQCLEAN_HQC128_CLEAN_vect_set_random(&pk_seedexpander, h);
    PQCLEAN_HQC128_CLEAN_vect_mul(s, y, h);
    PQCLEAN_HQC128_CLEAN_vect_add(s, x, s, VEC_N_SIZE_64);

    // Parse keys to string
    PQCLEAN_HQC128_CLEAN_hqc_public_key_to_string(pk, pk_seed, s);
    PQCLEAN_HQC128_CLEAN_hqc_secret_key_to_string(sk, sk_seed, sigma, pk);

    PQCLEAN_HQC128_CLEAN_seedexpander_release(&pk_seedexpander);
    PQCLEAN_HQC128_CLEAN_seedexpander_release(&sk_seedexpander);
	
	//----------------- Encryption ----------------------
	//PQCLEAN_HQC128_CLEAN_crypto_kem_enc(ct, key1, pk);

    shake256incctx shake256state;

    // Computing m
    randombytes(m, VEC_K_SIZE_BYTES);

    // Computing theta
    randombytes(salt, SALT_SIZE_BYTES);
    memcpy(tmp + VEC_K_SIZE_BYTES, pk, PUBLIC_KEY_BYTES);
    PQCLEAN_HQC128_CLEAN_shake256_512_ds(&shake256state, theta, tmp, VEC_K_SIZE_BYTES + PUBLIC_KEY_BYTES + SALT_SIZE_BYTES, G_FCT_DOMAIN);

    // Encrypting m
	//PQCLEAN_HQC128_CLEAN_hqc_pke_encrypt(u, v, m, theta, pk);
	
	seedexpander_state vec_seedexpander;

	// Create seed_expander from theta
	PQCLEAN_HQC128_CLEAN_seedexpander_init(&vec_seedexpander, theta, SEED_BYTES);

	// Retrieve h and s from public key
	PQCLEAN_HQC128_CLEAN_hqc_public_key_from_string(h, s, pk);

	// Generate r1, r2 and e
	PQCLEAN_HQC128_CLEAN_vect_set_random_fixed_weight(&vec_seedexpander, r1, PARAM_OMEGA_R);
	PQCLEAN_HQC128_CLEAN_vect_set_random_fixed_weight(&vec_seedexpander, r2, PARAM_OMEGA_R);
	PQCLEAN_HQC128_CLEAN_vect_set_random_fixed_weight(&vec_seedexpander, e, PARAM_OMEGA_E);

	// Compute u = r1 + r2.h
	PQCLEAN_HQC128_CLEAN_vect_mul(u, r2, h);
	PQCLEAN_HQC128_CLEAN_vect_add(u, r1, u, VEC_N_SIZE_64);

	// Compute v = m.G by encoding the message
	PQCLEAN_HQC128_CLEAN_code_encode(v, m);
	PQCLEAN_HQC128_CLEAN_vect_resize(tmp1, PARAM_N, v, PARAM_N1N2);

	// Compute v = m.G + s.r2 + e
	PQCLEAN_HQC128_CLEAN_vect_mul(tmp2, r2, s);
	PQCLEAN_HQC128_CLEAN_vect_add(tmp2, e, tmp2, VEC_N_SIZE_64);
	PQCLEAN_HQC128_CLEAN_vect_add(tmp2, tmp1, tmp2, VEC_N_SIZE_64);
	PQCLEAN_HQC128_CLEAN_vect_resize(v, PARAM_N1N2, tmp2, PARAM_N);

	PQCLEAN_HQC128_CLEAN_seedexpander_release(&vec_seedexpander);
	
	// Computing shared secret
    memcpy(mc, m, VEC_K_SIZE_BYTES);
    PQCLEAN_HQC128_CLEAN_store8_arr(mc + VEC_K_SIZE_BYTES, VEC_N_SIZE_BYTES, u, VEC_N_SIZE_64);
    PQCLEAN_HQC128_CLEAN_store8_arr(mc + VEC_K_SIZE_BYTES + VEC_N_SIZE_BYTES, VEC_N1N2_SIZE_BYTES, v, VEC_N1N2_SIZE_64);
    PQCLEAN_HQC128_CLEAN_shake256_512_ds(&shake256state, key1, mc, VEC_K_SIZE_BYTES + VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES, K_FCT_DOMAIN);

    // Computing ciphertext
    PQCLEAN_HQC128_CLEAN_hqc_ciphertext_to_string(ct, u, v, salt);


	//----------------- Decryption ----------------------
	//PQCLEAN_HQC128_CLEAN_crypto_kem_dec(key2, ct, sk);

    // Retrieving u, v and d from ciphertext
    PQCLEAN_HQC128_CLEAN_hqc_ciphertext_from_string(u, v, salt, ct);

    // Decrypting
    //result = PQCLEAN_HQC128_CLEAN_hqc_pke_decrypt(m, sigma, u, v, sk);

	// Retrieve x, y, pk from secret key
	PQCLEAN_HQC128_CLEAN_hqc_secret_key_from_string(x, y, sigma, pkk, sk);

	// Compute v - u.y
	PQCLEAN_HQC128_CLEAN_vect_resize(tmp1, PARAM_N, v, PARAM_N1N2);
	PQCLEAN_HQC128_CLEAN_vect_mul(tmp2, y, u);
	PQCLEAN_HQC128_CLEAN_vect_add(tmp2, tmp1, tmp2, VEC_N_SIZE_64);


	// Compute m by decoding v - u.y
	PQCLEAN_HQC128_CLEAN_code_decode(mm, tmp2);
		
	result = 0;

    // Computing theta
    memcpy(tmp + VEC_K_SIZE_BYTES, pkk, PUBLIC_KEY_BYTES);
    PQCLEAN_HQC128_CLEAN_shake256_512_ds(&shake256state, theta, tmp, VEC_K_SIZE_BYTES + PUBLIC_KEY_BYTES + SALT_SIZE_BYTES, G_FCT_DOMAIN);

    // Encrypting m'
    PQCLEAN_HQC128_CLEAN_hqc_pke_encrypt(u2, v2, mm, theta, pkk);

    // Check if c != c'
    result |= PQCLEAN_HQC128_CLEAN_vect_compare((uint8_t *)u, (uint8_t *)u2, VEC_N_SIZE_BYTES);
    result |= PQCLEAN_HQC128_CLEAN_vect_compare((uint8_t *)v, (uint8_t *)v2, VEC_N1N2_SIZE_BYTES);

    result -= 1;

    for (size_t i = 0; i < VEC_K_SIZE_BYTES; ++i) {
        mc[i] = (mm[i] & result) ^ (sigma[i] & ~result);
    }

    // Computing shared secret
    PQCLEAN_HQC128_CLEAN_store8_arr(mc + VEC_K_SIZE_BYTES, VEC_N_SIZE_BYTES, u, VEC_N_SIZE_64);
    PQCLEAN_HQC128_CLEAN_store8_arr(mc + VEC_K_SIZE_BYTES + VEC_N_SIZE_BYTES, VEC_N1N2_SIZE_BYTES, v, VEC_N1N2_SIZE_64);
    PQCLEAN_HQC128_CLEAN_shake256_512_ds(&shake256state, key2, mc, VEC_K_SIZE_BYTES + VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES, K_FCT_DOMAIN);

	return 0;
}
