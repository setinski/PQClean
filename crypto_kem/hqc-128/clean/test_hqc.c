#include "code.h"
#include "gf2x.h"
#include "hqc.h"
#include "parameters.h"
#include "parsing.h"
#include "randombytes.h"
#include "shake_prng.h"
#include "api.h"
#include "sha2.h"
#include "fips202.h"
#include "domains.h"
#include "shake_ds.h"
#include "vector.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define NOINLINE __attribute__((noinline))

shake256incctx shake256state;

typedef struct {
    uint8_t sk_seed[SEED_BYTES];
    uint8_t sigma[VEC_K_SIZE_BYTES];
    uint8_t pk_seed[SEED_BYTES];

    uint64_t x[VEC_N_SIZE_64];
    uint64_t y[VEC_N_SIZE_64];
    uint64_t h[VEC_N_SIZE_64];
    uint64_t s[VEC_N_SIZE_64];

    uint8_t pk[PUBLIC_KEY_BYTES];
    uint8_t sk[SECRET_KEY_BYTES];

    uint8_t m[VEC_K_SIZE_BYTES];
    uint8_t salt[SALT_SIZE_BYTES];
    uint8_t theta[SHAKE256_512_BYTES];

    uint64_t r1[VEC_N_SIZE_64];
    uint64_t r2[VEC_N_SIZE_64];
    uint64_t e[VEC_N_SIZE_64];

    uint64_t u[VEC_N_SIZE_64];
    uint64_t v[VEC_N1N2_SIZE_64];

    uint8_t ct[CIPHERTEXT_BYTES];
    uint8_t key1[SHARED_SECRET_BYTES];
    uint8_t key2[SHARED_SECRET_BYTES];

    uint8_t mc[VEC_K_SIZE_BYTES + VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES];
    uint8_t tmp1[VEC_N_SIZE_BYTES];
    uint8_t tmp2[VEC_N_SIZE_BYTES];
    uint8_t pkk[PUBLIC_KEY_BYTES];
} HQCTestContext;

unsigned char pk[PUBLIC_KEY_BYTES];
unsigned char sk[SECRET_KEY_BYTES];
unsigned char ct[CIPHERTEXT_BYTES];

unsigned char key1[SHARED_SECRET_BYTES];
unsigned char key2[SHARED_SECRET_BYTES];

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

uint64_t r1[VEC_N_SIZE_64] = {0};
uint64_t r2[VEC_N_SIZE_64] = {0};
uint64_t e[VEC_N_SIZE_64] = {0};

uint8_t mc[VEC_K_SIZE_BYTES + VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES] = {0};
uint8_t tmp[VEC_K_SIZE_BYTES + PUBLIC_KEY_BYTES + SALT_SIZE_BYTES] = {0};
uint8_t *m = tmp;
uint8_t *salt = tmp + VEC_K_SIZE_BYTES + PUBLIC_KEY_BYTES;

uint64_t tmp1[VEC_N_SIZE_64] = {0};
uint64_t tmp2[VEC_N_SIZE_64] = {0};

uint8_t result = 0;
uint64_t u2[VEC_N_SIZE_64] = {0};
uint64_t v2[VEC_N1N2_SIZE_64] = {0};
uint8_t *mm = tmp;
	
uint8_t pkk[PUBLIC_KEY_BYTES] = {0};


/* ======== Key Generation ======== */
static NOINLINE void keygen_generate_seeds() {
    randombytes(sk_seed, SEED_BYTES);
    randombytes(sigma, VEC_K_SIZE_BYTES);
    randombytes(pk_seed, SEED_BYTES);
}

static NOINLINE void keygen_generate_x_y() {
    seedexpander_state sk_seedexpander;
	
    PQCLEAN_HQC128_CLEAN_seedexpander_init(&sk_seedexpander, sk_seed, SEED_BYTES);
    PQCLEAN_HQC128_CLEAN_vect_set_random_fixed_weight(&sk_seedexpander, x, PARAM_OMEGA);
    PQCLEAN_HQC128_CLEAN_vect_set_random_fixed_weight(&sk_seedexpander, y, PARAM_OMEGA);
	
    PQCLEAN_HQC128_CLEAN_seedexpander_release(&sk_seedexpander);
}

static NOINLINE void keygen_generate_h() {
    seedexpander_state pk_seedexpander;
	
    PQCLEAN_HQC128_CLEAN_seedexpander_init(&pk_seedexpander, pk_seed, SEED_BYTES);
    PQCLEAN_HQC128_CLEAN_vect_set_random(&pk_seedexpander, h);
	
    PQCLEAN_HQC128_CLEAN_seedexpander_release(&pk_seedexpander);
}

static NOINLINE void keygen_compute_s() {
    PQCLEAN_HQC128_CLEAN_vect_mul(s, y, h);
    PQCLEAN_HQC128_CLEAN_vect_add(s, x, s, VEC_N_SIZE_64);
}

static NOINLINE void keygen_pack_keys() {
    PQCLEAN_HQC128_CLEAN_hqc_public_key_to_string(pk, pk_seed, s);
    PQCLEAN_HQC128_CLEAN_hqc_secret_key_to_string(sk, sk_seed, sigma, pk);
}

/* ======== Encryption ======== */

static NOINLINE void enc_generate_m_and_salt() {
    randombytes(m, VEC_K_SIZE_BYTES);
    randombytes(salt, SALT_SIZE_BYTES);
}

static NOINLINE void enc_compute_theta() {
    memcpy(tmp + VEC_K_SIZE_BYTES, pk, PUBLIC_KEY_BYTES);
	
    PQCLEAN_HQC128_CLEAN_shake256_512_ds(&shake256state, theta, tmp, VEC_K_SIZE_BYTES + PUBLIC_KEY_BYTES + SALT_SIZE_BYTES, G_FCT_DOMAIN);
}

static NOINLINE void enc_generate_r1_r2_e() {
    seedexpander_state vec_seedexpander;
	
    PQCLEAN_HQC128_CLEAN_seedexpander_init(&vec_seedexpander, theta, SEED_BYTES);
	
    PQCLEAN_HQC128_CLEAN_vect_set_random_fixed_weight(&vec_seedexpander, r1, PARAM_OMEGA_R);
	PQCLEAN_HQC128_CLEAN_vect_set_random_fixed_weight(&vec_seedexpander, r2, PARAM_OMEGA_R);
	PQCLEAN_HQC128_CLEAN_vect_set_random_fixed_weight(&vec_seedexpander, e, PARAM_OMEGA_E);
	
    PQCLEAN_HQC128_CLEAN_seedexpander_release(&vec_seedexpander);
}

static NOINLINE void enc_compute_u() {
    PQCLEAN_HQC128_CLEAN_hqc_public_key_from_string(h, s, pk);
	
    PQCLEAN_HQC128_CLEAN_vect_mul(u, r2, h);
	PQCLEAN_HQC128_CLEAN_vect_add(u, r1, u, VEC_N_SIZE_64);
}

static NOINLINE void enc_compute_v() {
    PQCLEAN_HQC128_CLEAN_code_encode(v, m);
	PQCLEAN_HQC128_CLEAN_vect_resize(tmp1, PARAM_N, v, PARAM_N1N2);
	
    PQCLEAN_HQC128_CLEAN_vect_mul(tmp2, r2, s);
	PQCLEAN_HQC128_CLEAN_vect_add(tmp2, e, tmp2, VEC_N_SIZE_64);
	PQCLEAN_HQC128_CLEAN_vect_add(tmp2, tmp1, tmp2, VEC_N_SIZE_64);
	PQCLEAN_HQC128_CLEAN_vect_resize(v, PARAM_N1N2, tmp2, PARAM_N);
}

static NOINLINE void enc_compute_shared_secret() {
    memcpy(mc, m, VEC_K_SIZE_BYTES);
    PQCLEAN_HQC128_CLEAN_store8_arr(mc + VEC_K_SIZE_BYTES, VEC_N_SIZE_BYTES, u, VEC_N_SIZE_64);
    PQCLEAN_HQC128_CLEAN_store8_arr(mc + VEC_K_SIZE_BYTES + VEC_N_SIZE_BYTES, VEC_N1N2_SIZE_BYTES, v, VEC_N1N2_SIZE_64);
    PQCLEAN_HQC128_CLEAN_shake256_512_ds(&shake256state, key1, mc, VEC_K_SIZE_BYTES + VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES, K_FCT_DOMAIN);
}

static NOINLINE void enc_pack_ciphertext() {
    PQCLEAN_HQC128_CLEAN_hqc_ciphertext_to_string(ct, u, v, salt);
}

/* ======== Decryption ======== */

static NOINLINE void dec_unpack_ciphertext() {
    PQCLEAN_HQC128_CLEAN_hqc_ciphertext_from_string(u, v, salt, ct);
}

static NOINLINE void dec_unpack_secret_key() {
    PQCLEAN_HQC128_CLEAN_hqc_secret_key_from_string(x, y, sigma, pkk, sk);
}

static NOINLINE void dec_compute_tmp2_for_decoding() {
    PQCLEAN_HQC128_CLEAN_vect_resize(tmp1, PARAM_N, v, PARAM_N1N2);
	PQCLEAN_HQC128_CLEAN_vect_mul(tmp2, y, u);
	PQCLEAN_HQC128_CLEAN_vect_add(tmp2, tmp1, tmp2, VEC_N_SIZE_64);
}

static NOINLINE void dec_decode_message() {
    PQCLEAN_HQC128_CLEAN_code_decode(mm, tmp2);
}

static NOINLINE void dec_rederive_theta() {
    memcpy(tmp + VEC_K_SIZE_BYTES, pkk, PUBLIC_KEY_BYTES);
    PQCLEAN_HQC128_CLEAN_shake256_512_ds(&shake256state, theta, tmp, VEC_K_SIZE_BYTES + PUBLIC_KEY_BYTES + SALT_SIZE_BYTES, G_FCT_DOMAIN);
}

static NOINLINE void dec_reencrypt() {
    PQCLEAN_HQC128_CLEAN_hqc_pke_encrypt(u2, v2, mm, theta, pkk);
}

static NOINLINE void dec_constant_time_check() {
    result |= PQCLEAN_HQC128_CLEAN_vect_compare((uint8_t *)u, (uint8_t *)u2, VEC_N_SIZE_BYTES);
    result |= PQCLEAN_HQC128_CLEAN_vect_compare((uint8_t *)v, (uint8_t *)v2, VEC_N1N2_SIZE_BYTES);

    result -= 1;
}

static NOINLINE void dec_select_message() {
    for (size_t i = 0; i < VEC_K_SIZE_BYTES; ++i) {
        mc[i] = (mm[i] & result) ^ (sigma[i] & ~result);
    }

}

static NOINLINE void dec_finalize_shared_secret() {
    PQCLEAN_HQC128_CLEAN_store8_arr(mc + VEC_K_SIZE_BYTES, VEC_N_SIZE_BYTES, u, VEC_N_SIZE_64);
    PQCLEAN_HQC128_CLEAN_store8_arr(mc + VEC_K_SIZE_BYTES + VEC_N_SIZE_BYTES, VEC_N1N2_SIZE_BYTES, v, VEC_N1N2_SIZE_64);
    PQCLEAN_HQC128_CLEAN_shake256_512_ds(&shake256state, key2, mc, VEC_K_SIZE_BYTES + VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES, K_FCT_DOMAIN);
}


/* ======== Main ======== */

int main() {
    //HQCTestContext ctx = {0};

    // Key Generation
    keygen_generate_seeds();
    keygen_generate_x_y();
    keygen_generate_h();
    keygen_compute_s();
    keygen_pack_keys();

    // Encryption
    enc_generate_m_and_salt();
    enc_compute_theta();
    enc_generate_r1_r2_e();
    enc_compute_u();
    enc_compute_v();
	enc_compute_shared_secret();
    enc_pack_ciphertext();

    // Decryption
	dec_unpack_ciphertext();
	dec_unpack_secret_key();
	dec_compute_tmp2_for_decoding();
	dec_decode_message();
	dec_rederive_theta();
	dec_reencrypt();
	dec_constant_time_check();
	dec_select_message();
	dec_finalize_shared_secret();

    return 0;
}

