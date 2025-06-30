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
	
} KeygenContext;

typedef struct {
	uint8_t theta[SHAKE256_512_BYTES];
    uint64_t u[VEC_N_SIZE_64];
    uint64_t v[VEC_N1N2_SIZE_64];
    uint8_t mc[VEC_K_SIZE_BYTES + VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES];
    uint8_t tmp[VEC_K_SIZE_BYTES + PUBLIC_KEY_BYTES + SALT_SIZE_BYTES];	
	
	uint64_t h[VEC_N_SIZE_64];
    uint64_t s[VEC_N_SIZE_64];
    uint64_t r1[VEC_N_SIZE_64];
    uint64_t r2[VEC_N_SIZE_64];
    uint64_t e[VEC_N_SIZE_64];
    uint64_t tmp1[VEC_N_SIZE_64];
    uint64_t tmp2[VEC_N_SIZE_64];
} EncryptContext;

typedef struct {
	uint8_t result;
    uint64_t u[VEC_N_SIZE_64];
    uint64_t v[VEC_N1N2_SIZE_64];
    uint8_t sigma[VEC_K_SIZE_BYTES];
    uint8_t theta[SHAKE256_512_BYTES];
    uint64_t u2[VEC_N_SIZE_64];
    uint64_t v2[VEC_N1N2_SIZE_64];
    uint8_t mc[VEC_K_SIZE_BYTES + VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES];
    uint8_t tmp[VEC_K_SIZE_BYTES + PUBLIC_KEY_BYTES + SALT_SIZE_BYTES];	
	
	uint64_t x[VEC_N_SIZE_64];
    uint64_t y[VEC_N_SIZE_64];
    uint8_t pk[PUBLIC_KEY_BYTES];
    uint64_t tmp1[VEC_N_SIZE_64];
    uint64_t tmp2[VEC_N_SIZE_64];
} DecryptContext;



/* ======== Key Generation ======== */
static NOINLINE void keygen_generate_seeds(KeygenContext *ctx) {
    randombytes(ctx -> sk_seed, SEED_BYTES);                                                      
    randombytes(ctx -> sigma, VEC_K_SIZE_BYTES);                                                  
    randombytes(ctx -> pk_seed, SEED_BYTES);                                                      
}

static NOINLINE void keygen_generate_x_y(KeygenContext *ctx) {
    seedexpander_state sk_seedexpander;
	
    PQCLEAN_HQC128_CLEAN_seedexpander_init(&sk_seedexpander, ctx -> sk_seed, SEED_BYTES);         
    PQCLEAN_HQC128_CLEAN_vect_set_random_fixed_weight(&sk_seedexpander, ctx -> x, PARAM_OMEGA);   
    PQCLEAN_HQC128_CLEAN_vect_set_random_fixed_weight(&sk_seedexpander, ctx -> y, PARAM_OMEGA);   
	
    PQCLEAN_HQC128_CLEAN_seedexpander_release(&sk_seedexpander);
}

static NOINLINE void keygen_generate_h(KeygenContext *ctx) {
    seedexpander_state pk_seedexpander;
	
    PQCLEAN_HQC128_CLEAN_seedexpander_init(&pk_seedexpander, ctx -> pk_seed, SEED_BYTES);         
    PQCLEAN_HQC128_CLEAN_vect_set_random(&pk_seedexpander, ctx -> h);                             
	
    PQCLEAN_HQC128_CLEAN_seedexpander_release(&pk_seedexpander);
}

static NOINLINE void keygen_compute_s(KeygenContext *ctx) {
    PQCLEAN_HQC128_CLEAN_vect_mul(ctx -> s, ctx -> y, ctx -> h);                                  
    PQCLEAN_HQC128_CLEAN_vect_add(ctx -> s, ctx -> x, ctx -> s, VEC_N_SIZE_64);                   
}

static NOINLINE void keygen_pack_keys(KeygenContext *ctx, uint8_t *pk, uint8_t *sk) {
    PQCLEAN_HQC128_CLEAN_hqc_public_key_to_string(pk, ctx -> pk_seed, ctx -> s);                  
    PQCLEAN_HQC128_CLEAN_hqc_secret_key_to_string(sk, ctx -> sk_seed, ctx -> sigma, pk);          
}

/* ======== Encryption ======== */

static NOINLINE void enc_compute_theta(EncryptContext *ctx, const uint8_t *pk) {
    memcpy(ctx -> tmp + VEC_K_SIZE_BYTES, pk, PUBLIC_KEY_BYTES);
	
    PQCLEAN_HQC128_CLEAN_shake256_512_ds(&shake256state, ctx -> theta, ctx -> tmp, VEC_K_SIZE_BYTES + PUBLIC_KEY_BYTES + SALT_SIZE_BYTES, G_FCT_DOMAIN);
}

static NOINLINE void enc_generate_r1_r2_e(EncryptContext *ctx) {
    seedexpander_state vec_seedexpander;
	
    PQCLEAN_HQC128_CLEAN_seedexpander_init(&vec_seedexpander, ctx -> theta, SEED_BYTES);
	
    PQCLEAN_HQC128_CLEAN_vect_set_random_fixed_weight(&vec_seedexpander, ctx -> r1, PARAM_OMEGA_R);
	PQCLEAN_HQC128_CLEAN_vect_set_random_fixed_weight(&vec_seedexpander, ctx -> r2, PARAM_OMEGA_R);
	PQCLEAN_HQC128_CLEAN_vect_set_random_fixed_weight(&vec_seedexpander, ctx -> e, PARAM_OMEGA_E);
	
    PQCLEAN_HQC128_CLEAN_seedexpander_release(&vec_seedexpander);
}

static NOINLINE void enc_compute_u(EncryptContext *ctx, const uint8_t *pk) {
    PQCLEAN_HQC128_CLEAN_hqc_public_key_from_string(ctx -> h, ctx -> s, pk);
	
    PQCLEAN_HQC128_CLEAN_vect_mul(ctx -> u, ctx -> r2, ctx -> h);
	PQCLEAN_HQC128_CLEAN_vect_add(ctx -> u, ctx -> r1, ctx -> u, VEC_N_SIZE_64);
}

static NOINLINE void enc_compute_v(EncryptContext *ctx, uint8_t *m) {
    PQCLEAN_HQC128_CLEAN_code_encode(ctx -> v, m);
	PQCLEAN_HQC128_CLEAN_vect_resize(ctx -> tmp1, PARAM_N, ctx -> v, PARAM_N1N2);
	
    PQCLEAN_HQC128_CLEAN_vect_mul(ctx -> tmp2, ctx -> r2, ctx -> s);
	PQCLEAN_HQC128_CLEAN_vect_add(ctx -> tmp2, ctx -> e, ctx -> tmp2, VEC_N_SIZE_64);
	PQCLEAN_HQC128_CLEAN_vect_add(ctx -> tmp2, ctx -> tmp1, ctx -> tmp2, VEC_N_SIZE_64);
	PQCLEAN_HQC128_CLEAN_vect_resize(ctx -> v, PARAM_N1N2, ctx -> tmp2, PARAM_N);
}

static NOINLINE void enc_compute_shared_secret(EncryptContext *ctx, uint8_t *ss, uint8_t *m) {
    memcpy(ctx -> mc, m, VEC_K_SIZE_BYTES);
    PQCLEAN_HQC128_CLEAN_store8_arr(ctx -> mc + VEC_K_SIZE_BYTES, VEC_N_SIZE_BYTES, ctx -> u, VEC_N_SIZE_64);
    PQCLEAN_HQC128_CLEAN_store8_arr(ctx -> mc + VEC_K_SIZE_BYTES + VEC_N_SIZE_BYTES, VEC_N1N2_SIZE_BYTES, ctx -> v, VEC_N1N2_SIZE_64);
    PQCLEAN_HQC128_CLEAN_shake256_512_ds(&shake256state, ss, ctx -> mc, VEC_K_SIZE_BYTES + VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES, K_FCT_DOMAIN);
}

static NOINLINE void enc_pack_ciphertext(EncryptContext *ctx, uint8_t *ct, uint8_t *salt) {
    PQCLEAN_HQC128_CLEAN_hqc_ciphertext_to_string(ct, ctx -> u, ctx -> v, salt);
}

/* ======== Decryption ======== */

static NOINLINE void dec_unpack_ciphertext(DecryptContext *ctx, uint8_t *salt, const uint8_t *ct) {
    PQCLEAN_HQC128_CLEAN_hqc_ciphertext_from_string(ctx -> u, ctx -> v, salt, ct);
}

static NOINLINE void dec_unpack_secret_key(DecryptContext *ctx, const uint8_t *sk) {
    PQCLEAN_HQC128_CLEAN_hqc_secret_key_from_string(ctx -> x, ctx -> y, ctx -> sigma, ctx -> pk, sk);
}

static NOINLINE void dec_compute_tmp2_for_decoding(DecryptContext *ctx) {
    PQCLEAN_HQC128_CLEAN_vect_resize(ctx -> tmp1, PARAM_N, ctx -> v, PARAM_N1N2);
	PQCLEAN_HQC128_CLEAN_vect_mul(ctx -> tmp2, ctx -> y, ctx -> u);
	PQCLEAN_HQC128_CLEAN_vect_add(ctx -> tmp2, ctx -> tmp1, ctx -> tmp2, VEC_N_SIZE_64);
}

static NOINLINE void dec_decode_message(DecryptContext *ctx, uint8_t *mm) {
    PQCLEAN_HQC128_CLEAN_code_decode(mm, ctx -> tmp2);
}

static NOINLINE void dec_rederive_theta(DecryptContext *ctx) {
    memcpy(ctx -> tmp + VEC_K_SIZE_BYTES, ctx -> pk, PUBLIC_KEY_BYTES);
    PQCLEAN_HQC128_CLEAN_shake256_512_ds(&shake256state, ctx -> theta, ctx -> tmp, VEC_K_SIZE_BYTES + PUBLIC_KEY_BYTES + SALT_SIZE_BYTES, G_FCT_DOMAIN);
}

static NOINLINE void dec_reencrypt(DecryptContext *ctx, uint8_t *mm) {
    PQCLEAN_HQC128_CLEAN_hqc_pke_encrypt(ctx -> u2,  ctx -> v2,  mm,  ctx -> theta,  ctx -> pk);
}

static NOINLINE void dec_constant_time_check(DecryptContext *ctx) {
    ctx -> result |= PQCLEAN_HQC128_CLEAN_vect_compare((uint8_t *) ctx -> u, (uint8_t *) ctx -> u2, VEC_N_SIZE_BYTES);
    ctx -> result |= PQCLEAN_HQC128_CLEAN_vect_compare((uint8_t *) ctx -> v, (uint8_t *) ctx -> v2, VEC_N1N2_SIZE_BYTES);

    ctx -> result -= 1;
}

static NOINLINE void dec_select_message(DecryptContext *ctx, uint8_t *mm) {
    for (size_t i = 0; i < VEC_K_SIZE_BYTES; ++i) {
        ctx -> mc[i] = (mm[i] & ctx -> result) ^ (ctx -> sigma[i] & ~ctx -> result);
    }
}

static NOINLINE void dec_finalize_shared_secret(DecryptContext *ctx, uint8_t *ss) {
    PQCLEAN_HQC128_CLEAN_store8_arr(ctx -> mc + VEC_K_SIZE_BYTES, VEC_N_SIZE_BYTES, ctx -> u, VEC_N_SIZE_64);
    PQCLEAN_HQC128_CLEAN_store8_arr(ctx -> mc + VEC_K_SIZE_BYTES + VEC_N_SIZE_BYTES, VEC_N1N2_SIZE_BYTES, ctx -> v, VEC_N1N2_SIZE_64);
    PQCLEAN_HQC128_CLEAN_shake256_512_ds(&shake256state, ss, ctx -> mc, VEC_K_SIZE_BYTES + VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES, K_FCT_DOMAIN);
}


/* ======== Main ======== */

int main() {
	
	// Set message, secret key, public key, shared key and salt
	uint8_t pk[PUBLIC_KEY_BYTES];
	uint8_t sk[SECRET_KEY_BYTES];
	uint8_t ct[CIPHERTEXT_BYTES];
	
	uint8_t ss[SHARED_SECRET_BYTES];
	
	uint8_t m[VEC_K_SIZE_BYTES], mm[VEC_K_SIZE_BYTES];
	randombytes(m, VEC_K_SIZE_BYTES);
	
	uint8_t salt[SALT_SIZE_BYTES];
    randombytes(salt, SALT_SIZE_BYTES);
	
	// Initialize contexts
	KeygenContext kctx = {0};
    EncryptContext ectx = {0};
    DecryptContext dctx = {0};
	
	// Print profile
	
	FILE *fp = fopen("output_memo.txt", "w");
	if (fp == NULL) {
		perror("Failed to open file");
		return 1;
	}

	
	fprintf(fp, "Public key size: %lu\n", sizeof(pk));
	fprintf(fp, "Secret key size: %lu\n", sizeof(sk));
	fprintf(fp, "Cypertext size: %lu\n", sizeof(ct));
	fprintf(fp, "Shared key size: %lu\n", sizeof(ss));
	fprintf(fp, "Message size: %lu\n", sizeof(m));
	fprintf(fp, "Salt size: %lu\n", sizeof(salt));
	
	fprintf(fp, "\nKeygenContext: %lu\n", sizeof(KeygenContext));
	fprintf(fp, "sk_seed: %lu\n", sizeof(kctx.sk_seed));
	fprintf(fp, "sigma: %lu\n", sizeof(kctx.sigma));
	fprintf(fp, "pk_seed: %lu\n", sizeof(kctx.pk_seed));
	fprintf(fp, "x: %lu\n", sizeof(kctx.x));
	fprintf(fp, "y: %lu\n", sizeof(kctx.y));
	fprintf(fp, "h: %lu\n", sizeof(kctx.h));
	fprintf(fp, "s: %lu\n", sizeof(kctx.s));	
	
	fprintf(fp, "\nEncryptContext: %lu\n", sizeof(EncryptContext));
	fprintf(fp, "theta: %lu\n", sizeof(ectx.theta));
	fprintf(fp, "u: %lu\n", sizeof(ectx.u));
	fprintf(fp, "v: %lu\n", sizeof(ectx.v));
	fprintf(fp, "mc: %lu\n", sizeof(ectx.mc));
	fprintf(fp, "tmp: %lu\n", sizeof(ectx.tmp));
	fprintf(fp, "h: %lu\n", sizeof(ectx.h));
	fprintf(fp, "s: %lu\n", sizeof(ectx.s));
	fprintf(fp, "r1: %lu\n", sizeof(ectx.r1));
	fprintf(fp, "r2: %lu\n", sizeof(ectx.r2));
	fprintf(fp, "e: %lu\n", sizeof(ectx.e));
	fprintf(fp, "tmp1: %lu\n", sizeof(ectx.tmp1));
	fprintf(fp, "tmp2: %lu\n", sizeof(ectx.tmp2));	
	
	fprintf(fp, "\nDecryptContext: %lu\n", sizeof(DecryptContext));
	fprintf(fp, "result: %lu\n", sizeof(dctx.result));
	fprintf(fp, "u: %lu\n", sizeof(dctx.u));
	fprintf(fp, "v: %lu\n", sizeof(dctx.v));
	fprintf(fp, "sigma: %lu\n", sizeof(dctx.sigma));
	fprintf(fp, "theta: %lu\n", sizeof(dctx.theta));
	fprintf(fp, "u2: %lu\n", sizeof(dctx.u2));
	fprintf(fp, "v2: %lu\n", sizeof(dctx.v2));
	fprintf(fp, "mc: %lu\n", sizeof(dctx.mc));
	fprintf(fp, "tmp: %lu\n", sizeof(dctx.tmp));
	fprintf(fp, "x: %lu\n", sizeof(dctx.x));
	fprintf(fp, "y: %lu\n", sizeof(dctx.y));
	fprintf(fp, "pk: %lu\n", sizeof(dctx.pk));
	fprintf(fp, "tmp1: %lu\n", sizeof(dctx.tmp1));
	fprintf(fp, "tmp2: %lu\n", sizeof(dctx.tmp2));
		
	long unsigned int all_together = sizeof(pk) + sizeof(sk) + sizeof(ct) + sizeof(ss) + 2*sizeof(m) + sizeof(salt) + sizeof(KeygenContext) + sizeof(EncryptContext) + sizeof(DecryptContext);
	fprintf(fp, "\nAll together: %lu\n", all_together);
	
	fclose(fp);
	
	
    // Key Generation
    keygen_generate_seeds(&kctx);
    keygen_generate_x_y(&kctx);
    keygen_generate_h(&kctx);
    keygen_compute_s(&kctx);
    keygen_pack_keys(&kctx, pk, sk);

    // Encryption
    enc_compute_theta(&ectx, pk);
    enc_generate_r1_r2_e(&ectx);
    enc_compute_u(&ectx, pk);
    enc_compute_v(&ectx, m);
	enc_compute_shared_secret(&ectx, ss, m);
    enc_pack_ciphertext(&ectx, ct, salt);

    // Decryption
	dec_unpack_ciphertext(&dctx, salt, ct);
	dec_unpack_secret_key(&dctx, sk);
	dec_compute_tmp2_for_decoding(&dctx);
	dec_decode_message(&dctx, mm);
	dec_rederive_theta(&dctx);
	dec_reencrypt(&dctx, mm);
	dec_constant_time_check(&dctx);
	dec_select_message(&dctx, mm);
	dec_finalize_shared_secret(&dctx , ss);

	if((dctx.result & 1) - 1 == 0)
		printf("\nTest passed.\n");
	else
		printf("\nTest failed.\n");

	return 0;
}

