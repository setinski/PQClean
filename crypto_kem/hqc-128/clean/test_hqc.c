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

/* ======== Key Generation ======== */
void keygen_generate_seeds(HQCTestContext *ctx);
NOINLINE void keygen_generate_seeds(HQCTestContext *ctx) {
    randombytes(ctx->sk_seed, SEED_BYTES);
    randombytes(ctx->sigma, VEC_K_SIZE_BYTES);
    randombytes(ctx->pk_seed, SEED_BYTES);
}

void keygen_generate_x_y(HQCTestContext *ctx);
NOINLINE void keygen_generate_x_y(HQCTestContext *ctx) {
    seedexpander_state exp;
    PQCLEAN_HQC128_CLEAN_seedexpander_init(&exp, ctx->sk_seed, SEED_BYTES);
    PQCLEAN_HQC128_CLEAN_vect_set_random_fixed_weight(&exp, ctx->x, PARAM_OMEGA);
    PQCLEAN_HQC128_CLEAN_vect_set_random_fixed_weight(&exp, ctx->y, PARAM_OMEGA);
    PQCLEAN_HQC128_CLEAN_seedexpander_release(&exp);
}

void keygen_generate_h(HQCTestContext *ctx);
NOINLINE void keygen_generate_h(HQCTestContext *ctx) {
    seedexpander_state exp;
    PQCLEAN_HQC128_CLEAN_seedexpander_init(&exp, ctx->pk_seed, SEED_BYTES);
    PQCLEAN_HQC128_CLEAN_vect_set_random(&exp, ctx->h);
    PQCLEAN_HQC128_CLEAN_seedexpander_release(&exp);
}

void keygen_compute_s(HQCTestContext *ctx);
NOINLINE void keygen_compute_s(HQCTestContext *ctx) {
    PQCLEAN_HQC128_CLEAN_vect_mul(ctx->s, ctx->y, ctx->h);
    PQCLEAN_HQC128_CLEAN_vect_add(ctx->s, ctx->x, ctx->s, VEC_N_SIZE_64);
}

void keygen_pack_keys(HQCTestContext *ctx);
NOINLINE void keygen_pack_keys(HQCTestContext *ctx) {
    PQCLEAN_HQC128_CLEAN_hqc_public_key_to_string(ctx->pk, ctx->pk_seed, ctx->s);
    PQCLEAN_HQC128_CLEAN_hqc_secret_key_to_string(ctx->sk, ctx->sk_seed, ctx->sigma, ctx->pk);
}

/* ======== Encryption ======== */

void enc_generate_m_and_salt(HQCTestContext *ctx);
NOINLINE void enc_generate_m_and_salt(HQCTestContext *ctx) {
    randombytes(ctx->m, VEC_K_SIZE_BYTES);
    randombytes(ctx->salt, SALT_SIZE_BYTES);
}

void enc_compute_theta(HQCTestContext *ctx);
NOINLINE void enc_compute_theta(HQCTestContext *ctx) {
    uint8_t input[VEC_K_SIZE_BYTES + PUBLIC_KEY_BYTES + SALT_SIZE_BYTES];

    // Prepare input = m || pk || salt
    memcpy(input, ctx->m, VEC_K_SIZE_BYTES);
    memcpy(input + VEC_K_SIZE_BYTES, ctx->pk, PUBLIC_KEY_BYTES);
    memcpy(input + VEC_K_SIZE_BYTES + PUBLIC_KEY_BYTES, ctx->salt, SALT_SIZE_BYTES);

    // Compute SHAKE256-based theta using domain-separated variant
    PQCLEAN_HQC128_CLEAN_shake256_512_ds(&shake256state, ctx->theta, input, sizeof(input), G_FCT_DOMAIN);
}

void enc_generate_r1_r2_e(HQCTestContext *ctx);
NOINLINE void enc_generate_r1_r2_e(HQCTestContext *ctx) {
    seedexpander_state exp;
    PQCLEAN_HQC128_CLEAN_seedexpander_init(&exp, ctx->theta, SEED_BYTES);
    PQCLEAN_HQC128_CLEAN_vect_set_random_fixed_weight(&exp, ctx->r1, PARAM_OMEGA_R);
    PQCLEAN_HQC128_CLEAN_vect_set_random_fixed_weight(&exp, ctx->r2, PARAM_OMEGA_R);
    PQCLEAN_HQC128_CLEAN_vect_set_random_fixed_weight(&exp, ctx->e, PARAM_OMEGA_E);
    PQCLEAN_HQC128_CLEAN_seedexpander_release(&exp);
}

void enc_compute_u(HQCTestContext *ctx);
NOINLINE void enc_compute_u(HQCTestContext *ctx) {
    PQCLEAN_HQC128_CLEAN_hqc_public_key_from_string(ctx->h, ctx->s, ctx->pk);
    PQCLEAN_HQC128_CLEAN_vect_mul(ctx->u, ctx->r2, ctx->h);
    PQCLEAN_HQC128_CLEAN_vect_add(ctx->u, ctx->r1, ctx->u, VEC_N_SIZE_64);
}

void enc_compute_v(HQCTestContext *ctx);
NOINLINE void enc_compute_v(HQCTestContext *ctx) {
    PQCLEAN_HQC128_CLEAN_code_encode(ctx->v, ctx->m);
    PQCLEAN_HQC128_CLEAN_vect_resize((uint64_t *)ctx->tmp1, PARAM_N, ctx->v, PARAM_N1N2);
    PQCLEAN_HQC128_CLEAN_vect_mul((uint64_t *)ctx->tmp2, ctx->r2, ctx->s);
    PQCLEAN_HQC128_CLEAN_vect_add((uint64_t *)ctx->tmp2, ctx->e, (uint64_t *)ctx->tmp2, VEC_N_SIZE_64);
    PQCLEAN_HQC128_CLEAN_vect_add((uint64_t *)ctx->tmp2, (uint64_t *)ctx->tmp1, (uint64_t *)ctx->tmp2, VEC_N_SIZE_64);
    PQCLEAN_HQC128_CLEAN_vect_resize(ctx->v, PARAM_N1N2, (uint64_t *)ctx->tmp2, PARAM_N);
}

void enc_pack_ciphertext(HQCTestContext *ctx);
NOINLINE void enc_pack_ciphertext(HQCTestContext *ctx) {
    PQCLEAN_HQC128_CLEAN_hqc_ciphertext_to_string(ctx->ct, ctx->u, ctx->v, ctx->salt);
}

void enc_compute_shared_secret(HQCTestContext *ctx);
NOINLINE void enc_compute_shared_secret(HQCTestContext *ctx) {
    memcpy(ctx->mc, ctx->m, VEC_K_SIZE_BYTES);
    PQCLEAN_HQC128_CLEAN_store8_arr(ctx->mc + VEC_K_SIZE_BYTES, VEC_N_SIZE_BYTES, ctx->u, VEC_N_SIZE_64);
    PQCLEAN_HQC128_CLEAN_store8_arr(ctx->mc + VEC_K_SIZE_BYTES + VEC_N_SIZE_BYTES, VEC_N1N2_SIZE_BYTES, ctx->v, VEC_N1N2_SIZE_64);
    PQCLEAN_HQC128_CLEAN_shake256_512_ds(&shake256state, ctx->key1, ctx->mc, sizeof(ctx->mc), K_FCT_DOMAIN);
}

/* ======== Decryption ======== */

void dec_unpack_ciphertext(HQCTestContext *ctx);
NOINLINE void dec_unpack_ciphertext(HQCTestContext *ctx) {
    PQCLEAN_HQC128_CLEAN_hqc_ciphertext_from_string(ctx->u, ctx->v, ctx->salt, ctx->ct);
}

void dec_unpack_secret_key(HQCTestContext *ctx);
NOINLINE void dec_unpack_secret_key(HQCTestContext *ctx) {
    PQCLEAN_HQC128_CLEAN_hqc_secret_key_from_string(ctx->x, ctx->y, ctx->sigma, ctx->pkk, ctx->sk);
}

void dec_compute_tmp2_for_decoding(HQCTestContext *ctx, uint64_t *tmp2);
NOINLINE void dec_compute_tmp2_for_decoding(HQCTestContext *ctx, uint64_t *tmp2) {
    PQCLEAN_HQC128_CLEAN_vect_resize((uint64_t *)ctx->tmp1, PARAM_N, ctx->v, PARAM_N1N2);
    PQCLEAN_HQC128_CLEAN_vect_mul(tmp2, ctx->y, ctx->u);
    PQCLEAN_HQC128_CLEAN_vect_add(tmp2, (uint64_t *)ctx->tmp1, tmp2, VEC_N_SIZE_64);
}

void dec_decode_message(HQCTestContext *ctx, const uint64_t *tmp2);
NOINLINE void dec_decode_message(HQCTestContext *ctx, const uint64_t *tmp2) {
    PQCLEAN_HQC128_CLEAN_code_decode(ctx->m, tmp2);
}

void dec_rederive_theta(HQCTestContext *ctx);
NOINLINE void dec_rederive_theta(HQCTestContext *ctx) {
    uint8_t input[VEC_K_SIZE_BYTES + PUBLIC_KEY_BYTES + SALT_SIZE_BYTES];
    memcpy(input, ctx->m, VEC_K_SIZE_BYTES);
    memcpy(input + VEC_K_SIZE_BYTES, ctx->pkk, PUBLIC_KEY_BYTES);
    memcpy(input + VEC_K_SIZE_BYTES + PUBLIC_KEY_BYTES, ctx->salt, SALT_SIZE_BYTES);
    PQCLEAN_HQC128_CLEAN_shake256_512_ds(&shake256state, ctx->theta, input, sizeof(input), G_FCT_DOMAIN);
}

void dec_reencrypt(HQCTestContext *ctx, uint64_t *u2, uint64_t *v2);
NOINLINE void dec_reencrypt(HQCTestContext *ctx, uint64_t *u2, uint64_t *v2) {
    PQCLEAN_HQC128_CLEAN_hqc_pke_encrypt(u2, v2, ctx->m, ctx->theta, ctx->pkk);
}

uint8_t dec_constant_time_check(HQCTestContext *ctx, const uint64_t *u2, const uint64_t *v2);
NOINLINE uint8_t dec_constant_time_check(HQCTestContext *ctx, const uint64_t *u2, const uint64_t *v2) {
    uint8_t result = 0;
    result |= PQCLEAN_HQC128_CLEAN_vect_compare((uint8_t *)ctx->u, (uint8_t *)u2, VEC_N_SIZE_BYTES);
    result |= PQCLEAN_HQC128_CLEAN_vect_compare((uint8_t *)ctx->v, (uint8_t *)v2, VEC_N1N2_SIZE_BYTES);
    return result - 1; // Map 0 -> 0xFF (success), nonzero -> 0x00 (failure)
}

void dec_select_message(HQCTestContext *ctx, uint8_t result);
NOINLINE void dec_select_message(HQCTestContext *ctx, uint8_t result) {
    for (size_t i = 0; i < VEC_K_SIZE_BYTES; ++i) {
        ctx->mc[i] = (ctx->m[i] & result) ^ (ctx->sigma[i] & ~result);
    }
}

void dec_finalize_shared_secret(HQCTestContext *ctx);
NOINLINE void dec_finalize_shared_secret(HQCTestContext *ctx) {
    PQCLEAN_HQC128_CLEAN_store8_arr(ctx->mc + VEC_K_SIZE_BYTES, VEC_N_SIZE_BYTES, ctx->u, VEC_N_SIZE_64);
    PQCLEAN_HQC128_CLEAN_store8_arr(ctx->mc + VEC_K_SIZE_BYTES + VEC_N_SIZE_BYTES, VEC_N1N2_SIZE_BYTES, ctx->v, VEC_N1N2_SIZE_64);
    PQCLEAN_HQC128_CLEAN_shake256_512_ds(&shake256state, ctx->key2, ctx->mc, sizeof(ctx->mc), K_FCT_DOMAIN);
}

void dec_decrypt_and_check(HQCTestContext *ctx);
NOINLINE void dec_decrypt_and_check(HQCTestContext *ctx) {
    uint64_t tmp2[VEC_N_SIZE_64] = {0};
    uint64_t u2[VEC_N_SIZE_64] = {0};
    uint64_t v2[VEC_N1N2_SIZE_64] = {0};

    dec_unpack_ciphertext(ctx);
    dec_unpack_secret_key(ctx);
    dec_compute_tmp2_for_decoding(ctx, tmp2);
    dec_decode_message(ctx, tmp2);
    dec_rederive_theta(ctx);
    dec_reencrypt(ctx, u2, v2);

    uint8_t valid = dec_constant_time_check(ctx, u2, v2);
    dec_select_message(ctx, valid);
    dec_finalize_shared_secret(ctx);
}


/* ======== Main ======== */

int main() {
    HQCTestContext ctx = {0};

    // Key Generation
    keygen_generate_seeds(&ctx);
    keygen_generate_x_y(&ctx);
    keygen_generate_h(&ctx);
    keygen_compute_s(&ctx);
    keygen_pack_keys(&ctx);

    // Encryption
    enc_generate_m_and_salt(&ctx);
    enc_compute_theta(&ctx);
    enc_generate_r1_r2_e(&ctx);
    enc_compute_u(&ctx);
    enc_compute_v(&ctx);
    enc_pack_ciphertext(&ctx);
    enc_compute_shared_secret(&ctx);

    // Decryption
    dec_decrypt_and_check(&ctx);

    return 0;
}

