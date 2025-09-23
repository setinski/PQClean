#include "kat_helpers.h" // common file for KAT mode, includes randombytes
#include "code.h"
#include "gf2x.h"
#include "hqc.h"
#include "parameters.h"
#include "parsing.h"
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
#include <stdlib.h>
#include <assert.h>



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

#define SEED_LEN 48
#define NTESTS 100  // Adjust if needed

/* ======== Key Generation ======== */
static NOINLINE void keygen_generate_seeds(KeygenContext *ctx, FILE *log) {
    randombytes(ctx->sk_seed, SEED_BYTES);
    if (log) { fprintf(log, "[keygen] sk_seed: "); fprint_hex(log, ctx->sk_seed, SEED_BYTES); }

    randombytes(ctx->sigma, VEC_K_SIZE_BYTES);
    if (log) { fprintf(log, "[keygen] sigma:   "); fprint_hex(log, ctx->sigma, VEC_K_SIZE_BYTES); }

    randombytes(ctx->pk_seed, SEED_BYTES);
    if (log) { fprintf(log, "[keygen] pk_seed: "); fprint_hex(log, ctx->pk_seed, SEED_BYTES); }
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

void print_hex_diff(const char *label, const uint8_t *a, const uint8_t *b, size_t len) {
    printf("%s (computed): ", label);
    for (size_t i = 0; i < len; i++) printf("%02x", a[i]);
    printf("\n%s (expected): ", label);
    for (size_t i = 0; i < len; i++) printf("%02x", b[i]);
    printf("\n");
}

// Helper: print hex to a file
void fprint_hex(FILE *fp, const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++)
        fprintf(fp, "%02x", buf[i]);
    fprintf(fp, "\n");
}

int verify_kats(const char *kat_rsp_filename, int *passed, int *total, FILE *log) {
    debug_log = log;

    FILE *fp_rsp = fopen(kat_rsp_filename, "r");
    if (!fp_rsp) {
        perror("KAT .rsp file");
        return 1;
    }

    uint8_t seed[SEED_LEN];
    uint8_t pk[PUBLIC_KEY_BYTES], pk_kat[PUBLIC_KEY_BYTES];
    uint8_t sk[SECRET_KEY_BYTES], sk_kat[SECRET_KEY_BYTES];
    uint8_t ct[CIPHERTEXT_BYTES], ct_kat[CIPHERTEXT_BYTES];
    uint8_t ss[SHARED_SECRET_BYTES], ss_kat[SHARED_SECRET_BYTES];

    int count, failures = 0, testno = 0;
    *passed = 0;
    *total = 0;

    while (FindMarker(fp_rsp, "count = ")) {
        if (fscanf(fp_rsp, "%d", &count) != 1) break;

        if (!ReadHex(fp_rsp, seed, SEED_LEN, "seed = ")) break;
        if (!ReadHex(fp_rsp, pk_kat, PUBLIC_KEY_BYTES, "pk = ")) break;
        if (!ReadHex(fp_rsp, sk_kat, SECRET_KEY_BYTES, "sk = ")) break;
        if (!ReadHex(fp_rsp, ct_kat, CIPHERTEXT_BYTES, "ct = ")) break;
        if (!ReadHex(fp_rsp, ss_kat, SHARED_SECRET_BYTES, "ss = ")) break;

        hqc_kat_init(seed, NULL, 256);

        fprintf(log, "\n============================\n");
        fprintf(log, "KAT Test Case [count = %d]\n", count);
        fprintf(log, "============================\n");

        fprintf(log, "seed = ");
        fprint_hex(log, seed, SEED_LEN);

        // --- Keygen ---
        fprintf(log, "\n--- [keygen] ---\n");
        KeygenContext kctx = {0};
        keygen_generate_seeds(&kctx, log);
        keygen_generate_x_y(&kctx);
        keygen_generate_h(&kctx);
        keygen_compute_s(&kctx);
        keygen_pack_keys(&kctx, pk, sk);

        fprintf(log, "[keygen] pk (packed): "); fprint_hex(log, pk, PUBLIC_KEY_BYTES);
        fprintf(log, "[KAT] pk (expected): "); fprint_hex(log, pk_kat, PUBLIC_KEY_BYTES);
        fprintf(log, "[keygen] sk (packed): "); fprint_hex(log, sk, SECRET_KEY_BYTES);
        fprintf(log, "[KAT] sk (expected): "); fprint_hex(log, sk_kat, SECRET_KEY_BYTES);

        // --- Encapsulation ---
        fprintf(log, "\n--- [encapsulation] ---\n");
        EncryptContext ectx = {0};
        uint8_t m[VEC_K_SIZE_BYTES];
        uint8_t salt[SALT_SIZE_BYTES];
        randombytes_labeled(m, VEC_K_SIZE_BYTES, "[encapsulation] message");
        randombytes_labeled(salt, SALT_SIZE_BYTES, "[encapsulation] salt");

        fprintf(log, "[encapsulation] m: "); fprint_hex(log, m, VEC_K_SIZE_BYTES);
        fprintf(log, "[encapsulation] salt: "); fprint_hex(log, salt, SALT_SIZE_BYTES);

        enc_compute_theta(&ectx, pk);
        fprintf(log, "[encapsulation] theta: "); fprint_hex(log, ectx.theta, VEC_N_SIZE_BYTES);

        enc_generate_r1_r2_e(&ectx);
        fprintf(log, "[encapsulation] r1: "); fprint_hex(log, ectx.r1, VEC_N_SIZE_BYTES);
        fprintf(log, "[encapsulation] r2: "); fprint_hex(log, ectx.r2, VEC_N_SIZE_BYTES);
        fprintf(log, "[encapsulation] e: "); fprint_hex(log, ectx.e, VEC_N_SIZE_BYTES);

        enc_compute_u(&ectx, pk);
        fprintf(log, "[encapsulation] u: "); fprint_hex(log, ectx.u, VEC_N_SIZE_BYTES);

        enc_compute_v(&ectx, m);
        fprintf(log, "[encapsulation] v: "); fprint_hex(log, ectx.v, VEC_N_SIZE_BYTES);

        enc_compute_shared_secret(&ectx, ss, m);
        fprintf(log, "[encapsulation] ss: "); fprint_hex(log, ss, SHARED_SECRET_BYTES);
        fprintf(log, "[KAT] ss (expected): "); fprint_hex(log, ss_kat, SHARED_SECRET_BYTES);

        enc_pack_ciphertext(&ectx, ct, salt);
        fprintf(log, "[encapsulation] ct (packed): "); fprint_hex(log, ct, CIPHERTEXT_BYTES);
        fprintf(log, "[KAT] ct (expected): "); fprint_hex(log, ct_kat, CIPHERTEXT_BYTES);

        // --- Decapsulation ---
        fprintf(log, "\n--- [decapsulation] ---\n");
        DecryptContext dctx = {0};
        uint8_t mm[VEC_K_SIZE_BYTES], ss_dec[SHARED_SECRET_BYTES];

        dec_unpack_ciphertext(&dctx, salt, ct);
        dec_unpack_secret_key(&dctx, sk);
        dec_compute_tmp2_for_decoding(&dctx);
        dec_decode_message(&dctx, mm);
        fprintf(log, "[decapsulation] decoded m: "); fprint_hex(log, mm, VEC_K_SIZE_BYTES);

        dec_rederive_theta(&dctx);
        fprintf(log, "[decapsulation] theta': "); fprint_hex(log, dctx.theta, VEC_N_SIZE_BYTES);

        dec_reencrypt(&dctx, mm);
        dec_constant_time_check(&dctx);
        dec_select_message(&dctx, mm);
        dec_finalize_shared_secret(&dctx, ss_dec);
        fprintf(log, "[decapsulation] ss_dec: "); fprint_hex(log, ss_dec, SHARED_SECRET_BYTES);

        // --- Comparison ---
        int fail = 0;
        fprintf(log, "\nKAT test %d:\n", testno);

        if (memcmp(pk, pk_kat, PUBLIC_KEY_BYTES) != 0) {
            fprintf(log, "  Public key mismatch\n");
            fail = 1;
        }
        if (memcmp(sk, sk_kat, SECRET_KEY_BYTES) != 0) {
            fprintf(log, "  Secret key mismatch\n");
            fail = 1;
        }
        if (memcmp(ct, ct_kat, CIPHERTEXT_BYTES) != 0) {
            fprintf(log, "  Ciphertext mismatch\n");
            fail = 1;
        }
        if (memcmp(ss, ss_kat, SHARED_SECRET_BYTES) != 0) {
            fprintf(log, "  Shared secret mismatch (encapsulation)\n");
            fail = 1;
        }
        if (memcmp(ss_dec, ss_kat, SHARED_SECRET_BYTES) != 0) {
            fprintf(log, "  Shared secret mismatch (decapsulation)\n");
            fail = 1;
        }

        if (!fail) {
            fprintf(log, "  PASS\n");
            (*passed)++;
        } else {
            failures++;
        }

        (*total)++;
        testno++;
        hqc_kat_release();
    }

    fclose(fp_rsp);
    debug_log = NULL;

    printf("\nKAT Summary:\n");
    printf("Total tests run: %d\n", *total);
    printf("Tests passed:    %d\n", *passed);
    printf("Tests failed:    %d\n", failures);

    return failures == 0 ? 0 : 1;
}




int main(int argc, char **argv) {
    FILE *log = fopen("debug.log", "w");
    if (!log) {
        perror("Failed to open debug.log");
        return 1;
    }
    debug_log = log;

    if (argc > 1 && strcmp(argv[1], "kat") == 0) {
        int passed = 0, total = 0;
        int result = verify_kats("PQCkemKAT_2305.rsp", &passed, &total, log);
        fclose(log);
        return result;
    }

    // Standard test mode
    uint8_t entropy_input[48] = {0}; 
    hqc_kat_init(entropy_input, NULL, 256);
    uint8_t pk[PUBLIC_KEY_BYTES];
    uint8_t sk[SECRET_KEY_BYTES];
    uint8_t ct[CIPHERTEXT_BYTES];
    uint8_t ss[SHARED_SECRET_BYTES];
    uint8_t m[VEC_K_SIZE_BYTES], mm[VEC_K_SIZE_BYTES];
    randombytes(m, VEC_K_SIZE_BYTES);
    uint8_t salt[SALT_SIZE_BYTES];
    randombytes(salt, SALT_SIZE_BYTES);

    KeygenContext kctx = {0};
    EncryptContext ectx = {0};
    DecryptContext dctx = {0};

    keygen_generate_seeds(&kctx, log);
    keygen_generate_x_y(&kctx);
    keygen_generate_h(&kctx);
    keygen_compute_s(&kctx);
    keygen_pack_keys(&kctx, pk, sk);

    enc_compute_theta(&ectx, pk);
    enc_generate_r1_r2_e(&ectx);
    enc_compute_u(&ectx, pk);
    enc_compute_v(&ectx, m);
    enc_compute_shared_secret(&ectx, ss, m);
    enc_pack_ciphertext(&ectx, ct, salt);

    dec_unpack_ciphertext(&dctx, salt, ct);
    dec_unpack_secret_key(&dctx, sk);
    dec_compute_tmp2_for_decoding(&dctx);
    dec_decode_message(&dctx, mm);
    dec_rederive_theta(&dctx);
    dec_reencrypt(&dctx, mm);
    dec_constant_time_check(&dctx);
    dec_select_message(&dctx, mm);
    dec_finalize_shared_secret(&dctx, ss);

    if ((dctx.result & 1) - 1 == 0) {
        printf("\nTest passed.\n");
    } else {
        printf("\nTest failed.\n");
    }

    fclose(log);
    return 0;
}

