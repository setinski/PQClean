#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

#include "api.h"
#include "randombytes.h"
#include "code.h"
#include "gf2x.h"
#include "hqc.h"
#include "parameters.h"
#include "parsing.h"
#include "shake_prng.h"
#include "sha2.h"
#include "fips202.h"
#include "domains.h"
#include "shake_ds.h"
#include "vector.h"

#define MAX_MARKER_LEN      50
#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

#define NTESTS 100
#define SEED_LEN 48

static shake256incctx shake_prng_state;

void hqc_kat_init(uint8_t *entropy_input, uint8_t *personalization_string, int security_strength);
void hqc_kat_release(void);
void fprintBstr(FILE *fp, const char *S, const uint8_t *A, size_t L);
int FindMarker(FILE *infile, const char *marker);
int ReadHex(FILE *infile, unsigned char *A, int Length, char *str);

void hqc_kat_init(uint8_t *entropy_input, uint8_t *personalization_string, int security_strength) {
    assert(security_strength == 256);
    uint8_t domain = 1;
    shake256_inc_init(&shake_prng_state);
    shake256_inc_absorb(&shake_prng_state, entropy_input, 48);
    if (personalization_string) {
        shake256_inc_absorb(&shake_prng_state, personalization_string, 48);
    }
    shake256_inc_absorb(&shake_prng_state, &domain, 1);
    shake256_inc_finalize(&shake_prng_state);
}

void hqc_kat_release(void) {
    shake256_inc_ctx_release(&shake_prng_state);
}

int randombytes(uint8_t *buf, size_t n) {
    shake256_inc_squeeze(buf, n, &shake_prng_state);
    return 0;
}

void fprintBstr(FILE *fp, const char *S, const uint8_t *A, size_t L) {
    fprintf(fp, "%s", S);
    for (size_t i = 0; i < L; i++) {
        fprintf(fp, "%02X", A[i]);
    }
    if (L == 0) fprintf(fp, "00");
    fprintf(fp, "\n");
}

int FindMarker(FILE *infile, const char *marker) {
    char line[MAX_MARKER_LEN];
    int i, len = (int)strlen(marker);
    if (len > MAX_MARKER_LEN - 1) len = MAX_MARKER_LEN - 1;

    for (i = 0; i < len; i++)
        if ((line[i] = fgetc(infile)) == EOF) return 0;
    line[len] = '\0';

    while (1) {
        if (!strncmp(line, marker, len)) return 1;
        for (i = 0; i < len - 1; i++) line[i] = line[i + 1];
        if ((line[len - 1] = fgetc(infile)) == EOF) return 0;
        line[len] = '\0';
    }
    return 0;
}

int ReadHex(FILE *infile, unsigned char *A, int Length, char *str) {
    int i, ch, started = 0;
    unsigned char ich;
    if (Length == 0) {
        A[0] = 0x00;
        return 1;
    }
    memset(A, 0x00, Length);
    if (FindMarker(infile, str)) {
        while ((ch = fgetc(infile)) != EOF) {
            if (!isxdigit(ch)) {
                if (!started) {
                    if (ch == '\n') break;
                    else continue;
                } else break;
            }
            started = 1;
            if ((ch >= '0') && (ch <= '9')) ich = ch - '0';
            else if ((ch >= 'A') && (ch <= 'F')) ich = ch - 'A' + 10;
            else if ((ch >= 'a') && (ch <= 'f')) ich = ch - 'a' + 10;
            else ich = 0;

            for (i = 0; i < Length - 1; i++) A[i] = (A[i] << 4) | (A[i + 1] >> 4);
            A[Length - 1] = (A[Length - 1] << 4) | ich;
        }
    } else return 0;
    return 1;
}

int main(void) {
    char fn_req[32], fn_rsp[32];
    FILE *fp_req, *fp_rsp;
    uint8_t entropy_input[SEED_LEN], seed[SEED_LEN];
    uint8_t pk[PUBLIC_KEY_BYTES], sk[SECRET_KEY_BYTES];
    uint8_t ct[CIPHERTEXT_BYTES], ss[SHARED_SECRET_BYTES], ss1[SHARED_SECRET_BYTES];
    int ret_val, count, done;

    sprintf(fn_req, "PQCkemKAT_%d.req", SECRET_KEY_BYTES);
    sprintf(fn_rsp, "PQCkemKAT_%d.rsp", SECRET_KEY_BYTES);

    // === Generate .req ===
    if ((fp_req = fopen(fn_req, "w")) == NULL) {
        printf("Couldn't open <%s> for writing\n", fn_req);
        return KAT_FILE_OPEN_ERROR;
    }
    for (int i = 0; i < SEED_LEN; i++) entropy_input[i] = i;
    hqc_kat_init(entropy_input, NULL, 256);
    for (int i = 0; i < NTESTS; i++) {
        fprintf(fp_req, "count = %d\n", i);
        randombytes(seed, SEED_LEN);
        fprintBstr(fp_req, "seed = ", seed, SEED_LEN);
        fprintf(fp_req, "pk =\n");
        fprintf(fp_req, "sk =\n");
        fprintf(fp_req, "ct =\n");
        fprintf(fp_req, "ss =\n\n");
    }
    hqc_kat_release();
    fclose(fp_req);

    // === Generate .rsp ===
    if ((fp_req = fopen(fn_req, "r")) == NULL) {
        printf("Couldn't open <%s> for reading\n", fn_req);
        return KAT_FILE_OPEN_ERROR;
    }
    if ((fp_rsp = fopen(fn_rsp, "w")) == NULL) {
        printf("Couldn't open <%s> for writing\n", fn_rsp);
        return KAT_FILE_OPEN_ERROR;
    }

    fprintf(fp_rsp, "# hqc-128\n\n");
    done = 0;
    do {
        if (FindMarker(fp_req, "count = ")) fscanf(fp_req, "%d", &count);
        else { done = 1; break; }

        fprintf(fp_rsp, "count = %d\n", count);

        if (!ReadHex(fp_req, seed, SEED_LEN, "seed = ")) {
            printf("ERROR: unable to read 'seed' from <%s>\n", fn_req);
            return KAT_DATA_ERROR;
        }
        fprintBstr(fp_rsp, "seed = ", seed, SEED_LEN);

        hqc_kat_init(seed, NULL, 256);

        if ((ret_val = PQCLEAN_HQC128_CLEAN_crypto_kem_keypair(pk, sk)) != 0) {
            printf("crypto_kem_keypair returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }
        fprintBstr(fp_rsp, "pk = ", pk, PUBLIC_KEY_BYTES);
        fprintBstr(fp_rsp, "sk = ", sk, SECRET_KEY_BYTES);

        if ((ret_val = PQCLEAN_HQC128_CLEAN_crypto_kem_enc(ct, ss, pk)) != 0) {
            printf("crypto_kem_enc returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }
        fprintBstr(fp_rsp, "ct = ", ct, CIPHERTEXT_BYTES);
        fprintBstr(fp_rsp, "ss = ", ss, SHARED_SECRET_BYTES);

        if ((ret_val = PQCLEAN_HQC128_CLEAN_crypto_kem_dec(ss1, ct, sk)) != 0) {
            printf("crypto_kem_dec returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }

        if (memcmp(ss, ss1, SHARED_SECRET_BYTES)) {
            printf("ERROR: shared secrets mismatch\n");
            return KAT_CRYPTO_FAILURE;
        }

        hqc_kat_release();
        fprintf(fp_rsp, "\n");
    } while (!done);

    fclose(fp_req);
    fclose(fp_rsp);

    return KAT_SUCCESS;
}