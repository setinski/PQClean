#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include "kat_helpers.h"
#include "fips202.h"  // for SHAKE functions

shake256incctx shake_prng_state;

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
