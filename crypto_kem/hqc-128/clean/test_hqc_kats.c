#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "api.h"
#include "kat_helpers.h"  // common file for KAT mode
#include "code.h"
#include "gf2x.h"
#include "hqc.h"
#include "parameters.h"
#include "parsing.h"
#include "reed_muller.h"
#include "reed_solomon.h"
#include "sha2.h"
#include "shake_ds.h"
#include "shake_prng.h"
#include "vector.h"
#include "fips202.h"
#include "domains.h"

#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

#define NTESTS 100
#define SEED_LEN 48

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
