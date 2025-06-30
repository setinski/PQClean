#ifndef SHAKE_PRNG_H
#define SHAKE_PRNG_H


/**
 * @file shake_prng.h
 * @brief Header file of shake_prng.c
 */
#include "fips202.h"
#include <stddef.h>
#include <stdint.h>

typedef shake256incctx seedexpander_state;

void shake_prng_init(uint8_t *entropy_input, uint8_t *personalization_string, uint32_t enlen, uint32_t perlen);

void shake_prng(uint8_t *output, uint32_t outlen);

void PQCLEAN_HQC128_CLEAN_seedexpander_init(seedexpander_state *state, const uint8_t *seed, size_t seedlen);

void PQCLEAN_HQC128_CLEAN_seedexpander(seedexpander_state *state, uint8_t *output, size_t outlen);

void PQCLEAN_HQC128_CLEAN_seedexpander_release(seedexpander_state *state);


#endif
