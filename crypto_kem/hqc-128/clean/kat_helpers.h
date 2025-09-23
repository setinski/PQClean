#ifndef KAT_HELPERS_H
#define KAT_HELPERS_H

#include <stdint.h>
#include <stdio.h>
extern FILE *debug_log;

#define MAX_MARKER_LEN 50

void hqc_kat_init(uint8_t *entropy_input, uint8_t *personalization_string, int security_strength);
void hqc_kat_release(void);
int randombytes(uint8_t *buf, size_t n);
void fprintBstr(FILE *fp, const char *S, const uint8_t *A, size_t L);
int FindMarker(FILE *infile, const char *marker);
int ReadHex(FILE *infile, unsigned char *A, int Length, char *str);
void print_hex(const uint8_t *buf, size_t len);
void fprint_hex(FILE *fp, const uint8_t *buf, size_t len);
void print_hex_diff(const char *label, const uint8_t *a, const uint8_t *b, size_t len);
int verify_kats(const char *kat_rsp_filename, int *passed, int *total, FILE *log);
int randombytes_labeled(uint8_t *buf, size_t n, const char *label);

#endif
