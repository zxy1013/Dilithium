#ifndef rng_h
#define rng_h
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h> 

void rrandombytes(uint8_t *out, size_t outlen, size_t len);

int randombytes(unsigned char *x, unsigned long long xlen);

#endif
