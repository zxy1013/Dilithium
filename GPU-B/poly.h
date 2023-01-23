#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "params.h"

typedef struct {
  int32_t coeffs[N];
} poly;


__device__ void poly_reduce(poly *a);


__device__ void poly_caddq(poly *a);


__device__ void poly_add(poly *c, const poly *a, const poly *b);


__device__ void poly_sub(poly *c, const poly *a, const poly *b);

__device__ void poly_shiftl(poly *a);


__device__ void poly_invntt_tomont(poly *a);

__device__ void poly_pointwise_montgomery(poly *c, const poly *a, const poly *b);

__device__ void poly_ntt(poly *a);

__device__ void poly_power2round(poly *a1, poly *a0, const poly *a);

__device__ void poly_decompose(poly *a1, poly *a0, const poly *a);

__device__ unsigned int poly_make_hint(poly *h, const poly *a0, const poly *a1);


__device__ void poly_use_hint(poly *b, const poly *a, const poly *h);


__device__ void poly_chknorm(const poly *a,  int *f, int32_t B);

__device__ void poly_uniform(poly *a,
                  const uint8_t seed[SEEDBYTES],
                  uint16_t nonce);


__device__ void poly_uniform_eta(poly *a,
                      const uint8_t seed[SEEDBYTES],
                      uint16_t nonce);


__device__ void poly_uniform_gamma1(poly *a,
                         const uint8_t seed[CRHBYTES],
                         uint16_t nonce);

__global__ void poly_challenge(int group, int step, int *f, unsigned int *n,poly *c, const uint8_t seed[(MESSAGELEN + CRYPTO_BYTES) * MAXGROUP]);

__global__ void poly_challenge1(int group, int step, int *f, unsigned int *n,poly *c, const uint8_t seed[SEEDBYTES * MAXGROUP]);

__global__ void poly_ntt1(int group,int step, int *f, unsigned int *n, poly *c);

__device__ void polyeta_pack(uint8_t *r, const poly *a);


__device__ void polyeta_unpack(poly *r, const uint8_t *a);

__device__ void polyt1_pack(uint8_t *r, const poly *a);


__device__ void polyt1_unpack(poly *r, const uint8_t *a);


__device__ void polyt0_pack(uint8_t *r, const poly *a);

__device__ void polyt0_unpack(poly *r, const uint8_t *a);



__device__ void polyz_pack(uint8_t *r, const poly *a);

__device__ void polyz_unpack(poly *r, const uint8_t *a);


__device__ void polyw1_pack(uint8_t *r, const poly *a);

#endif
