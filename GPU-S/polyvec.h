#ifndef POLYVEC_H
#define POLYVEC_H

#include <stdint.h>
#include "params.h"
#include "poly.h"

/* Vectors of polynomials of length L */
typedef struct {
  poly vec[L];
} polyvecl;
/* Vectors of polynomials of length K */
typedef struct {
  poly vec[K];
} polyveck;


void polyvecl_uniform_eta(polyvecl *Cv, polyvecl *v, const uint8_t seed[2*SEEDBYTES], uint16_t nonce);
void polyvecl_uniform_gamma1(polyvecl *v, polyvecl *Cv,const uint8_t seed[CRHBYTES], uint16_t nonce);
void polyvec_matrix_expand(polyvecl mat[K], const uint8_t rho[3*SEEDBYTES]);
void polyvec_matrix_expand1(polyvecl mat[K], const uint8_t rho[2*SEEDBYTES + 3*CRHBYTES]);
void polyvec_matrix_expand2(polyvecl mat[K], const uint8_t rho[SEEDBYTES]);
void polyveck_uniform_eta(polyveck *v, const uint8_t seed[2*SEEDBYTES], uint16_t nonce);
void polyveck_pack_w(uint8_t r[MESSAGELEN + CRYPTO_BYTES], const polyveck *w1);
int polyvecl_chknorm(const polyvecl *v, int32_t bound);
int polyveck_chknorm(const polyveck *v, int32_t bound);
unsigned int polyveck_make_hint(polyveck *h,
                                const polyveck *v0,
                                const polyveck *v1);





__global__ void Gpolyveck_use_hint(polyveck *w, const polyveck *v, const polyveck *h);
__global__ void Gpolyveck_shiftl(polyveck *v);
__global__ void Gpolyvecl_reduce(polyvecl *v);
__global__ void Gpolyveck_reduce(polyveck *v);
__global__ void Gpolyveck_caddq(polyveck *v);
__global__ void GpolyK_add(polyveck *w, const polyveck *u, const polyveck *v);
__global__ void GpolyL_add(polyvecl *w, const polyvecl *u, const polyvecl *v);
__global__ void Gpolyveck_sub(polyveck *w, const polyveck *u, const polyveck *v);
__global__ void Gpolyveck_pointwise_poly_montgomery(polyveck *r, const poly *a, const polyveck *v);
__global__ void Gpolyvecl_pointwise_poly_montgomery(polyvecl *r, const poly *a, const polyvecl *v);
__global__ void Gpolyvec_matrix_pointwise_montgomery(polyveck *t, const polyvecl mat[K], const polyvecl *v);
__global__ void Gpolyveck_power2round(polyveck *v1, polyveck *v0, const polyveck *v);
__global__ void Gpolyveck_decompose(polyveck *v1, polyveck *v0, const polyveck *v);
__global__ void Gpolyveck_pack_w1(uint8_t r[K * POLYW1_PACKEDBYTES], const polyveck *w1);


#endif
