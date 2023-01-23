#ifndef POLYVEC_H
#define POLYVEC_H

#include <stdint.h>
#include "params.h"
#include "poly.h"

/* Vectors of polynomials of length L */
typedef struct {
  poly vec[L];
} polyvecl;


__global__ void polyvecl_uniform_eta(int group, polyvecl *Cv, polyvecl *v, const uint8_t seed[3*SEEDBYTES*MAXGROUP-SEEDBYTES], uint16_t nonce);


__global__ void polyvecl_uniform_gamma1(int group,int step, int *f, unsigned int *n,polyvecl *v, polyvecl *Cv,const uint8_t seed[(2*SEEDBYTES + 3*CRHBYTES)*MAXGROUP-2*SEEDBYTES-2*CRHBYTES], uint16_t nonce);

__global__ void polyvecl_reduce(int group,int step,int *f, unsigned int *n,polyvecl *v);


__global__ void polyvecl_add(int group,int step,int *f, unsigned int *n,polyvecl *w, const polyvecl *u, const polyvecl *v);

__global__ void polyvecl_ntt(int group,int step, int *f, unsigned int *n,polyvecl *v);

__global__ void polyvecl_invntt_tomont(int group,int step, int *f, unsigned int *n,polyvecl *v);

__global__ void polyvecl_pointwise_poly_montgomery(int group,int step, int *f, unsigned int *n,polyvecl *r, const poly *a, const polyvecl *v);

__device__ void polyvecl_pointwise_acc_montgomery(poly *w,const polyvecl *u,const polyvecl *v);


/* Vectors of polynomials of length K */
typedef struct {
  poly vec[K];
} polyveck;



// yyyyy

__global__ void polyvecl_chknorm(int group,int step,int *f, unsigned int *n,const polyvecl *v,int32_t bound);

__global__ void polyveck_chknorm(int group,int step,int *f, unsigned int *n,const polyveck *v,int32_t bound);


__global__ void polyveck_uniform_eta(int group,polyveck *v, const uint8_t seed[3*SEEDBYTES*MAXGROUP-SEEDBYTES], uint16_t nonce);



// __global__ void polyveck_reduce(polyveck *v);
__global__ void polyveck_reduce(int group,int step, int *f, unsigned int *n,polyveck *v);


__global__ void polyveck_caddq(int group,int step, int *f, unsigned int *n,polyveck *v);

__global__ void polyveck_add(int group,int step,int *f, unsigned int *n,polyveck *w, const polyveck *u, const polyveck *v);


__global__ void polyveck_sub(int group,int step,int *f, unsigned int *n,polyveck *w, const polyveck *u, const polyveck *v);

__global__ void polyveck_shiftl(int group,int step,int *f, unsigned int *n,polyveck *v);



__global__ void polyveck_ntt(int group,polyveck *v);


__global__ void polyveck_invntt_tomont(int group,int step, int *f, unsigned int *n,polyveck *v);


__global__ void polyveck_pointwise_poly_montgomery(int group,int step,int *f, unsigned int *n,polyveck *r, const poly *a, const polyveck *v);





__global__ void polyveck_power2round(int group,polyveck *v1, polyveck *v0, const polyveck *v);

__global__ void polyveck_decompose(int group,int step, int *f, unsigned int *n,polyveck *v1, polyveck *v0, const polyveck *v);


__global__ void polyveck_make_hint(int group,int step,int *f, unsigned int *n,polyveck *h,
                                const polyveck *v0,
                                const polyveck *v1);


__global__ void polyveck_use_hint(int group, polyveck *w, const polyveck *v, const polyveck *h);


__global__ void polyveck_pack_w1(int group,int step, int *f, unsigned int *n,uint8_t r[(MESSAGELEN + CRYPTO_BYTES) * MAXGROUP], const polyveck *w1);

__global__ void polyveck_pack_w11(int group,uint8_t r[K * POLYW1_PACKEDBYTES * MAXGROUP], const polyveck *w1);

__global__ void polyvec_matrix_expand(int group,polyvecl mat[K*MAXGROUP], const uint8_t rho[3*SEEDBYTES*MAXGROUP]);
__global__ void polyvec_matrix_expand1(int group,polyvecl mat[K*MAXGROUP], const uint8_t rho[(2*SEEDBYTES + 3*CRHBYTES)*MAXGROUP]);

__global__ void polyvec_matrix_expand2(int group,polyvecl mat[K*MAXGROUP], const uint8_t rho[SEEDBYTES*MAXGROUP]);

__global__ void polyvec_matrix_pointwise_montgomery(int group,int step,int *f, unsigned int *n,polyveck *t, const polyvecl mat[K*MAXGROUP], const polyvecl *v);
#endif
