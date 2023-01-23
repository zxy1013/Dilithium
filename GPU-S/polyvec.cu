#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "reduce.h"
#include "params.h"
#include "polyvec.h"
#include "poly.h"
#include "ntt.h"
#include "rounding.h"


void polyvec_matrix_expand(polyvecl mat[K], const uint8_t rho[3*SEEDBYTES]) {
  unsigned int i, j;
  for(i = 0; i < K; ++i)
    for(j = 0; j < L; ++j)
      poly_uniform(&mat[i].vec[j], rho, (i << 8) + j);
}

void polyvec_matrix_expand1(polyvecl mat[K], const uint8_t rho[2*SEEDBYTES + 3*CRHBYTES]){
    unsigned int i, j;
    for(i = 0; i < K; ++i)
      for(j = 0; j < L; ++j)
        poly_uniform(&mat[i].vec[j], rho, (i << 8) + j);

}

void polyvec_matrix_expand2(polyvecl mat[K], const uint8_t rho[SEEDBYTES]){
    unsigned int i, j;
    for(i = 0; i < K; ++i)
      for(j = 0; j < L; ++j)
        poly_uniform(&mat[i].vec[j], rho, (i << 8) + j);
}

void polyvecl_uniform_eta(polyvecl *Cv, polyvecl *v, const uint8_t seed[2*SEEDBYTES], uint16_t nonce){
    unsigned int i;
    for(i = 0; i < L; ++i)
      poly_uniform_eta(&v->vec[i], seed, nonce++);
    for(i = 0; i < L; ++i)
      for(int k = 0; k < N; ++k) Cv->vec[i].coeffs[k] = v->vec[i].coeffs[k];
}

void polyvecl_uniform_gamma1(polyvecl *v, polyvecl *Cv,const uint8_t seed[CRHBYTES], uint16_t nonce){
  unsigned int i;
  for(i = 0; i < L; ++i)
    poly_uniform_gamma1(&v->vec[i], seed, L*nonce + i);
  for(i = 0; i < L; ++i)
    for(int k = 0; k < N; ++k) Cv->vec[i].coeffs[k] = v->vec[i].coeffs[k];
}

void polyveck_uniform_eta(polyveck *v, const uint8_t seed[2*SEEDBYTES], uint16_t nonce) {
    unsigned int i;
    for(i = 0; i < K; ++i)
      poly_uniform_eta(&v->vec[i], seed, nonce++);
}

int polyvecl_chknorm(const polyvecl *v, int32_t bound)  {
  unsigned int i;
  for(i = 0; i < L; ++i)
    if(poly_chknorm(&v->vec[i], bound))
      return 1;
  return 0;
}

int polyveck_chknorm(const polyveck *v, int32_t bound) {
  unsigned int i;

  for(i = 0; i < K; ++i)
    if(poly_chknorm(&v->vec[i], bound))
      return 1;

  return 0;
}


unsigned int polyveck_make_hint(polyveck *h,
                                const polyveck *v0,
                                const polyveck *v1)
{
  unsigned int i, s = 0;

  for(i = 0; i < K; ++i)
    s += poly_make_hint(&h->vec[i], &v0->vec[i], &v1->vec[i]);
  return s;
}






__global__ void Gpolyvecl_reduce(polyvecl *v){
    int tid = threadIdx.x;
    v->vec[blockIdx.x].coeffs[tid] = reduce32(v->vec[blockIdx.x].coeffs[tid]);
}

__global__ void Gpolyvec_matrix_pointwise_montgomery(polyveck *t, const polyvecl mat[K], const polyvecl *v){
    int32_t tm;
    unsigned int i;
    int tid = threadIdx.x;
    t->vec[blockIdx.x].coeffs[tid] = montgomery_reduce((int64_t)mat[blockIdx.x].vec[0].coeffs[tid] * v->vec[0].coeffs[tid]);
    
    for(i = 1; i < L; ++i) {
      tm = montgomery_reduce((int64_t)mat[blockIdx.x].vec[i].coeffs[tid] * v->vec[i].coeffs[tid]);
      __syncthreads();
      t->vec[blockIdx.x].coeffs[tid] = t->vec[blockIdx.x].coeffs[tid]  + tm;
    }
}

__global__ void Gpolyvecl_pointwise_poly_montgomery(polyvecl *r, const poly *a, const polyvecl *v){
  int tid = threadIdx.x;
  r->vec[blockIdx.x].coeffs[tid] = montgomery_reduce((int64_t)a->coeffs[tid] * v->vec[blockIdx.x].coeffs[tid]);
}


__global__ void Gpolyveck_reduce(polyveck *v) {
    int tid = threadIdx.x;
    v->vec[blockIdx.x].coeffs[tid] = reduce32(v->vec[blockIdx.x].coeffs[tid]);
}


__global__ void Gpolyveck_caddq(polyveck *v) {
  int tid = threadIdx.x;
  v->vec[blockIdx.x].coeffs[tid] = caddq(v->vec[blockIdx.x].coeffs[tid]);
}


__global__ void GpolyK_add(polyveck *w, const polyveck *u, const polyveck *v){
    int tid = threadIdx.x;
    w->vec[blockIdx.x].coeffs[tid] = u->vec[blockIdx.x].coeffs[tid] + v->vec[blockIdx.x].coeffs[tid];
}


__global__ void GpolyL_add(polyvecl *w, const polyvecl *u, const polyvecl *v){
    int tid = threadIdx.x;
    w->vec[blockIdx.x].coeffs[tid] = u->vec[blockIdx.x].coeffs[tid] + v->vec[blockIdx.x].coeffs[tid];
}


__global__ void Gpolyveck_sub(polyveck *w, const polyveck *u, const polyveck *v){
  int tid = threadIdx.x;
  w->vec[blockIdx.x].coeffs[tid] = u->vec[blockIdx.x].coeffs[tid] - v->vec[blockIdx.x].coeffs[tid];
}



__global__ void Gpolyveck_shiftl(polyveck *v){
  int tid = threadIdx.x;
  v->vec[blockIdx.x].coeffs[tid] <<= D;
}


__global__ void Gpolyveck_pointwise_poly_montgomery(polyveck *r, const poly *a, const polyveck *v){
  int tid = threadIdx.x;
  r->vec[blockIdx.x].coeffs[tid] = montgomery_reduce((int64_t)a->coeffs[tid] * v->vec[blockIdx.x].coeffs[tid]);
}


__global__ void Gpolyveck_power2round(polyveck *v1, polyveck *v0, const polyveck *v){
  int tid = threadIdx.x;
  v1->vec[blockIdx.x].coeffs[tid] = power2round(&v0->vec[blockIdx.x].coeffs[tid] , v->vec[blockIdx.x].coeffs[tid]);
}


__global__ void Gpolyveck_decompose(polyveck *v1, polyveck *v0, const polyveck *v){
  int tid = threadIdx.x;
  v1->vec[blockIdx.x].coeffs[tid] = decompose(&v0->vec[blockIdx.x].coeffs[tid] , v->vec[blockIdx.x].coeffs[tid]);
}



__global__ void Gpolyveck_use_hint(polyveck *w, const polyveck *v, const polyveck *h){
  int tid = threadIdx.x;
  w->vec[blockIdx.x].coeffs[tid] = use_hint(v->vec[blockIdx.x].coeffs[tid], h->vec[blockIdx.x].coeffs[tid]);
}


void polyveck_pack_w(uint8_t r[MESSAGELEN + CRYPTO_BYTES], const polyveck *w1){
  unsigned int i;
  for(i = 0; i < K; ++i)
    polyw1_pack(&r[i*POLYW1_PACKEDBYTES], &w1->vec[i]);
}

__global__ void Gpolyveck_pack_w1(uint8_t r[K * POLYW1_PACKEDBYTES], const polyveck *w1){
  int tid = threadIdx.x;
  r[tid + blockIdx.x * POLYW1_PACKEDBYTES] = w1->vec[blockIdx.x].coeffs[2*tid+0] | (w1->vec[blockIdx.x].coeffs[2*tid+1] << 4);
}