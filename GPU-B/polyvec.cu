#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "params.h"
#include "polyvec.h"
#include "poly.h"
#include "ntt.h"
/*************************************************
* Name:        expand_mat
*
* Description: Implementation of ExpandA. Generates matrix A with uniformly
*              random coefficients a_{i,j} by performing rejection
*              sampling on the output stream of SHAKE128(rho|j|i)
*              or AES256CTR(rho,j|i).
*
* Arguments:   - polyvecl mat[K]: output matrix
*              - const uint8_t rho[]: byte array containing seed rho
**************************************************/

__global__ void polyvec_matrix_expand(int group,polyvecl mat[K*MAXGROUP], const uint8_t rho[3*SEEDBYTES*MAXGROUP]) {
  unsigned int i, j;
  int X = threadIdx.x + blockIdx.x * blockDim.x;
  if(X < group){
    for(i = 0; i < K; ++i)
      for(j = 0; j <L; ++j)
        poly_uniform(&mat[i+X*K].vec[j], rho+X*3*SEEDBYTES, (i << 8) + j);
  }
  //if(X == 0)
    //for(int k = 0;k<N;k++) printf(" %d ",mat[K-1].vec[j-1].coeffs[k]);
}
__global__ void polyvec_matrix_expand1(int group,polyvecl mat[K*MAXGROUP], const uint8_t rho[(2*SEEDBYTES + 3*CRHBYTES)*MAXGROUP]){
  unsigned int i, j;
  int X = threadIdx.x + blockIdx.x * blockDim.x;
  if(X < group){
    for(i = 0; i < K; ++i)
      for(j = 0; j < L; ++j)
        poly_uniform(&mat[i+X*K].vec[j], rho+X*(2*SEEDBYTES + 3*CRHBYTES), (i << 8) + j);
  }
  //if(X == 0)
    //for(int k = 0;k<N;k++) printf(" %d ",mat[2*K-1].vec[L-1].coeffs[k]);
}

__global__ void polyvec_matrix_expand2(int group,polyvecl mat[K*MAXGROUP], const uint8_t rho[SEEDBYTES*MAXGROUP]){
  unsigned int i, j;
  int X = threadIdx.x + blockIdx.x * blockDim.x;
  if(X < group){
    for(i = 0; i < K; ++i)
      for(j = 0; j < L; ++j)
        poly_uniform(&mat[i+X*K].vec[j], rho+X*SEEDBYTES, (i << 8) + j);
  }
  //if(X == 0)
    //for(int k = 0;k<N;k++) printf(" %d ",mat[2*K-1].vec[L-1].coeffs[k]);
}


__global__ void polyvec_matrix_pointwise_montgomery(int group, int step, int *f, unsigned int *n,polyveck *t, const polyvecl mat[K*MAXGROUP], const polyvecl *v) {
  unsigned int i;
  int X = threadIdx.x + blockIdx.x * blockDim.x;
  if(X < group && (f[X] == step && n[X] > OMEGA)){
    for(i = 0; i < K; ++i)
      polyvecl_pointwise_acc_montgomery(&t->vec[i+X*K], &mat[i+X*K], v+X);
  }
  //if(X == 0)
    //for(int y = 0;y<N;y++) printf(" %d ",t->vec[1].coeffs[y]);
}

/**************************************************************/
/************ Vectors of polynomials of length L **************/
/**************************************************************/

__global__ void polyvecl_uniform_eta(int group,polyvecl *Cv, polyvecl *v, const uint8_t seed[3*SEEDBYTES*MAXGROUP-SEEDBYTES], uint16_t nonce){
  unsigned int i;
  int X = threadIdx.x + blockIdx.x * blockDim.x;
  if (X < group){
    for(i = 0; i < L; ++i)
      poly_uniform_eta(&v->vec[i+X*L], seed+X*3*SEEDBYTES, nonce++);
    for(i = 0; i < L; ++i)
      for(int k = 0; k < N; ++k) Cv->vec[i+X*L].coeffs[k] = v->vec[i+X*L].coeffs[k];
  }
  //if(X == 0)
    //for(int k = 0;k<256;k++) printf(" %d ",Cv->vec[L-1].coeffs[k]);
}


__global__ void polyvecl_uniform_gamma1(int group,int step, int *f, unsigned int *n,polyvecl *v, polyvecl *Cv,const uint8_t seed[(2*SEEDBYTES + 3*CRHBYTES)*MAXGROUP-2*SEEDBYTES-2*CRHBYTES], uint16_t nonce){
  unsigned int i;
  int X = threadIdx.x + blockIdx.x * blockDim.x;
  if (X < group && (f[X] == step && n[X] > OMEGA)){
      for(i = 0; i < L; ++i)
        poly_uniform_gamma1(&v->vec[i+X*L], seed+(2*SEEDBYTES + 3*CRHBYTES)*X, L*nonce + i);
      for(i = 0; i < L; ++i)
        for(int k = 0; k < N; ++k) Cv->vec[i+X*L].coeffs[k] = v->vec[i+X*L].coeffs[k];
  }
  //if(X == 0)
    //for(int k = 0;k<48;k++) printf(" %d ",seed[k+2*SEEDBYTES + 3*CRHBYTES]);
    //for(int k = 0;k<N;k++) printf(" %d ",v->vec[2*L-1].coeffs[k]);
}


__global__ void polyvecl_reduce(int group,int step, int *f, unsigned int *n,polyvecl *v){
  unsigned int i;
  int X = threadIdx.x + blockIdx.x * blockDim.x;
  if (X < group && (f[X] == step && n[X] > OMEGA)){
      for(i = 0; i < L; ++i)
        poly_reduce(&v->vec[i+X*L]);
  }
  //if(X == 0)for(int k = 0;k<N;k++) printf(" %d ",v->vec[2*L-1].coeffs[k]);
}

/*************************************************
* Name:        polyvecl_add
*
* Description: Add vectors of polynomials of length L.
*              No modular reduction is performed.
*
* Arguments:   - polyvecl *w: pointer to output vector
*              - const polyvecl *u: pointer to first summand
*              - const polyvecl *v: pointer to second summand
**************************************************/

__global__ void polyvecl_add(int group,int step, int *f, unsigned int *n,polyvecl *w, const polyvecl *u, const polyvecl *v) {
  unsigned int i;
  int X = threadIdx.x + blockIdx.x * blockDim.x;

  if(X < group && (f[X] == step && n[X] > OMEGA)){
      for(i = 0; i < L; ++i)
        poly_add(&w->vec[i+X*L], &u->vec[i+X*L], &v->vec[i+X*L]);
  }
}

/*************************************************
* Name:        polyvecl_ntt
*
* Description: Forward NTT of all polynomials in vector of length L. Output
*              coefficients can be up to 16*Q larger than input coefficients.
*
* Arguments:   - polyvecl *v: pointer to input/output vector
**************************************************/

__global__ void polyvecl_ntt(int group,int step, int *f, unsigned int *n,polyvecl *v){
  unsigned int i;
  int X = threadIdx.x + blockIdx.x * blockDim.x;

  if(X < group && (f[X] == step && n[X] > OMEGA)){
    for(i = 0; i < L; ++i)
      poly_ntt(&v->vec[i+X*L]);
  }
  //if(X == 0)
    //for(int y = 0;y<N;y++) printf(" %d ",v->vec[0].coeffs[y]);
}

__global__ void polyvecl_invntt_tomont(int group,int step, int *f, unsigned int *n,polyvecl *v){
  unsigned int i;
  int X = threadIdx.x + blockIdx.x * blockDim.x;
  if(X < group && (f[X] == step && n[X] > OMEGA)){
      for(i = 0; i < L; ++i)
        poly_invntt_tomont(&v->vec[i+X*L]);
  }
}


__global__ void polyvecl_pointwise_poly_montgomery(int group,int step, int *f, unsigned int *n,polyvecl *r, const poly *a, const polyvecl *v){
  unsigned int i;
  int X = threadIdx.x + blockIdx.x * blockDim.x;

  if(X < group && (f[X] == step && n[X] > OMEGA)){
      for(i = 0; i < L; ++i)
        poly_pointwise_montgomery(&r->vec[i+X*L], a+X, &v->vec[i+X*L]);
  }
  // if(X == 0) for(int k =0 ;k<N;k++)printf(" %d ",r->vec[2*L-1].coeffs[k]); 
}

/*************************************************
* Name:        polyvecl_pointwise_acc_montgomery
*
* Description: Pointwise multiply vectors of polynomials of length L, multiply
*              resulting vector by 2^{-32} and add (accumulate) polynomials
*              in it. Input/output vectors are in NTT domain representation.
*
* Arguments:   - poly *w: output polynomial
*              - const polyvecl *u: pointer to first input vector
*              - const polyvecl *v: pointer to second input vector
**************************************************/

__device__ void polyvecl_pointwise_acc_montgomery(poly *w,
                                       const polyvecl *u,
                                       const polyvecl *v)
{
  unsigned int i;
  poly t;
  poly_pointwise_montgomery(w, &u->vec[0], &v->vec[0]);
  for(i = 1; i < L; ++i) {
    poly_pointwise_montgomery(&t, &u->vec[i], &v->vec[i]);
    poly_add(w, w, &t);
  }
}

/*************************************************
* Name:        polyvecl_chknorm
*
* Description: Check infinity norm of polynomials in vector of length L.
*              Assumes input polyvecl to be reduced by polyvecl_reduce().
*
* Arguments:   - const polyvecl *v: pointer to vector
*              - int32_t B: norm bound
*
* Returns 0 if norm of all polynomials is strictly smaller than B <= (Q-1)/8
* and 1 otherwise.
**************************************************/
__global__ void polyvecl_chknorm(int group,int step, int *f, unsigned int *n,const polyvecl *v,int32_t bound){

  unsigned int i;
  int X = threadIdx.x + blockIdx.x * blockDim.x;
  
  if(X < group && (f[X] == step && n[X] > OMEGA)){
      *(f + X) = step+1;
      for(i = 0; i < L; ++i)
        poly_chknorm(&v->vec[i+X*L], f+X, bound);
  }
  // if(X == 0)printf(" %d %d ",*f,*f+X);
}
/*************************************************
* Name:        polyveck_chknorm
*
* Description: Check infinity norm of polynomials in vector of length K.
*              Assumes input polyveck to be reduced by polyveck_reduce().
*
* Arguments:   - const polyveck *v: pointer to vector
*              - int32_t B: norm bound
*
* Returns 0 if norm of all polynomials are strictly smaller than B <= (Q-1)/8
* and 1 otherwise.
**************************************************/
__global__ void polyveck_chknorm(int group,int step, int *f, unsigned int *n,const polyveck *v, int32_t bound){
  unsigned int i;
  int X = threadIdx.x + blockIdx.x * blockDim.x;
  
  if(X < group && (f[X] == step && n[X] > OMEGA)){
      *(f + X) = step+1;
      for(i = 0; i < K; ++i)
        poly_chknorm(&v->vec[i+X*K],f+X, bound);
  }
  //if(X == 0)printf(" %d %d ",*f,*f+X);
}


/**************************************************************/
/************ Vectors of polynomials of length K **************/
/**************************************************************/

__global__ void polyveck_uniform_eta(int group,polyveck *v, const uint8_t seed[3*SEEDBYTES*MAXGROUP-SEEDBYTES], uint16_t nonce) {
  unsigned int i;
  int X = threadIdx.x + blockIdx.x * blockDim.x;
  if (X < group)
    for(i = 0; i < K; ++i)
      poly_uniform_eta(&v->vec[i+X*K], seed+X*3*SEEDBYTES, nonce++);
  //if(X == 0)
    //for(int y = 0;y<N;y++) printf(" %d ",v->vec[K-1].coeffs[y]);
}


/*************************************************
* Name:        polyveck_reduce
*
* Description: Reduce coefficients of polynomials in vector of length K
*              to representatives in [-6283009,6283007].
*
* Arguments:   - polyveck *v: pointer to input/output vector
**************************************************/

__global__ void polyveck_reduce(int group,int step, int *f, unsigned int *n,polyveck *v) {
  unsigned int i;
  int X = threadIdx.x + blockIdx.x * blockDim.x;
  if (X < group && (f[X] == step && n[X] > OMEGA)){
    for(i = 0; i < K; ++i)
      poly_reduce(&v->vec[i+X*K]);}
  //if(X == 0)
    //for(int y = 0;y<N;y++) printf(" %d ",v->vec[2*K-1].coeffs[y]);
}

/*************************************************
* Name:        polyveck_caddq
*
* Description: For all coefficients of polynomials in vector of length K
*              add Q if coefficient is negative.
*
* Arguments:   - polyveck *v: pointer to input/output vector
**************************************************/
__global__ void polyveck_caddq(int group,int step, int *f, unsigned int *n,polyveck *v) {
  unsigned int i;
  int X = threadIdx.x + blockIdx.x * blockDim.x;
  if (X < group && (f[X] == step && n[X] > OMEGA)){
    for(i = 0; i < K; ++i)
      poly_caddq(&v->vec[i+X*K]);}
  //if(X == 0)
    //for(int y = 0;y<N;y++) printf(" %d ",v->vec[1].coeffs[y]);
}

/*************************************************
* Name:        polyveck_add
*
* Description: Add vectors of polynomials of length K.
*              No modular reduction is performed.
*
* Arguments:   - polyveck *w: pointer to output vector
*              - const polyveck *u: pointer to first summand
*              - const polyveck *v: pointer to second summand
**************************************************/
__global__ void polyveck_add(int group,int step, int *f, unsigned int *n,polyveck *w, const polyveck *u, const polyveck *v){
  unsigned int i;
  int X = threadIdx.x + blockIdx.x * blockDim.x;
  if (X < group && (f[X] == step && n[X] > OMEGA)){
    for(i = 0; i < K; ++i)
      poly_add(&w->vec[i+X*K], &u->vec[i+X*K], &v->vec[i+X*K]);}
  //if(X == 0)
    //for(int y = 0;y<N;y++) printf(" %d ",u->vec[1].coeffs[y]);
}

/*************************************************
* Name:        polyveck_sub
*
* Description: Subtract vectors of polynomials of length K.
*              No modular reduction is performed.
*
* Arguments:   - polyveck *w: pointer to output vector
*              - const polyveck *u: pointer to first input vector
*              - const polyveck *v: pointer to second input vector to be
*                                   subtracted from first input vector
**************************************************/

__global__ void polyveck_sub(int group,int step, int *f, unsigned int *n,polyveck *w, const polyveck *u, const polyveck *v){
  unsigned int i;
  int X = threadIdx.x + blockIdx.x * blockDim.x;
  if (X < group && (f[X] == step && n[X] > OMEGA)){
      for(i = 0; i < K; ++i)
        poly_sub(&w->vec[i+X*K], &u->vec[i+X*K], &v->vec[i+X*K]);}
  //if(X == 0)
    //for(int y = 0;y<N;y++) printf(" %d ",w->vec[2*K-1].coeffs[y]);
}

/*************************************************
* Name:        polyveck_shiftl
*
* Description: Multiply vector of polynomials of Length K by 2^D without modular
*              reduction. Assumes input coefficients to be less than 2^{31-D}.
*
* Arguments:   - polyveck *v: pointer to input/output vector
**************************************************/

__global__ void polyveck_shiftl(int group,int step,int *f, unsigned int *n,polyveck *v){
  unsigned int i;
  int X = threadIdx.x + blockIdx.x * blockDim.x;
  if (X < group && (f[X] == step && n[X] > OMEGA)){
      for(i = 0; i < K; ++i)
        poly_shiftl(&v->vec[i+X*K]);}
  //if(X == 0)
    //for(int y = 0;y<N;y++) printf(" %d ",v->vec[2*K-1].coeffs[y]);
}

/*************************************************
* Name:        polyveck_ntt
*
* Description: Forward NTT of all polynomials in vector of length K. Output
*              coefficients can be up to 16*Q larger than input coefficients.
*
* Arguments:   - polyveck *v: pointer to input/output vector
**************************************************/
__global__ void polyveck_ntt(int group,polyveck *v){
  unsigned int i;
  int X = threadIdx.x + blockIdx.x * blockDim.x;
  if(X < group){
    for(i = 0; i < K; ++i)
      poly_ntt(&v->vec[i+X*K]);
  }
  //if(X == 0)
    //for(int y = 0;y<N;y++) printf(" %d ",v->vec[2*K-1].coeffs[y]);
}

/*************************************************
* Name:        polyveck_invntt_tomont
*
* Description: Inverse NTT and multiplication by 2^{32} of polynomials
*              in vector of length K. Input coefficients need to be less
*              than 2*Q.
*
* Arguments:   - polyveck *v: pointer to input/output vector
**************************************************/
__global__ void polyveck_invntt_tomont(int group,int step, int *f, unsigned int *n,polyveck *v){
  unsigned int i;
  int X = threadIdx.x + blockIdx.x * blockDim.x;
  
  if (X < group && (f[X] == step && n[X] > OMEGA)){
    for(i = 0; i < K; ++i)
      poly_invntt_tomont(&v->vec[i+X*K]);}
  //if(X == 0)
    //for(int y = 0;y<N;y++) printf(" %d ",v->vec[2*K-1].coeffs[y]);
}


__global__ void polyveck_pointwise_poly_montgomery(int group,int step,int *f, unsigned int *n,polyveck *r, const poly *a, const polyveck *v){
  unsigned int i;
  int X = threadIdx.x + blockIdx.x * blockDim.x;
  if (X < group && (f[X] == step && n[X] > OMEGA)){
  for(i = 0; i < K; ++i)
    poly_pointwise_montgomery(&r->vec[i+X*K], a+X, &v->vec[i+X*K]);}
  //if(X == 0) for(int y = 0;y<N;y++) printf(" %d ",r->vec[2*K-1].coeffs[y]);
}

/*************************************************
* Name:        polyveck_power2round
*
* Description: For all coefficients a of polynomials in vector of length K,
*              compute a0, a1 such that a mod^+ Q = a1*2^D + a0
*              with -2^{D-1} < a0 <= 2^{D-1}. Assumes coefficients to be
*              standard representatives.
*
* Arguments:   - polyveck *v1: pointer to output vector of polynomials with
*                              coefficients a1
*              - polyveck *v0: pointer to output vector of polynomials with
*                              coefficients a0
*              - const polyveck *v: pointer to input vector
**************************************************/
__global__ void polyveck_power2round(int group,polyveck *v1, polyveck *v0, const polyveck *v){
  unsigned int i;
  int X = threadIdx.x + blockIdx.x * blockDim.x;
  //if(X == 0)
    //for(int y = 0;y<N;y++) printf(" %d ",v->vec[1].coeffs[y]);
  if (X < group)
    for(i = 0; i < K; ++i)
       poly_power2round(&v1->vec[i+K*X], &v0->vec[i+K*X], &v->vec[i+K*X]);
  
}

/*************************************************
* Name:        polyveck_decompose
*
* Description: For all coefficients a of polynomials in vector of length K,
*              compute high and low bits a0, a1 such a mod^+ Q = a1*ALPHA + a0
*              with -ALPHA/2 < a0 <= ALPHA/2 except a1 = (Q-1)/ALPHA where we
*              set a1 = 0 and -ALPHA/2 <= a0 = a mod Q - Q < 0.
*              Assumes coefficients to be standard representatives.
*
* Arguments:   - polyveck *v1: pointer to output vector of polynomials with
*                              coefficients a1
*              - polyveck *v0: pointer to output vector of polynomials with
*                              coefficients a0
*              - const polyveck *v: pointer to input vector
**************************************************/
__global__ void polyveck_decompose(int group,int step, int *f, unsigned int *n,polyveck *v1, polyveck *v0, const polyveck *v){
  unsigned int i;
  int X = threadIdx.x + blockIdx.x * blockDim.x;
  if (X < group && (f[X] == step && n[X] > OMEGA)){
      for(i = 0; i < K; ++i)
        poly_decompose(&v1->vec[i+X*K], &v0->vec[i+X*K], &v->vec[i+X*K]);
  }
  //if(X == 0)
    //for(int y = 0;y<N;y++) printf(" %d ",v1->vec[2*K-1].coeffs[y]);
}
/*************************************************
* Name:        polyveck_make_hint
*
* Description: Compute hint vector.
*
* Arguments:   - polyveck *h: pointer to output vector
*              - const polyveck *v0: pointer to low part of input vector
*              - const polyveck *v1: pointer to high part of input vector
*
* Returns number of 1 bits.
**************************************************/
__global__ void polyveck_make_hint(int group,int step,int *f, unsigned int *n,polyveck *h,
                                const polyveck *v0,
                                const polyveck *v1){
  unsigned int i, s = 0;
  int X = threadIdx.x + blockIdx.x * blockDim.x;
  if (X < group && (f[X] == step && n[X] > OMEGA)){
      for(i = 0; i < K; ++i)
        s += poly_make_hint(&h->vec[i+X*K], &v0->vec[i+X*K], &v1->vec[i+X*K]);
      *(n+X) = s;
      if (s > OMEGA){
        *(f+X) = 2;
      }
  }
  // if(X == 0){printf(" %d ",*(n+1));}
}
/*************************************************
* Name:        polyveck_use_hint
*
* Description: Use hint vector to correct the high bits of input vector.
*
* Arguments:   - polyveck *w: pointer to output vector of polynomials with
*                             corrected high bits
*              - const polyveck *u: pointer to input vector
*              - const polyveck *h: pointer to input hint vector
**************************************************/

__global__ void polyveck_use_hint(int group, polyveck *w, const polyveck *v, const polyveck *h){
  unsigned int i;
  int X = threadIdx.x + blockIdx.x * blockDim.x;
  if (X < group){
      for(i = 0; i < K; ++i)
        poly_use_hint(&w->vec[i+X*K], &v->vec[i+X*K], &h->vec[i+X*K]);}
  //if(X == 0){
      //for(int y = 0;y<N;y++) printf(" %d ",w->vec[2*K-1].coeffs[y]);
  //}
}


__global__ void polyveck_pack_w1(int group,int step, int *f, unsigned int *n,uint8_t r[(MESSAGELEN + CRYPTO_BYTES) * MAXGROUP], const polyveck *w1){
  unsigned int i;
  int X = threadIdx.x + blockIdx.x * blockDim.x;
  if (X < group && (f[X] == step && n[X] > OMEGA)){
      for(i = 0; i < K; ++i)
        polyw1_pack(&r[i*POLYW1_PACKEDBYTES+X*(MESSAGELEN + CRYPTO_BYTES)], &w1->vec[i+X*K]);
  }
  //if(X == 0)
   //for(int y = 0;y<K*POLYW1_PACKEDBYTES;y++) printf(" %d ",r[y+(MESSAGELEN + CRYPTO_BYTES)]);
}

__global__ void polyveck_pack_w11(int group,uint8_t r[K * POLYW1_PACKEDBYTES * MAXGROUP], const polyveck *w1){
  unsigned int i;
  int X = threadIdx.x + blockIdx.x * blockDim.x;
  if (X < group){
      for(i = 0; i < K; ++i)
        polyw1_pack(&r[i*POLYW1_PACKEDBYTES + X* K * POLYW1_PACKEDBYTES], &w1->vec[i+X*K]);
  }
  //if(X == 0)
   //for(int y = 0;y<K*POLYW1_PACKEDBYTES;y++) printf(" %d ",r[y + K * POLYW1_PACKEDBYTES]);
}