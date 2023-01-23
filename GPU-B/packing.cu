#include "params.h"
#include "packing.h"
#include "polyvec.h"
#include "poly.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/*************************************************
* Name:        pack_pk
*
* Description: Bit-pack public key pk = (rho, t1).
*
* Arguments:   - uint8_t pk[]: output byte array
*              - const uint8_t rho[]: byte array containing rho
*              - const polyveck *t1: pointer to vector t1
**************************************************/

__global__ void pack_pk(int group,uint8_t pk[CRYPTO_PUBLICKEYBYTES*MAXGROUP],
             const uint8_t rho[3*SEEDBYTES*MAXGROUP], const polyveck *t1){
  unsigned int i;
  int X = threadIdx.x + blockIdx.x * blockDim.x;
  if(X < group){
      for(i = 0; i < SEEDBYTES; ++i)
        pk[i+X*CRYPTO_PUBLICKEYBYTES] = rho[i+3*X*SEEDBYTES];
      pk = pk + SEEDBYTES;
      for(i = 0; i < K; ++i)
        polyt1_pack(pk + i*POLYT1_PACKEDBYTES+X*CRYPTO_PUBLICKEYBYTES, &t1->vec[i+X*K]);
  }
  /*
  if(X == 0){
    for(int k = CRYPTO_PUBLICKEYBYTES-SEEDBYTES;k<2*CRYPTO_PUBLICKEYBYTES-SEEDBYTES;k++) printf(" %d ",pk[k]);
    for(int k = 0;k<SEEDBYTES;k++) printf(" %d ",rho[k+3*1*SEEDBYTES]);
    for(int k = 0;k<N;k++) printf(" %d ",t1->vec[K-1].coeffs[k]);
  }
  */
}

/*************************************************
* Name:        unpack_pk
*
* Description: Unpack public key pk = (rho, t1).
*
* Arguments:   - const uint8_t rho[]: output byte array for rho
*              - const polyveck *t1: pointer to output vector t1
*              - uint8_t pk[]: byte array containing bit-packed pk
**************************************************/
__global__ void unpack_pk(int group,uint8_t rho[SEEDBYTES * MAXGROUP], polyveck *t1,
               const uint8_t pk[CRYPTO_PUBLICKEYBYTES * MAXGROUP])
{
  unsigned int i;
  int X = threadIdx.x + blockIdx.x * blockDim.x;
  if(X < group){
      for(i = 0; i < SEEDBYTES; ++i)
        rho[i+X*SEEDBYTES] = pk[i+X*CRYPTO_PUBLICKEYBYTES];
      pk += SEEDBYTES;

      for(i = 0; i < K; ++i)
        polyt1_unpack(&t1->vec[i+X*K], pk + i*POLYT1_PACKEDBYTES + X*CRYPTO_PUBLICKEYBYTES);
   }
  /*
  if(X == 0){
      for(int l =0;l<SEEDBYTES;l++) printf(" %d ",rho[l+SEEDBYTES]);
      printf("\n\n\n");
      for(int j = 0; j < K; j++) {
          for(int l =0;l<N;l++) printf(" %d ",t1->vec[j+K].coeffs[l]);
          printf("    ");
      }
  }
  */
}
/*************************************************
* Name:        pack_sk
*
* Description: Bit-pack secret key sk = (rho, tr, key, t0, s1, s2).
*
* Arguments:   - uint8_t sk[]: output byte array
*              - const uint8_t rho[]: byte array containing rho
*              - const uint8_t tr[]: byte array containing tr
*              - const uint8_t key[]: byte array containing key
*              - const polyveck *t0: pointer to vector t0
*              - const polyvecl *s1: pointer to vector s1
*              - const polyveck *s2: pointer to vector s2
**************************************************/
__global__ void pack_sk(int group,uint8_t sk[CRYPTO_SECRETKEYBYTES*MAXGROUP],
             const uint8_t rho[3*SEEDBYTES*MAXGROUP],
             const uint8_t tr[CRHBYTES * MAXGROUP],
             const uint8_t key[3*SEEDBYTES*MAXGROUP-2*SEEDBYTES],
             const polyveck *t0,
             const polyvecl *s1,
             const polyveck *s2)
{
  unsigned int i;
  int X = threadIdx.x + blockIdx.x * blockDim.x;
  if(X < group){
      for(i = 0; i < SEEDBYTES; ++i)
        sk[i+CRYPTO_SECRETKEYBYTES*X] = rho[i+3*SEEDBYTES*X];
      sk += SEEDBYTES+CRYPTO_SECRETKEYBYTES*X;

      for(i = 0; i < SEEDBYTES; ++i)
        sk[i] = key[i+3*SEEDBYTES*X];
      sk += SEEDBYTES;

      for(i = 0; i < CRHBYTES; ++i)
        sk[i] = tr[i+CRHBYTES*X];
      sk += CRHBYTES;
      
      for(i = 0; i < L; ++i)
        polyeta_pack(sk + i*POLYETA_PACKEDBYTES, &s1->vec[i+X*L]);
      sk += L*POLYETA_PACKEDBYTES;
      
      for(i = 0; i < K; ++i)
        polyeta_pack(sk + i*POLYETA_PACKEDBYTES, &s2->vec[i+X*K]);
      sk += K*POLYETA_PACKEDBYTES;

      for(i = 0; i < K; ++i)
        polyt0_pack(sk + i*POLYT0_PACKEDBYTES, &t0->vec[i+X*K]);
  }
}

/*************************************************
* Name:        unpack_sk
*
* Description: Unpack secret key sk = (rho, tr, key, t0, s1, s2).
*
* Arguments:   - const uint8_t rho[]: output byte array for rho
*              - const uint8_t tr[]: output byte array for tr
*              - const uint8_t key[]: output byte array for key
*              - const polyveck *t0: pointer to output vector t0
*              - const polyvecl *s1: pointer to output vector s1
*              - const polyveck *s2: pointer to output vector s2
*              - uint8_t sk[]: byte array containing bit-packed sk
**************************************************/
__global__ void unpack_sk(int group,uint8_t rho[(2*SEEDBYTES + 3*CRHBYTES) * MAXGROUP],
               uint8_t tr[(2*SEEDBYTES + 3*CRHBYTES) * MAXGROUP - 2 * SEEDBYTES],
               uint8_t key[(2*SEEDBYTES + 3*CRHBYTES) * MAXGROUP - SEEDBYTES],
               polyveck *t0,
               polyvecl *s1,
               polyveck *s2,
               const uint8_t sk[CRYPTO_SECRETKEYBYTES * MAXGROUP])
{
  unsigned int i;
  int X = threadIdx.x + blockIdx.x * blockDim.x;
  if(X < group){
      for(i = 0; i < SEEDBYTES; ++i)
        rho[i+(2*SEEDBYTES + 3*CRHBYTES)*X] = sk[i+X*CRYPTO_SECRETKEYBYTES];
      sk += SEEDBYTES;

      for(i = 0; i < SEEDBYTES; ++i)
        key[i+(2*SEEDBYTES + 3*CRHBYTES)*X] = sk[i+X*CRYPTO_SECRETKEYBYTES];
      sk += SEEDBYTES;

      for(i = 0; i < CRHBYTES; ++i)
        tr[i+(2*SEEDBYTES + 3*CRHBYTES)*X] = sk[i+X*CRYPTO_SECRETKEYBYTES];
      sk += CRHBYTES;

      for(i=0; i < L; ++i)
        polyeta_unpack(&s1->vec[i+X*L], sk + i*POLYETA_PACKEDBYTES+X*CRYPTO_SECRETKEYBYTES);
      sk += L*POLYETA_PACKEDBYTES;

      for(i=0; i < K; ++i)
        polyeta_unpack(&s2->vec[i+X*K], sk + i*POLYETA_PACKEDBYTES+X*CRYPTO_SECRETKEYBYTES);
      sk += K*POLYETA_PACKEDBYTES;

      for(i=0; i < K; ++i)
        polyt0_unpack(&t0->vec[i+X*K], sk + i*POLYT0_PACKEDBYTES+X*CRYPTO_SECRETKEYBYTES);
   }
   /*
   if( X == 0){
        for(int i = 0;i<N;i++) printf(" %d ",s1->vec[2*L-1].coeffs[i]);
        printf("\n");
        for(int i = 0;i<N;i++) printf(" %d ",s2->vec[2*K-1].coeffs[i]);
        printf("\n");
        for(int i = 0;i<N;i++) printf(" %d ",t0->vec[2*K-1].coeffs[i]);
        printf("\n");
        
        for(int i = 0;i<SEEDBYTES;i++) printf(" %d ",rho[i+(2*SEEDBYTES + 3*CRHBYTES)]);
        printf("\n");
        for(int i = 0;i<CRHBYTES;i++) printf(" %d ",tr[i+(2*SEEDBYTES + 3*CRHBYTES)]);
        printf("\n");
        for(int i = 0;i<SEEDBYTES;i++) printf(" %d ",key[i+(2*SEEDBYTES + 3*CRHBYTES)]);
        printf("\n");
   }
  */
}

/*************************************************
* Name:        pack_sig
*
* Description: Bit-pack signature sig = (c, z, h).
*
* Arguments:   - uint8_t sig[]: output byte array
*              - const uint8_t *c: pointer to challenge hash length SEEDBYTES
*              - const polyvecl *z: pointer to vector z
*              - const polyveck *h: pointer to hint vector h
**************************************************/
__global__ void pack_sig(int group,uint8_t sig[(MESSAGELEN + CRYPTO_BYTES) * MAXGROUP],
              const uint8_t c[(MESSAGELEN + CRYPTO_BYTES) * MAXGROUP], const polyvecl *z, const polyveck *h){
  unsigned int i, j, k;
  int X = threadIdx.x + blockIdx.x * blockDim.x;
  if(X < group){
      for(i=0; i < SEEDBYTES; ++i)
        sig[i+X*(MESSAGELEN + CRYPTO_BYTES)] = c[i+X*(MESSAGELEN + CRYPTO_BYTES)];
      
      for(i = 0; i < L; ++i)
        polyz_pack(sig + i*POLYZ_PACKEDBYTES+X*(MESSAGELEN + CRYPTO_BYTES)+ SEEDBYTES, &z->vec[i+X*L]);
      
      // Encode h 
      for(i = 0; i < OMEGA + K; ++i)
        sig[i+X*(MESSAGELEN + CRYPTO_BYTES)+ SEEDBYTES+L*POLYZ_PACKEDBYTES] = 0;

      k = 0;
      for(i = 0; i < K; ++i) {
        for(j = 0; j < N; ++j)
          if(h->vec[i+X*K].coeffs[j] != 0){
            sig[k+X*(MESSAGELEN + CRYPTO_BYTES)+ SEEDBYTES+L*POLYZ_PACKEDBYTES] = j;
            k++;
          }
          __syncthreads();
        sig[OMEGA + i + X*(MESSAGELEN + CRYPTO_BYTES)+ SEEDBYTES+L*POLYZ_PACKEDBYTES] = k;
      }
  }
  /*
  if(X == 0) {
    for(int k =0 ;k<MESSAGELEN + CRYPTO_BYTES;k++)printf(" %d ",sig[k+MESSAGELEN + CRYPTO_BYTES]);
  }
  */
}
/*************************************************
* Name:        unpack_sig
*
* Description: Unpack signature sig = (c, z, h).
*
* Arguments:   - uint8_t *c: pointer to output challenge hash
*              - polyvecl *z: pointer to output vector z
*              - polyveck *h: pointer to output hint vector h
*              - const uint8_t sig[]: byte array containing
*                bit-packed signature
*
* Returns 1 in case of malformed signature; otherwise 0.
**************************************************/
__global__ void unpack_sig(int group,int *f,uint8_t c[SEEDBYTES * MAXGROUP], polyvecl *z, polyveck *h,
               const uint8_t sig[(MESSAGELEN + CRYPTO_BYTES) * MAXGROUP]){
  unsigned int i, j, k;
  int X = threadIdx.x + blockIdx.x * blockDim.x;
  if(X < group){
      for(i = 0; i < SEEDBYTES; ++i)
        c[i + SEEDBYTES * X] = sig[i + (MESSAGELEN + CRYPTO_BYTES) * X];
      sig += SEEDBYTES;

      for(i = 0; i < L; ++i)
        polyz_unpack(&z->vec[i+X*L], sig + i*POLYZ_PACKEDBYTES + (MESSAGELEN + CRYPTO_BYTES) * X);
      sig += L*POLYZ_PACKEDBYTES;

      k = 0;
      for(i = 0; i < K; ++i) {
        for(j = 0; j < N; ++j)
          h->vec[i + X * K].coeffs[j] = 0;

        if(sig[OMEGA + i + (MESSAGELEN + CRYPTO_BYTES) * X] < k || sig[OMEGA + i + (MESSAGELEN + CRYPTO_BYTES) * X] > OMEGA)
          *(f+X) = 1;
        __syncthreads();
        for(j = k; j < sig[OMEGA + i + (MESSAGELEN + CRYPTO_BYTES) * X]; ++j) {
          if(j > k && sig[j+ (MESSAGELEN + CRYPTO_BYTES) * X] <= sig[j-1 + (MESSAGELEN + CRYPTO_BYTES) * X]) 
             *(f+X) = 1;
          __syncthreads();
          h->vec[i + X * K].coeffs[sig[j+ (MESSAGELEN + CRYPTO_BYTES) * X]] = 1;
        }
        k = sig[OMEGA + i + (MESSAGELEN + CRYPTO_BYTES) * X];
      }

      /* Extra indices are zero for strong unforgeability */
      for(j = k; j < OMEGA; ++j)
        if(sig[j+ (MESSAGELEN + CRYPTO_BYTES) * X])
          *(f+X) = 1;
  }
  /*
  if(X == 0){
      for(i = 0; i < SEEDBYTES; ++i) printf(" %d ",c[i+SEEDBYTES]);
      printf("\n\n\n");
      for(int j = 0; j < L; j++) {
          for(int l =0;l<N;l++) printf(" %d ",z->vec[j+L].coeffs[l]);
          printf("    ");
      }
      printf("\n\n\n");
      for(int j = 0; j < K; j++) {
          for(int l =0;l<N;l++) printf(" %d ",h->vec[j+K].coeffs[l]);
          printf("    ");
      }
  }
  */
}
