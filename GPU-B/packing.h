#ifndef PACKING_H
#define PACKING_H

#include <stdint.h>
#include "params.h"
#include "polyvec.h"

__global__ void pack_pk(int group,uint8_t pk[CRYPTO_PUBLICKEYBYTES*MAXGROUP],
             const uint8_t rho[3*SEEDBYTES*MAXGROUP], const polyveck *t1);


__global__ void pack_sk(int group,uint8_t sk[CRYPTO_SECRETKEYBYTES*MAXGROUP],
             const uint8_t rho[3*SEEDBYTES*MAXGROUP],
             const uint8_t tr[CRHBYTES * MAXGROUP],
             const uint8_t key[3*SEEDBYTES*MAXGROUP-2*SEEDBYTES],
             const polyveck *t0,
             const polyvecl *s1,
             const polyveck *s2);


__global__ void pack_sig(int group,uint8_t sig[(MESSAGELEN + CRYPTO_BYTES) * MAXGROUP],
              const uint8_t c[(MESSAGELEN + CRYPTO_BYTES) * MAXGROUP], const polyvecl *z, const polyveck *h);

__global__ void unpack_pk(int group,uint8_t rho[SEEDBYTES* MAXGROUP], polyveck *t1,
               const uint8_t pk[CRYPTO_PUBLICKEYBYTES * MAXGROUP]);

__global__ void unpack_sk(int group,uint8_t rho[(2*SEEDBYTES + 3*CRHBYTES) * MAXGROUP],
               uint8_t tr[(2*SEEDBYTES + 3*CRHBYTES) * MAXGROUP - 2 * SEEDBYTES],
               uint8_t key[(2*SEEDBYTES + 3*CRHBYTES) * MAXGROUP - SEEDBYTES],
               polyveck *t0,
               polyvecl *s1,
               polyveck *s2,
               const uint8_t sk[CRYPTO_SECRETKEYBYTES * MAXGROUP]);

__global__ void unpack_sig(int group,int *f,uint8_t c[SEEDBYTES * MAXGROUP], polyvecl *z, polyveck *h,
               const uint8_t sig[(MESSAGELEN + CRYPTO_BYTES) * MAXGROUP]);

#endif
