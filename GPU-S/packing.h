#ifndef PACKING_H
#define PACKING_H

#include <stdint.h>
#include "params.h"
#include "polyvec.h"


void pack_pk(uint8_t pk[CRYPTO_PUBLICKEYBYTES],
             const uint8_t rho[3*SEEDBYTES], const polyveck *t1);

void pack_sk(uint8_t sk[CRYPTO_SECRETKEYBYTES],
             const uint8_t rho[3*SEEDBYTES],
             const uint8_t tr[CRHBYTES ],
             const uint8_t key[SEEDBYTES],
             const polyveck *t0,
             const polyvecl *s1,
             const polyveck *s2);

void unpack_sk(uint8_t rho[2*SEEDBYTES + 3*CRHBYTES],
               uint8_t tr[3*CRHBYTES],
               uint8_t key[SEEDBYTES + 3*CRHBYTES],
               polyveck *t0,
               polyvecl *s1,
               polyveck *s2,
               const uint8_t sk[CRYPTO_SECRETKEYBYTES]);

void pack_sig(uint8_t sig[(MESSAGELEN + CRYPTO_BYTES) ],
              const uint8_t c[(MESSAGELEN + CRYPTO_BYTES) ], const polyvecl *z, const polyveck *h);

void unpack_pk(uint8_t rho[SEEDBYTES], polyveck *t1,
               const uint8_t pk[CRYPTO_PUBLICKEYBYTES ]);


int unpack_sig(uint8_t c[SEEDBYTES],
               polyvecl *z,
               polyveck *h,
               const uint8_t sig[CRYPTO_BYTES]);

#endif
