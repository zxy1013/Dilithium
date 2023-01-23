#ifndef SIGN_H
#define SIGN_H

#include <stddef.h>
#include <stdint.h>
#include "params.h"
#include "polyvec.h"
#include "poly.h"
#include "fips202.h"



typedef struct {
    polyvecl* z; // keypaire s1hat sign z
    polyvecl* zh;
    polyvecl* mat;
    polyvecl* math;
    polyvecl* s1;
    polyvecl* s1h;
    polyvecl* y;
    polyvecl* yh;
    polyveck* w1;
    polyveck* w1h;
    polyveck* t0; 
    polyveck* t0h;
    polyveck* s2;
    polyveck* s2h;
    polyveck* w0; // keypaire/verify t1 sign w0
    polyveck* w0h;
    poly* cp;
    poly* cph;
    uint8_t* mu; // keypaire tr verify mu 
    uint8_t* muh;
    uint8_t* rho;
    uint8_t* rhoh;
    polyveck* h;
    polyveck* hh;
    uint8_t* buf;
    uint8_t* bufh;
    uint8_t* c2;
    uint8_t* c2h;
    uint8_t* c;
    uint8_t* ch;
    keccak_state* stateh;
} sign_sign;


typedef struct {
    polyvecl* z; // keypaire s1hat sign z
    polyvecl* mat;
    polyveck* s2;
} key_host;

int crypto_sign_keypair(uint8_t *seedbuf, sign_sign* keypair,uint8_t *pk, uint8_t *sk);



int crypto_sign_signature(uint8_t *seedbuf, sign_sign* sign,uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen,
                          const uint8_t *sk);


int crypto_sign(uint8_t *seedbuf, sign_sign* sign, uint8_t *sm, size_t *smlen,
                const uint8_t *m, size_t mlen,
                const uint8_t *sk);


int crypto_sign_verify(sign_sign* verify, const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen,
                       const uint8_t *pk);

int crypto_sign_open(sign_sign* verify, uint8_t *m, size_t *mlen,
                     const uint8_t *sm, size_t smlen,
                     const uint8_t *pk);

#endif
