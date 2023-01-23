#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "params.h"
#include "sign.h"
#include "packing.h"
#include "rng.h"
#include "symmetric.h"
#include "fips202.h"
#include "ntt.h"
#include <sys/time.h>


double get_time1(void){
    struct timeval tv;
    double t;
    gettimeofday(&tv, (struct timezone *)0);
    t = tv.tv_sec*1000000 + tv.tv_usec; // us
    return t;
}


int crypto_sign_keypair(uint8_t *seedbuf, sign_sign* keypair,uint8_t *pk, uint8_t *sk){

  // CPU函数
  const uint8_t *rho, *rhoprime, *key;
  shake256(seedbuf, 3*SEEDBYTES, seedbuf, SEEDBYTES);
  rho = seedbuf;
  // Expand matrix
  polyvec_matrix_expand(keypair->math, rho);
  rhoprime = seedbuf + SEEDBYTES;
  // Sample short vectors s1 and s2 
  polyvecl_uniform_eta(keypair->zh, keypair->s1h, rhoprime, 0);
  polyveck_uniform_eta(keypair->s2h, rhoprime, L);
  
  
  // 拷贝函数
  cudaMemcpy(keypair->mat, keypair->math, K * sizeof(polyvecl) , cudaMemcpyHostToDevice);
  cudaMemcpy(keypair->z, keypair->zh, sizeof(polyvecl) , cudaMemcpyHostToDevice);
  cudaMemcpy(keypair->s2, keypair->s2h, sizeof(polyveck) , cudaMemcpyHostToDevice);
  
  
  // GPU函数
  GNTT<<<L,128>>>(keypair->z->vec[0].coeffs);
  Gpolyvec_matrix_pointwise_montgomery<<<K,256>>>(keypair->w0, keypair->mat, keypair->z);
  Gpolyveck_reduce<<<K,256>>>(keypair->w0);
  GINTT<<<K,128>>>(keypair->w0->vec[0].coeffs);

  GpolyK_add<<<K,256>>>(keypair->w0, keypair->w0, keypair->s2);
  Gpolyveck_caddq<<<K,256>>>(keypair->w0);
  Gpolyveck_power2round<<<K,256>>>(keypair->w0, keypair->t0, keypair->w0);
  
  // 拷贝t0 w0 同步的
  cudaMemcpy(keypair->t0h, keypair->t0, sizeof(polyveck) , cudaMemcpyDeviceToHost);
  cudaMemcpy(keypair->w0h, keypair->w0, sizeof(polyveck) , cudaMemcpyDeviceToHost);
  
  
  // CPU函数
  pack_pk(pk, rho, keypair->w0h);
  // Compute CRH(rho, t1) and write secret key 
  shake256(keypair->muh, CRHBYTES,pk, CRYPTO_PUBLICKEYBYTES); 
  key = seedbuf + 2*SEEDBYTES;
  pack_sk(sk, rho, keypair->muh, key, keypair->t0h, keypair->s1h, keypair->s2h);

  return 0;
}

/*************************************************
* Name:        crypto_sign_signature
*
* Description: Computes signature.
*
* Arguments:   - uint8_t *sig:   pointer to output signature (of length CRYPTO_BYTES)
*              - size_t *siglen: pointer to output length of signature
*              - uint8_t *m:     pointer to message to be signed
*              - size_t mlen:    length of message
*              - uint8_t *sk:    pointer to bit-packed secret key
*
* Returns 0 (success)
**************************************************/
int crypto_sign_signature(uint8_t *seedbuf, sign_sign* sign,uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen,
                          const uint8_t *sk)
{
  // CPU函数
  uint8_t *rho, *tr, *key, *mu, *rhoprime;
  uint16_t nonce = 0;
  rho = seedbuf;
  tr = rho + SEEDBYTES;
  key = tr + CRHBYTES;
  unpack_sk(rho, tr, key, sign->t0h, sign->s1h, sign->s2h, sk);
  mu = key + SEEDBYTES;
  shake256_sign(sign->stateh, mu, CRHBYTES, tr , CRHBYTES,m, mlen);
  rhoprime = mu + CRHBYTES;
  shake256(rhoprime, CRHBYTES,key, SEEDBYTES + CRHBYTES); 
  polyvec_matrix_expand1(sign->math, rho);
  
  
  // 拷贝函数
  cudaMemcpy(sign->mat, sign->math, K * sizeof(polyvecl) , cudaMemcpyHostToDevice);
  cudaMemcpy(sign->t0, sign->t0h, sizeof(polyveck) , cudaMemcpyHostToDevice);
  cudaMemcpy(sign->s1, sign->s1h, sizeof(polyvecl) , cudaMemcpyHostToDevice);
  cudaMemcpy(sign->s2, sign->s2h, sizeof(polyveck) , cudaMemcpyHostToDevice);
  
  // GPU函数
  GNTT<<<L,128>>>(sign->s1->vec[0].coeffs);
  GNTT<<<K,128>>>(sign->s2->vec[0].coeffs);
  GNTT<<<K,128>>>(sign->t0->vec[0].coeffs);

rej:
  // Sample intermediate vector y 
  polyvecl_uniform_gamma1(sign->yh, sign->zh,rhoprime, nonce++);
  cudaMemcpy(sign->y, sign->yh, sizeof(polyvecl) , cudaMemcpyHostToDevice);
  cudaMemcpy(sign->z, sign->zh, sizeof(polyvecl) , cudaMemcpyHostToDevice);
  
  // Matrix-vector multiplication
  GNTT<<<L,128>>>(sign->z->vec[0].coeffs);
  Gpolyvec_matrix_pointwise_montgomery<<<K,256>>>(sign->w1, sign->mat, sign->z);
  Gpolyveck_reduce<<<K,256>>>(sign->w1);
  GINTT<<<K,128>>>(sign->w1->vec[0].coeffs);
  Gpolyveck_caddq<<<K,256>>>(sign->w1);
  Gpolyveck_decompose<<<K,256>>>(sign->w1, sign->w0, sign->w1);
  
  
  // 拷贝w1
  cudaMemcpy(sign->w1h, sign->w1, sizeof(polyveck) , cudaMemcpyDeviceToHost);
  polyveck_pack_w(sig, sign->w1h);
  shake256_sign(sign->stateh,sig , SEEDBYTES, mu, CRHBYTES, sig, K*POLYW1_PACKEDBYTES);
  poly_challenge(sign->cph, sig);
  
  
  // 拷贝cp
  cudaMemcpy(sign->cp, sign->cph, sizeof(poly) , cudaMemcpyHostToDevice);
  GNTT<<<1,128>>>(sign->cp[0].coeffs);
  Gpolyvecl_pointwise_poly_montgomery<<<L,256>>>(sign->z, sign->cp, sign->s1);
  GINTT<<<L,128>>>(sign->z->vec[0].coeffs);
  GpolyL_add<<<L,256>>>(sign->z, sign->z, sign->y);
  Gpolyvecl_reduce<<<L,256>>>(sign->z);
  

  cudaMemcpy(sign->zh, sign->z, sizeof(polyvecl) , cudaMemcpyDeviceToHost);
  int kk = polyvecl_chknorm(sign->zh,GAMMA1 - BETA); // try
  if(kk){
    goto rej;
  }
  
  Gpolyveck_pointwise_poly_montgomery<<<K,256>>>(sign->h, sign->cp, sign->s2);
  GINTT<<<K,128>>>(sign->h->vec[0].coeffs);
  Gpolyveck_sub<<<K,256>>>(sign->w0, sign->w0, sign->h); // try
  Gpolyveck_reduce<<<K,256>>>(sign->w0);
  

  cudaMemcpy(sign->w0h, sign->w0, sizeof(polyveck) , cudaMemcpyDeviceToHost);
  kk = polyveck_chknorm(sign->w0h,GAMMA2 - BETA); // try
  if(kk){
    goto rej;
  }
  
  // Compute hints for w1
  Gpolyveck_pointwise_poly_montgomery<<<K,256>>>(sign->h, sign->cp, sign->t0);
  GINTT<<<K,128>>>(sign->h->vec[0].coeffs);
  Gpolyveck_reduce<<<K,256>>>(sign->h);
  

  cudaMemcpy(sign->hh, sign->h, sizeof(polyveck) , cudaMemcpyDeviceToHost);
  kk = polyveck_chknorm(sign->hh,GAMMA2);
  if(kk){
    goto rej;
  }
  
  GpolyK_add<<<K,256>>>(sign->w0, sign->w0, sign->h);
  Gpolyveck_caddq<<<K,256>>>(sign->w0);
  

  cudaMemcpy(sign->w0h, sign->w0, sizeof(polyveck) , cudaMemcpyDeviceToHost);
  kk = polyveck_make_hint(sign->hh, sign->w0h, sign->w1h);
  if(kk > OMEGA){
    goto rej;}

  pack_sig(sig, sig, sign->zh, sign->hh);
  *siglen = CRYPTO_BYTES;
  
  
  return 0;
}

/*************************************************
* Name:        crypto_sign
*
* Description: Compute signed message.
*
* Arguments:   - uint8_t *sm: pointer to output signed message (allocated
*                             array with CRYPTO_BYTES + mlen bytes),
*                             can be equal to m
*              - size_t *smlen: pointer to output length of signed
*                               message
*              - const uint8_t *m: pointer to message to be signed
*              - size_t mlen: length of message
*              - const uint8_t *sk: pointer to bit-packed secret key
*
* Returns 0 (success)
**************************************************/

int crypto_sign(uint8_t *seedbuf, sign_sign* sign, uint8_t *sm, size_t *smlen,
                const uint8_t *m, size_t mlen,
                const uint8_t *sk)
{

  crypto_sign_signature(seedbuf,sign,sm, smlen, sm + CRYPTO_BYTES, mlen, sk);
  *smlen += mlen;
  return 0; 
}

/*************************************************
* Name:        crypto_sign_verify
*
* Description: Verifies signature.
*
* Arguments:   - uint8_t *m: pointer to input signature
*              - size_t siglen: length of signature
*              - const uint8_t *m: pointer to message
*              - size_t mlen: length of message
*              - const uint8_t *pk: pointer to bit-packed public key
*
* Returns 0 if signature could be verified correctly and -1 otherwise
**************************************************/

int crypto_sign_verify(sign_sign* verify, const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen,
                       const uint8_t *pk)
{

  if(siglen != CRYPTO_BYTES){
      return -1;
  }
  
  unpack_pk(verify->rhoh, verify->w0h, pk);

  if(unpack_sig(verify->ch, verify->zh, verify->hh, sig))
    return -1;
  
  int kk = polyvecl_chknorm(verify->zh,GAMMA1 - BETA);
  if(kk){
    return -1;
  }

  shake256(verify->muh, CRHBYTES,pk, CRYPTO_PUBLICKEYBYTES); 
  shake256_sign(verify->stateh,verify->muh,CRHBYTES, verify->muh, CRHBYTES, m, mlen);
  poly_challenge1(verify->cph, verify->ch);
  polyvec_matrix_expand2(verify->math, verify->rhoh);
  
  
  cudaMemcpy(verify->z, verify->zh, sizeof(polyvecl) , cudaMemcpyHostToDevice);
  cudaMemcpy(verify->mat, verify->math, K * sizeof(polyvecl) , cudaMemcpyHostToDevice);
  cudaMemcpy(verify->cp, verify->cph, sizeof(poly) , cudaMemcpyHostToDevice);
  cudaMemcpy(verify->w0, verify->w0h, sizeof(polyveck) , cudaMemcpyHostToDevice);
  cudaMemcpy(verify->h, verify->hh, sizeof(polyveck) , cudaMemcpyHostToDevice);
  
  GNTT<<<L,128>>>(verify->z->vec[0].coeffs);
  Gpolyvec_matrix_pointwise_montgomery<<<K,256>>>(verify->w1, verify->mat, verify->z);
  GNTT<<<1,128>>>(verify->cp[0].coeffs);
  Gpolyveck_shiftl<<<K,256>>>(verify->w0); // try
  GNTT<<<K,128>>>(verify->w0->vec[0].coeffs);
  Gpolyveck_pointwise_poly_montgomery<<<K,256>>>(verify->w0, verify->cp, verify->w0);
  Gpolyveck_sub<<<K,256>>>(verify->w1, verify->w1, verify->w0);
  Gpolyveck_reduce<<<K,256>>>(verify->w1);
  GINTT<<<K,128>>>(verify->w1->vec[0].coeffs);
  Gpolyveck_caddq<<<K,256>>>(verify->w1);
  Gpolyveck_use_hint<<<K,256>>>(verify->w1, verify->w1, verify->h);
  Gpolyveck_pack_w1<<<K,128>>>(verify->buf, verify->w1);
  
  
  cudaMemcpy(verify->bufh, verify->buf, sizeof(uint8_t) * K * POLYW1_PACKEDBYTES , cudaMemcpyDeviceToHost);
  shake256_sign(verify->stateh,verify->c2h,SEEDBYTES, verify->muh, CRHBYTES, verify->bufh, K*POLYW1_PACKEDBYTES);
  for(int i = 0; i < SEEDBYTES; ++i){
    if(verify->ch[i] != verify->c2h[i])
      return -1;
  }

  return 0;
}

/*************************************************
* Name:        crypto_sign_open
*
* Description: Verify signed message.
*
* Arguments:   - uint8_t *m: pointer to output message (allocated
*                            array with smlen bytes), can be equal to sm
*              - size_t *mlen: pointer to output length of message
*              - const uint8_t *sm: pointer to signed message
*              - size_t smlen: length of signed message
*              - const uint8_t *pk: pointer to bit-packed public key
*
* Returns 0 if signed message could be verified correctly and -1 otherwise
**************************************************/

int crypto_sign_open(sign_sign* verify, uint8_t *m, size_t *mlen,
                     const uint8_t *sm, size_t smlen,
                     const uint8_t *pk){
  // 长度不对
  if(smlen < CRYPTO_BYTES)
    return -1;
    
  // 定位message位置
  *mlen = smlen - CRYPTO_BYTES;
  
  // 进行验签
  int x = crypto_sign_verify(verify,sm, CRYPTO_BYTES, sm + CRYPTO_BYTES, *mlen, pk);

  return x;
}

