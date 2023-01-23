#include <stdint.h>
#include "params.h"
#include "sign.h"
#include "packing.h"
#include "polyvec.h"
#include "poly.h"
#include "rng.h"
#include "symmetric.h"
#include "fips202.h"

#include <sys/time.h>


double get_time1(void){
    struct timeval tv;
    double t;
    gettimeofday(&tv, (struct timezone *)0);
    //  tv_sec 秒 long tv_usec 微秒 
    t = tv.tv_sec*1000000 + tv.tv_usec;
    return t;
}

/*************************************************
* Name:        crypto_sign_keypair
*
* Description: Generates public and private key.
*
* Arguments:   - uint8_t *pk: pointer to output public key (allocated
*                             array of CRYPTO_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key (allocated
*                             array of CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_sign_keypair(uint8_t *pk, uint8_t *sk, uint16_t nonce){
  double CPUtime;
    
  uint8_t seedbuf[3*SEEDBYTES];
  uint8_t tr[CRHBYTES];
  const uint8_t *rho, *rhoprime, *key;
  polyvecl mat[K];
  polyvecl s1, s1hat;
  polyveck s2, t1, t0;

  rrandombytes(seedbuf, SEEDBYTES,nonce);
  shake256(seedbuf, 3*SEEDBYTES, seedbuf, SEEDBYTES);
    
  rho = seedbuf;
  rhoprime = seedbuf + SEEDBYTES;
  key = seedbuf + 2*SEEDBYTES;
  polyvec_matrix_expand(mat, rho);
  polyvecl_uniform_eta(&s1, rhoprime, 0);
  polyveck_uniform_eta(&s2, rhoprime, L);
  
    
  /* Matrix-vector multiplication */
  s1hat = s1;
  CPUtime = get_time1();
  polyvecl_ntt(&s1hat);
  CPUtime = get_time1() - CPUtime;
  printf("polyvecl_ntt Time Elapsed: %f us.\n", CPUtime);
  CPUtime = get_time1();
  polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
  CPUtime = get_time1() - CPUtime;
  printf("polyvec_matrix_pointwise_montgomery Time Elapsed: %f us.\n", CPUtime);
  CPUtime = get_time1();
  polyveck_reduce(&t1);
  CPUtime = get_time1() - CPUtime;
  printf("polyveck_reduce Time Elapsed: %f us.\n", CPUtime);
  CPUtime = get_time1();
  polyveck_invntt_tomont(&t1);
  CPUtime = get_time1() - CPUtime;
  printf("polyveck_invntt_tomont Time Elapsed: %f us.\n", CPUtime);  
  polyveck_add(&t1, &t1, &s2);
  CPUtime = get_time1();
  polyveck_caddq(&t1);
  CPUtime = get_time1() - CPUtime;
  printf("polyveck_caddq Time Elapsed: %f us.\n", CPUtime); 
  CPUtime = get_time1();  
  polyveck_power2round(&t1, &t0, &t1); // 可以gpu
  CPUtime = get_time1() - CPUtime;
  printf("polyveck_power2round Time Elapsed: %f us.\n", CPUtime);  
    
  pack_pk(pk, rho, &t1); // 可以gpu
  /* Compute CRH(rho, t1) and write secret key */
  crh(tr, pk, CRYPTO_PUBLICKEYBYTES); 
    
    
  pack_sk(sk, rho, tr, key, &t0, &s1, &s2);
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
int crypto_sign_signature(uint8_t *sig,
                          size_t *siglen,
                          const uint8_t *m,
                          size_t mlen,
                          const uint8_t *sk)
{
  double CPUtime;
    
  unsigned int n;
  uint8_t seedbuf[2*SEEDBYTES + 3*CRHBYTES];
  uint8_t *rho, *tr, *key, *mu, *rhoprime;
  uint16_t nonce = 0;
  polyvecl mat[K], s1, y, z;
  polyveck t0, s2, w1, w0, h;
  poly cp;
  keccak_state state;

  rho = seedbuf;
  tr = rho + SEEDBYTES;
  key = tr + CRHBYTES;
  mu = key + SEEDBYTES;
  rhoprime = mu + CRHBYTES;
    
  unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);   
  
  shake256_init(&state);

  shake256_absorb(&state, tr, CRHBYTES);

  shake256_absorb(&state, m, mlen);

  shake256_finalize(&state);
  
  shake256_squeeze(mu, CRHBYTES, &state);

#ifdef DILITHIUM_RANDOMIZED_SIGNING
  randombytes(rhoprime, CRHBYTES);
  
#else
  crh(rhoprime, key, SEEDBYTES + CRHBYTES);
   
#endif

  polyvec_matrix_expand(mat, rho);

  
    
  
  polyvecl_ntt(&s1);
  polyveck_ntt(&s2);
  CPUtime = get_time1(); 
  polyveck_ntt(&t0);
  CPUtime = get_time1() - CPUtime;
  printf("polyveck_ntt Time Elapsed: %f us.\n", CPUtime); 
    
rej:

  polyvecl_uniform_gamma1(&y, rhoprime, nonce++);

    

  z = y;
  polyvecl_ntt(&z);


  polyvec_matrix_pointwise_montgomery(&w1, mat, &z);
  polyveck_reduce(&w1);


  polyveck_invntt_tomont(&w1);

  polyveck_caddq(&w1);

  CPUtime = get_time1();
  polyveck_decompose(&w1, &w0, &w1);
  CPUtime = get_time1() - CPUtime;
  printf("polyveck_decompose Time Elapsed: %f us.\n", CPUtime);   
  
  polyveck_pack_w1(sig, &w1);
    

  shake256_init(&state);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_absorb(&state, sig, K*POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(sig, SEEDBYTES, &state);
    

  poly_challenge(&cp, sig);

    
  poly_ntt(&cp);
 
  CPUtime = get_time1(); 
  polyvecl_pointwise_poly_montgomery(&z, &cp, &s1);

  CPUtime = get_time1() - CPUtime;
  printf("polyvecl_pointwise_poly_montgomery Time Elapsed: %f us.\n", CPUtime);  
  
  CPUtime = get_time1(); 
  polyvecl_invntt_tomont(&z);
  CPUtime = get_time1() - CPUtime;
  printf("polyvecl_invntt_tomont Time Elapsed: %f us.\n", CPUtime);  
  
  polyvecl_add(&z, &z, &y);
    
  CPUtime = get_time1();    
  polyvecl_reduce(&z);
  CPUtime = get_time1() - CPUtime;
  printf("polyvecl_reduce Time Elapsed: %f us.\n", CPUtime);  
  
    
  int kk = polyvecl_chknorm(&z, GAMMA1 - BETA);
  if(kk){
    goto rej;}


  CPUtime = get_time1(); 
  polyveck_pointwise_poly_montgomery(&h, &cp, &s2);
  CPUtime = get_time1() - CPUtime;
  printf("polyveck_pointwise_poly_montgomery Time Elapsed: %f us.\n", CPUtime);  
    
  polyveck_invntt_tomont(&h);
  polyveck_sub(&w0, &w0, &h);

    
  polyveck_reduce(&w0);
  

  kk = polyveck_chknorm(&w0, GAMMA2 - BETA);
  if(kk){
    goto rej;}
  
    
  polyveck_pointwise_poly_montgomery(&h, &cp, &t0);
  polyveck_invntt_tomont(&h);
  polyveck_reduce(&h);
  kk = polyveck_chknorm(&h, GAMMA2);
    if(kk){
        goto rej;}

    
  polyveck_add(&w0, &w0, &h);
  polyveck_caddq(&w0);
  n = polyveck_make_hint(&h, &w0, &w1);

  if(n > OMEGA){
    goto rej;}

  pack_sig(sig, sig, &z, &h);
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
int crypto_sign(uint8_t *sm,
                size_t *smlen,
                const uint8_t *m,
                size_t mlen,
                const uint8_t *sk)
{
  size_t i;

  for(i = 0; i < mlen; ++i)
    sm[CRYPTO_BYTES + mlen - 1 - i] = m[mlen - 1 - i];
  crypto_sign_signature(sm, smlen, sm + CRYPTO_BYTES, mlen, sk);
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
int crypto_sign_verify(const uint8_t *sig,
                       size_t siglen,
                       const uint8_t *m,
                       size_t mlen,
                       const uint8_t *pk)
{
  double CPUtime;
 
  unsigned int i;
  uint8_t buf[K*POLYW1_PACKEDBYTES];
  uint8_t rho[SEEDBYTES];
  uint8_t mu[CRHBYTES];
  uint8_t c[SEEDBYTES];
  uint8_t c2[SEEDBYTES];
  poly cp;
  polyvecl mat[K], z;
  polyveck t1, w1, h;
  keccak_state state;

    
  if(siglen != CRYPTO_BYTES)
    return -1;
    
  unpack_pk(rho, &t1, pk);  


  if(unpack_sig(c, &z, &h, sig))
    return -1;
    
    
  if(polyvecl_chknorm(&z, GAMMA1 - BETA))
    return -1;

  /* Compute CRH(CRH(rho, t1), msg) */
  crh(mu, pk, CRYPTO_PUBLICKEYBYTES);
    
    
  shake256_init(&state);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, CRHBYTES, &state);
    
  
  poly_challenge(&cp, c);
  
  polyvec_matrix_expand(mat, rho);
    
  polyvecl_ntt(&z);
  polyvec_matrix_pointwise_montgomery(&w1, mat, &z);

  poly_ntt(&cp);
    
  polyveck_shiftl(&t1);
    
  polyveck_ntt(&t1);
  polyveck_pointwise_poly_montgomery(&t1, &cp, &t1);

  polyveck_sub(&w1, &w1, &t1);
  polyveck_reduce(&w1);
  polyveck_invntt_tomont(&w1);

  /* Reconstruct w1 */
  polyveck_caddq(&w1);
    
  CPUtime = get_time1();  
  polyveck_use_hint(&w1, &w1, &h);
  CPUtime = get_time1() - CPUtime;
  printf("polyveck_use_hint Time Elapsed: %f us.\n", CPUtime);  
  
    
  polyveck_pack_w1(buf, &w1);
  
    
  shake256_init(&state);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_absorb(&state, buf, K*POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(c2, SEEDBYTES, &state);
  
    
  for(i = 0; i < SEEDBYTES; ++i)
    if(c[i] != c2[i])
      return -1;
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
int crypto_sign_open(uint8_t *m,
                     size_t *mlen,
                     const uint8_t *sm,
                     size_t smlen,
                     const uint8_t *pk)
{
  size_t i;

  if(smlen < CRYPTO_BYTES)
    goto badsig;

  *mlen = smlen - CRYPTO_BYTES;
  if(crypto_sign_verify(sm, CRYPTO_BYTES, sm + CRYPTO_BYTES, *mlen, pk))
    goto badsig;
  else {
    /* All good, copy msg, return 0 */
    for(i = 0; i < *mlen; ++i)
      m[i] = sm[CRYPTO_BYTES + i];
    return 0;
  }

badsig:
  /* Signature verification failed */
  *mlen = -1;
  for(i = 0; i < smlen; ++i)
    m[i] = 0;

  return -1;
}
