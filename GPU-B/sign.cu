#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "params.h"
#include "sign.h"
#include "packing.h"
#include "rng.h"
#include "symmetric.h"
#include "fips202.h"


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
int crypto_sign_keypair(int group,uint8_t *seedbuf, sign_sign* keypair,uint8_t *pk, uint8_t *sk){

  const uint8_t *rho, *rhoprime, *key;
  
  // Get randomness for rho, rhoprime and key
  shake2562<<<(group-1)/BLOCK + 1,BLOCK>>>(group,seedbuf, 3*SEEDBYTES, seedbuf, SEEDBYTES);
  
  rho = seedbuf;
  // Expand matrix
  polyvec_matrix_expand<<<(group-1)/BLOCK + 1,BLOCK>>>(group,keypair->mat, rho);
  
  rhoprime = seedbuf + SEEDBYTES;
  // Sample short vectors s1 and s2 
  polyvecl_uniform_eta<<<(group-1)/BLOCK + 1,BLOCK>>>(group,keypair->z, keypair->s1, rhoprime, 0);
  polyveck_uniform_eta<<<(group-1)/BLOCK + 1,BLOCK>>>(group,keypair->s2, rhoprime, L);
  
  polyvecl_ntt<<<(group-1)/BLOCK + 1,BLOCK>>>(group,2,keypair->flag,keypair->n,keypair->z);
  
  polyvec_matrix_pointwise_montgomery<<<(group-1)/BLOCK + 1,BLOCK>>>(group,2,keypair->flag,keypair->n,keypair->w0, keypair->mat, keypair->z);
  
  polyveck_reduce<<<(group-1)/BLOCK + 1,BLOCK>>>(group,2,keypair->flag,keypair->n,keypair->w0);
  polyveck_invntt_tomont<<<(group-1)/BLOCK + 1,BLOCK>>>(group,2,keypair->flag,keypair->n,keypair->w0);
  
  // Add error vector s2
  polyveck_add<<<(group-1)/BLOCK + 1,BLOCK>>>(group,2,keypair->flag,keypair->n,keypair->w0, keypair->w0, keypair->s2);
  
  // Extract t1 and write public key
  polyveck_caddq<<<(group-1)/BLOCK + 1,BLOCK>>>(group,2,keypair->flag,keypair->n,keypair->w0);
  
  polyveck_power2round<<<(group-1)/BLOCK + 1,BLOCK>>>(group,keypair->w0, keypair->t0, keypair->w0); // 可以gpu
  
  pack_pk<<<(group-1)/BLOCK + 1,BLOCK>>>(group, pk, rho, keypair->w0); // 可以gpu
  
  // Compute CRH(rho, t1) and write secret key 
  shake2561<<<(group-1)/BLOCK + 1,BLOCK>>>(group,keypair->mu, CRHBYTES,pk, CRYPTO_PUBLICKEYBYTES); 
  
  key = seedbuf + 2*SEEDBYTES;
  pack_sk<<<(group-1)/BLOCK + 1,BLOCK>>>(group, sk, rho, keypair->mu, key, keypair->t0, keypair->s1, keypair->s2);
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
int crypto_sign_signature(int group,uint8_t *seedbuf, sign_sign* sign,uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen,
                          const uint8_t *sk)
{
  
  uint8_t *rho, *tr, *key, *mu, *rhoprime;
  uint16_t nonce = 0;

  rho = seedbuf;
  tr = rho + SEEDBYTES;
  key = tr + CRHBYTES;

  unpack_sk<<<(group-1)/BLOCK + 1,BLOCK>>>(group, rho, tr, key, sign->t0, sign->s1, sign->s2, sk);
  
  mu = key + SEEDBYTES;

  shake256_sign1<<<(group-1)/BLOCK + 1,BLOCK>>>(group,2,sign->flag,sign->n, sign->state, mu, CRHBYTES, tr , CRHBYTES,m, mlen);
  
  rhoprime = mu + CRHBYTES; 
  shake2563<<<(group-1)/BLOCK + 1,BLOCK>>>(group , rhoprime, CRHBYTES,key, SEEDBYTES + CRHBYTES);
  
  // Expand matrix and transform vectors
  polyvec_matrix_expand1<<<(group-1)/BLOCK + 1,BLOCK>>>(group,sign->mat, rho);
  polyvecl_ntt<<<(group-1)/BLOCK + 1,BLOCK>>>(group,2,sign->flag,sign->n,sign->s1);
  polyveck_ntt<<<(group-1)/BLOCK + 1,BLOCK>>>(group,sign->s2);
  polyveck_ntt<<<(group-1)/BLOCK + 1,BLOCK>>>(group,sign->t0);

rej:
  // Sample intermediate vector y 
  polyvecl_uniform_gamma1<<<(group-1)/BLOCK + 1,BLOCK>>>(group,2,sign->flag,sign->n,sign->y, sign->z,rhoprime, nonce++);
  
  // Matrix-vector multiplication
  polyvecl_ntt<<<(group-1)/BLOCK + 1,BLOCK>>>(group,2,sign->flag,sign->n,sign->z);
  
  polyvec_matrix_pointwise_montgomery<<<(group-1)/BLOCK + 1,BLOCK>>>(group,2,sign->flag,sign->n,sign->w1, sign->mat, sign->z);
  
  polyveck_reduce<<<(group-1)/BLOCK + 1,BLOCK>>>(group,2,sign->flag,sign->n,sign->w1);
  polyveck_invntt_tomont<<<(group-1)/BLOCK + 1,BLOCK>>>(group,2,sign->flag,sign->n,sign->w1);
  
  // Decompose w and call the random oracle
  polyveck_caddq<<<(group-1)/BLOCK + 1,BLOCK>>>(group,2,sign->flag,sign->n,sign->w1);

  polyveck_decompose<<<(group-1)/BLOCK + 1,BLOCK>>>(group,2,sign->flag,sign->n,sign->w1, sign->w0, sign->w1);
  
  polyveck_pack_w1<<<(group-1)/BLOCK + 1,BLOCK>>>(group,2,sign->flag,sign->n,sig, sign->w1);

  
  shake256_sign2<<<(group-1)/BLOCK + 1,BLOCK>>>(group,2,sign->flag,sign->n, sign->state,sig , SEEDBYTES, mu, CRHBYTES, sig, K*POLYW1_PACKEDBYTES);
  poly_challenge<<<(group-1)/BLOCK + 1,BLOCK>>>(group,2,sign->flag,sign->n, sign->cp, sig);
  
  poly_ntt1<<<(group-1)/BLOCK + 1,BLOCK>>>(group,2,sign->flag,sign->n, sign->cp);
  
  // Compute z, reject if it reveals secret 
  polyvecl_pointwise_poly_montgomery<<<(group-1)/BLOCK + 1,BLOCK>>>(group,2,sign->flag,sign->n,sign->z, sign->cp, sign->s1);
  polyvecl_invntt_tomont<<<(group-1)/BLOCK + 1,BLOCK>>>(group,2,sign->flag,sign->n,sign->z);
  
  polyvecl_add<<<(group-1)/BLOCK + 1,BLOCK>>>(group,2,sign->flag,sign->n,sign->z, sign->z, sign->y);
  polyvecl_reduce<<<(group-1)/BLOCK + 1,BLOCK>>>(group,2,sign->flag,sign->n,sign->z);
  
  // Y 3 N 2
  polyvecl_chknorm<<<(group-1)/BLOCK + 1,BLOCK>>>(group,2,sign->flag,sign->n,sign->z,GAMMA1 - BETA);
  cudaDeviceSynchronize();
  for(int k = 0;k<group;k++){
    if(sign->flag[k] == 2){
      goto rej;
    }
  }

  // Check that subtracting cs2 does not change high bits of w and low bits * do not reveal secret information 
  polyveck_pointwise_poly_montgomery<<<(group-1)/BLOCK + 1,BLOCK>>>(group,3,sign->flag,sign->n,sign->h, sign->cp, sign->s2);
  polyveck_invntt_tomont<<<(group-1)/BLOCK + 1,BLOCK>>>(group,3,sign->flag,sign->n,sign->h);
  polyveck_sub<<<(group-1)/BLOCK + 1,BLOCK>>>(group,3,sign->flag,sign->n,sign->w0, sign->w0, sign->h);
  polyveck_reduce<<<(group-1)/BLOCK + 1,BLOCK>>>(group,3,sign->flag,sign->n,sign->w0);
  

  // Y 4 N 2
  polyveck_chknorm<<<(group-1)/BLOCK + 1,BLOCK>>>(group,3,sign->flag,sign->n,sign->w0,GAMMA2 - BETA);
  cudaDeviceSynchronize();
  for(int k = 0;k<group;k++){
    if(sign->flag[k] == 2){
      goto rej;
    }
  }

  // Compute hints for w1
  polyveck_pointwise_poly_montgomery<<<(group-1)/BLOCK + 1,BLOCK>>>(group,4,sign->flag,sign->n,sign->h, sign->cp, sign->t0);
  polyveck_invntt_tomont<<<(group-1)/BLOCK + 1,BLOCK>>>(group,4,sign->flag,sign->n,sign->h);
  polyveck_reduce<<<(group-1)/BLOCK + 1,BLOCK>>>(group,4,sign->flag,sign->n,sign->h);
  
  // Y 5 N 2
  polyveck_chknorm<<<(group-1)/BLOCK + 1,BLOCK>>>(group,4,sign->flag,sign->n,sign->h,GAMMA2);
  cudaDeviceSynchronize();
  for(int k = 0;k<group;k++){
    if(sign->flag[k] == 2){
      goto rej;
    }
  }
  
  polyveck_add<<<(group-1)/BLOCK + 1,BLOCK>>>(group,5,sign->flag,sign->n,sign->w0, sign->w0, sign->h);
  polyveck_caddq<<<(group-1)/BLOCK + 1,BLOCK>>>(group,5,sign->flag,sign->n,sign->w0);
  
  polyveck_make_hint<<<(group-1)/BLOCK + 1,BLOCK>>>(group,5,sign->flag,sign->n, sign->h, sign->w0, sign->w1);
  cudaDeviceSynchronize();
  for(int k = 0;k<group;k++){
    if(sign->n[k] > OMEGA){
      goto rej;}
  }
  
  // Write signature
  pack_sig<<<(group-1)/BLOCK + 1,BLOCK>>>(group,sig, sig, sign->z, sign->h);
  *siglen = CRYPTO_BYTES;
  // 最后 flag == 5 n < OMEGA
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

int crypto_sign(int group,uint8_t *seedbuf, sign_sign* sign, uint8_t *sm, size_t *smlen,
                const uint8_t *m, size_t mlen,
                const uint8_t *sk)
{

  crypto_sign_signature(group,seedbuf,sign,sm, smlen, sm + CRYPTO_BYTES, mlen, sk);
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
__global__ void judge(int group, int *f, uint8_t *a, uint8_t *b){
    int X = threadIdx.x + blockIdx.x * blockDim.x;
    if(X < group){
      for(int i = 0; i < SEEDBYTES; ++i){
        if(a[i + X * SEEDBYTES] != b[i + X * SEEDBYTES]){
          *(f+X) = -1;
        }
      }
    }
    // if(X == 0) for(int k = 0;k<SEEDBYTES;k++) printf(" %d",a[k+15359 * SEEDBYTES]);
}

void crypto_sign_verify(int group, int* result,sign_sign* verify, const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen,
                       const uint8_t *pk)
{
  // 初始化为验签正确
  for(int k =0 ;k< group;k++){
      result[k] = 1;
  }
  // 长度不对 直接返回错误
  if(siglen != CRYPTO_BYTES){
    for(int k =0 ;k<group;k++){
      result[k] = -1;
    }
    return;
  }
  
  unpack_pk<<<(group-1)/BLOCK + 1,BLOCK>>>(group,verify->rho, verify->w0, pk);
   
  // 错误是1 正确是5
  unpack_sig<<<(group-1)/BLOCK + 1,BLOCK>>>(group,verify->flag,verify->c, verify->z, verify->h, sig);
  if(*verify->flag == 1){
      return;
  }
  // 错误是2 正确是6
  polyvecl_chknorm<<<(group-1)/BLOCK + 1,BLOCK>>>(group,5,verify->flag,verify->n,verify->z,GAMMA1 - BETA);
  
  cudaDeviceSynchronize();
  for(int k =0 ;k<group;k++){
   if(verify->flag[k] == 2){
      result[k] = -1;
   }
  }
  
  // Compute CRH(CRH(rho, t1), msg) 
  shake2561<<<(group-1)/BLOCK + 1,BLOCK>>>(group,verify->mu, CRHBYTES,pk, CRYPTO_PUBLICKEYBYTES); 
  
  shake256_sign3<<<(group-1)/BLOCK + 1,BLOCK>>>(group,6,verify->flag,verify->n, verify->state,verify->mu,CRHBYTES, verify->mu, CRHBYTES, m, mlen);

  // Matrix-vector multiplication; compute Az - c2^dt1
  poly_challenge1<<<(group-1)/BLOCK + 1,BLOCK>>>(group,6,verify->flag,verify->n, verify->cp, verify->c);
  
  polyvec_matrix_expand2<<<(group-1)/BLOCK + 1,BLOCK>>>(group,verify->mat, verify->rho);
  
  polyvecl_ntt<<<(group-1)/BLOCK + 1,BLOCK>>>(group,6,verify->flag,verify->n,verify->z);
  
  polyvec_matrix_pointwise_montgomery<<<(group-1)/BLOCK + 1,BLOCK>>>(group,6,verify->flag,verify->n,verify->w1, verify->mat, verify->z);
  
  poly_ntt1<<<(group-1)/BLOCK + 1,BLOCK>>>(group,6,verify->flag,verify->n, verify->cp);
  
  polyveck_shiftl<<<(group-1)/BLOCK + 1,BLOCK>>>(group,6,verify->flag,verify->n, verify->w0);
  
  polyveck_ntt<<<(group-1)/BLOCK + 1,BLOCK>>>(group,verify->w0);
  
  polyveck_pointwise_poly_montgomery<<<(group-1)/BLOCK + 1,BLOCK>>>(group,6,verify->flag,verify->n,verify->w0, verify->cp, verify->w0);
  
  polyveck_sub<<<(group-1)/BLOCK + 1,BLOCK>>>(group,6,verify->flag,verify->n,verify->w1, verify->w1, verify->w0);
  
  polyveck_reduce<<<(group-1)/BLOCK + 1,BLOCK>>>(group,6,verify->flag,verify->n,verify->w1);

  polyveck_invntt_tomont<<<(group-1)/BLOCK + 1,BLOCK>>>(group,6,verify->flag,verify->n,verify->w1);
  
  // Reconstruct w1
  polyveck_caddq<<<(group-1)/BLOCK + 1,BLOCK>>>(group,6,verify->flag,verify->n,verify->w1);
  
  polyveck_use_hint<<<(group-1)/BLOCK + 1,BLOCK>>>(group, verify->w1, verify->w1, verify->h);
  polyveck_pack_w11<<<(group-1)/BLOCK + 1,BLOCK>>>(group,verify->buf, verify->w1);

  shake256_sign4<<<(group-1)/BLOCK + 1,BLOCK>>>(group,6,verify->flag,verify->n, verify->state,verify->c2,SEEDBYTES, verify->mu, CRHBYTES, verify->buf, K*POLYW1_PACKEDBYTES);
  
  judge<<<(group-1)/BLOCK + 1,BLOCK>>>(group, verify->flag, verify->c, verify->c2);
  cudaDeviceSynchronize();
  for(int k = 0;k<group;k++){
    if(verify->flag[k] == -1){
      result[k] = -1;
    }
  }
  
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

int crypto_sign_open(int group,sign_sign* verify, uint8_t *m, size_t *mlen,
                     const uint8_t *sm, size_t smlen,
                     const uint8_t *pk){
  int* result;
  result = (int*) malloc(group * sizeof(int));
  
  // 长度不对
  if(smlen < CRYPTO_BYTES)
    return -1;
    
  // 定位message位置
  *mlen = smlen - CRYPTO_BYTES;
  
  // 进行验签
  crypto_sign_verify(group,result,verify,sm, CRYPTO_BYTES, sm + CRYPTO_BYTES, *mlen, pk);
  
  // 1是正确 -1是错误
  //for(int k = 0;k<group;k++){
    //printf(" %d ",result[k]);
  //}
  
  return 0;
}

