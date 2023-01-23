/*
nvcc -arch=sm_61 -rdc=true -cudart static --machine 64 -use_fast_math -O1 fips202.cu main.cu ntt.cu packing.cu poly.cu polyvec.cu reduce.cu rng.cu rounding.cu sign.cu symmetric-shake.cu -o dilithium -lcudadevrt -std=c++11

nvprof ./dilithium
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "params.h"
#include "rng.h"
#include "sign.h"
#include "times.h"
#include "fips202.h"
#define KAT_SUCCESS          0
#define KAT_CRYPTO_FAILURE  -4



// 处理错误
void HandleError(cudaError_t err, const char* file, int line)
{
	if (err != cudaSuccess) {
		printf("%s in %s at line %d\n", cudaGetErrorString(err),
			file, line);
		exit(EXIT_FAILURE);
	}
}
#define HANDLE_ERROR( err ) (HandleError( err, __FILE__, __LINE__ ))


// 签名需要用到的变量
void allocateSign_Sign(sign_sign* sign){
    HANDLE_ERROR(cudaMalloc(&(sign->z), sizeof(polyvecl) )); // keypaire s1hat sign z
    HANDLE_ERROR(cudaHostAlloc(&(sign->zh), sizeof(polyvecl), cudaHostAllocDefault));
    HANDLE_ERROR(cudaMalloc(&(sign->mat), K * sizeof(polyvecl)));
    HANDLE_ERROR(cudaHostAlloc(&(sign->math), K * sizeof(polyvecl), cudaHostAllocDefault));
    HANDLE_ERROR(cudaMalloc(&(sign->s1), sizeof(polyvecl) ));
    HANDLE_ERROR(cudaHostAlloc(&(sign->s1h), sizeof(polyvecl), cudaHostAllocDefault));
    HANDLE_ERROR(cudaMalloc(&(sign->y), sizeof(polyvecl) ));
    HANDLE_ERROR(cudaHostAlloc(&(sign->yh), sizeof(polyvecl), cudaHostAllocDefault));
    HANDLE_ERROR(cudaMalloc(&(sign->h), sizeof(polyveck) ));
    HANDLE_ERROR(cudaHostAlloc(&(sign->hh), sizeof(polyveck), cudaHostAllocDefault));
    HANDLE_ERROR(cudaMalloc(&(sign->w0), sizeof(polyveck) )); // keypaire/verify t1 sign w0
    HANDLE_ERROR(cudaHostAlloc(&(sign->w0h), sizeof(polyveck), cudaHostAllocDefault));
    HANDLE_ERROR(cudaMalloc(&(sign->w1), sizeof(polyveck) ));
    HANDLE_ERROR(cudaHostAlloc(&(sign->w1h), sizeof(polyveck), cudaHostAllocDefault));
    HANDLE_ERROR(cudaMalloc(&(sign->t0), sizeof(polyveck) ));
    HANDLE_ERROR(cudaHostAlloc(&(sign->t0h), sizeof(polyveck), cudaHostAllocDefault));
    HANDLE_ERROR(cudaMalloc(&(sign->s2), sizeof(polyveck) ));
    HANDLE_ERROR(cudaHostAlloc(&(sign->s2h), sizeof(polyveck), cudaHostAllocDefault));
    HANDLE_ERROR(cudaMallocManaged(&(sign->mu), sizeof(uint8_t) * CRHBYTES )); // keypaire tr verify mu 
    HANDLE_ERROR(cudaHostAlloc(&(sign->muh), sizeof(uint8_t) * CRHBYTES, cudaHostAllocDefault));
    HANDLE_ERROR(cudaMalloc(&(sign->cp), sizeof(poly) ));
    HANDLE_ERROR(cudaHostAlloc(&(sign->cph), sizeof(poly), cudaHostAllocDefault));
    HANDLE_ERROR(cudaMalloc(&(sign->rho), sizeof(uint8_t) * SEEDBYTES ));
    HANDLE_ERROR(cudaHostAlloc(&(sign->rhoh), sizeof(uint8_t) * SEEDBYTES, cudaHostAllocDefault));
    HANDLE_ERROR(cudaMalloc(&(sign->buf), sizeof(uint8_t) * K * POLYW1_PACKEDBYTES ));
    HANDLE_ERROR(cudaHostAlloc(&(sign->bufh), sizeof(uint8_t) * K * POLYW1_PACKEDBYTES , cudaHostAllocDefault));
    HANDLE_ERROR(cudaMalloc(&(sign->c2), sizeof(uint8_t) * SEEDBYTES ));
    HANDLE_ERROR(cudaHostAlloc(&(sign->c2h), sizeof(uint8_t) * SEEDBYTES , cudaHostAllocDefault));
    HANDLE_ERROR(cudaMalloc(&(sign->c), sizeof(uint8_t) * SEEDBYTES ));
    HANDLE_ERROR(cudaHostAlloc(&(sign->ch), sizeof(uint8_t) * SEEDBYTES , cudaHostAllocDefault));

    HANDLE_ERROR(cudaHostAlloc(&(sign->stateh), sizeof(keccak_state), cudaHostAllocDefault));
}


int main()
{
    double sum1,sum2,sum3;
    for(int o=0;o<1000;o++){
        size_t              mlen, smlen, mlen1;
        int                 ret_val;
        mlen = MESSAGELEN;

        // 在主机创建内存
        unsigned char *sm_h;
        unsigned char *msg1_h;
        unsigned char *msg_h;
        uint8_t *keypairseedbuf_h;
        uint8_t *signseedbuf_h;
        unsigned char *pk_h;
        unsigned char *sk_h;

        cudaHostAlloc((void**)&sm_h, (mlen + CRYPTO_BYTES) , cudaHostAllocDefault);
        cudaHostAlloc((void**)&msg1_h, mlen , cudaHostAllocDefault);
        cudaHostAlloc((void**)&msg_h, mlen , cudaHostAllocDefault);
        cudaHostAlloc((void**)&keypairseedbuf_h, (3*SEEDBYTES) , cudaHostAllocDefault);
        cudaHostAlloc((void**)&signseedbuf_h, (2*SEEDBYTES + 3*CRHBYTES), cudaHostAllocDefault);
        cudaHostAlloc((void**)&pk_h, CRYPTO_PUBLICKEYBYTES,cudaHostAllocDefault);
        cudaHostAlloc((void**)&sk_h, CRYPTO_SECRETKEYBYTES,cudaHostAllocDefault);

        // 生成随机数
        randombytes(msg_h, mlen );
        rrandombytes(keypairseedbuf_h, 3 * SEEDBYTES , SEEDBYTES,o);

        // 拷贝m到sm
        for(int i = 0; i < mlen; ++i){
           sm_h[CRYPTO_BYTES + mlen - 1 - i ] = msg_h[mlen - 1 - i ];
        }

        // Device端创建内存 sign
        sign_sign sign[1];
        allocateSign_Sign(&sign[0]);


        double CPUtime1,CPUtime2,CPUtime3;
        cudaDeviceSynchronize();
        CPUtime1 = get_time();
        if ( (ret_val = crypto_sign_keypair(keypairseedbuf_h,&sign[0], pk_h, sk_h)) != 0) {
            printf("crypto_sign_keypair returned <%d>\n", ret_val);
            cudaDeviceSynchronize();
            return KAT_CRYPTO_FAILURE;
        }
        cudaDeviceSynchronize();
        sum1 += get_time() - CPUtime1;
        
        CPUtime2 = get_time();
        if ( (ret_val = crypto_sign(signseedbuf_h,&sign[0],sm_h, &smlen, msg_h, mlen, sk_h)) != 0) {
            printf("crypto_sign returned <%d>\n", ret_val);
            cudaDeviceSynchronize();
            return KAT_CRYPTO_FAILURE;
        }
        cudaDeviceSynchronize();
        sum2 += get_time() - CPUtime2;
        //for(int i =0 ;i <smlen;i++)printf("%d ",sm_h[i]);
        CPUtime3 = get_time();
        if ( (ret_val = crypto_sign_open(&sign[0],msg1_h, &mlen1, sm_h, smlen, pk_h)) != 0) {
            printf("crypto_sign_open returned <%d>\n", ret_val);
            cudaDeviceSynchronize();
            return KAT_CRYPTO_FAILURE;
        }
        cudaDeviceSynchronize();
        sum3 += get_time() - CPUtime3;
    }
    printf("key %f ms. sign  %f ms. verify  %f ms.", sum1/(1000*1000),sum2/(1000*1000),sum3/(1000*1000));
    return KAT_SUCCESS;
}
