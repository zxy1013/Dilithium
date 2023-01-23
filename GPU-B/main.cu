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
    HANDLE_ERROR(cudaMalloc(&(sign->z), sizeof(polyvecl)*MAXGROUP )); // keypaire s1hat sign z
    HANDLE_ERROR(cudaMalloc(&(sign->mat), K * sizeof(polyvecl)*MAXGROUP));
    HANDLE_ERROR(cudaMalloc(&(sign->s1), sizeof(polyvecl)*MAXGROUP ));
    HANDLE_ERROR(cudaMalloc(&(sign->y), sizeof(polyvecl)*MAXGROUP ));
    
    HANDLE_ERROR(cudaMalloc(&(sign->h), sizeof(polyveck)*MAXGROUP ));
    HANDLE_ERROR(cudaMalloc(&(sign->w0), sizeof(polyveck)*MAXGROUP )); // keypaire/verify t1 sign w0
    HANDLE_ERROR(cudaMalloc(&(sign->w1), sizeof(polyveck)*MAXGROUP ));
    HANDLE_ERROR(cudaMalloc(&(sign->t0), sizeof(polyveck)*MAXGROUP ));
    HANDLE_ERROR(cudaMalloc(&(sign->s2), sizeof(polyveck)*MAXGROUP ));
    
    HANDLE_ERROR(cudaMalloc(&(sign->rho), sizeof(uint8_t) * SEEDBYTES*MAXGROUP ));
    HANDLE_ERROR(cudaMalloc(&(sign->c), sizeof(uint8_t) * SEEDBYTES*MAXGROUP ));
    HANDLE_ERROR(cudaMalloc(&(sign->buf), sizeof(uint8_t) * K * POLYW1_PACKEDBYTES*MAXGROUP ));
    HANDLE_ERROR(cudaMalloc(&(sign->c2), sizeof(uint8_t) * SEEDBYTES*MAXGROUP ));
    HANDLE_ERROR(cudaMalloc(&(sign->mu), sizeof(uint8_t) * CRHBYTES*MAXGROUP )); // keypaire tr verify mu 
    
    HANDLE_ERROR(cudaMalloc(&(sign->cp), sizeof(poly)*MAXGROUP ));
    HANDLE_ERROR(cudaMalloc(&(sign->state), sizeof(keccak_state)*MAXGROUP ));
    // CPU和GPU共用内存
    cudaMallocManaged(&(sign->flag), sizeof(int)*MAXGROUP );
    // 初始化为2
    for(int i=0;i<MAXGROUP;i++)sign->flag[i] = 2;
    cudaMallocManaged(&(sign->n), sizeof(unsigned int)*MAXGROUP );
    // 初始化为OMEGA+1
    for(int i=0;i<MAXGROUP;i++)sign->n[i]= OMEGA+1;
}

int NORMAL_COUNTS[18] = {1,32,256,512,1024,2048,3072,4096,5120,6144,7168,8192,9216,10496,11520,12800,14080,15360};

int main()
{
    size_t              mlen, smlen, mlen1;
    int                 ret_val;
    mlen = MESSAGELEN;
    
    // 在主机创建内存
    unsigned char *sm_h;
    unsigned char *msg1_h;
    unsigned char *msg_h;
    unsigned char *pk_h;
    unsigned char *sk_h;
    uint8_t *keypairseedbuf_h;
    uint8_t *signseedbuf_h;
    
    cudaHostAlloc((void**)&sm_h, (mlen + CRYPTO_BYTES)*MAXGROUP , cudaHostAllocDefault);
    cudaHostAlloc((void**)&msg1_h, mlen*MAXGROUP , cudaHostAllocDefault);
    cudaHostAlloc((void**)&msg_h, mlen*MAXGROUP , cudaHostAllocDefault);
    cudaHostAlloc((void**)&pk_h, CRYPTO_PUBLICKEYBYTES*MAXGROUP , cudaHostAllocDefault);
    cudaHostAlloc((void**)&sk_h, CRYPTO_SECRETKEYBYTES*MAXGROUP , cudaHostAllocDefault);
    cudaHostAlloc((void**)&keypairseedbuf_h, (3*SEEDBYTES)*MAXGROUP , cudaHostAllocDefault);
    cudaHostAlloc((void**)&signseedbuf_h, (2*SEEDBYTES + 3*CRHBYTES)*MAXGROUP, cudaHostAllocDefault);
    
    // 将某一块内存中的内容全部设置为指定的值
	memset(sm_h, 0, (mlen + CRYPTO_BYTES)*MAXGROUP );
    memset(msg1_h, 0, mlen*MAXGROUP);
    memset(msg_h, 0, mlen*MAXGROUP );
    memset(pk_h, 0, CRYPTO_PUBLICKEYBYTES*MAXGROUP );
    memset(sk_h, 0, CRYPTO_SECRETKEYBYTES*MAXGROUP );
    memset(keypairseedbuf_h, 0, (3*SEEDBYTES)*MAXGROUP );
    memset(signseedbuf_h, 0, (2*SEEDBYTES + 3*CRHBYTES)*MAXGROUP);
    
    // 生成随机数
    randombytes(msg_h, mlen*MAXGROUP );
    rrandombytes(keypairseedbuf_h, 3 * SEEDBYTES*MAXGROUP , SEEDBYTES);

    // 拷贝m到sm
    for (int k = 0; k < MAXGROUP; ++k){
        for(int i = 0; i < mlen; ++i){
           sm_h[CRYPTO_BYTES + mlen - 1 - i + (mlen + CRYPTO_BYTES)*k] = msg_h[mlen - 1 - i + mlen * k];
        }
    }
    // Host端创建一个指针变量，将这个指针变量传入到cudaMalloc()函数，Device端根据设置创建内存后，会将内存首地址赋值给Host端的指针变量
	unsigned char *sm_d;
    unsigned char *msg1_d;
    unsigned char *msg_d;
    unsigned char *pk_d;
    unsigned char *sk_d;
    uint8_t *keypairseedbuf_d;
    uint8_t *signseedbuf_d;
    
    cudaMalloc((void**)&sm_d, (mlen + CRYPTO_BYTES)*MAXGROUP );
    cudaMalloc((void**)&msg1_d, mlen*MAXGROUP );
    cudaMalloc((void**)&msg_d, mlen*MAXGROUP );
    cudaMalloc((void**)&pk_d, CRYPTO_PUBLICKEYBYTES*MAXGROUP );
    cudaMalloc((void**)&sk_d, CRYPTO_SECRETKEYBYTES*MAXGROUP );
    cudaMalloc((void**)&keypairseedbuf_d, (3*SEEDBYTES)*MAXGROUP );
    cudaMalloc((void**)&signseedbuf_d, (2*SEEDBYTES + 3*CRHBYTES)*MAXGROUP);

    
    // Device端创建内存 sign
    sign_sign sign[1];
	allocateSign_Sign(&sign[0]);
    
    
    double GPUtime;
    for(int l = 0;l<18;l++){
        int group = NORMAL_COUNTS[l];
        cudaMemcpy(sm_d, sm_h, (mlen + CRYPTO_BYTES) * group , cudaMemcpyHostToDevice);
        cudaMemcpy(msg1_d, msg1_h, mlen * group , cudaMemcpyHostToDevice);
        cudaMemcpy(msg_d, msg_h, mlen * group , cudaMemcpyHostToDevice);
        cudaMemcpy(pk_d, pk_h, CRYPTO_PUBLICKEYBYTES * group , cudaMemcpyHostToDevice);
        cudaMemcpy(sk_d, sk_h, CRYPTO_SECRETKEYBYTES * group , cudaMemcpyHostToDevice);
        cudaMemcpy(keypairseedbuf_d, keypairseedbuf_h, (3*SEEDBYTES) * group , cudaMemcpyHostToDevice);
        cudaMemcpy(signseedbuf_d, signseedbuf_h, (2*SEEDBYTES + 3*CRHBYTES) * group, cudaMemcpyHostToDevice);
        for(int i=0;i<MAXGROUP;i++)sign->flag[i] = 2;
        cudaMallocManaged(&(sign->n), sizeof(unsigned int)*MAXGROUP );
        // 初始化为OMEGA+1
        for(int i=0;i<MAXGROUP;i++)sign->n[i]= OMEGA+1;
        
        cudaDeviceSynchronize();
        GPUtime = get_time();
        // Generate the public/private keypair
        if ( (ret_val = crypto_sign_keypair(group,keypairseedbuf_d,&sign[0], pk_d, sk_d)) != 0) {
            printf("crypto_sign_keypair returned <%d>\n", ret_val);
            cudaDeviceSynchronize();
            return KAT_CRYPTO_FAILURE;
        }

        // smlen
        if ( (ret_val = crypto_sign(group,signseedbuf_d,&sign[0],sm_d, &smlen, msg_d, mlen, sk_d)) != 0) {
            printf("crypto_sign returned <%d>\n", ret_val);
            cudaDeviceSynchronize();
            return KAT_CRYPTO_FAILURE;
        }
        
        for(int i=0;i<MAXGROUP;i++)sign->n[i]= OMEGA+1;
        
        // mlen1
        if ( (ret_val = crypto_sign_open(group,&sign[0],msg1_d, &mlen1, sm_d, smlen, pk_d)) != 0) {
            printf("crypto_sign_open returned <%d>\n", ret_val);
            cudaDeviceSynchronize();
            return KAT_CRYPTO_FAILURE;
        }

        cudaDeviceSynchronize();
        GPUtime = get_time() - GPUtime;
        printf("\n =================--------------================------------==================");
        printf("\n COUNT %d , Time Elapsed: %f ms. ", group, GPUtime/1000);
        printf("\n =================--------------================------------================== \n");

    }
    //cudaMemcpy(pk_h, pk_d, CRYPTO_PUBLICKEYBYTES , cudaMemcpyDeviceToHost);
    //cudaMemcpy(sk_h, sk_d, CRYPTO_SECRETKEYBYTES , cudaMemcpyDeviceToHost);
    //cudaMemcpy(sm_h, sm_d, (mlen + CRYPTO_BYTES) , cudaMemcpyDeviceToHost);
    //for(int k =0 ;k<MESSAGELEN + CRYPTO_BYTES;k++)printf(" %d ",sm_h[k]);
    // for(int k =0 ;k<CRYPTO_SECRETKEYBYTES;k++)printf(" %d ",sk_h[k]);
    
    cudaDeviceSynchronize();
    return KAT_SUCCESS;
}
