#include <string.h>
#include "rng.h"
#include "params.h"

int randombytes(unsigned char* x, unsigned long long xlen)
{ // 生成随机值的x，利用i代替aes计算
	for (unsigned int i = 0; i < xlen; i++)
	{
		x[i] =  i;
	}
	return 0;
}

void rrandombytes(uint8_t *out, size_t outlen, size_t len,uint16_t nonce)
{
	for (unsigned int i = 0; i < outlen; i += 3 * len)
	{
        for(int j = i; j < i + len; j++){
            out[j] = nonce+j;
        }
	}
}