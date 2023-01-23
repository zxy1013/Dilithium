#ifndef NTT_H
#define NTT_H

#include <stdint.h>
#include "params.h"

__device__ void ntt(int32_t a[N]);

__device__ void invntt_tomont(int32_t a[N]);

#endif
