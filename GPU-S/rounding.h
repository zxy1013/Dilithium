#ifndef ROUNDING_H
#define ROUNDING_H

#include <stdint.h>
#include "params.h"


__device__ int32_t power2round(int32_t *a0, int32_t a);
__device__ int32_t decompose(int32_t *a0, int32_t a);
__device__ int32_t use_hint(int32_t a, unsigned int hint);


unsigned int make_hint(int32_t a0, int32_t a1);
#endif
