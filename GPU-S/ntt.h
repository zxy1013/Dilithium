#ifndef NTT_H
#define NTT_H

#include <stdint.h>
#include "params.h"

__global__ void GNTT(int32_t* a);
__global__ void GINTT(int32_t* a);

#endif
