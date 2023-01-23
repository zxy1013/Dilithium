#include <stdint.h>
#include "params.h"
#include "reduce.h"


__device__ int32_t montgomery_reduce(int64_t a) {
  int32_t t;

  t = (int32_t)a*QINV;
  t = (a - (int64_t)t*Q) >> 32;
  return t;
}


__device__ int32_t reduce32(int32_t a) {
  int32_t t;

  t = (a + (1 << 22)) >> 23;
  t = a - t*Q;
  return t;
}


__device__ int32_t caddq(int32_t a) {
  a += (a >> 31) & Q;
  return a;
}

