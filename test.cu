// nvcc -arch=sm_61 -rdc=true -cudart static --machine 64 -use_fast_math -O2 test.cu -o test -lcudadevrt -std=c++11
// nvprof ./test

#include <stdio.h>
#include <stdlib.h>

int Hardware()
{
	cudaDeviceProp prop;
	int count;
	cudaGetDeviceCount(&count);
    printf("所在机器共有%d块GPU，以下输出详细信息\n", count);
	for (int i = 0; i < count; i++) {
		cudaGetDeviceProperties(&prop, i);
		printf(" --- General Information for device %d ---\n", i);
		printf("Name: %s\n", prop.name);
		printf("Compute capability: %d.%d\n", prop.major, prop.minor);
		printf("Clock rate: %d\n", prop.clockRate);
		printf("Device copy overlap: ");
		if (prop.deviceOverlap)
			printf("Enabled\n");
		else
			printf("Disabled\n");
		printf("Kernel execition timeout : ");
		if (prop.kernelExecTimeoutEnabled)
			printf("Enabled\n");
		else
			printf("Disabled\n");
		printf(" --- Memory Information for device %d ---\n", i);
		printf("Total global mem: %lu\n", prop.totalGlobalMem);
		printf("Total constant Mem: %lu\n", prop.totalConstMem);
		printf("Max mem pitch: %zd\n", prop.memPitch);
		printf("Texture Alignment: %zd\n", prop.textureAlignment);
		printf(" --- MP Information for device %d ---\n", i);
		printf("Multiprocessor count: %d\n", prop.multiProcessorCount);

		printf("Shared mem per mp: %zd\n", prop.sharedMemPerBlock);
		printf("Registers per mp: %d\n", prop.regsPerBlock);
		printf("Threads in warp: %d\n", prop.warpSize);
		printf("Max threads per block: %d\n", prop.maxThreadsPerBlock);
		printf("Max thread dimensions: (%d, %d, %d)\n", prop.maxThreadsDim[0], prop.maxThreadsDim[1], prop.maxThreadsDim[2]);
		printf("Max grid dimensions: (%d, %d, %d)\n", prop.maxGridSize[0], prop.maxGridSize[1], prop.maxGridSize[2]);
		printf("\n");
	}
	return count;
}

int main()
{
	printf("以下输出所在机器的GPU信息\n");
	int gpu_count = Hardware();
    
}