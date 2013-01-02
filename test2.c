#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

#define page_align(address)  (char*)((unsigned long)(address) & -pagesize)

extern void libsegfault_protect(void* addr, size_t size, FILE* log);

int main(void)
{
	char* fault_address;
	unsigned long pagesize;
	char* area;
	char t;

	printf("(D) 0x44 : %d\n", 0x44);

	pagesize = getpagesize();
	area = (char*)malloc(6*pagesize);
	if (!area) {
		printf("No memory.\n");
		exit(1);
	}
	fault_address = area + pagesize*7/2;

	*fault_address = 'G';

	libsegfault_protect(page_align(fault_address), pagesize, stderr);

	printf("(I)Address : 0x%08x\n", (unsigned int)fault_address);
	printf("(I)Reading : '%c'\n",*fault_address);

	*fault_address = 'A';
	t = 'T';
	printf("(I)Reading : '%c'\n",t);
	t = *fault_address;
	printf("(I)Reading : '%c'\n",t);

	return 0;
}
