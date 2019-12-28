
#include "lwip/mem.h"

void mem_free(void *rmem)
{free(rmem);}
void * mem_malloc(mem_size_t size)
{return (void *) malloc(size)  ;}




