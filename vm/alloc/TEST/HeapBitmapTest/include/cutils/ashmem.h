#ifndef ASHMEM_H_
#define ASHMEM_H_

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#define ASHMEM_NAME_LEN 128

inline int
ashmem_create_region(const char *name, size_t len)
{
	printf("ZHK in ashmem.h: ashmem_create_region\n");
    return open(name, O_RDWR);
}

#endif
