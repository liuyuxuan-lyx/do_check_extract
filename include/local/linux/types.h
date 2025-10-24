#ifndef __LOCAL_LINUX_TYPES_H__
#define __LOCAL_LINUX_TYPES_H__


#include "common.h"


#ifdef CONFIG_64BIT
typedef struct {
	s64 counter;
} atomic64_t;
#endif


#endif
