#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdbool.h>

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/const.h>
#include <asm-generic/errno-base.h>

typedef __s8  s8;
typedef __u8  u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;

typedef typeof(sizeof(0)) size_t; 

#define MAX_USED_MAPS 64 /* max number of maps accessed by one eBPF program */
#define MAX_USED_BTFS 64 /* max number of BTFs accessed by one BPF program */

#define BPF_MAX_SUBPROGS 256

/**
 * DECLARE_FLEX_ARRAY() - Declare a flexible array usable in a union
 *
 * @TYPE: The type of each flexible array element
 * @NAME: The name of the flexible array member
 *
 * In order to have a flexible array member in a union or alone in a
 * struct, it needs to be wrapped in an anonymous struct with at least 1
 * named member, but that member can be empty.
 */
#define DECLARE_FLEX_ARRAY(TYPE, NAME) \
	__DECLARE_FLEX_ARRAY(TYPE, NAME)

#define BPF_COMPLEXITY_LIMIT_INSNS      1000000 /* yes. 1M insns */




#define UL(x)		(_UL(x))

#define BIT(nr)			(UL(1) << (nr))


// typedef struct {
// 	union {
// 		void		*kernel;
// 		void __user	*user;
// 	};
// 	bool		is_kernel : 1;
// } sockptr_t;

// typedef sockptr_t bpfptr_t;




#endif
