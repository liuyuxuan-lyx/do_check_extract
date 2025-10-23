#ifndef __LOCAL_LINUX_BPF_H__
#define __LOCAL_LINUX_BPF_H__


#include "include/common.h"




/* bpf_type_flag contains a set of flags that are applicable to the values of
 * arg_type, ret_type and reg_type. For example, a pointer value may be null,
 * or a memory is read-only. We classify types into two categories: base types
 * and extended types. Extended types are base types combined with a type flag.
 *
 * Currently there are no more than 32 base types in arg_type, ret_type and
 * reg_types.
 */
#define BPF_BASE_TYPE_BITS	8

enum bpf_type_flag {
	/* PTR may be NULL. */
	PTR_MAYBE_NULL		= BIT(0 + BPF_BASE_TYPE_BITS),

	/* MEM is read-only. When applied on bpf_arg, it indicates the arg is
	 * compatible with both mutable and immutable memory.
	 */
	MEM_RDONLY		= BIT(1 + BPF_BASE_TYPE_BITS),

	__BPF_TYPE_LAST_FLAG	= MEM_RDONLY,
};

/* Max number of base types. */
#define BPF_BASE_TYPE_LIMIT	(1UL << BPF_BASE_TYPE_BITS)

/* Max number of all types. */
#define BPF_TYPE_LIMIT		(__BPF_TYPE_LAST_FLAG | (__BPF_TYPE_LAST_FLAG - 1))

/* function argument constraints */
enum bpf_arg_type {
	ARG_DONTCARE = 0,	/* unused argument in helper function */

	/* the following constraints used to prototype
	 * bpf_map_lookup/update/delete_elem() functions
	 */
	ARG_CONST_MAP_PTR,	/* const argument used as pointer to bpf_map */
	ARG_PTR_TO_MAP_KEY,	/* pointer to stack used as map key */
	ARG_PTR_TO_MAP_VALUE,	/* pointer to stack used as map value */
	ARG_PTR_TO_UNINIT_MAP_VALUE,	/* pointer to valid memory used to store a map value */

	/* the following constraints used to prototype bpf_memcmp() and other
	 * functions that access data on eBPF program stack
	 */
	ARG_PTR_TO_MEM,		/* pointer to valid memory (stack, packet, map value) */
	ARG_PTR_TO_UNINIT_MEM,	/* pointer to memory does not need to be initialized,
				 * helper function must fill all bytes or clear
				 * them in error case.
				 */

	ARG_CONST_SIZE,		/* number of bytes accessed from memory */
	ARG_CONST_SIZE_OR_ZERO,	/* number of bytes accessed from memory or 0 */

	ARG_PTR_TO_CTX,		/* pointer to context */
	ARG_ANYTHING,		/* any (initialized) argument is ok */
	ARG_PTR_TO_SPIN_LOCK,	/* pointer to bpf_spin_lock */
	ARG_PTR_TO_SOCK_COMMON,	/* pointer to sock_common */
	ARG_PTR_TO_INT,		/* pointer to int */
	ARG_PTR_TO_LONG,	/* pointer to long */
	ARG_PTR_TO_SOCKET,	/* pointer to bpf_sock (fullsock) */
	ARG_PTR_TO_BTF_ID,	/* pointer to in-kernel struct */
	ARG_PTR_TO_ALLOC_MEM,	/* pointer to dynamically allocated memory */
	ARG_CONST_ALLOC_SIZE_OR_ZERO,	/* number of allocated bytes requested */
	ARG_PTR_TO_BTF_ID_SOCK_COMMON,	/* pointer to in-kernel sock_common or bpf-mirrored bpf_sock */
	ARG_PTR_TO_PERCPU_BTF_ID,	/* pointer to in-kernel percpu type */
	ARG_PTR_TO_FUNC,	/* pointer to a bpf program function */
	ARG_PTR_TO_STACK,	/* pointer to stack */
	ARG_PTR_TO_CONST_STR,	/* pointer to a null terminated read-only string */
	ARG_PTR_TO_TIMER,	/* pointer to bpf_timer */
	__BPF_ARG_TYPE_MAX,

	/* Extended arg_types. */
	ARG_PTR_TO_MAP_VALUE_OR_NULL	= PTR_MAYBE_NULL | ARG_PTR_TO_MAP_VALUE,
	ARG_PTR_TO_MEM_OR_NULL		= PTR_MAYBE_NULL | ARG_PTR_TO_MEM,
	ARG_PTR_TO_CTX_OR_NULL		= PTR_MAYBE_NULL | ARG_PTR_TO_CTX,
	ARG_PTR_TO_SOCKET_OR_NULL	= PTR_MAYBE_NULL | ARG_PTR_TO_SOCKET,
	ARG_PTR_TO_ALLOC_MEM_OR_NULL	= PTR_MAYBE_NULL | ARG_PTR_TO_ALLOC_MEM,
	ARG_PTR_TO_STACK_OR_NULL	= PTR_MAYBE_NULL | ARG_PTR_TO_STACK,

	/* This must be the last entry. Its purpose is to ensure the enum is
	 * wide enough to hold the higher bits reserved for bpf_type_flag.
	 */
	__BPF_ARG_TYPE_LIMIT	= BPF_TYPE_LIMIT,
};
// static_assert(__BPF_ARG_TYPE_MAX <= BPF_BASE_TYPE_LIMIT);

/* type of values returned from helper functions */
enum bpf_return_type {
	RET_INTEGER,			/* function returns integer */
	RET_VOID,			/* function doesn't return anything */
	RET_PTR_TO_MAP_VALUE,		/* returns a pointer to map elem value */
	RET_PTR_TO_SOCKET,		/* returns a pointer to a socket */
	RET_PTR_TO_TCP_SOCK,		/* returns a pointer to a tcp_sock */
	RET_PTR_TO_SOCK_COMMON,		/* returns a pointer to a sock_common */
	RET_PTR_TO_ALLOC_MEM,		/* returns a pointer to dynamically allocated memory */
	RET_PTR_TO_MEM_OR_BTF_ID,	/* returns a pointer to a valid memory or a btf_id */
	RET_PTR_TO_BTF_ID,		/* returns a pointer to a btf_id */
	__BPF_RET_TYPE_MAX,

	/* Extended ret_types. */
	RET_PTR_TO_MAP_VALUE_OR_NULL	= PTR_MAYBE_NULL | RET_PTR_TO_MAP_VALUE,
	RET_PTR_TO_SOCKET_OR_NULL	= PTR_MAYBE_NULL | RET_PTR_TO_SOCKET,
	RET_PTR_TO_TCP_SOCK_OR_NULL	= PTR_MAYBE_NULL | RET_PTR_TO_TCP_SOCK,
	RET_PTR_TO_SOCK_COMMON_OR_NULL	= PTR_MAYBE_NULL | RET_PTR_TO_SOCK_COMMON,
	RET_PTR_TO_ALLOC_MEM_OR_NULL	= PTR_MAYBE_NULL | RET_PTR_TO_ALLOC_MEM,
	RET_PTR_TO_BTF_ID_OR_NULL	= PTR_MAYBE_NULL | RET_PTR_TO_BTF_ID,

	/* This must be the last entry. Its purpose is to ensure the enum is
	 * wide enough to hold the higher bits reserved for bpf_type_flag.
	 */
	__BPF_RET_TYPE_LIMIT	= BPF_TYPE_LIMIT,
};
// static_assert(__BPF_RET_TYPE_MAX <= BPF_BASE_TYPE_LIMIT);

/* eBPF function prototype used by verifier to allow BPF_CALLs from eBPF programs
 * to in-kernel helper functions and for adjusting imm32 field in BPF_CALL
 * instructions after verifying
 */
struct bpf_func_proto {
	u64 (*func)(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5);
	bool gpl_only;
	bool pkt_access;
	enum bpf_return_type ret_type;
	union {
		struct {
			enum bpf_arg_type arg1_type;
			enum bpf_arg_type arg2_type;
			enum bpf_arg_type arg3_type;
			enum bpf_arg_type arg4_type;
			enum bpf_arg_type arg5_type;
		};
		enum bpf_arg_type arg_type[5];
	};
	union {
		struct {
			u32 *arg1_btf_id;
			u32 *arg2_btf_id;
			u32 *arg3_btf_id;
			u32 *arg4_btf_id;
			u32 *arg5_btf_id;
		};
		u32 *arg_btf_id[5];
	};
	int *ret_btf_id; /* return value btf_id */
	bool (*allowed)(const struct bpf_prog *prog);
};

/* bpf_context is intentionally undefined structure. Pointer to bpf_context is
 * the first argument to eBPF programs.
 * For socket filters: 'struct bpf_context *' == 'struct sk_buff *'
 */
struct bpf_context;

enum bpf_access_type {
	BPF_READ = 1,
	BPF_WRITE = 2
};

/* types of values stored in eBPF registers */
/* Pointer types represent:
 * pointer
 * pointer + imm
 * pointer + (u16) var
 * pointer + (u16) var + imm
 * if (range > 0) then [ptr, ptr + range - off) is safe to access
 * if (id > 0) means that some 'var' was added
 * if (off > 0) means that 'imm' was added
 */
enum bpf_reg_type {
	NOT_INIT = 0,		 /* nothing was written into register */
	SCALAR_VALUE,		 /* reg doesn't contain a valid pointer */
	PTR_TO_CTX,		 /* reg points to bpf_context */
	CONST_PTR_TO_MAP,	 /* reg points to struct bpf_map */
	PTR_TO_MAP_VALUE,	 /* reg points to map element value */
	PTR_TO_MAP_KEY,		 /* reg points to a map element key */
	PTR_TO_STACK,		 /* reg == frame_pointer + offset */
	PTR_TO_PACKET_META,	 /* skb->data - meta_len */
	PTR_TO_PACKET,		 /* reg points to skb->data */
	PTR_TO_PACKET_END,	 /* skb->data + headlen */
	PTR_TO_FLOW_KEYS,	 /* reg points to bpf_flow_keys */
	PTR_TO_SOCKET,		 /* reg points to struct bpf_sock */
	PTR_TO_SOCK_COMMON,	 /* reg points to sock_common */
	PTR_TO_TCP_SOCK,	 /* reg points to struct tcp_sock */
	PTR_TO_TP_BUFFER,	 /* reg points to a writable raw tp's buffer */
	PTR_TO_XDP_SOCK,	 /* reg points to struct xdp_sock */
	/* PTR_TO_BTF_ID points to a kernel struct that does not need
	 * to be null checked by the BPF program. This does not imply the
	 * pointer is _not_ null and in practice this can easily be a null
	 * pointer when reading pointer chains. The assumption is program
	 * context will handle null pointer dereference typically via fault
	 * handling. The verifier must keep this in mind and can make no
	 * assumptions about null or non-null when doing branch analysis.
	 * Further, when passed into helpers the helpers can not, without
	 * additional context, assume the value is non-null.
	 */
	PTR_TO_BTF_ID,
	/* PTR_TO_BTF_ID_OR_NULL points to a kernel struct that has not
	 * been checked for null. Used primarily to inform the verifier
	 * an explicit null check is required for this struct.
	 */
	PTR_TO_MEM,		 /* reg points to valid memory region */
	PTR_TO_BUF,		 /* reg points to a read/write buffer */
	PTR_TO_PERCPU_BTF_ID,	 /* reg points to a percpu kernel variable */
	PTR_TO_FUNC,		 /* reg points to a bpf program function */
	__BPF_REG_TYPE_MAX,

	/* Extended reg_types. */
	PTR_TO_MAP_VALUE_OR_NULL	= PTR_MAYBE_NULL | PTR_TO_MAP_VALUE,
	PTR_TO_SOCKET_OR_NULL		= PTR_MAYBE_NULL | PTR_TO_SOCKET,
	PTR_TO_SOCK_COMMON_OR_NULL	= PTR_MAYBE_NULL | PTR_TO_SOCK_COMMON,
	PTR_TO_TCP_SOCK_OR_NULL		= PTR_MAYBE_NULL | PTR_TO_TCP_SOCK,
	PTR_TO_BTF_ID_OR_NULL		= PTR_MAYBE_NULL | PTR_TO_BTF_ID,

	/* This must be the last entry. Its purpose is to ensure the enum is
	 * wide enough to hold the higher bits reserved for bpf_type_flag.
	 */
	__BPF_REG_TYPE_LIMIT	= BPF_TYPE_LIMIT,
};


#endif
