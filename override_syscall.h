#ifndef __OVERRIDE_SYSCALL_H_
#define __OVERRIDE_SYSCALL_H_

#ifndef MAX_VECTOR_NAME_LEN
#define MAX_VECTOR_NAME_LEN 256
#endif

struct overriden_syscall {
	int syscall_no;
	unsigned long function_ptr;
};

struct syscall_vector {
	struct overriden_syscall sys_call;
	struct syscall_vector *next;	
};


#endif
