#ifndef __REG_UNREG_H_
#define __REG_UNREG_H_

#define MAX_VECTOR_NAME_LEN 256
#define MAX_BUFFER_SIZE 4096

#include "override_syscall.h"

struct new_vector {
	char vector_name[MAX_VECTOR_NAME_LEN];
	unsigned long vector_address;
	int ref_count;
	struct module *vector_module;
	struct new_vector *next;
};

#endif
