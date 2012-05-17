/*
 *@Author: Group-12 cse 506
 */

/*
 * the function signature for do_syscall_inherit_check 
 * is in signal.h which is included by entry_32.S
*/
#include<asm/signal.h>
#include<asm/thread_info.h>
#include<asm/errno.h>
#include<asm/unistd.h>
#include<asm/current.h>
#include<linux/sched.h>
#include "override_syscall.h"

#define NOT_OVERRIDDEN -9999
#define WRAPPED -8888
int ret;

/*
 * do_syscall_inherit_check checks the void *
 * field syscall_inherit_data which is added by us to the
 * processes task_struct and calls the overridden function
 * if this field is not null.
 * returns -9999 if the syscall is not overridden
 * or returns the return value of the overridden function if
 * the syscall is overridden.
*/
int do_syscall_inherit_check(void){

	int syscall_number;
	struct syscall_vector *vec_head = NULL;
	struct syscall_vector *temp = NULL;
	struct task_struct *tsk = NULL;
 	/*
	 * return value initialized to -9999 
	*/
	ret = NOT_OVERRIDDEN;
 	/*
	 * since values of few registers are altered by the time
  	 * this function is called, we are saving the state by pushing the important
 	 * in the stack.
	*/
	asm(
		"pushl %eax\n\t"
		"pushl %ebx\n\t"
		"pushl %ecx\n\t"
		"pushl %edx\n\t"
		"pushl %esi\n\t"
		"pushl %edi\n\t"
	);
	
	/*
	 * The value in eax, which is the system call number is
 	 * moved into syscalL_number variable.
	*/
	asm("movl %%eax, %0":"=r"(syscall_number): :"%eax");
	
	/*
	 * get the current process' task structure
	*/
	tsk = get_current(); 
	/*
	 * check if the syscall_inherit_data is null or not.
	 * that is if the syscall is overridden or not.
	 * syscall_inherit_data will have the address
 	 * of the head of the vector of system calls that are overridden
	*/
	if(tsk->syscall_inherit_data == NULL) {
		ret = NOT_OVERRIDDEN;
		goto out;
	}
	/*
	 * if overridden
	*/
	else{	
		printk(KERN_INFO "Syscall number: %d", syscall_number);
		
		/*
		 * get the address of the overriden syscall vector
		*/
		vec_head = (struct syscall_vector*) tsk->syscall_inherit_data;
		/*
		 * If vector is enpty
		*/
		if(vec_head == NULL) {
			ret = NOT_OVERRIDDEN;
			goto out;
	        }
		/*
		 * vector is not empty
		*/
		temp = vec_head;
		/*
		 * parsing through the overriden syscall vector
		*/
		while (temp != NULL){
			/*
			 * when we find the overridden function 
			*/
			if(temp->sys_call.syscall_no == syscall_number) {
				/*
				 * Push the original function arguments in the kernel
				 * stack so that when the function call is made, it is 
				 * directly taken from the kernel stack.
				 * These arguments can be accessed by adding offsets to the
                                 * base pointer. 
				 * Like linux system calls, our overridden functions are also
				 * declared as asmlinkage which means that the system has to 
				 * look for the arguments from the kernel stack. 
				*/
				asm(
					"pushl 0x20(%ebp)\n\t"
					"pushl 0x1c(%ebp)\n\t"
					"pushl 0x18(%ebp)\n\t"
					"pushl 0x14(%ebp)\n\t"
					"pushl 0x10(%ebp)\n\t"
					"pushl 0x0c(%ebp)\n\t"
				);
				
				/*
				 * address of the overridden function is pushed to eax
				 * and the call to that function is made
				*/
				asm("movl %0, %%eax\n\t": :"r"(temp->sys_call.function_ptr) :"%eax");
				asm("call *%eax\n\t");

				/*
				 * return value is moved from eax to variable ret 
				*/
				asm("movl %%eax, %0":"=r"(ret): :"%eax");
				printk(KERN_INFO "Ret after function call: %d", ret);
				
				/*
				 * all function arguments that were pushed 
			 	 * in the stack are removed 
				*/
				asm(	"popl %ebx\n\t"
					"popl %ecx\n\t"
					"popl %edx\n\t"
					"popl %esi\n\t"
					"popl %edi\n\t"
					"popl %eax\n\t"
					);
		
				break;
			}
			else {
 				/*
				 * if we see that that particular syscall is not 
				 * overridden 
				*/
				ret = NOT_OVERRIDDEN;
			}

			temp = temp->next;
		}
	}
out:
	/*
	 * restoring the kernel register values which were
	 * pushed into the kernel stack at the start of this
	 * function
	*/
	asm(
		"popl %edi\n\t"
		"popl %esi\n\t"
		"popl %edx\n\t"
		"popl %ecx\n\t"
		"popl %ebx\n\t"
		"popl %eax\n\t"
	);

if(ret == WRAPPED) {
	printk(KERN_INFO "This is a wrapped system call. Now, calling original system call.");
	ret = NOT_OVERRIDDEN;
}

return ret;
}
