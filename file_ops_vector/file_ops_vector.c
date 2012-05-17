/*
 * This module is an implementation of an overridden system_call_vector/table.
 * This module can represent any application that wants to override basic file
 * operations call like open and read.
 * 
 * open, read, and fchown have been implemented.
 *
 * A vector ("struct syscall_vector") is a linked list of all the system 
 * calls, here represented as a structure "struct overriden_syscall". Both structures
 * are declared in "override_syscall.h". 
 *
 * The vector contains all the system calls that this module wants to override. 
 * "struct overridden_syscall" contains information about one particular system call -  
 * 1) system call number("syscall_no") and 2) the address of function or function pointer
 *     of implementation of that systemcall function("function_ptr").
 *
 * register_syscall() and unregister_syscall() API are used to add and remove the vector
 * respectively, in the list of registered and unregistered vectors maintained in "reg_unreg"
 * module. These functions are exported in "reg_unreg" module.
 * 
 * overridden functions are declared as "asmlinkage" to tell the compiler that arguements
 * are to be taken from stack.
 *
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/unistd.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "../override_syscall.h"

#define MAX_USER_BUF_INPUT_SIZE 512
#define AUTHOR "Group 12"
#define DESCRIPTION "\'open_read_fchown_override\' LKM"

MODULE_LICENSE("GPL");
MODULE_AUTHOR(AUTHOR);
MODULE_DESCRIPTION(DESCRIPTION);

char vector_name[MAX_VECTOR_NAME_LEN] = "file_ops_vector";
struct syscall_vector *vec_head = NULL;

/*
 * exported functions - defined in "reg_unreg" module.
 */
extern int register_syscall(char *vector_name, unsigned long vector_address, struct module *vector_module);
extern int unregister_syscall(unsigned long vector_address);

/*
 * Implementation of wrapped "sys_open".
 * Apart from the action done in this function, it will also call original sys_open.
 * Arguements received are printed. Look for these messages in "/var/log/messages" or "dmesg"
 * Dummy value -8888 is returned indicating that this system call is wrapped and not overridden.
 * According to our design all system calls that are wrapped return -8888
 */
asmlinkage long myopen_syscall(const char __user *filename, int flags, umode_t mode ){
	long ret = -8888;
	char *received_fname = NULL;

	received_fname = (char *)kmalloc(MAX_USER_BUF_INPUT_SIZE, GFP_KERNEL);
	if (received_fname == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	if (IS_ERR(received_fname)) {
		ret = PTR_ERR(received_fname);
		goto out;
	}

	ret = copy_from_user(received_fname, filename, MAX_USER_BUF_INPUT_SIZE);
	if(ret < 0) {                                
		ret = -EFAULT;
		goto out;
	}     

	ret = -8888;
	printk(KERN_INFO "Inside My Wrapped Open System Call Function ..");
	printk(KERN_INFO "Apart from the action done in this function, it will also call original sys_open.");
	printk(KERN_INFO "Received file name is: %s", received_fname);
	printk(KERN_INFO "Received flags: %d", flags );
	printk(KERN_INFO "Received mode: %d", mode );
out:
	if(received_fname != NULL)
		kfree(received_fname);
	return ret;
}

/*
 * Implementation of overridden "sys_fchown".
 * Arguements received are printed. Look for these messages in "/var/log/messages" or "dmesg"
 * Dummy value 2070 is returned.
 */
asmlinkage long myfchown_syscall(unsigned int fd, uid_t user, gid_t group) {
	printk(KERN_INFO "Inside My Overridden fchown System Call Function ..");
	printk(KERN_INFO "Received fd: %u", fd);
	printk(KERN_INFO "Received user id: %u", (unsigned int)user);
	printk(KERN_INFO "Received group id: %u", (unsigned int)group);
	return 2070;
}

/*
 * Implementation of overridden "sys_read".
 * Arguements received are printed. Look for these messages in "/var/log/messages" or "dmesg"
 * Dummy value 3030 is returned.
 */
asmlinkage long myread_syscall( unsigned int fd, char __user *buf, size_t count ){

	int ret = 3030;
	char *output_buf = NULL;

	output_buf = (char *)kmalloc(MAX_USER_BUF_INPUT_SIZE, GFP_KERNEL);
	if (output_buf == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	if (IS_ERR(output_buf)) {
		ret = PTR_ERR(output_buf);
		goto out;
	}
	memcpy(output_buf, "random_text", 100);

        ret = copy_to_user(buf, output_buf, 100);
        if(ret < 0) {
                ret = -EFAULT;
                goto out;
        }

	ret = 3030;
	printk(KERN_INFO "Inside My Overridden Read System Call Function ..");
	printk(KERN_INFO "Received fd: %u", fd);
	printk(KERN_INFO "Received count: %d", count );
out:
	if(output_buf != NULL) {
		kfree(output_buf);
	}
	return ret;
}

/*
 * This function is helper to add a new system call to the already built system call table
 * or vector. This allocates a new syscall_vector and populates the fields with syscall_no
 * and function pointer taken as arguement.
 *
 * Returns negative on error, 0 otherwise.
 */
static int add_syscall_to_vector(int syscall_no, unsigned long func_ptr) {
	int ret = 0;
	struct syscall_vector *sys_vec = NULL;
	struct syscall_vector *temp = NULL;

	sys_vec = (struct syscall_vector *)kmalloc(sizeof(struct syscall_vector), GFP_KERNEL);
        if(sys_vec == NULL) {
                ret = -ENOMEM;
                goto out;
        }
        if (IS_ERR(sys_vec)) {
                ret = PTR_ERR(sys_vec);
                goto out;
        }

        memset(sys_vec, 0, sizeof(struct syscall_vector));
	sys_vec->sys_call.syscall_no = syscall_no;
	sys_vec->sys_call.function_ptr = func_ptr;

	// printk(KERN_INFO "Vector address = %ld", vector_address);
        if(vec_head == NULL) {
                vec_head = sys_vec;
                goto out;
        }

        temp = vec_head;
        while(temp->next != NULL) {
                temp = temp->next;
        }

        temp->next = sys_vec;
out:
	return ret;
}

/*
 * This function is called when the module is initialized. It creates the table of
 * all the system calls we want to override.
 * 
 * Then we call the register_syscall API to register our syscall_vector, so that it 
 * is made visible in "/proc/syscall_vectors" and can be used by the user process.
 * 
 * Returns negative on error and 0 if OK
 */
static int initialize_syscall_vector(void) {
	int ret = 0;
	int open_syscall_no = 5;
	int read_syscall_no = 3;
	int fchown_syscall_no = 207;
	
	ret = add_syscall_to_vector(open_syscall_no, (unsigned long)myopen_syscall);
	if(ret < 0) {
		goto out;
	}
	ret = add_syscall_to_vector(read_syscall_no, (unsigned long)myread_syscall);
	if(ret < 0) {
		goto out;
	}
	ret = add_syscall_to_vector(fchown_syscall_no, (unsigned long)myfchown_syscall);
	if(ret < 0) {
		goto out;
	}

	ret = register_syscall(vector_name, (unsigned long)vec_head, THIS_MODULE);
	// printk(KERN_INFO " ret from register = %d", ret);
out:
	return ret;
}

/*
 * This is a 'cleanup' helper function which deletes the vector, deallocates all the memory
 * allocated earlier while creating the vector.
 * This helper is called when removing the module or when some error occurs.
 */
static void delete_vector(void) {
	struct syscall_vector *temp = NULL;
	struct syscall_vector *new_head = NULL;
	new_head = vec_head;

	if(vec_head == NULL) {
		goto end;
	}

	while(new_head->next != NULL) {
		temp = new_head;
		new_head = new_head->next;
		kfree(temp);
		temp = NULL;
	}	

	kfree(new_head);
	new_head = NULL;
	vec_head = NULL;
	goto end;
end:
;
}

/*
 * This creates syscall_vector. Called when insmod is done.
 * Returns negative on error. 0 otherwise.
 */
static int __init init_override(void)
{
	int ret = 0;
	ret = initialize_syscall_vector();
	if(ret < 0) {
		delete_vector();
	}
	return ret;
}


/*
 * Calls unregister_syscall API to remove the vector from list of registered vectors.
 * Then calls delete_vector() to clean up the memory.
 */
static void __exit cleanup_override(void)
{
	int ret;
	ret = unregister_syscall((unsigned long)vec_head);
	if(vec_head != NULL) {
		delete_vector();
	}
}

module_init(init_override);
module_exit(cleanup_override);


