/*
 * This file contains API for adding new system call vectors or tables.
 * Four symbols are exported which are used by different modules for respective
 * tasks performed by the functions.
 *
 * A new file is created in proc filesystem and can be accessed at 
 * "/proc/syscall_vectors". This file shows the system call vectors registered
 * in this system.
 * 
 * Proc filesystem is used because we do not require users to write in the file,
 * or do any other file operations. Further proc filesystem allows an easy hook to
 * data structures defined in kernel. Also provides easy way to access them using
 * callback functions available like read_proc and write_proc.
 * 
 * Note: write_proc is not implemented since we don't want user to write anything 
 * to our data structures. User will get Input/Output error if he tries to echo
 * or save anything to file.
 * "cat" will show all vector names added in the system.
 *
 * List is locked with mutex lock when addition or removal is done from it.
 * All possible lock conditions have been handled.
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <asm/uaccess.h>	/* for get_user and put_user */
#include <linux/string.h>
#include <linux/mutex.h>

#include "reg_unreg.h"

#define EXPORT_SYMTAB
#define AUTHOR "Group 12"
#define DESCRIPTION "\'reg_unreg\' LKM"

MODULE_LICENSE("GPL");
MODULE_AUTHOR(AUTHOR);
MODULE_DESCRIPTION(DESCRIPTION);


/*
 * Name of this file created in proc filesystem
 */
static const char filename[] = "syscall_vectors";
struct proc_dir_entry* pde = NULL;

/*
 * this head is the beginning of list of all the vectors or new system call
 * tables created by different applications.
 */
struct new_vector *head = NULL;
char buffer[MAX_BUFFER_SIZE];
struct mutex list_lock;


/*
 * This function is implementation of "/proc/syscall_vectors" "read_proc"
 * callback function present in "struct proc_dir_entry". 
 * Here, the list of all the vectors registered is traversed and the names
 * of vectors are taken and stored in a buffer on the fly which is than put 
 * or copied to user buffer taken as arguement. 
 * return 0 if no error
 * return -1 if error
*/
static int show_vectors(char *user_buffer,
	      char **buffer_location,
	      off_t offset, int buffer_length, int *eof, void *data ) {

	int ret;
	char *current_ptr;
	struct new_vector *temp;
	int vec_len;

	ret = 0;
	temp = NULL;
	current_ptr = NULL;
	if (offset > 0) {
		/* we have finished to read, return 0 */
		ret  = 0;
		goto out;
	} 
	memset(buffer, 0, MAX_BUFFER_SIZE);
	current_ptr = buffer;
	if(head == NULL) {
		goto out;
	}

	temp = head;
	while ((temp != NULL) && (ret < MAX_BUFFER_SIZE)){
		vec_len = strlen(temp->vector_name);
		memcpy(current_ptr, temp->vector_name, vec_len);
		current_ptr[vec_len] = '\n';
		current_ptr = current_ptr + vec_len + 1;
		ret = ret + vec_len +1 ;	
		temp = temp->next;
	}

	memcpy(user_buffer, buffer, ret);
out:
	return ret;
}


/*
 * allocate a new_vector structure.
 * populate the fields, with reference count = 0 initially.
 * add to the list of registered vectors.
 * return 0 if no error.
 * negative number other wise.
 */
static int add_vector_address(char *vector_name, unsigned long vector_address, struct module *vector_module){
	int ret = 0;
	struct new_vector *va = NULL;
	struct new_vector *temp = NULL;
	// printk(KERN_INFO "Inside add vector address");

	va = (struct new_vector*)kmalloc(sizeof(struct new_vector), GFP_KERNEL);
        if(va == NULL) {
                ret = -ENOMEM;
                goto out;
        }
        if (IS_ERR(va)) {
                ret = PTR_ERR(va);
                goto out;
        }

        memset(va, 0, sizeof(struct new_vector));

        memcpy(va->vector_name, vector_name, strlen(vector_name));
        va->vector_address = vector_address;
	va->ref_count = 0;
        va->vector_module = vector_module;
        va->next = NULL;

	//printk(KERN_INFO "Vector address = %ld", vector_address);
	if(head == NULL) {
		head = va;
		goto out;
	}

	temp = head;
	while(temp->next != NULL) {
		temp = temp->next;
	}

	temp->next = va;
	//printk(KERN_INFO "Added to list");
out:
	return ret;
}


/*
 * traverse the list and find the location of vector_address.
 * remove the vector from the list of vectors only if reference count is 0.
 * returning -2222 for indication that the vector is in use by some process.
 * Therby failing the unregister system_call_vector call.
 *
 * return 0 if everything alright.
 */
static int remove_vector_address(unsigned long vector_address){
	int ret = 0;
	int flag = 0;
	struct new_vector *ptr = NULL;
	struct new_vector *temp = NULL;
	
	//printk(KERN_INFO "Inside remove vector address");

	if(head == NULL) {
		printk(KERN_INFO "Head null");
		ret = -EFAULT;
		goto out;
	}

	if( (head->next == NULL) && (head->vector_address == vector_address)) {
		//printk(KERN_INFO " Condition True : %ld", vector_address);
		ptr = head;
		goto check_ref_count;
	}

	else if(head->next != NULL) {
		temp = head;
		ptr = temp->next;
		while(ptr != NULL) {
			if(ptr->vector_address == vector_address) {
				flag = 1;
				break;
			}
			ptr=ptr->next;
			temp = ptr;
		}
	}
	else ;

	//printk(KERN_INFO "Before printing if temp->next");
	if(flag == 0) {
		ret = -EFAULT;
		goto out;
	}

check_ref_count:	
	if(ptr->ref_count > 0) {
		//printk(KERN_INFO" reference count: %d", ptr->ref_count);
		ret = -2222;
		goto out;
	}

	if(ptr != head) 
		temp->next = ptr->next;
	else 
		head = NULL;
	kfree(ptr);
	ptr = NULL;
	//printk(KERN_INFO "removed from list");
out:
	return ret;
}


/*
 * This is the function called by any module which wants to add new system_call_vector/table to 
 * the list of other vectors. This function name is exported to be accessible to other modules.
 *
 * This will create a new structure adding vector_name, address, struct module pointer of module 
 * trying to add the vector and reference count for this vector.
 *
 * struct module* pointer is added because when we want that if some process is using the vector,
 * the module implementing the functions/overriden system calls in vector is not removed. So, 
 * we will control the reference count of module by using try_get_module() and module_put() on that 
 * struct module* pointer.
 * 
 * "Mutex" lock has been taken before adding the vector address to the list to ensure mutual exclusion.
 * We want only one module to use the API at a time.
 *
 * returns 0 if no error.
 * else negative number.
 */
int register_syscall(char *vector_name, unsigned long vector_address, struct module* vector_module) {
	int ret = 0;

	// printk(KERN_INFO " Inside register_syscall");
	mutex_lock(&list_lock);
	ret = add_vector_address(vector_name, vector_address, vector_module);
	if(ret < 0) {
		goto out;
	}
	mutex_unlock(&list_lock);
out:
	return ret;
}
EXPORT_SYMBOL(register_syscall);


/* 
 * This is called by module implementing the vector to remove the vector/table from list of
 * registered vectors. This is also exported.
 *
 * This will fail if the vector is in use by some process and is being tried to remove.
 * Otherwise it will remove the vector and deallocate the memory taken by vector.
 *
 * "Mutex" lock has been taken before removing the vector address from the list to ensure mutual exclusion.
 * We want only one module to use the API at a time.
 *
 * returns 0 if no error.
 * else negative number.
 *
 */
int unregister_syscall(unsigned long vector_address) {
	int ret = 0;

	//printk(KERN_INFO " Inside register_syscall");
	mutex_lock(&list_lock);
	ret = remove_vector_address(vector_address);
	if(ret < 0) {
		goto out;
	}
	mutex_unlock(&list_lock);
out:
	return ret;
}
EXPORT_SYMBOL(unregister_syscall);


/*
 * This will be called by ioctl module which takes in name of vector and asks
 * this module to get the address of vector, so that user process can use the overridden
 * functions implemented by owner of vector module.
 *
 * This is also exported.
 * If the vector is found in the list of registered vectors, the reference count of the module
 * implementing it, is incremented by calling try_module_get() to make sure that nobody removes 
 * the vector as the vector is in use by some process.
 * Also the reference counter field kept in the new_vector structure is incremented.
 *
 * Mutex lock has been taken before retreiving the vector address to ensure mutual exclusion.
 * We don't want any addition/deletion of any vector address while traversing the list.
 *
 * returns vector address if OK otherwise returns 0
 */
unsigned long get_vector_address(char *vector_name) {
	unsigned long va = 0;
	struct new_vector *temp = NULL;
	
	mutex_lock(&list_lock);
	if(head == NULL) {
		goto out;
	}
	
	temp = head;
	while (temp != NULL){
		if( memcmp(temp->vector_name, vector_name, strlen(vector_name)) == 0 ) {
			if(strlen(vector_name)==strlen(temp->vector_name))
				break;
		}
		temp = temp->next;
	}

	if(temp != NULL) {
		temp->ref_count = temp->ref_count + 1;
		try_module_get(temp->vector_module);
		va = temp->vector_address;
	}
	mutex_unlock(&list_lock);
out:
	return va;
}
EXPORT_SYMBOL(get_vector_address);


/* 
 * This exported function will be called by ioctl module, to reduce the reference count,
 * of the vector.
 * This indicates that the process no longer wants to use overriden system call vector.
 * In this case we will do a module_put() on the module implementing the vector, also
 * we will reduce the reference counter field in new_vector structure.
 *
 * Mutex lock has been taken before traversing the list to reduce the reference counter.
 * This is to ensure mutual exclusion. We don't want any addition/deletion from list while
 * traversing the list.
 *
 * returns negative error or updated reference count(0 or positive) if everything is OK.
 *
 */
int reduce_ref_count(char *vector_name) {
	int ref_cnt = -1;
	struct new_vector *temp = NULL;
	
	mutex_lock(&list_lock);
	if(head == NULL) {
		goto out;
	}
	
	temp = head;
	while (temp != NULL){
		if( memcmp(temp->vector_name, vector_name, strlen(vector_name)) == 0 ) {
			if(strlen(vector_name)==strlen(temp->vector_name))
				break;
		}
		temp = temp->next;
	}

	if(temp != NULL) {
		temp->ref_count = temp->ref_count - 1 ;
		ref_cnt = temp->ref_count;
		module_put(temp->vector_module);
		// printk(KERN_INFO "New Ref Count: %d", ref_cnt);
	}
	mutex_unlock(&list_lock);
out:
	return ref_cnt;
}
EXPORT_SYMBOL(reduce_ref_count);

/*
 * This initializes the module and creates a proc_entry or a file with name 
 * "syscall_vectors" in proc filesystem.
 *
 * The file is created with read only permission for owner and group.
 * returns 0 if everything is fine else returns error.
 *
 */
int init_module(void)
{
	int ret = 0;

	pde = create_proc_entry(filename, 0444, 0);
        if (IS_ERR(pde)) {
                ret = PTR_ERR(pde);
                goto out;
        }

	pde->read_proc = show_vectors;
	mutex_init(&list_lock);

out:
	return ret;
}


/*
 * This will remove the file created by this module from proc filesystem
 */
void cleanup_module(void)
{
	remove_proc_entry(filename, 0);
}


