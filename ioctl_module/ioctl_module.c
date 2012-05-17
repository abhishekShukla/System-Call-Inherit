/*
 * This file is a module code for creating a character device. Two new IOCTLs
 * are defined for this character device.The name of the device is "ioctl_device".
 * 
 * Ioctls are:
 * 1) IOCTL_SET_VECTOR - This ioctl is used by user process to pass the vector name
 *    to this module, where this module finds the corresponding address of vector 
 *    corresponding to its name in the list of registered vectors maintained by 
 *    "reg_unreg" module. 
 *    If it finds the address it changes adds this address to a newly added 
 *    field "void *syscall_inherit_data" in "struct task_struct". 
 *
 * 2) IOCTL_REMOVE - This ioctl is used by user process to clear the 
 *    "void * syscall_inherit_data" field in task structure. Also, it calls the helper
 *    which reduces the reference counter of system_call_vector which was earlier 
 *    incremented when the IOCTL_SET_VECTOR was called.
 *
 * Thus, to maintain consistency of system, both the IOCTLs must be called by user process.
 * IOCTL_SET_VECTOR marks the beginning of usage of overridden system call function table.
 * IOCTL_REMOVE marks ending of its usage. So, Former ioctl must be called on starting
 * the process and latter while exiting.
 *
 * The device created is registered in /proc/devices with major number "121"(randomly chosen).
 *
 * Before making ioctl system call device file needs to be created in /dev file system.
 * For that "mknod" command is used.
 * Syntax:   mknod <device_file_path> <device_type> <major_number> <minor_number>
 * eg:-  mknod /dev/ioctl_device c 121 212
 * c denotes character device, 121 major number and 212 minor number. The numbers are chosen
 * randomly but are made sure that no other device uses them.
 * (see "make.sh")
 *
 * Locking has been taken care of before accessing the task structure.
 *
 */


#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/sched.h>
#include <linux/mutex.h>

#include "../override_syscall.h"
#include "ioctl_proc.h"

#define AUTHOR "Group 12"
#define DESCRIPTION "\'proc_test\' LKM"
#define DEVICE_NAME "ioctl_device"

MODULE_LICENSE("GPL");
MODULE_AUTHOR(AUTHOR);
MODULE_DESCRIPTION(DESCRIPTION);

/*
 * exported in reg_unreg.c
 */
extern unsigned long get_vector_address(char *vector_name);
extern int reduce_ref_count(char *vector_name);
struct mutex mut_lock;

/*
 * This function checks if void *syscall_inherit_data field is empty or not
 * in "current" process' task structure.
 * If empty, adds the vector address to it.
 * returns -1 if error else 0
 */
static int add_to_task_structure(struct syscall_vector *sys_vec) {
	int ret = -1;
	int pid;
	struct task_struct *tsk = NULL;

	tsk = get_current();
	pid = tsk->pid;
	// printk(KERN_INFO " pid is: %d", pid);
	if(tsk->syscall_inherit_data == NULL) {
		ret = 0;
		printk(KERN_INFO "Adding vector address to void* syscall_inherit_data field");
		tsk->syscall_inherit_data = (void *)sys_vec;
	}
	return ret;
}

/*
 * This removes the vector address from syscall_inherit_data field of "current"
 * task structure.
 */
static void remove_from_task_struct(void) {
	struct task_struct *tsk = NULL;

	tsk = get_current();
	if(tsk->syscall_inherit_data != NULL) {
		printk(KERN_INFO "Removing vector address from void* syscall_inherit_data field");
		tsk->syscall_inherit_data = NULL;
	}
}

/*
 * This is the implementation of "unlocked_ioctl" file operation for this character device.
 * Two ioctls have been defined IOCTL_SET_VECTOR and IOCTL_REMOVE, and corresponding 
 * actions as defined on the top has been done.
 *
 * Mutex lock has been used before accessing the task structure of the current process' task 
 * structure, to make sure that nobody else changes its contents at the same time.
 *
 */
static long device_ioctl(struct file *file,	/* ditto */
		 unsigned int ioctl_num,	/* number and param for ioctl */
		 unsigned long ioctl_param)
{
	int ret;
	char  *temp;
	char *vector_name;
	struct syscall_vector* sys_vec;

	mutex_lock(&mut_lock);

	ret = 0;
	vector_name = NULL;
	sys_vec = NULL;
	temp = (char *)ioctl_param;
	vector_name = kmalloc(MAX_VECTOR_NAME_LEN, GFP_KERNEL);
        if(vector_name == NULL) {
                ret = -ENOMEM;
                goto out;
        }
        if (IS_ERR(vector_name)) {
                ret = PTR_ERR(vector_name);
                goto out;
        }

	/* 
	 * Switch according to the ioctl called 
	 */
	switch (ioctl_num) {
	case IOCTL_SET_VECTOR:
		try_module_get(THIS_MODULE);
		ret = copy_from_user(vector_name, temp, MAX_VECTOR_NAME_LEN);
		if(ret < 0) {
			ret = -1;
			goto out;
		}
		printk(KERN_INFO " VECTOR_NAME_RECEIVED is: %s", vector_name);

		sys_vec = (struct syscall_vector *)get_vector_address(vector_name);
		if(sys_vec == NULL) {
			ret = -EINVAL;
		}
		else {
			// printk(KERN_INFO " VECTOR ADDRESS RECEIVED is: %ld", (unsigned long)sys_vec);
			ret = add_to_task_structure(sys_vec);
		}
		if(ret < 0) {
			module_put(THIS_MODULE);
		}
		break;
	case IOCTL_REMOVE:
		ret = copy_from_user(vector_name, temp, MAX_VECTOR_NAME_LEN);
		if(ret < 0) {
			ret = -1;
			goto out;
		}
		// printk(KERN_INFO " VECTOR_NAME_RECEIVED is: %s", vector_name);

		ret = reduce_ref_count(vector_name);
		if(ret < 0) {
			ret = -EINVAL;
		}
		remove_from_task_struct();	
		module_put(THIS_MODULE);
		break;

	default:
		ret = -1;
		break;
	}
out:
	kfree(vector_name);
	mutex_unlock(&mut_lock);
	return (long)ret;
}


/*
 * Only unlocked_ioctl operation is implemented because we only need this for ioctl.
 */
struct file_operations fops = {
	.unlocked_ioctl = device_ioctl,
};

/*
 * Here when we initialize the module a new character device with name "ioctl_device"
 * and major number "121" is registered. It can be seen as registered in "/proc/devices"
 *
 * Returns negative number on error else 0.
 */
static int __init init_ioctl_module(void)
{
	int ret = 0;
	ret = register_chrdev(DEVICE_NUM, DEVICE_NAME, &fops);
	if (ret < 0) {
		printk(KERN_ALERT "%s failed with %d\n",
		       "Sorry, registering the character device ", ret);
		goto out;
	}
	mutex_init(&mut_lock);	
out:
	return ret;
}

/*
 * On exiting, the character device is unregistered.
 */
static void __exit exit_ioctl_module(void)
{
	unregister_chrdev(DEVICE_NUM, DEVICE_NAME);
}

module_init(init_ioctl_module);
module_exit(exit_ioctl_module);
