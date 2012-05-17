/*
 *  fork_eg.c - the process to use ioctl's to control the kernel module
 *
 */

/* 
 * device specifics, such as ioctl numbers and the
 * major device file. 
 */
#include "ioctl_proc.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>		/* open */
#include <unistd.h>		/* exit */
#include <sys/ioctl.h>		/* ioctl */
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <sched.h>

#define MAX_FILENAME 512
#define MAX_VECTOR_NAME_LEN 256
/* 
 * Functions for the ioctl calls 
 */

int ioctl_remove_vector(int file_desc, char* addr)
{
	int ret = 0;
	
	printf("\n");
	ret = ioctl(file_desc, IOCTL_REMOVE, addr);
	if (ret < 0) {
		printf("ioctl_remove_vector failed:%d %d\n", errno, file_desc);
		perror("ERROR ");
	}
	return ret;
}

int ioctl_set_vector(int file_desc, char* addr)
{
	int ret = 0;

	ret = ioctl(file_desc, IOCTL_SET_VECTOR, addr);
	if (ret < 0) {
		printf("ioctl_set_vector failed:%d %d\n", errno, file_desc);
		perror("ERROR ");
	}

	return ret;
}

clone_body(void *arg) {
	int ret1 = 0;
	printf("Child process ID : %d\n", getpid());
	ret1 = open("test_clone", 66, 77);
	printf("child return value is: %d\n\n", ret1);
	_exit(0);
}



/* 
 * Main - Call the ioctl functions 
 */
int main(int argc, char **argv)
{
	int ret = 0;
	int child_id = -1;
	int file_desc, i;
	int status = 0;
	pid_t wpid;
	char *vector_name;
	char *file_name; 	
	char proc[]= "/dev/ioctl_device";
	void **stack = NULL;

	if((argc < 2) || (strlen(argv[1]) > MAX_VECTOR_NAME_LEN)) {  
		printf("Format: \n$/> ./fork_ioctl {vector_name}\n");
		printf("Vector name must be of maximum length of 256\n");
		goto out;
	}

	file_name = (char*)malloc(MAX_FILENAME);
	memset(file_name, 0, MAX_FILENAME);
	memcpy(file_name, proc, strlen(proc));

	vector_name = (char*)malloc(MAX_VECTOR_NAME_LEN);
	memcpy(vector_name, argv[1], strlen(argv[1]));
	file_desc = open(file_name, 0);
	if (file_desc < 0) {
		printf("Can't open file: %s\n", file_name);
		goto clean_out;
	}

	printf("\n");
	ret = ioctl_set_vector(file_desc, vector_name);
	if(ret < 0) {	
		goto free_out;
	}

	printf("\nTesting clone() for \"open\" only. So need to use \"file_ops_vector\"\n\n");
	printf("Parent process ID : %d\n", getpid());
	ret = open("test2", 22, 33);
	printf("parent return value for open call is: %d\n\n", ret);

	// sleep(1);
	stack = (void**)malloc(65536);
	printf("Calling clone .. \n");
	ret = clone(&clone_body, stack+6553, SIGCHLD | CLONE_FILES | CLONE_VM, NULL);
	if(ret < 0) {
		printf("ERROR:  Ret of clone is negative\n\n");
	}

	wpid = wait(&status);

free_out:
	printf("Removing vector address from task structure .. \n\n");
	ret = ioctl_remove_vector(file_desc, vector_name);
	if(ret < 0) {
		goto free_out;
	}
	printf("Exiting .. \n");

clean_out:
	if(file_desc > 0) 	{ close(file_desc); }
	if(stack != NULL) 	{ free(stack); }
	if(vector_name != NULL) { free(vector_name); }
	if(file_name != NULL) 	{ free(file_name); }
out:
	return ret;
}
