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

#define MAX_FILENAME 512
#define MAX_VECTOR_NAME_LEN 256
/* 
 * Functions for the ioctl calls 
 */

int ioctl_remove_vector(int file_desc, char* addr)
{
	int ret = 0;

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

	if((argc < 2) || (strlen(argv[1]) > MAX_VECTOR_NAME_LEN)) {  
		printf("Format: \n$/> ./fork_ioctl {vector_name}\n");
		printf("Vector name must be of maximum length of 256\n");
		goto out;
	}

	printf("\nTesting fork. For testing we are using \"file_ops_vector\" \n\n");

	file_name = (char*)malloc(MAX_FILENAME);
	memset(file_name, 0, MAX_FILENAME);
	memcpy(file_name, proc, strlen(proc));

	vector_name = (char*)malloc(MAX_VECTOR_NAME_LEN);
	memcpy(vector_name, argv[1], strlen(argv[1]));
	file_desc = open(file_name, 0);
	if (file_desc < 0) {
		printf("Can't open file: %s\n", file_name);
		goto free_out;
	}

	ret = ioctl_set_vector(file_desc, vector_name);
	if(ret < 0) {	
		goto free_out;
	}

	printf("Parent process ID : %d\n", getpid());
	ret = open("test3_parent", O_CREAT);
	printf("OPEN: New File is created with name \"test3_file\" and file descriptor : %d\n\n", ret);

	if ( ( child_id = fork()) == 0)                // child
	{
		printf("Child process ID : %d\n", getpid());
		printf("Calling overridden fchown() in child ... \n");
		ret =  fchown(11, 22 , 33); 
		printf("FCHOWN: Return value for overridden fchown call is: %d\n\n", ret);

		_exit(0);
	}

	wpid = wait(&status);

	printf("Removing vector address from task structure\n\n");
	ret = ioctl_remove_vector(file_desc, vector_name);
	if(ret < 0) {
		goto free_out;
	}

	printf("Exiting ... \n\n");

free_out:
	if(file_desc > 0)
		close(file_desc);

	free(vector_name);
	free(file_name);
out:
	return ret;
}
