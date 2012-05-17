/*
 *  user_ioctl.c - the process to use ioctl's to control the kernel module
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
int main( )
{
	int ret = 0;
	int child_id = -1;
	int file_desc, i;
	char proc[]= "/dev/ioctl_device";
	char file_ops[] = "file_ops_vector\0";
	char link_vector[] = "link_vector\0";
	char *vector_name;
	char *file_name; 	
	char *buf = NULL;

	printf("\nTest for inserting multiple vectors in single user process at different times.. \n\n");
	printf("My process ID : %d\n", getpid());

	file_name = (char*)malloc(MAX_FILENAME);
	memset(file_name, 0, MAX_FILENAME);
	memcpy(file_name, proc, strlen(proc));

	vector_name = (char*)malloc(MAX_VECTOR_NAME_LEN);
	memcpy(vector_name, file_ops, strlen(file_ops));
	file_desc = open(file_name, 0);
	if (file_desc < 0) {
		printf("Can't open file: %s\n", file_name);
		goto free_out;
	}

	printf("Adding \"file_ops_vector\" to current user process ... \n");
	ret = ioctl_set_vector(file_desc, vector_name);
	if(ret < 0) {
		goto free_out;
	}
	
	printf("Task Structure has new vector address now. \n\n");

	printf("Calling wrapped function open\n");
	ret = open("test5_file", O_CREAT, 777);
	printf("OPEN: New File is created with name \"test5_file\" and file descriptor : %d\n\n", ret);

	printf("Removing \"file_ops_vector\" vector address from task structure\n\n");
	ret = ioctl_remove_vector(file_desc, vector_name);
	if(ret < 0) {
		goto free_out;
	}

	sleep(15);

	printf("Adding \"link_vector\" to current user process ... \n");
	ret = ioctl_set_vector(file_desc, vector_name);
	if(ret < 0) {
		goto free_out;
	}
	
	printf("Task Structure has new vector address now. \n\n");

	printf("Calling wrapped function unlink\n");
	ret = unlink("test5_file");

	printf("Removing \"link_vector\" vector address from task structure\n\n");
	ret = ioctl_remove_vector(file_desc, vector_name);
	if(ret < 0) {
		goto free_out;
	}

	sleep(15);

	printf("Task Structure has no vector address now. Calling open system call.\n");
	ret = open("test5_new_file", O_CREAT, 777);
	printf("OPEN: New File is created with name \"test5_new_file\" and file descriptor : %d\n\n", ret);


	printf("Exiting ... \n\n");

	close(file_desc);

free_out:
	free(file_name);
	free(vector_name);
out:
	return ret;
}
