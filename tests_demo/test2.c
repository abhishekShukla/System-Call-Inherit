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
int main(int argc, char **argv)
{
	int ret = 0;
	int child_id = -1;
	int file_desc, i;
	char proc[]= "/dev/ioctl_device";
	char *vector_name;
	char *file_name; 	
	char buf[100];

        if((argc < 2) || (strlen(argv[1]) > MAX_VECTOR_NAME_LEN)) {
                printf("Format: \n$/> ./fork_ioctl {vector_name}\n");
                printf("Vector name must be of maximum length of 256\n");
                goto out;
        }

	printf("\nTest for \"link_vector\" which overrides link and wraps unlink system calls .. \n\n");
	printf("My process ID : %d\n", getpid());

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
	
	printf("Task Structure has new vector address now .. \n\n");

	printf("Calling overridden function link\n");
	ret = link("link_old", "link_new");
	printf("LINK: Return value for link call is: %d\n\n", ret);

	printf("Calling wrapped function unlink. Unlinking \"test1_file\"\n");
	ret =  unlink("test1_file"); 
	printf("UNLINK: Return value for unlink call is: %d\n\n", ret);

	printf("Removing vector address from task structure .. \n\n");
	ret = ioctl_remove_vector(file_desc, vector_name);
	if(ret < 0) {
		goto free_out;
	}

	printf("Exiting ... \n\n");

	close(file_desc);

free_out:
	free(file_name);
	free(vector_name);
out:
	return ret;
}
