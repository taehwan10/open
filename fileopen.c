#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>


int main(void){

	int fd;
	char *fname = "/mnt/test/test.txt";
	if((fd = open(fname, O_RDONLY)) < 0){
		printf("\n실패\n");
		return -1;
	}
	else
		printf("success!\nFilename : %s\nDescriptor :%d\n", fname, fd);

	close(fd);
	return 0;

}
