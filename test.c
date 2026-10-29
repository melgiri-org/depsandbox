#include <stdio.h>
#include <sys/types.h>
#include <wait.h>
#include <unistd.h>

int main(){
	pid_t p = fork();

	if(p == 0){
		printf("child\n");
		FILE *f = fopen("/home/cicd/.npm/sign", "r");
		char buffer[256];

		if (f == NULL) {
			printf("Error opening file.\n");
		}
		// 2. Read line by line until the end of the file (EOF)
		while (fgets(buffer, sizeof(buffer), f) != NULL) {
			printf("%s", buffer);
		}
		fclose(f);
	}
	else {
		printf("Parent\n");
		// wait(NULL);

		FILE *f = fopen("/bin/ls", "r");
		fclose(f);	
	}
	return 0;
}
