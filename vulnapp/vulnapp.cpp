// vulnapp.cpp : Defines the entry point for the console application.
//

#include <stdio.h>
#include <windows.h>

//reads file into buffer and prints it
void printfile(char *filename) {
	char buf[64];
	FILE *fp;
	int filesize;

	fp = fopen(filename,"r");
	if(!fp) {
		printf("Error opening %s\n", filename);
		return;
	}

	fseek(fp, 0, SEEK_END);
	filesize = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	//buffer overflow happens here
	fgets(buf, filesize+1, fp);

	fclose(fp);

	puts(buf);
}

int main(int argc, char* argv[])
{
	char buf[200]; //some local variables, making sure there is enough place on the stack for the paylaod
	for(int i=0;i<200;i++) buf[i] = 'b'; //use local variables so compiler won't remove them

	if(argc!=2) {
		printf("Usage: %s <filename>\n", argv[0]);
		return 0;
	}

	//needed for the rop payload
	if(!LoadLibrary("msvcr71.dll")) {
		printf("msvcr71.dll not found\n");
		return 0;
	}

	//buffer overflow happens in this function
	printfile(argv[1]);

	if(buf[199]) { //use local variables so compiler won't remove them
		return 0;
	}

	return 0;
}
