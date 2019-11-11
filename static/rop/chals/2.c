#include <stdio.h>

void be_exploited() {
	char buffer[8];
	printf("this binary seems a lot larger than most...\n");
	gets(buffer);
}

int main(int argc, char* argv[]) {
	char buffer[1024];
	setbuf(stdout,NULL);
	be_exploited();
}
