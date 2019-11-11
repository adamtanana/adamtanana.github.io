#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char * not_used = "/bin/sh";
char * used     = "/bin/date";

int not_call() {
    return system(used);
}

void vulnerable_function() {
    char buf[128];
    read(0, buf, 256);
}

int main(){
    setbuf(stdout, NULL);
    printf("how can i haq?\n> ");
    vulnerable_function();
}
