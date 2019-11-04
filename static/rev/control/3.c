#include <stdio.h>

int somefunc(long int a, long int b, long int c, char* d) {
    printf("Hi %s\n", d);

    if (a > 0) {
        return a + b + c;
    } else {
        return -1;
    }

}

void reme() {
    somefunc(0x9121321313, 0xdeadbeeffeeddead, 0x123333456, "Hi Sir");
}


int main(int argc, char* argv[], char* envp[]) {
    reme();
}

