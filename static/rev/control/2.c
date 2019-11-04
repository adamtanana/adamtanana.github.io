#include <stdio.h>

void reme(char *dst, char* src) {
    while(*src != '\000') {
        *dst = *src;
        dst++;
        src++;
    }
}

int main(int argc, char* argv[], char* envp[]) {
    reme(argc, "I love me");
}

