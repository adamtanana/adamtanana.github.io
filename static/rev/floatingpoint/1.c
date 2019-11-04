#include <stdio.h>

#define LOVE_CONSTANT 1.295f

// Formula to calculate love
float reme(float r1, float r2) {
    return (r1 * (r2 - LOVE_CONSTANT)) / r1;
}

int main(int argc, char* argv[], char* envp[]) {
    printf("%lf", reme(1.8f, 7.2f));
}

