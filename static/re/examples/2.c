#include <stdio.h>

int reme() {
    int sum = 0;
    for (int i = 0; i < 100; i++) {
        sum += i;
    }
    return sum;
}

int main(int argc, char* argv[], char* envp[]) {
    reme();
}

