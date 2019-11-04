#include <stdio.h>

int reme(int count) {
    if (count < 0) {
        return -1;
    }

    while (count-- > 0) {
        printf("Time is almost up... %d\n", count);
    }

    return 0;
}

int main(int argc, char* argv[], char* envp[]) {
    reme(8);
}

