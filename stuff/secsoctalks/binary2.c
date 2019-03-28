#include <stdio.h>

void notcalled() {
    printf("What\n");
}

void echo() {
    char buffer[16];

    printf("Enter some text\n");
    gets(buffer);
    printf("You entered %s\n", buffer);
}

int main() {
    echo();
    return 0;
}

