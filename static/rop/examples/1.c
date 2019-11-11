#include <stdio.h>

void reme() {
    __asm__("pop rdi; pop rax; ret");
    __asm__("pop rsi; ret;");
}

int main(int argc, char* argv[], char* envp[]) {
    reme();
}

