#include <stdio.h>

void reme() {
    __asm__("syscall; ret");
    __asm__("pop rdi; pop rdx; ret;");
    __asm__("pop rsi; ret;");
    __asm__("inc rax; ret;");
    __asm__("xor rax, rax; ret;");
}

int main(int argc, char* argv[], char* envp[]) {
    reme();
}

