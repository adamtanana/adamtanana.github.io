#include <stdio.h>

void login() {
    int is_admin = 0;
    char username[16];

    gets(username);
    
    if (is_admin) {
        printf("You now have admin permissions\n");
    } else {
        printf("You aren't an admin\n");
    }
}

int main() {
    login();
}
