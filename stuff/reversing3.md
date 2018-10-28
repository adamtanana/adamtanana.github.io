```c
struct node {
    char* a;
    struct node* next;
};


int main(int argc, char** argv) {
    if(argc < 2) {
        return -1;
    }


    int number = atoi(argv[1]);
    struct node* head;

    for (int i = 0; i < number; i++) {
        struct node* new = malloc(16);

        new->a = argv[2];
        new->next = head;

        head = new;
    }

    return 0;
}
```
