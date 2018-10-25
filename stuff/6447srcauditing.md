gcc gave me like 30 warnings so enjoy


```c
#include <stdio.h>
#include <stdlib.h>

#define MAX_INPUT 10
#define NAME_SIZE 0x10 + 1 // The nullbyte

typedef struct human* human; // humanception


struct human {
    char* name;
    unsigned int age;
    unsigned int version; // wtf r we all droids??
    human next;
};

// Global variables
human head_of_humans;

human create_human(char* name, int age, int version);
void create_humans(unsigned int number_of_humans);
void print_list();
void old_print_list();
char* generate_html_human(human hummy);
void free_by_name(char* name);

int main(int argc, char* argv[])
{

    if (argc < 2) {
        puts("Required arguments 1!.. ./program number \n") ;
        return -1;
    }


    int number = atoi(argv[1]);


    if (MAX_INPUT < number) {
        puts("Oi nah max input 10\n");
    }


    create_humans(number);

    while(1) {
        char cmd[100] = {0};

        if(strncmp(cmd, 3, "del")) {
            free_by_name(cmd + 3);
        } else if(strncmp(cmd, 3, "prn")) {
            print_list();
        } else if(strncmp(cmd, 3, "gen")) {
            // generate html for later usage. current not used
            generate_html_human(head_of_humans);
        }
    }

}

void print_list() {
    printf("human found! ");
    for(human curr = head_of_humans; curr != NULL; curr = curr->next) {
        printf("%s", curr->name);
        puts("\n");
    }
}

void old_print_list() {
    printf("human found! ");
    for(human curr = head_of_humans; curr != NULL; curr = curr->next) {
        printf(curr->name);
        puts("\n");
    }
}

void free_by_name(char* name) {
    puts("Clearing names: ");
    for(human curr = head_of_humans; curr != NULL; curr = curr->next) {
        if(strcmp(curr->name, name)) {
            printf("%d", curr->name);
            puts(", ");
            if(curr != head_of_humans) {
                free(curr);
                free(curr->name);
            }

        }
    }
}


void create_humans(unsigned int number_of_humans) {
    for(int i = 0; i < number_of_humans; i++) {
        char* name = malloc(0x10);
        memset(name, 0x10, 0); // Clear name

        fgets(name, NAME_SIZE, stdin);

        char age[5];
        scanf("%5s", age);

        char version[3];
        scanf("%%s", version);

        if(atoi(version) > 10) {
            exit(-1);
        }

        human new = create_human(name, atoi(age), atoi(version));
        new->next = head_of_humans;

        head_of_humans = new; //prepend to list
        free(name);
    }
}

human create_human(char* name, int age, int version) {
    human new = malloc(sizeof(struct human));
    new->name = malloc(sizeof(name));
    strcpy(new->name, name);
    new->age = age;
    new->version = version;
    return new;
}


char* generate_html_human(human hummy) {
    char yes[1000] = {0};
    sprintf(yes, hummy->name);
    strcat(yes, " is my name. say it proud!");
    strcat(yes, " idk how to add age as a string so pretend i did that here thx");
    return yes;
}
```
