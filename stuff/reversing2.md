```c
struct person {
    char* name;
    int age;
    char* course;
};

struct person*  doStuff(char* name, int age, char* course) {
    if(name == NULL || course == NULL) {
        return NULL;
    }

    if (strlen(name) == strlen(course) && strlen(name) == 0) {
        return NULL;
    }

    if (age < 18) {
        return NULL;
    }

    struct person* new = malloc(sizeof(struct person));
    if(!new) {
        return NULL;
    }

    new->name = name;
    new->age = age;
    new->course = course;

    return new;
}
```
