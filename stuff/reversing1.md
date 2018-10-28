```c
int printEvenSum(int* a) {
    int sum = 0;
    for(int i = 0; i < 50; i++) {
        if (a[i] % 2 == 0) {
            sum += a[i];
        }
    }
}
```
