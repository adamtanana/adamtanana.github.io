```
#include <stdio.h>

int xor_array[100] = {0, 1, 2, 3}; // 2 lazy to do rest
int iv_array[100] = {3, 2, 1, 0}; // 2 lazy to do rest

int md18(int len, char* s) {
    int number = 0; 

    for(int i = 0; i < len; i++) {
        number += xor_array[i % 100] ^ s[i] % iv_array[i % 100];
    }

    int masker = 0;
    int done = 0;
    while (!done) {
        if (masker == 0)
            goto stage_a;
        if (masker == 1)
            goto stage_b;
        if (masker == xor_array[masker % 100] ^ iv_array[masker % 100])
            goto stage_c;
        if (masker == xor_array[17]) 
            goto stage_d;

stage_a:
        for (int i = 0; i < 100; i++) {
            masker += xor_array[i ^ masker] % 100;
        }
        goto end_loop;

stage_b:
        number += masker;
        goto end_loop;

stage_c:
        for(int i = 0; i < 100; i++) 
            xor_array[i] = iv_array[i] ^ masker;
        goto end_loop;

stage_d:
        done = 1;
        goto end_loop;


end_loop:
        if(done) 
            break;
    }

    

end:
    return number;
}

int main(

        ){
md18(1, NULL);
}
```
