If you want the source to compare hmu on slack `@adamt`
<br />
sorry that the first chal is messed up the compiler did random shit... (skip it is hard)

first chal
---------------------

![easy](../static/6447rev/easy1_ida.png)


<details><summary>Challenge 1 Solution</summary>
<p>
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

</p>
</details>

<br />

second first chal
------------------

![easy](../static/6447rev/medium1_ida.png)

<br />


third chal
----------------------

![easy](../static/6447rev/medium2_ida.png)
