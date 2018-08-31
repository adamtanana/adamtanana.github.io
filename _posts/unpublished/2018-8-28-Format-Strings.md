---
layout: post
title: Format Strings!
author: adamt
---

Let's learn how printf works.
-------------------------------------------------------------

Exploit development is a tricky subject, it isn't meant to be easy, however I will try my best to make this post/tutorial as easy to understand and follow through as possible, with as little prerequisite knowledge as possible. But please do understand that it's impossible to teach everything (man 3 printf) and by the end of this post you should have a pretty good understanding of pre 2005 format string vulnerabilities and enough knowledge to go and do more research.

Hopefully by the end of this post we will have successfully understood and solved the Defcon 2015 babyecho challenge.

## Table of contents.... ?
----------------------------------------
1 tools and stuff you should use

2 how printf works low level

  * super basic intro to x86 assembly
  * super basic into to function calls in x86 assembly/libc
  * different format modifiers (plus how they work)

3 leaking data from the stack

  * manipulating what we learnt in part 1, to take advantage of a vulnerable program
  * mapping out all the variables on a stack

4 leaking data from... anywhere??
  
  * Reading from any arbitrary memory address

5 leaking the entire binary

  * virtual memory
  * how a program is loaded into memory
  * memory regions

6 writing data to a pointer stored on the stack
  * writing data to anywhere in the program??
  * writing large ints/pointers/words quickly

7 Popping Shellz for fun
  
  * not changing code flow?
  * overwriting the return address
  * overwriting a got address

8 how to solve a defcon challenge

9 maybe a history lesson if i remember to do it


1) Useful tools
--------------------------------------
____________________________________________________________________

In this section I'll be discussing what tools I'll be using below, as well as a super basic introduction into how to use them. (They all have amazing documentation)
I'm assuming you are running on a unix environment (mac or linux). Some of these tools do have issues running on mac but there are fixes online. ***Linux*** is the best option however (virtual machine or dual boot).

First thing you are going to need is a text editor you are confident with, whether it be vim,emacs,subslime,googledocs,atom. As long as you are confident using it we are good to go.

The rest of the tools (and many tools used within the security field) require either ***python2.7 or python3***, installing both of these ever in a virtual machine, a virtual environment or your main machine will be essential.

Debugger - You are going to need to know how to use gdb to follow through in this post, furthermore I would highly recommend installing either the; pwndbg, gef, or peda addons for gdb, these make it so much easier to step through the program and build an understanding of the program, which is essential. (I personally use ***pwndbg*** for its wide range of commands and colour coding of different memory regions)

A Scripting API - Having python is one thing, but I'd highly recommend installing the ***pwntools***  library. It is a stand alone library that implements so many useful features and makes connecting to binaries/servers and writing exploits super easy.

A good disassembler - Although this isn't really required, it is super useful to a graphical interface (other than objdump/gdb) for moving around large chunks of code whilst trying to build a picture of how a program works. I personally use ***binaryninja*** (has a demo version available), it has a great user interface, and is simple and intuitive to use. Other options include IDA (super fkin complicated), Hopper, Radare (super fkin complicatedtoo). Each has its own set of skills and it's good to have a basic understanding of how to use each of them.

2) what is printf?
--------------------------------------
if you already have a basic understanding of intel x86 assembly and libc function calling conventions you can skip this section.
____________________________________________________________________

before we have fun with breaking programs let's learn a bit of assembly. This post will mainly discuss 32 bit systems, but 64 bit systems are vulnerable to the exact same style of attack. Here I've compiled a simple C program that prints `Hello world\n100`

```C
int main() {
  printf("Hello World %d \n", 100);
}
```

We can then disassemble the binary using objdump or binaryninja:

```
 0x8048426 <main>:
 0x8048426: 8d 4c 24 04           lea    ecx,[esp+0x4]
 0x804842a: 83 e4 f0              and    esp,0xfffffff0
 0x804842d: ff 71 fc              push   DWORD PTR [ecx-0x4]
 0x8048430: 55                    push   ebp
 0x8048431: 89 e5                 mov    ebp,esp
 0x8048433: 53                    push   ebx
 0x8048434: 51                    push   ecx
 0x8048435: e8 2a 00 00 00        call   0x8048464 <__x86.get_pc_thunk.ax>
 0x804843a: 05 c6 1b 00 00        add    eax,0x1bc6
 0x804843f: 83 ec 08              sub    esp,0x8
 0x8048442: 6a 64                 push   0x64
 0x8048444: 8d 90 f0 e4 ff ff     lea    edx,[eax-0x1b10] {"Hello World %d\n"}
 0x804844a: 52                    push   edx
 0x804844b: 89 c3                 mov    ebx,eax
 0x804844d: e8 8e fe ff ff        call   0x80482e0 <printf@plt>
 0x8048452: 83 c4 10              add    esp,0x10
 0x8048455: b8 00 00 00 00        mov    eax,0x0
 0x804845a: 8d 65 f8              lea    esp,[ebp-0x8]
 0x804845d: 59                    pop    ecx
 0x804845e: 5b                    pop    ebx
 0x804845f: 5d                    pop    ebp
 0x8048460: 8d 61 fc              lea    esp,[ecx-0x4]
 0x8048463: c3                    ret  
``` 

We can break this down into 3 main parts. <br />
\> Function prologue <br />
\> Printf call <br />
\> Function epiloge <br />

The function prologue essentially initiates a stack frame for our function to store any local variables it requires. Understanding what each command is doing isn't really important at this point, but understanding the big picture is important.

```
 0x8048426 <main>:
 0x8048426: 8d 4c 24 04           lea    ecx,[esp+0x4]
 0x804842a: 83 e4 f0              and    esp,0xfffffff0
 0x804842d: ff 71 fc              push   DWORD PTR [ecx-0x4]
 0x8048430: 55                    push   ebp
 0x8048431: 89 e5                 mov    ebp,esp
 0x8048433: 53                    push   ebx
 0x8048434: 51                    push   ecx
 0x8048435: e8 2a 00 00 00        call   0x8048464 <__x86.get_pc_thunk.ax>
 0x804843a: 05 c6 1b 00 00        add    eax,0x1bc6
 0x804843f: 83 ec 08              sub    esp,0x8
 ```
The first thing this function does is (`and esp, 0xfffffff0`) align the stack to the nearest byte boundary. It then follows by setting up the new stack frame by moving around ebp and esp. This essentially sets up the new stack frame, setting the `EBP` register as the lower boundary of our stackframe and `ESP` as the higher boundary.
`EBP` is usually constant throughout the function, and so if the function wants to add another variable it can move the `ESP` register. 

This function requires 8 bytes of stack space, So it subtracts 8 bytes from esp. Essentially allowing the storage of two 32 bit(4 byte) ints to be stored on the stack




### C/x86 Calling conventions


3) leaking memory
--------------------------------------
____________________________________________________________________

4) more advanced memory leaking
--------------------------------------
____________________________________________________________________

5) even more advanced memory leaking (leaking entire binary)
--------------------------------------
____________________________________________________________________

6) Writing data with %n
--------------------------------------
____________________________________________________________________

7) more advanced data writing
--------------------------------------
____________________________________________________________________

8) large and efficient writes
--------------------------------------
____________________________________________________________________

9) Poppin shellz
--------------------------------------
____________________________________________________________________

10) Defcon CTF 2015 Babyecho Writeup (finally)
--------------------------------------
____________________________________________________________________


