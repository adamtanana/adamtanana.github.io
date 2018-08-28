---
layout: post
title: Format Strings!
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
____________________________________________________________________

before we have fun with breaking programs let's learn a bit of assembly. This post will mainly discuss 32 bit systems, but 64 bit systems are vulnerable to the exact same style of attack. Here I've compiled a simple C program that calls printf("Hello World\n%d", 100)



 

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


