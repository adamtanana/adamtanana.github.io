---
layout: page
title: projects
permalink: /projects/
---

todo:
writeup on Modular malware
Writeup on rootkit

As part of the UNSW Course COMP6447: System and Software Security Assessment, I worked in a team of four to write a basic rootkit for the FreeBSD OS

# Basic Assignment Specification
## Rootkit

You are permitted to do anything you wish to achieve the following fundamental functionality

    Provide a method to escalate to uid(0) (root) by a low privileged/non-root user/binary.
    Attempt to hide itself from detection. e.g. concealing itself from kldstat, and userland components from find.

## Rootkit Detection

You must return status code 0 if no rootkit is detected, and return 1 if a rootkit is detected. You may print whatever output you wish during the script.

## Fundamental Functionality


### Key Utilities 

#### Inline Hooking

We need a way of communicate to the kernel from userland, we do this via inline hooking of system calls.<br />
We have a utility called `do_hook`, which takes in a function to overwrite and a function to overwrite it with.<br />
```c
void do_hook(void* overwrite, void* func) {
	char* function_to_overwrite = (char*) overwrite;
	char* function_to_call = (char*) func;

	uprintf("Overwriting %p with %p\n", function_to_overwrite, function_to_call);

	int diff = (int) ((function_to_call - function_to_overwrite) - 5);

	int* new_lol = (int*) (function_to_overwrite+1);
	function_to_overwrite[0] = 0xe9; // JMP
	new_lol[0] = diff;
}
```

The first instruction of the original function becomes a x86 JMP32 command. This command has the opcode 0xe9 followed by a 4 byte relative address to where you want to jump to. <br />

We can calculate the relative address by subtracting the function we want to jump to by the address we are patching. `func_to_overwrite - func_to_jump_to`.
To summarise, we overwrite the function with 0xe9 followed by the calculated offset. This is all done by just referencing the function as a char array, and setting the first 5 bytes.

#### Hidden Files

We also needed a way of creating hidden files from the userland <br />

You'll often see files prepended with hd. We refere to these as hidden files. This indicates the file is hidden from the user and can neither be listed or read from syscalls. <br />

This is all done by using the hooker described above to change `getdirentries`, `open` and `read`.<br />
Specifically the hooks do the following:

* getdirentries: Hidden files are removed from the outputed entries list.
* open: Keeps track of all file descriptors that references a Hidden file via a linked list.
* read: Returns NULL back to the user if the file descriptor refernced is in the linked list of Hidden files.

### Priv Esc

Now we needed a way to escalate to root privs from userland. <br />
This is done by implementing a backdoor in our rootkit module. Specically, the following line of C will increase the privledges of the caller to uid=0.
```c
read(0xdeadbeef, NULL, 0xdeadb33f)
```

This is done internally by editing the current processes `struct ucred`

```c
void escalate_privs(struct thread* td) {
    struct ucred* creds = td->td_ucred;

    // uid
    creds->cr_uid = 0;
    creds->cr_ruid = 0;
    creds->cr_svuid = 0;

    // groups
    creds->cr_rgid = 0;
    creds->cr_svgid = 0;
}
```

### Concealment

## Hiding processes

Freebsd keeps a few lists of running processes in the kernel. Particularly the global lists `p_list` and `p_hash` contains a linked list of running processes. We can therefore simply unlink any processes we wish from these lists, making the processes hidden from other users running tests.

## Bonuses



## Extended Detector

TODO explain detector

